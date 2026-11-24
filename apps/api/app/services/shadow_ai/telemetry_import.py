"""Bounded, metadata-only imports of customer-reported network observations."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.db.models.tenant import Tenant
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.shadow_ai.provider_catalog import infer_from_signal


class TelemetryImportError(ValueError):
    def __init__(self, message: str, status_code: int = 422):
        super().__init__(message)
        self.status_code = status_code


def _digest(*values: str) -> str:
    return hashlib.sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


def _time(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError()
        return result.astimezone(timezone.utc)
    except (ValueError, TypeError):
        raise TelemetryImportError("Timestamps must be ISO 8601 with a timezone.") from None


def _domain(value: str) -> str:
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        host = (parsed.hostname or "").lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
            raise ValueError()
        return host
    except ValueError:
        raise TelemetryImportError("A row has an invalid destination hostname.") from None


def parse_telemetry(*, content: str, format: str, source_instance: str,
                    tenant_id: str, window_start: datetime, window_end: datetime):
    if len(content.encode("utf-8")) > 1024 * 1024:
        raise TelemetryImportError("Export exceeds the 1 MiB limit.")
    start, end = _time(window_start.isoformat()), _time(window_end.isoformat())
    if start >= end:
        raise TelemetryImportError("The collection window must end after it starts.")
    fields = {
        "defender_csv": ("Timestamp", "ReportId", "DeviceId", "RemoteUrl", "InitiatingProcessFileName", "InitiatingProcessAccountUpn"),
        "swg_csv": ("timestamp", "event_id", "device_id", "destination", "process_name", "account_id"),
    }[format]
    reader = csv.DictReader(io.StringIO(content.lstrip("\ufeff")))
    try:
        headers = reader.fieldnames or []
    except csv.Error:
        raise TelemetryImportError("CSV headers could not be parsed.") from None
    if len(headers) != len(set(headers)) or not set(fields[:4]).issubset(headers):
        raise TelemetryImportError("CSV headers are missing required fields or contain duplicates.")
    records, outside, unmatched, total = [], 0, 0, 0
    try:
        for row in reader:
            total += 1
            if total > 500:
                raise TelemetryImportError("Export exceeds 500 rows; narrow the collection window.")
            if None in row or any(row.get(key) is None for key in fields[:4]):
                raise TelemetryImportError(f"Row {total + 1} has an invalid column count.")
            timestamp, event_id, device_id, destination = [str(row.get(key) or "").strip() for key in fields[:4]]
            if not event_id or not device_id or max(len(event_id), len(device_id)) > 256:
                raise TelemetryImportError(f"Row {total + 1} needs a bounded event and device identifier.")
            observed = _time(timestamp)
            if not start <= observed < end:
                outside += 1
                continue
            domain = _domain(destination)
            inferred = infer_from_signal({"domain": domain, "source_surface": "endpoint" if format == "defender_csv" else "proxy"})
            if not inferred.get("catalog_match"):
                unmatched += 1
                continue
            process = str(row.get(fields[4]) or "").strip()
            # Exported command lines and paths are never accepted as executable names.
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", process) or re.search(r"(?i)(?:token|secret|password|bearer|sk-)", process):
                process = "unknown"
            account = str(row.get(fields[5]) or "").strip()
            record = {
                "source_event_id": _digest(tenant_id, format, source_instance, device_id, event_id, observed.isoformat()),
                "domain": domain, "tool_name": str(inferred.get("tool_name") or domain),
                "provider": str(inferred.get("provider") or "unknown"),
                "product_key": str(inferred.get("canonical_key") or domain),
                "source_surface": "endpoint" if format == "defender_csv" else "proxy",
                "observed_at": observed.isoformat(), "process_name": process,
                "device_reference": _digest(tenant_id, source_instance, device_id),
                "account_reference": _digest(tenant_id, source_instance, account) if account else None,
                "source_instance": source_instance, "source_format": format,
                "observation_state": "connection_observed", "provenance": "customer_uploaded_export",
            }
            record["payload_hash"] = _digest(json.dumps(record, sort_keys=True))
            records.append(record)
    except csv.Error:
        raise TelemetryImportError("CSV could not be parsed.") from None
    if not total:
        raise TelemetryImportError("Export contains no data rows.")
    return records, {"total": total, "outside_window": outside, "unmatched": unmatched}


def import_telemetry(db: Session, *, tenant_id: str, actor_user_id: str, payload: dict):
    preview = payload["preview"]
    records, counts = parse_telemetry(tenant_id=tenant_id, **{key: payload[key] for key in (
        "content", "format", "source_instance", "window_start", "window_end")})
    if not preview:
        # PostgreSQL serializes imports for the tenant, including concurrent first imports.
        db.execute(select(Tenant.id).where(Tenant.id == tenant_id).with_for_update()).scalar_one()
    ids = [r["source_event_id"] for r in records]
    existing = {r.source_event_id: r for r in db.scalars(select(ShadowAISignal).where(
        ShadowAISignal.tenant_id == tenant_id, ShadowAISignal.source_event_id.in_(ids))).all()}
    seen, observations, duplicates, imported = {}, [], 0, 0
    for record in records:
        event_id = record["source_event_id"]
        previous = existing.get(event_id)
        old_hash = (previous.raw_fingerprint or {}).get("payload_hash") if previous else seen.get(event_id)
        if old_hash and old_hash != record["payload_hash"]:
            raise TelemetryImportError("An event identifier already exists with different metadata. Check the export and source instance.", 409)
        if old_hash:
            duplicates += 1
            continue
        seen[event_id] = record["payload_hash"]
        item = {key: record[key] for key in ("tool_name", "domain", "process_name", "observed_at", "observation_state")}
        if not preview:
            # Keep device/account instances distinct; product approval never transfers implicitly.
            instance = _digest(record["product_key"], record["device_reference"], record["account_reference"] or "unknown")
            name = f'{record["tool_name"][:180]} ({instance[:16]})'
            entity = db.scalar(select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == tenant_id, ShadowAIEntity.canonical_name == name))
            observed = _time(record["observed_at"])
            if entity is None:
                entity = ShadowAIEntity(tenant_id=tenant_id, canonical_name=name, source_surfaces=[record["source_surface"]],
                    vendor=record["provider"], first_seen=observed, last_seen=observed, approved_status="unknown",
                    confidence_score=0.5, metadata_json={"product_key": record["product_key"], "instance_reference": instance})
                db.add(entity)
                db.flush()
            else:
                first = entity.first_seen.replace(tzinfo=timezone.utc) if entity.first_seen.tzinfo is None else entity.first_seen
                last = entity.last_seen.replace(tzinfo=timezone.utc) if entity.last_seen.tzinfo is None else entity.last_seen
                entity.first_seen, entity.last_seen = min(first, observed), max(last, observed)
                entity.source_surfaces = sorted(set(entity.source_surfaces or []) | {record["source_surface"]})
            signal = ShadowAISignal(tenant_id=tenant_id, shadow_ai_entity_id=entity.id,
                source_surface=record["source_surface"], source_event_id=event_id, domain=record["domain"],
                tool_name=record["tool_name"], provider=record["provider"], created_at=observed,
                confidence_signal={"catalog_match": True, "usage_confirmed": False}, raw_fingerprint=record)
            db.add(signal)
            db.flush()
            evidence = create_evidence_node(db, tenant_id=tenant_id, node_type="shadow_ai_source_signal",
                signal_type="shadow_ai.telemetry_import", label=f'Network observation: {record["tool_name"]}',
                payload={"shadow_ai_signal_id": signal.id, "shadow_ai_entity_id": entity.id, **record})
            signal.raw_fingerprint = {**record, "evidence_node_id": evidence.id}
            item.update(entity_id=entity.id, signal_id=signal.id, evidence_id=evidence.id)
            imported += 1
        observations.append(item)
    if not preview:
        write_audit_log(db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human",
            action="shadow_ai.telemetry.import", resource_type="shadow_ai_signal", resource_id=tenant_id,
            payload={"imported": imported, "duplicates": duplicates, "source_instance": payload["source_instance"], **counts})
    return {**counts, "preview": preview, "matched": len(records), "imported": imported,
        "duplicates": duplicates, "observations": observations, "coverage_percent": None,
        "limitations": ["Customer-uploaded evidence; source authenticity is not independently verified.",
            "Connections do not prove prompts, model invocations, account ownership, approval or protection.",
            "Unmatched destinations are not classified; fleet coverage and collection failures cannot be inferred from an export."]}
