from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _to_datetime(value: str | None) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _severity_from_cvss(score: float | None, fallback: str | None = None) -> str:
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "med"
        return "low"
    token = str(fallback or "").strip().lower()
    if token in {"critical", "high", "med", "medium", "low"}:
        return "med" if token == "medium" else token
    return "med"


def _exploit_status_from_text(*, source: str, text_blob: str) -> str:
    if source == "cisa_kev":
        return "known_exploited"
    text = str(text_blob or "").lower()
    if "known exploited" in text or "actively exploited" in text:
        return "known_exploited"
    if "public exploit" in text or "proof-of-concept" in text or "exploit available" in text:
        return "publicly_exploitable"
    return "unknown"


def _nvd_cvss(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None
    keys = [
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV40",
        "cvssMetricV2",
    ]
    for key in keys:
        values = metrics.get(key)
        if not isinstance(values, list):
            continue
        for row in values:
            if not isinstance(row, dict):
                continue
            data = row.get("cvssData")
            if isinstance(data, dict):
                score = data.get("baseScore")
                try:
                    return float(score)
                except Exception:  # noqa: BLE001
                    continue
    return None


def _extract_references(references: Any) -> list[str]:
    rows: list[str] = []
    if isinstance(references, list):
        for item in references:
            if isinstance(item, dict):
                url = str(item.get("url") or "").strip()
            else:
                url = str(item or "").strip()
            if url:
                rows.append(url)
    return sorted(set(rows))


def _normalize_nvd(row: dict[str, Any]) -> dict[str, Any] | None:
    cve = row.get("cve") if isinstance(row.get("cve"), dict) else row
    cve_id = str(cve.get("id") or cve.get("cveId") or "").strip()
    if not cve_id:
        return None

    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    desc = ""
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang") or "").lower() in {"en", "eng", ""}:
            desc = str(item.get("value") or "").strip()
            if desc:
                break

    cvss = _nvd_cvss(cve)
    severity = _severity_from_cvss(cvss)
    references = _extract_references(cve.get("references"))

    configurations = cve.get("configurations")
    components: list[str] = []
    if isinstance(configurations, list):
        for cfg in configurations:
            if not isinstance(cfg, dict):
                continue
            nodes = cfg.get("nodes")
            if not isinstance(nodes, list):
                continue
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                matches = node.get("cpeMatch")
                if not isinstance(matches, list):
                    continue
                for cpe in matches:
                    if not isinstance(cpe, dict):
                        continue
                    uri = str(cpe.get("criteria") or cpe.get("cpe23Uri") or "").strip()
                    if uri:
                        components.append(uri)

    published = _to_datetime(cve.get("published") or row.get("published"))
    updated = _to_datetime(cve.get("lastModified") or row.get("lastModified") or row.get("updated"))

    text_blob = " ".join([desc, " ".join(references)])
    exploit_status = _exploit_status_from_text(source="nvd", text_blob=text_blob)

    return {
        "source_record_id": cve_id,
        "title": cve_id,
        "description": desc,
        "severity": severity,
        "cvss_score": cvss,
        "exploit_status": exploit_status,
        "affected_components": sorted(set(components)),
        "affected_versions": [],
        "references": references,
        "published_at": published,
        "source_updated_at": updated,
        "integrity_status": "verified" if references and desc else "partial",
        "raw_artifact_ref": f"nvd:{cve_id}",
        "raw_payload_ref": {
            "id": cve_id,
            "descriptions": len(descriptions),
            "reference_count": len(references),
        },
    }


def _normalize_cisa_kev(row: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = str(row.get("cveID") or row.get("cveId") or row.get("cve") or "").strip()
    if not cve_id:
        return None

    vendor = str(row.get("vendorProject") or "").strip()
    product = str(row.get("product") or "").strip()
    vuln_name = str(row.get("vulnerabilityName") or cve_id).strip()
    description = str(row.get("shortDescription") or "").strip()
    references = [url for url in [str(row.get("notes") or "").strip()] if url]

    component = " ".join(item for item in [vendor, product] if item)
    published = _to_datetime(row.get("dateAdded"))
    updated = _to_datetime(row.get("dueDate")) or published

    return {
        "source_record_id": cve_id,
        "title": vuln_name,
        "description": description,
        "severity": "critical",
        "cvss_score": None,
        "exploit_status": "known_exploited",
        "affected_components": [component] if component else [],
        "affected_versions": [],
        "references": references,
        "published_at": published,
        "source_updated_at": updated,
        "integrity_status": "verified" if description else "partial",
        "raw_artifact_ref": f"cisa_kev:{cve_id}",
        "raw_payload_ref": {
            "vendor": vendor,
            "product": product,
        },
    }


def _normalize_github(row: dict[str, Any]) -> dict[str, Any] | None:
    advisory_id = str(row.get("ghsa_id") or row.get("id") or "").strip()
    cve_id = str(row.get("cve_id") or "").strip()
    source_id = cve_id or advisory_id
    if not source_id:
        return None

    cvss_score = None
    cvss = row.get("cvss")
    if isinstance(cvss, dict):
        try:
            cvss_score = float(cvss.get("score"))
        except Exception:  # noqa: BLE001
            cvss_score = None

    severity = _severity_from_cvss(cvss_score, str(row.get("severity") or ""))
    references: list[str] = []
    for key in ("html_url", "url"):
        url = str(row.get(key) or "").strip()
        if url:
            references.append(url)

    components: list[str] = []
    vulnerabilities = row.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            package = item.get("package")
            if isinstance(package, dict):
                name = str(package.get("name") or "").strip()
                ecosystem = str(package.get("ecosystem") or "").strip()
                if ecosystem and name:
                    components.append(f"{ecosystem}:{name}")
                elif name:
                    components.append(name)

    description = str(row.get("description") or row.get("summary") or "").strip()
    published = _to_datetime(row.get("published_at"))
    updated = _to_datetime(row.get("updated_at"))
    exploit_status = _exploit_status_from_text(source="github", text_blob=description)

    return {
        "source_record_id": source_id,
        "title": str(row.get("summary") or source_id),
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "exploit_status": exploit_status,
        "affected_components": sorted(set(components)),
        "affected_versions": [],
        "references": sorted(set(references)),
        "published_at": published,
        "source_updated_at": updated,
        "integrity_status": "verified" if source_id and description else "partial",
        "raw_artifact_ref": f"github:{source_id}",
        "raw_payload_ref": {
            "ghsa_id": advisory_id,
            "cve_id": cve_id,
        },
    }


def _normalize_osv(row: dict[str, Any]) -> dict[str, Any] | None:
    osv_id = str(row.get("id") or "").strip()
    aliases = [str(item).strip() for item in (row.get("aliases") or []) if str(item).strip()]
    cve_alias = next((alias for alias in aliases if alias.startswith("CVE-")), "")
    source_id = cve_alias or osv_id
    if not source_id:
        return None

    severity_rows = row.get("severity") if isinstance(row.get("severity"), list) else []
    cvss_score = None
    for item in severity_rows:
        if not isinstance(item, dict):
            continue
        score = str(item.get("score") or "").strip().upper()
        if "CVSS:" in score:
            try:
                cvss_score = float(score.rsplit("/", 1)[-1])
            except Exception:  # noqa: BLE001
                cvss_score = None

    description = str(row.get("details") or row.get("summary") or "").strip()
    severity = _severity_from_cvss(cvss_score)
    exploit_status = _exploit_status_from_text(source="osv", text_blob=description)

    components: list[str] = []
    versions: list[str] = []
    affected = row.get("affected") if isinstance(row.get("affected"), list) else []
    for item in affected:
        if not isinstance(item, dict):
            continue
        package = item.get("package")
        if isinstance(package, dict):
            name = str(package.get("name") or "").strip()
            ecosystem = str(package.get("ecosystem") or "").strip()
            if ecosystem and name:
                components.append(f"{ecosystem}:{name}")
            elif name:
                components.append(name)
        ranges = item.get("ranges")
        if isinstance(ranges, list):
            for rng in ranges:
                if not isinstance(rng, dict):
                    continue
                events = rng.get("events")
                if isinstance(events, list):
                    for event in events:
                        if not isinstance(event, dict):
                            continue
                        for val in event.values():
                            text = str(val or "").strip()
                            if text:
                                versions.append(text)

    references: list[str] = []
    for ref in row.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if url:
            references.append(url)

    return {
        "source_record_id": source_id,
        "title": str(row.get("summary") or source_id),
        "description": description,
        "severity": severity,
        "cvss_score": cvss_score,
        "exploit_status": exploit_status,
        "affected_components": sorted(set(components)),
        "affected_versions": sorted(set(versions)),
        "references": sorted(set(references)),
        "published_at": _to_datetime(row.get("published")),
        "source_updated_at": _to_datetime(row.get("modified")),
        "integrity_status": "verified" if description else "partial",
        "raw_artifact_ref": f"osv:{source_id}",
        "raw_payload_ref": {
            "aliases": aliases,
        },
    }


def _normalize_mitre(row: dict[str, Any]) -> dict[str, Any] | None:
    cve_meta = row.get("cve") if isinstance(row.get("cve"), dict) else row
    cve_id = str(cve_meta.get("id") or cve_meta.get("CVE_data_meta", {}).get("ID") or row.get("cve_id") or "").strip()
    if not cve_id:
        return None

    description = ""
    containers = cve_meta.get("containers") if isinstance(cve_meta.get("containers"), dict) else {}
    cna = containers.get("cna") if isinstance(containers.get("cna"), dict) else {}
    descriptions = cna.get("descriptions") if isinstance(cna.get("descriptions"), list) else []
    for item in descriptions:
        if isinstance(item, dict) and str(item.get("lang") or "").lower() in {"en", ""}:
            description = str(item.get("value") or "").strip()
            if description:
                break

    references = _extract_references(cna.get("references"))
    text_blob = " ".join([description, " ".join(references)])
    exploit_status = _exploit_status_from_text(source="mitre", text_blob=text_blob)

    return {
        "source_record_id": cve_id,
        "title": cve_id,
        "description": description,
        "severity": _severity_from_cvss(None),
        "cvss_score": None,
        "exploit_status": exploit_status,
        "affected_components": [],
        "affected_versions": [],
        "references": references,
        "published_at": _to_datetime(cve_meta.get("datePublished") or row.get("datePublished")),
        "source_updated_at": _to_datetime(cve_meta.get("dateUpdated") or row.get("dateUpdated")),
        "integrity_status": "verified" if description else "partial",
        "raw_artifact_ref": f"mitre:{cve_id}",
        "raw_payload_ref": {
            "container": "cna" if cna else "none",
        },
    }


def normalize_source_records(
    *,
    source: str,
    records: list[dict[str, Any]],
    ingestion_trace_id: str,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    source_key = str(source or "").strip().lower()

    normalizer = {
        "nvd": _normalize_nvd,
        "mitre": _normalize_mitre,
        "cisa_kev": _normalize_cisa_kev,
        "github": _normalize_github,
        "github_advisory": _normalize_github,
        "osv": _normalize_osv,
    }.get(source_key)

    for row in records:
        if not isinstance(row, dict):
            continue
        if normalizer is None:
            source_record_id = str(row.get("id") or row.get("cve") or row.get("advisory_id") or "").strip()
            if not source_record_id:
                continue
            item = {
                "source_record_id": source_record_id,
                "title": str(row.get("title") or source_record_id),
                "description": str(row.get("description") or "").strip(),
                "severity": _severity_from_cvss(None, str(row.get("severity") or "med")),
                "cvss_score": None,
                "exploit_status": _exploit_status_from_text(source=source_key, text_blob=str(row)),
                "affected_components": [str(item).strip() for item in (row.get("affected_components") or []) if str(item).strip()],
                "affected_versions": [str(item).strip() for item in (row.get("affected_versions") or []) if str(item).strip()],
                "references": [str(item).strip() for item in (row.get("references") or []) if str(item).strip()],
                "published_at": _to_datetime(row.get("published_at")),
                "source_updated_at": _to_datetime(row.get("updated_at")),
                "integrity_status": "partial",
                "raw_artifact_ref": f"{source_key}:{source_record_id}",
                "raw_payload_ref": {"record_keys": sorted(str(k) for k in row.keys())[:20]},
            }
        else:
            item = normalizer(row)
            if item is None:
                continue

        item["ingestion_trace_id"] = ingestion_trace_id
        normalized.append(item)

    return normalized
