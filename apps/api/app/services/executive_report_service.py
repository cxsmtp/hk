from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.db.models.user import User
from app.services.simple_pdf import SimplePdfDocument


_SYSTEM_TELEMETRY_LABELS = {
    "about",
    "browser_extension",
    "extension.local",
    "hawk_extension",
    "localhost",
    "monitoring_signal_ingest",
    "unknown_ai_system",
    "unknown_tool",
}
_SYSTEM_EVENT_TYPES = {
    "extension_health_status",
    "extension_status",
    "health",
    "heartbeat",
    "monitoring_signal_ingest",
    "policy_sync",
}

_PALETTE = {
    "ink": (0.11, 0.13, 0.19),
    "muted": (0.42, 0.46, 0.57),
    "line": (0.84, 0.87, 0.92),
    "panel": (0.95, 0.96, 0.99),
    "accent": (0.16, 0.45, 0.93),
    "success": (0.12, 0.60, 0.32),
    "warn": (0.82, 0.55, 0.10),
    "danger": (0.80, 0.23, 0.23),
}


def _is_system_telemetry_label(value: Any) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return True
    return normalized in _SYSTEM_TELEMETRY_LABELS


def _is_system_telemetry_event(event: RuntimeEvent) -> bool:
    metadata = event.metadata_json if isinstance(event.metadata_json, dict) else {}
    labels = {
        str(event.event_type or "").strip().lower(),
        str(event.application or "").strip().lower(),
        str(event.app_id or "").strip().lower(),
        str(metadata.get("domain") or "").strip().lower(),
        str(metadata.get("application") or "").strip().lower(),
        str(metadata.get("app") or "").strip().lower(),
    }
    if labels & _SYSTEM_EVENT_TYPES:
        return True
    return any(_is_system_telemetry_label(label) for label in labels if label)


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _decision(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or "observe"


def _severity(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "medium":
        return "med"
    return normalized or "low"


def _severity_rank(value: Any) -> int:
    return {"critical": 5, "high": 4, "med": 3, "medium": 3, "low": 2}.get(_severity(value), 1)


def _event_prompt_preview(event: RuntimeEvent) -> str:
    metadata = event.metadata_json if isinstance(event.metadata_json, dict) else {}
    for key in ("prompt_preview_redacted", "redacted_prompt_preview", "prompt_redacted", "scrubbed_prompt_preview"):
        value = str(metadata.get(key) or "").strip()
        if value:
            return value
    return ""


def _app_label(*, finding: Finding | None = None, event: RuntimeEvent | None = None) -> str:
    if event is not None:
        metadata = event.metadata_json if isinstance(event.metadata_json, dict) else {}
        for value in (
            event.application,
            metadata.get("application"),
            metadata.get("app"),
            metadata.get("domain"),
            event.app_id,
        ):
            text = str(value or "").strip()
            if text:
                return text
    if finding is not None:
        for value in (finding.application, finding.ai_tool):
            text = str(value or "").strip()
            if text:
                return text
    return "unknown"


def _user_label(
    *,
    user_id: str | None,
    email: str | None,
    user_lookup: dict[str, str],
    machine_id: str | None = None,
) -> str:
    if email and str(email).strip():
        return str(email).strip()
    if user_id and str(user_id).strip():
        return user_lookup.get(str(user_id), str(user_id))
    if machine_id and str(machine_id).strip():
        return f"machine:{str(machine_id).strip()}"
    return "unknown"


def _policy_lookup(db: Session, *, tenant_id: str, findings: list[Finding]) -> dict[str, str]:
    version_ids = sorted({str(row.policy_version_id) for row in findings if str(row.policy_version_id or "").strip()})
    if not version_ids:
        return {}
    versions = db.scalars(
        select(PolicyVersion).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id.in_(version_ids),
        )
    ).all()
    pack_ids = sorted({str(row.pack_id) for row in versions if str(row.pack_id or "").strip()})
    packs = db.scalars(select(PolicyPack).where(PolicyPack.id.in_(pack_ids) if pack_ids else PolicyPack.id == "__none__")).all()
    pack_lookup = {str(row.id): str(row.name or "").strip() for row in packs}
    labels: dict[str, str] = {}
    for version in versions:
        pack_name = pack_lookup.get(str(version.pack_id), "Policy Pack")
        labels[str(version.id)] = f"{pack_name} v{version.version}"
    return labels


def build_executive_report(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    period_start: str,
    period_end: str,
    findings: list[Finding],
    runtime_events: list[RuntimeEvent],
) -> dict[str, Any]:
    discovery_query = select(DiscoveryApplication).where(DiscoveryApplication.tenant_id == tenant_id)
    shadow_entity_query = select(ShadowAIEntity).where(ShadowAIEntity.tenant_id == tenant_id)
    shadow_signal_query = select(ShadowAISignal).where(ShadowAISignal.tenant_id == tenant_id)
    user_ids = sorted(
        {
            str(row.user_id)
            for row in findings
            if str(row.user_id or "").strip()
        }
        | {
            str(row.user_id)
            for row in runtime_events
            if str(row.user_id or "").strip()
        }
    )
    if ai_system_id:
        discovery_query = discovery_query.where(DiscoveryApplication.ai_system_id == ai_system_id)
        shadow_entity_query = shadow_entity_query.where(ShadowAIEntity.linked_ai_system_id == ai_system_id)
        runtime_event_ids = sorted({str(row.event_id) for row in runtime_events if str(row.event_id or "").strip()})
        if runtime_event_ids:
            shadow_signal_query = shadow_signal_query.where(ShadowAISignal.source_event_id.in_(runtime_event_ids))
        else:
            shadow_signal_query = shadow_signal_query.where(ShadowAISignal.id == "__none__")
    users = db.scalars(select(User).where(User.id.in_(user_ids) if user_ids else User.id == "__none__")).all()
    user_lookup = {str(row.id): str(row.email or "").strip() for row in users}
    policy_lookup = _policy_lookup(db, tenant_id=tenant_id, findings=findings)
    discovery_apps = db.scalars(discovery_query).all()
    shadow_entities = db.scalars(shadow_entity_query).all()
    shadow_signals = db.scalars(shadow_signal_query).all()

    severity_counts = Counter(_severity(row.severity) for row in findings)
    decision_counts = Counter(
        _decision(row.decision or (row.status if str(row.status or "").strip().lower() in {"allowed", "blocked", "warned"} else ""))
        for row in findings
    )
    for event in runtime_events:
        decision_counts[_decision(event.decision)] += 1
    risk_category_counts = Counter(str(row.risk_category or "unknown").strip().lower() or "unknown" for row in findings)

    top_violators_map: dict[str, dict[str, Any]] = {}
    for row in findings:
        label = _user_label(
            user_id=str(row.user_id or "").strip() or None,
            email=str(row.user_email or "").strip() or None,
            user_lookup=user_lookup,
            machine_id=str(row.machine_id or "").strip() or None,
        )
        bucket = top_violators_map.setdefault(
            label,
            {
                "user": label,
                "machine_ids": set(),
                "browsers": set(),
                "apps": Counter(),
                "policies": Counter(),
                "findings_count": 0,
                "high_or_critical_count": 0,
                "blocked_count": 0,
            },
        )
        bucket["findings_count"] += int(row.occurrence_count or 1)
        if _severity_rank(row.severity) >= 4:
            bucket["high_or_critical_count"] += 1
        if _decision(row.decision) == "block":
            bucket["blocked_count"] += 1
        if str(row.machine_id or "").strip():
            bucket["machine_ids"].add(str(row.machine_id))
        if str(row.browser_type or "").strip():
            bucket["browsers"].add(str(row.browser_type))
        bucket["apps"][_app_label(finding=row)] += int(row.occurrence_count or 1)
        policy_label = policy_lookup.get(str(row.policy_version_id or ""), str(row.policy_id or "").strip() or "unmapped")
        bucket["policies"][policy_label] += int(row.occurrence_count or 1)

    top_violators = sorted(
        (
            {
                "user": key,
                "findings_count": value["findings_count"],
                "high_or_critical_count": value["high_or_critical_count"],
                "blocked_count": value["blocked_count"],
                "machine_ids": sorted(value["machine_ids"])[:3],
                "browsers": sorted(value["browsers"])[:3],
                "top_app": (value["apps"].most_common(1)[0][0] if value["apps"] else "unknown"),
                "top_policy": (value["policies"].most_common(1)[0][0] if value["policies"] else "unmapped"),
            }
            for key, value in top_violators_map.items()
        ),
        key=lambda row: (int(row["blocked_count"]), int(row["high_or_critical_count"]), int(row["findings_count"])),
        reverse=True,
    )[:8]

    policy_counts: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "blocked": 0, "users": set(), "apps": Counter()})
    for row in findings:
        label = policy_lookup.get(str(row.policy_version_id or ""), str(row.policy_id or "").strip() or "unmapped")
        bucket = policy_counts[label]
        bucket["count"] += int(row.occurrence_count or 1)
        if _decision(row.decision) == "block":
            bucket["blocked"] += 1
        bucket["users"].add(
            _user_label(
                user_id=str(row.user_id or "").strip() or None,
                email=str(row.user_email or "").strip() or None,
                user_lookup=user_lookup,
                machine_id=str(row.machine_id or "").strip() or None,
            )
        )
        bucket["apps"][_app_label(finding=row)] += int(row.occurrence_count or 1)
    policies_violated = sorted(
        (
            {
                "policy": key,
                "count": value["count"],
                "blocked": value["blocked"],
                "users": len(value["users"]),
                "top_app": value["apps"].most_common(1)[0][0] if value["apps"] else "unknown",
            }
            for key, value in policy_counts.items()
        ),
        key=lambda row: (int(row["blocked"]), int(row["count"])),
        reverse=True,
    )[:10]

    blocked_prompts = sorted(
        [
            {
                "timestamp": (_to_datetime(row.created_at) or datetime.min.replace(tzinfo=timezone.utc)).isoformat(),
                "user": _user_label(
                    user_id=str(row.user_id or "").strip() or None,
                    email=str(user_lookup.get(str(row.user_id), "")).strip() or None,
                    user_lookup=user_lookup,
                    machine_id=str(row.machine_id or "").strip() or None,
                ),
                "application": _app_label(event=row),
                "policy": str((row.metadata_json or {}).get("policy_id") or "").strip() or "policy-bound",
                "decision": _decision(row.decision),
                "prompt_preview": _event_prompt_preview(row),
            }
            for row in runtime_events
            if _decision(row.decision) == "block" and _event_prompt_preview(row)
        ],
        key=lambda row: row["timestamp"],
        reverse=True,
    )[:12]

    app_usage_counts: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "blocked": 0, "warned": 0, "users": set()})
    for row in findings:
        label = _app_label(finding=row)
        bucket = app_usage_counts[label]
        bucket["count"] += int(row.occurrence_count or 1)
        decision = _decision(row.decision)
        if decision == "block":
            bucket["blocked"] += 1
        elif decision == "warn":
            bucket["warned"] += 1
        bucket["users"].add(
            _user_label(
                user_id=str(row.user_id or "").strip() or None,
                email=str(row.user_email or "").strip() or None,
                user_lookup=user_lookup,
                machine_id=str(row.machine_id or "").strip() or None,
            )
        )
    for row in runtime_events:
        if _is_system_telemetry_event(row):
            continue
        label = _app_label(event=row)
        if _is_system_telemetry_label(label):
            continue
        bucket = app_usage_counts[label]
        bucket["count"] += 1
        decision = _decision(row.decision)
        if decision == "block":
            bucket["blocked"] += 1
        elif decision == "warn":
            bucket["warned"] += 1
        bucket["users"].add(
            _user_label(
                user_id=str(row.user_id or "").strip() or None,
                email=str(user_lookup.get(str(row.user_id), "")).strip() or None,
                user_lookup=user_lookup,
                machine_id=str(row.machine_id or "").strip() or None,
            )
        )
    for row in discovery_apps:
        label = str(row.tool_name or row.tool_key or "unknown")
        if _is_system_telemetry_label(label):
            continue
        bucket = app_usage_counts[label]
        bucket["count"] += 1
    top_apps_tools = sorted(
        (
            {
                "name": key,
                "count": value["count"],
                "blocked": value["blocked"],
                "warned": value["warned"],
                "users": len(value["users"]),
            }
            for key, value in app_usage_counts.items()
        ),
        key=lambda row: (int(row["count"]), int(row["blocked"])),
        reverse=True,
    )[:12]

    top_shadow_apps = sorted(
        [
            {
                "name": str(row.tool_name or row.tool_key or "unknown"),
                "status": str(row.status or "discovered"),
                "risk_tier": str(row.provisional_risk_tier or "unknown"),
                "vendor": str(row.vendor or "unknown"),
                "last_seen": (_to_datetime(row.last_seen_at) or datetime.min.replace(tzinfo=timezone.utc)).isoformat(),
            }
            for row in discovery_apps
            if not _is_system_telemetry_label(row.tool_name or row.tool_key)
        ],
        key=lambda row: row["last_seen"],
        reverse=True,
    )[:8]
    top_shadow_entities = sorted(
        [
            {
                "name": str(row.canonical_name or "unknown"),
                "status": str(row.discovery_status or "discovered"),
                "risk_tier": str(row.provisional_risk_tier or "unknown"),
                "confidence": round(float(row.confidence_score or 0.0), 2),
                "last_seen": (_to_datetime(row.last_seen) or datetime.min.replace(tzinfo=timezone.utc)).isoformat(),
            }
            for row in shadow_entities
            if not _is_system_telemetry_label(row.canonical_name)
        ],
        key=lambda row: (row["confidence"], row["last_seen"]),
        reverse=True,
    )[:8]

    active_users = sorted(
        {
            _user_label(
                user_id=str(row.user_id or "").strip() or None,
                email=str(row.user_email or "").strip() or None,
                user_lookup=user_lookup,
                machine_id=str(row.machine_id or "").strip() or None,
            )
            for row in findings
        }
        | {
            _user_label(
                user_id=str(row.user_id or "").strip() or None,
                email=str(user_lookup.get(str(row.user_id), "")).strip() or None,
                user_lookup=user_lookup,
                machine_id=str(row.machine_id or "").strip() or None,
            )
            for row in runtime_events
        }
    )

    return {
        "title": "Hawk AI Pilot Executive Report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": {"start": period_start, "end": period_end},
        "summary": {
            "total_findings": len(findings),
            "total_runtime_events": len(runtime_events),
            "blocked_events": sum(1 for row in runtime_events if _decision(row.decision) == "block"),
            "warned_events": sum(1 for row in runtime_events if _decision(row.decision) == "warn"),
            "active_users": len([row for row in active_users if row != "unknown"]),
            "shadow_ai_discovered_count": len(discovery_apps) + len(shadow_entities),
            "shadow_ai_signal_count": len(shadow_signals),
        },
        "sections": {
            "shadow_ai_discovered": {
                "total_discovered": len(discovery_apps) + len(shadow_entities),
                "discovery_applications_count": len(discovery_apps),
                "shadow_entities_count": len(shadow_entities),
                "high_risk_count": sum(
                    1
                    for row in [*discovery_apps, *shadow_entities]
                    if str(getattr(row, "provisional_risk_tier", "") or "").strip().lower() in {"high", "critical"}
                ),
                "top_shadow_apps": top_shadow_apps,
                "top_shadow_entities": top_shadow_entities,
            },
            "risk_breakdown": {
                "severity_counts": dict(sorted(severity_counts.items())),
                "decision_counts": dict(sorted(decision_counts.items())),
                "risk_category_counts": dict(risk_category_counts.most_common(8)),
            },
            "top_violators": top_violators,
            "policies_violated": policies_violated,
            "blocked_prompts": blocked_prompts,
            "top_apps_tools": top_apps_tools,
        },
    }


def _draw_header(page: Any, *, title: str, subtitle: str, y: float) -> float:
    page.add_text(title, x=48, y=y, font_size=24, color=_PALETTE["ink"])
    return page.add_wrapped_text(subtitle, x=48, y=y - 26, max_width=516, font_size=11, color=_PALETTE["muted"])


def _draw_metric_card(page: Any, *, x: float, y: float, label: str, value: str, width: float = 116, height: float = 68) -> None:
    page.add_rect(x=x, y=y - height, width=width, height=height, fill=_PALETTE["panel"], stroke=_PALETTE["line"])
    page.add_text(label.upper(), x=x + 10, y=y - 20, font_size=9, color=_PALETTE["muted"])
    page.add_text(value, x=x + 10, y=y - 44, font_size=22, color=_PALETTE["ink"])


def _draw_bar_group(page: Any, *, title: str, items: list[tuple[str, int]], x: float, y: float, width: float) -> float:
    page.add_text(title, x=x, y=y, font_size=14, color=_PALETTE["ink"])
    cursor = y - 24
    max_value = max([value for _, value in items] or [1])
    for label, value in items[:6]:
        page.add_text(label, x=x, y=cursor + 2, font_size=10, color=_PALETTE["muted"])
        page.add_rect(x=x + 120, y=cursor - 6, width=width - 160, height=12, fill=(0.92, 0.93, 0.97))
        if value > 0:
            bar_width = max(4.0, (width - 160) * (float(value) / float(max_value)))
            color = _PALETTE["danger"] if label == "critical" else _PALETTE["accent"]
            page.add_rect(x=x + 120, y=cursor - 6, width=bar_width, height=12, fill=color)
        page.add_text(str(value), x=x + width - 28, y=cursor + 2, font_size=10, color=_PALETTE["ink"])
        cursor -= 24
    return cursor


def _draw_table(
    page: Any,
    *,
    x: float,
    y: float,
    title: str,
    headers: list[str],
    rows: list[list[str]],
    widths: list[float],
    row_height: float = 20,
    font_size: float = 9,
) -> float:
    page.add_text(title, x=x, y=y, font_size=14, color=_PALETTE["ink"])
    cursor = y - 18
    page.add_rect(x=x, y=cursor - row_height + 4, width=sum(widths), height=row_height, fill=(0.91, 0.94, 0.99), stroke=_PALETTE["line"])
    offset = x + 6
    for idx, header in enumerate(headers):
        page.add_text(header, x=offset, y=cursor - 10, font_size=font_size, color=_PALETTE["ink"])
        offset += widths[idx]
    cursor -= row_height + 6
    for row in rows:
        page.add_rect(x=x, y=cursor - row_height + 4, width=sum(widths), height=row_height, fill=(1, 1, 1), stroke=_PALETTE["line"])
        offset = x + 6
        for idx, cell in enumerate(row):
            max_chars = max(6, int((widths[idx] - 12) / max(font_size * 0.55, 1)))
            page.add_text(str(cell or "")[:max_chars], x=offset, y=cursor - 10, font_size=font_size, color=_PALETTE["ink"])
            offset += widths[idx]
        cursor -= row_height
    return cursor


def render_executive_report_pdf(report: dict[str, Any], *, output_path: Path) -> None:
    summary = dict(report.get("summary") or {})
    sections = dict(report.get("sections") or {})
    period = dict(report.get("period") or {})
    shadow = dict(sections.get("shadow_ai_discovered") or {})
    risk = dict(sections.get("risk_breakdown") or {})
    top_violators = list(sections.get("top_violators") or [])
    policies = list(sections.get("policies_violated") or [])
    blocked_prompts = list(sections.get("blocked_prompts") or [])
    apps_tools = list(sections.get("top_apps_tools") or [])
    pilot_activity = dict(sections.get("pilot_user_activity") or {})

    doc = SimplePdfDocument(title=str(report.get("title") or "Hawk AI Pilot Executive Report"))

    cover = doc.new_page()
    y = _draw_header(
        cover,
        title=str(report.get("title") or "Hawk AI Pilot Executive Report"),
        subtitle=(
            f"Leadership export for pilot reporting. Period: {str(period.get('start') or '')[:10]} to "
            f"{str(period.get('end') or '')[:10]}."
        ),
        y=734,
    )
    cards = [
        ("Findings", str(summary.get("total_findings") or 0)),
        ("Blocked", str(summary.get("blocked_events") or 0)),
        ("Warned", str(summary.get("warned_events") or 0)),
        ("Users", str(summary.get("active_users") or 0)),
    ]
    card_x = 48
    for label, value in cards:
        _draw_metric_card(cover, x=card_x, y=y - 18, label=label, value=value)
        card_x += 128
    severity_items = [(str(key).title(), int(value)) for key, value in dict(risk.get("severity_counts") or {}).items()]
    decision_items = [(str(key).replace("_", " ").title(), int(value)) for key, value in dict(risk.get("decision_counts") or {}).items()]
    left_bottom = _draw_bar_group(cover, title="Risk Breakdown", items=severity_items, x=48, y=580, width=240)
    _draw_bar_group(cover, title="Decision Breakdown", items=decision_items, x=324, y=580, width=240)
    cover.add_wrapped_text(
        (
            f"Shadow AI discovered: {summary.get('shadow_ai_discovered_count') or 0}. "
            f"High-risk shadow items: {shadow.get('high_risk_count') or 0}. "
            f"Top blocked prompt entries and policy hot spots continue on the next pages."
        ),
        x=48,
        y=min(left_bottom, 420),
        max_width=516,
        font_size=11,
        color=_PALETTE["muted"],
    )

    page = doc.new_page()
    _draw_header(page, title="Shadow AI Discovered", subtitle="Pilot visibility into shadow apps and ungoverned AI usage surfaces.", y=734)
    shadow_rows = [
        [
            str(row.get("name") or ""),
            str(row.get("status") or ""),
            str(row.get("risk_tier") or ""),
            str(row.get("vendor") or ""),
        ]
        for row in shadow.get("top_shadow_apps") or []
    ][:8]
    _draw_table(
        page,
        x=48,
        y=670,
        title="Top Shadow Apps",
        headers=["App", "Status", "Risk", "Vendor"],
        rows=shadow_rows or [["No shadow apps", "-", "-", "-"]],
        widths=[200, 110, 80, 126],
    )
    entity_rows = [
        [
            str(row.get("name") or ""),
            str(row.get("status") or ""),
            str(row.get("risk_tier") or ""),
            str(row.get("confidence") or ""),
        ]
        for row in shadow.get("top_shadow_entities") or []
    ][:8]
    _draw_table(
        page,
        x=48,
        y=436,
        title="Top Shadow Entities",
        headers=["Entity", "Status", "Risk", "Confidence"],
        rows=entity_rows or [["No shadow entities", "-", "-", "-"]],
        widths=[220, 110, 90, 96],
    )

    page = doc.new_page()
    _draw_header(page, title="User Risk and Policy Violations", subtitle="Top violators and the policies most frequently triggered in the pilot.", y=734)
    violator_rows = [
        [
            str(row.get("user") or ""),
            str(row.get("findings_count") or 0),
            str(row.get("blocked_count") or 0),
            str(row.get("top_policy") or ""),
        ]
        for row in top_violators
    ][:8]
    _draw_table(
        page,
        x=48,
        y=670,
        title="Top Violators",
        headers=["User", "Findings", "Blocked", "Top Policy"],
        rows=violator_rows or [["No violators", "0", "0", "-"]],
        widths=[230, 80, 80, 156],
    )
    policy_rows = [
        [
            str(row.get("policy") or ""),
            str(row.get("count") or 0),
            str(row.get("blocked") or 0),
            str(row.get("top_app") or ""),
        ]
        for row in policies
    ][:8]
    _draw_table(
        page,
        x=48,
        y=436,
        title="Policies Violated",
        headers=["Policy", "Total", "Blocked", "Top App"],
        rows=policy_rows or [["No policy data", "0", "0", "-"]],
        widths=[250, 70, 70, 156],
    )

    page = doc.new_page()
    _draw_header(page, title="Blocked Prompts and App Usage", subtitle="Redacted blocked prompt previews and the most active apps/tools in the pilot.", y=734)
    prompt_rows = [
        [
            str(row.get("user") or ""),
            str(row.get("application") or ""),
            str(row.get("prompt_preview") or ""),
        ]
        for row in blocked_prompts
    ][:8]
    _draw_table(
        page,
        x=48,
        y=670,
        title="Blocked Prompts (Redacted)",
        headers=["User", "Application", "Prompt Preview"],
        rows=prompt_rows or [["No blocked prompts", "-", "-"]],
        widths=[140, 120, 256],
        row_height=24,
    )
    app_rows = [
        [
            str(row.get("name") or ""),
            str(row.get("count") or 0),
            str(row.get("blocked") or 0),
            str(row.get("warned") or 0),
        ]
        for row in apps_tools
    ][:8]
    _draw_table(
        page,
        x=48,
        y=394,
        title="Top Apps and Tools Used",
        headers=["App / Tool", "Events", "Blocked", "Warned"],
        rows=app_rows or [["No app usage", "0", "0", "0"]],
        widths=[260, 70, 80, 106],
    )

    if pilot_activity:
        page = doc.new_page()
        _draw_header(
            page,
            title="Pilot User Activity Detail",
            subtitle="Per-user pilot evidence: AI tools visited, prompts recorded under storage policy, Shadow AI use, and violations.",
            y=734,
        )
        pilot_cards = [
            ("Pilot Users", str(pilot_activity.get("user_count") or 0)),
            ("Endpoints", str(pilot_activity.get("endpoint_count") or 0)),
            ("Prompts", str(pilot_activity.get("prompt_count") or 0)),
            ("Violations", str(pilot_activity.get("violation_count") or 0)),
        ]
        card_x = 48
        for label, value in pilot_cards:
            _draw_metric_card(page, x=card_x, y=660, label=label, value=value)
            card_x += 128
        pilot_rows = []
        for row in list(pilot_activity.get("users") or [])[:8]:
            tools = list(row.get("ai_tools_visited") or [])
            prompts = list(row.get("prompts_entered") or [])
            shadow_usage = list(row.get("shadow_ai_usage") or [])
            devices = list(row.get("devices") or [])
            device_label = "-"
            if devices:
                first_device = dict(devices[0] or {})
                device_label = str(
                    first_device.get("hostname")
                    or first_device.get("endpoint_id")
                    or first_device.get("browser_name")
                    or "-"
                )
            pilot_rows.append(
                [
                    str(row.get("email") or row.get("display_name") or row.get("user_id") or "unknown"),
                    device_label,
                    ", ".join(str(item.get("tool") or item.get("domain") or "") for item in tools[:2]) or "-",
                    str(len(prompts)),
                    str(len(shadow_usage)),
                    str(len(row.get("violations") or [])),
                ]
            )
        _draw_table(
            page,
            x=48,
            y=566,
            title="User Activity Summary",
            headers=["User", "Device", "AI Tools", "Prompts", "Shadow", "Violations"],
            rows=pilot_rows or [["No pilot user activity", "-", "-", "0", "0", "0"]],
            widths=[150, 112, 148, 58, 58, 74],
            row_height=24,
        )
        rollup_rows = []
        top_tools = list(pilot_activity.get("top_ai_tools") or [])
        decisions = dict(pilot_activity.get("decision_breakdown") or {})
        storage_modes = dict(pilot_activity.get("prompt_storage_breakdown") or {})
        action_types = dict(pilot_activity.get("action_type_breakdown") or {})
        for tool in top_tools[:4]:
            rollup_rows.append(
                [
                    str(tool.get("tool") or "-"),
                    str(tool.get("visit_count") or 0),
                    str(tool.get("unique_users") or 0),
                    str(tool.get("blocked_count") or 0),
                    str(tool.get("warned_count") or 0),
                ]
            )
        y_after_rollups = _draw_table(
            page,
            x=48,
            y=334,
            title="Pilot Activity Rollups",
            headers=["AI Tool", "Visits", "Users", "Blocked", "Warned"],
            rows=rollup_rows or [["No AI tool usage", "0", "0", "0", "0"]],
            widths=[220, 70, 70, 80, 76],
            row_height=22,
        )
        page.add_wrapped_text(
            (
                "Decisions: "
                + ", ".join(f"{key}={value}" for key, value in sorted(decisions.items()))
                + " | Prompt storage: "
                + ", ".join(f"{key}={value}" for key, value in sorted(storage_modes.items()))
                + " | Actions: "
                + ", ".join(f"{key}={value}" for key, value in sorted(action_types.items()))
            ),
            x=48,
            y=y_after_rollups - 10,
            max_width=516,
            font_size=9,
            color=_PALETTE["muted"],
            max_lines=3,
        )

        prompt_evidence_rows = [
            [
                str(row.get("email") or row.get("display_name") or row.get("user_id") or "unknown"),
                str(row.get("ai_app") or "-"),
                str(row.get("enforcement_action") or "-"),
                str(row.get("prompt") or row.get("prompt_hash") or "-"),
            ]
            for row in list(pilot_activity.get("prompt_evidence") or [])[:8]
        ]
        _draw_table(
            page,
            x=48,
            y=170,
            title="Prompt Evidence (Storage Policy Applied)",
            headers=["User", "AI App", "Decision", "Prompt / Hash"],
            rows=prompt_evidence_rows or [["No prompt evidence", "-", "-", "-"]],
            widths=[140, 100, 80, 196],
            row_height=24,
        )

        page = doc.new_page()
        _draw_header(
            page,
            title="Justification Evidence",
            subtitle="Business justifications captured before sensitive AI actions were allowed, reviewed, warned, or blocked.",
            y=734,
        )
        justification_rows = [
            [
                str(row.get("email") or row.get("display_name") or row.get("user_id") or "unknown"),
                str(row.get("ai_app") or row.get("domain") or "-"),
                str(row.get("decision") or "-"),
                str(row.get("control_mode") or "-"),
                str(row.get("justification_status") or "-"),
                str(row.get("justification") or row.get("prompt_preview") or "-"),
            ]
            for row in list(pilot_activity.get("justification_evidence") or [])[:12]
        ]
        _draw_table(
            page,
            x=48,
            y=670,
            title="Review / Justification Trail",
            headers=["User", "AI App", "Decision", "Mode", "Status", "Justification / Evidence"],
            rows=justification_rows or [["No justification evidence", "-", "-", "-", "-", "-"]],
            widths=[112, 78, 64, 86, 76, 184],
            row_height=26,
            font_size=8,
        )
        detail_lines = []
        for row in list(pilot_activity.get("justification_evidence") or [])[:4]:
            detail_lines.append(
                (
                    f"{str(row.get('email') or row.get('display_name') or row.get('user_id') or 'unknown')}: "
                    f"{str(row.get('justification') or row.get('prompt_preview') or '-')}"
                )
            )
        page.add_wrapped_text(
            "Justification details: " + (" | ".join(detail_lines) if detail_lines else "No justification evidence."),
            x=48,
            y=318,
            max_width=516,
            font_size=9,
            color=_PALETTE["muted"],
            max_lines=6,
        )

        page = doc.new_page()
        _draw_header(
            page,
            title="Detailed Violations",
            subtitle="Blocked, warned, and justified actions with user, device, AI app, policy reason, and redacted evidence.",
            y=734,
        )
        violation_rows = [
            [
                str(row.get("email") or row.get("display_name") or row.get("user_id") or "unknown"),
                str(row.get("application") or row.get("ai_tool") or "-"),
                str(row.get("decision") or "-"),
                str(row.get("finding_type") or "-"),
                str(row.get("prompt_preview") or row.get("recommended_action") or "-"),
            ]
            for row in list(pilot_activity.get("detailed_violations") or [])[:14]
        ]
        _draw_table(
            page,
            x=48,
            y=670,
            title="Violation Evidence",
            headers=["User", "AI App", "Decision", "Type", "Evidence"],
            rows=violation_rows or [["No detailed violations", "-", "-", "-", "-"]],
            widths=[132, 88, 64, 126, 190],
            row_height=24,
            font_size=8,
        )

        page = doc.new_page()
        _draw_header(
            page,
            title="AI Action Control Ledger",
            subtitle="User, device, AI app, action, decision, control mode, and evidence trace for pilot investigation.",
            y=734,
        )
        ledger_rows = [
            [
                str(row.get("email") or row.get("display_name") or row.get("user_id") or "unknown"),
                str(row.get("hostname") or row.get("endpoint_id") or "-"),
                str(row.get("ai_app") or row.get("domain") or "-"),
                str(row.get("action_type") or "-"),
                str(row.get("control_mode") or "-"),
                str(row.get("decision") or row.get("enforcement_action") or "-"),
                str(row.get("evidence_bundle_id") or row.get("trace_id") or row.get("runtime_event_id") or "-"),
            ]
            for row in list(pilot_activity.get("action_control_ledger") or [])[:14]
        ]
        _draw_table(
            page,
            x=48,
            y=670,
            title="Action-Control Evidence",
            headers=["User", "Device", "AI App", "Action", "Mode", "Decision", "Evidence / Trace"],
            rows=ledger_rows or [["No action-control ledger entries", "-", "-", "-", "-", "-", "-"]],
            widths=[112, 86, 76, 78, 96, 64, 88],
            row_height=24,
            font_size=8,
        )
        modes = dict(pilot_activity.get("control_mode_breakdown") or {})
        apps = list(pilot_activity.get("app_usage_summary") or [])
        devices = list(pilot_activity.get("device_activity_rollup") or [])
        page.add_wrapped_text(
            (
                "Control modes: "
                + (", ".join(f"{key}={value}" for key, value in sorted(modes.items())) or "none")
                + " | Top apps: "
                + (
                    ", ".join(
                        f"{row.get('ai_app') or 'unknown'}={row.get('action_count') or 0}"
                        for row in apps[:5]
                    )
                    or "none"
                )
                + " | Devices: "
                + (
                    ", ".join(
                        f"{row.get('hostname') or row.get('endpoint_id') or 'unknown'}={row.get('action_count') or 0}"
                        for row in devices[:4]
                    )
                    or "none"
                )
            ),
            x=48,
            y=300,
            max_width=516,
            font_size=9,
            color=_PALETTE["muted"],
            max_lines=4,
        )

    output_path.write_bytes(doc.render())
