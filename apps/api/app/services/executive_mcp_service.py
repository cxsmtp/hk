from __future__ import annotations

import base64
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import html
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.control_coverage.executive import get_executive_coverage_summary
from app.services.enterprise_developer_ai_control import (
    build_enterprise_developer_ai_control_from_db,
)
from app.services.provider_signals import build_provider_signal_workspace


ExecutiveMetric = Literal[
    "actions",
    "blocked",
    "top_violations",
    "violations_by_framework",
    "providers",
    "mcp_tools",
    "github_repositories",
    "control_coverage",
    "spend",
    "tokens",
]


@dataclass(frozen=True)
class ExecutiveQuery:
    metric: ExecutiveMetric
    window_days: int = 30
    group_by: str | None = None
    limit: int = 10
    include_named_users: bool = False


_BLOCK_DECISIONS = {"block", "blocked", "deny", "denied", "quarantine", "redact"}
_WARN_DECISIONS = {"warn", "warning"}
_APPROVAL_DECISIONS = {"approval", "require_approval", "human_review", "require_second_approval"}
_FRAMEWORK_PATTERNS: tuple[tuple[str, str], ...] = (
    ("OWASP LLM / GenAI", r"\b(llm|prompt|jailbreak|injection|output|rag|embedding)\b"),
    ("OWASP Agentic", r"\b(agent|tool|mcp|delegation|authority|plugin|capability)\b"),
    ("MITRE ATLAS", r"\b(atlas|model|evasion|poison|exfiltration|credential|recon)\b"),
    ("NIST AI RMF", r"\b(governance|risk|monitor|measure|manage|validat|control)\b"),
    ("ISO/IEC 42001", r"\b(iso|management|audit|policy|accountability)\b"),
    ("Data Protection", r"\b(data|privacy|secret|credential|pii|sensitive|exfiltration)\b"),
)
_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
}


def _now() -> datetime:
    return datetime.now(UTC)


def _window_start(days: int, now: datetime | None = None) -> datetime:
    bounded = max(1, min(int(days or 30), 366))
    return (now or _now()) - timedelta(days=bounded)


def _safe_limit(limit: int) -> int:
    return max(1, min(int(limit or 10), 100))


def _norm(value: Any, fallback: str = "unknown") -> str:
    text = str(value or "").strip()
    return text if text else fallback


def _lower(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_blocked(value: Any) -> bool:
    return _lower(value) in _BLOCK_DECISIONS


def _is_warning(value: Any) -> bool:
    return _lower(value) in _WARN_DECISIONS


def _is_approval(value: Any) -> bool:
    return _lower(value) in _APPROVAL_DECISIONS


def _safe_user_label(
    *,
    role: str,
    include_named_users: bool,
    tenant_id: str,
    user_id: str | None,
    user_email: str | None = None,
) -> str:
    privileged = role in {"auditor", "admin", "owner"}
    if include_named_users and privileged:
        return _norm(user_email or user_id, "unknown-user")
    material = f"{tenant_id}:{user_id or user_email or 'unknown'}"
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:10]
    return f"user:{digest}"


def _framework_for_finding(row: Finding) -> str:
    haystack = " ".join(
        [
            _lower(row.risk_category),
            _lower(row.finding_type),
            _lower(row.recommended_action),
            _lower(row.ai_tool),
        ]
    )
    for label, pattern in _FRAMEWORK_PATTERNS:
        if re.search(pattern, haystack):
            return label
    return "Unmapped / customer-specific"


def _finding_priority(row: Finding) -> tuple[int, int, datetime]:
    return (
        _SEVERITY_RANK.get(_lower(row.severity), 0),
        int(row.occurrence_count or 1),
        row.last_seen_at or datetime.min.replace(tzinfo=UTC),
    )


def build_executive_mcp_summary(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    window_days: int = 30,
) -> dict[str, Any]:
    start_at = _window_start(window_days)
    now = _now()
    actions = db.scalars(
        select(AIAction)
        .where(AIAction.tenant_id == tenant_id, AIAction.timestamp >= start_at)
        .order_by(AIAction.timestamp.desc())
        .limit(10_000)
    ).all()
    runtime_events = db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == tenant_id, RuntimeEvent.created_at >= start_at)
        .order_by(RuntimeEvent.created_at.desc())
        .limit(10_000)
    ).all()
    findings = db.scalars(
        select(Finding)
        .where(Finding.tenant_id == tenant_id, Finding.last_seen_at >= start_at)
        .order_by(Finding.last_seen_at.desc())
        .limit(2_000)
    ).all()
    provider_workspace = build_provider_signal_workspace(
        db,
        tenant_id=tenant_id,
        now=now,
        window_days=max(1, min(int(window_days or 30), 366)),
        limit=5_000,
        role=role,
    )
    github = build_enterprise_developer_ai_control_from_db(db, tenant_id=tenant_id)
    coverage = get_executive_coverage_summary(db, tenant_id=tenant_id)
    blocked_count = sum(1 for row in actions if _is_blocked(row.enforcement_action)) + sum(
        1 for row in runtime_events if _is_blocked(row.decision)
    )
    warning_count = sum(1 for row in actions if _is_warning(row.enforcement_action)) + sum(
        1 for row in runtime_events if _is_warning(row.decision)
    )
    approval_count = sum(1 for row in actions if _is_approval(row.enforcement_action)) + sum(
        1 for row in runtime_events if _is_approval(row.decision)
    )
    provider_overview = provider_workspace.get("overview") or {}
    spend = provider_workspace.get("spend_utilization") or {}
    github_inventory = github.get("repository_inventory") or {}
    coverage_summary = coverage or {
        "validated_coverage_percent": None,
        "denominator": 0,
        "assessment_count": 0,
        "state_distribution": {},
        "status": "unavailable",
    }

    next_actions = []
    for item in (provider_workspace.get("executive_report") or {}).get("next_actions") or []:
        if isinstance(item, dict):
            next_actions.append(item)
        elif item:
            next_actions.append({"title": str(item), "source": "provider_workspace"})
    if github_inventory.get("denominator", {}).get("status") not in {"complete", "COMPLETE"}:
        next_actions.append(
            {
                "title": "Complete GitHub repository inventory denominator",
                "why": "Approved-repository controls are stronger when the GitHub App selected-repository installation is connected.",
                "source": "github_repository_inventory",
            }
        )
    if not coverage:
        next_actions.append(
            {
                "title": "Refresh Control Coverage from current evidence",
                "why": "Executive coverage should be based on a fresh bounded snapshot.",
                "source": "control_coverage",
            }
        )

    return {
        "tenant_id": tenant_id,
        "generated_at": now.isoformat(),
        "window": {
            "days": max(1, min(int(window_days or 30), 366)),
            "start_at": start_at.isoformat(),
            "end_at": now.isoformat(),
        },
        "privacy": {
            "raw_prompt_content_included": False,
            "named_users_require_role": "auditor/admin/owner",
            "usage_is_not_productivity_score": True,
        },
        "headline": {
            "total_ai_actions": len(actions),
            "runtime_events": len(runtime_events),
            "blocked_or_restricted": blocked_count,
            "warnings": warning_count,
            "approval_required": approval_count,
            "open_findings": sum(1 for row in findings if _lower(row.status) in {"open", "active", "new"}),
            "providers_observed": provider_overview.get("providers_observed", 0),
            "mcp_servers": provider_overview.get("mcp_servers", 0),
            "github_repositories": len(github_inventory.get("repositories") or []),
            "control_coverage_percent": coverage_summary.get("validated_coverage_percent"),
            "spend_status": (spend.get("summary") or {}).get("status", "unavailable") if isinstance(spend, dict) else "unavailable",
        },
        "outcomes": {
            "blocked": blocked_count,
            "warned": warning_count,
            "approval_required": approval_count,
        },
        "providers": provider_workspace.get("providers") or [],
        "mcp_tools": provider_workspace.get("mcp_tools") or {},
        "spend_utilization": spend,
        "github": {
            "summary": github.get("summary") or {},
            "repository_inventory": github_inventory,
            "controls": github.get("controls_and_gaps") or github.get("control_coverage") or [],
        },
        "control_coverage": coverage_summary,
        "top_findings": [
            {
                "finding_id": row.finding_id,
                "severity": row.severity,
                "type": row.finding_type,
                "risk_category": row.risk_category,
                "surface": row.source_surface,
                "application": row.application,
                "department": row.department,
                "occurrences": row.occurrence_count,
                "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
            }
            for row in sorted(findings, key=_finding_priority, reverse=True)[:10]
        ],
        "recommendations": next_actions[:8],
    }


def query_executive_mcp_metrics(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    query: ExecutiveQuery,
) -> dict[str, Any]:
    start_at = _window_start(query.window_days)
    limit = _safe_limit(query.limit)
    metric = query.metric
    if metric in {"actions", "blocked", "tokens"}:
        rows = db.scalars(
            select(AIAction)
            .where(AIAction.tenant_id == tenant_id, AIAction.timestamp >= start_at)
            .order_by(AIAction.timestamp.desc())
            .limit(10_000)
        ).all()
        if metric == "blocked":
            rows = [row for row in rows if _is_blocked(row.enforcement_action)]
        if metric == "tokens":
            total_tokens = 0
            by_app: Counter[str] = Counter()
            for row in rows:
                meta = row.metadata_json or {}
                tokens = int(meta.get("total_tokens") or meta.get("tokens") or 0)
                total_tokens += tokens
                by_app[_norm(row.ai_app)] += tokens
            return {
                "metric": metric,
                "total_tokens": total_tokens,
                "by_application": [{"key": key, "value": value} for key, value in by_app.most_common(limit)],
                "source": "ai_actions.metadata_json",
                "raw_prompt_content_included": False,
            }
        group_key = query.group_by or "decision"
        counter: Counter[str] = Counter()
        for row in rows:
            if group_key == "user":
                label = _safe_user_label(
                    role=role,
                    include_named_users=query.include_named_users,
                    tenant_id=tenant_id,
                    user_id=row.user_id,
                )
            elif group_key == "department":
                label = _norm((row.metadata_json or {}).get("department"))
            elif group_key == "app":
                label = _norm(row.ai_app)
            elif group_key == "model":
                label = _norm(row.ai_model)
            elif group_key == "surface":
                label = _norm((row.metadata_json or {}).get("surface"))
            else:
                label = _norm(row.enforcement_action, "observed")
            counter[label] += 1
        return {
            "metric": metric,
            "group_by": group_key,
            "total": len(rows),
            "items": [{"key": key, "value": value} for key, value in counter.most_common(limit)],
            "raw_prompt_content_included": False,
        }

    if metric == "top_violations":
        rows = db.scalars(
            select(Finding)
            .where(Finding.tenant_id == tenant_id, Finding.last_seen_at >= start_at)
            .order_by(Finding.occurrence_count.desc(), Finding.last_seen_at.desc())
            .limit(1_000)
        ).all()
        counter: Counter[str] = Counter()
        for row in rows:
            label = _safe_user_label(
                role=role,
                include_named_users=query.include_named_users,
                tenant_id=tenant_id,
                user_id=row.user_id,
                user_email=row.user_email,
            )
            counter[label] += int(row.occurrence_count or 1)
        return {
            "metric": metric,
            "total": sum(counter.values()),
            "items": [{"key": key, "value": value} for key, value in counter.most_common(limit)],
            "named_user_detail": query.include_named_users and role in {"auditor", "admin", "owner"},
        }

    if metric == "violations_by_framework":
        rows = db.scalars(
            select(Finding).where(Finding.tenant_id == tenant_id, Finding.last_seen_at >= start_at).limit(2_000)
        ).all()
        counter = Counter()
        for row in rows:
            counter[_framework_for_finding(row)] += int(row.occurrence_count or 1)
        return {
            "metric": metric,
            "total": sum(counter.values()),
            "items": [{"key": key, "value": value} for key, value in counter.most_common(limit)],
            "mapping_note": "Framework labels are informative mappings from finding categories, not compliance certification.",
        }

    if metric in {"providers", "mcp_tools", "spend"}:
        workspace = build_provider_signal_workspace(
            db,
            tenant_id=tenant_id,
            now=_now(),
            window_days=query.window_days,
            limit=5_000,
            role=role,
        )
        return {
            "metric": metric,
            "result": workspace.get({"providers": "providers", "mcp_tools": "mcp_tools", "spend": "spend_utilization"}[metric]) or {},
            "raw_prompt_content_included": False,
        }

    if metric == "github_repositories":
        governance = build_enterprise_developer_ai_control_from_db(db, tenant_id=tenant_id)
        inventory = governance.get("repository_inventory") or {}
        return {
            "metric": metric,
            "summary": governance.get("summary") or {},
            "repository_inventory": {
                key: inventory.get(key)
                for key in ("organizations", "repositories", "access_relations", "ai_connections", "denominator", "blind_spots")
            },
        }

    if metric == "control_coverage":
        return {
            "metric": metric,
            "result": get_executive_coverage_summary(db, tenant_id=tenant_id) or {"status": "unavailable"},
        }

    return {"metric": metric, "status": "unsupported"}


def create_executive_mcp_presentation(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    title: str = "Executive AI Governance Brief",
    window_days: int = 30,
) -> dict[str, Any]:
    summary = build_executive_mcp_summary(db, tenant_id=tenant_id, role=role, window_days=window_days)
    slides = [
        (
            title,
            [
                f"Window: last {summary['window']['days']} days",
                f"Total AI actions: {summary['headline']['total_ai_actions']}",
                f"Blocked or restricted: {summary['headline']['blocked_or_restricted']}",
                f"Providers observed: {summary['headline']['providers_observed']}",
            ],
        ),
        (
            "Governance outcomes",
            [
                f"Warnings: {summary['outcomes']['warned']}",
                f"Approvals required: {summary['outcomes']['approval_required']}",
                f"Open findings: {summary['headline']['open_findings']}",
                "Raw prompt content is excluded from this report.",
            ],
        ),
        (
            "GitHub and developer AI",
            [
                f"Repositories in inventory: {summary['headline']['github_repositories']}",
                f"MCP servers observed: {summary['headline']['mcp_servers']}",
                "Repository controls remain scoped to approved identities and selected repositories.",
            ],
        ),
        (
            "Recommended next actions",
            [
                _norm(item.get("title") if isinstance(item, dict) else item)
                for item in (summary.get("recommendations") or [])[:5]
            ]
            or ["No prioritized recommendations were available from the current evidence."],
        ),
    ]
    artifact_id = f"exec-mcp-{uuid4()}"
    output_dir = Path(tempfile.gettempdir()) / "hawk-executive-mcp"
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{artifact_id}.pptx"
    path = output_dir / filename
    _write_pptx(path, slides)
    pptx_bytes = path.read_bytes()
    return {
        "artifact_id": artifact_id,
        "filename": filename,
        "path": str(path),
        "content_base64": base64.b64encode(pptx_bytes).decode("ascii"),
        "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "slide_count": len(slides),
        "raw_prompt_content_included": False,
        "source_summary": {
            "tenant_id": tenant_id,
            "generated_at": summary["generated_at"],
            "window": summary["window"],
        },
    }


def _write_pptx(path: Path, slides: list[tuple[str, list[str]]]) -> None:
    """Write a minimal standards-compatible PPTX without introducing runtime deps."""

    slide_files = []
    rel_files = []
    for index, (title, bullets) in enumerate(slides, start=1):
        slide_files.append((f"ppt/slides/slide{index}.xml", _slide_xml(title, bullets)))
        rel_files.append(
            f'<Relationship Id="rId{index}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{index}.xml"/>'
        )
    content_types = "".join(
        f'<Override PartName="/ppt/slides/slide{index}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        for index in range(1, len(slides) + 1)
    )
    presentation_slides = "".join(
        f'<p:sldId id="{255 + index}" r:id="rId{index}"/>' for index in range(1, len(slides) + 1)
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", _content_types_xml(content_types))
        archive.writestr("_rels/.rels", _root_rels_xml())
        archive.writestr("ppt/presentation.xml", _presentation_xml(presentation_slides))
        archive.writestr("ppt/_rels/presentation.xml.rels", _presentation_rels_xml("".join(rel_files)))
        archive.writestr("ppt/theme/theme1.xml", _theme_xml())
        archive.writestr("ppt/slideMasters/slideMaster1.xml", _empty_master_xml())
        archive.writestr("ppt/slideLayouts/slideLayout1.xml", _empty_layout_xml())
        archive.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", _master_rels_xml())
        for name, xml in slide_files:
            archive.writestr(name, xml)


def _escape(value: str) -> str:
    return html.escape(str(value), quote=True)


def _slide_xml(title: str, bullets: list[str]) -> str:
    bullet_paragraphs = "".join(
        f'<a:p><a:r><a:t>{_escape("• " + item)}</a:t></a:r></a:p>' for item in bullets[:8]
    )
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>
    <p:sp><p:nvSpPr><p:cNvPr id="2" name="Title"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr sz="3200" b="1"/><a:t>{_escape(title)}</a:t></a:r></a:p></p:txBody></p:sp>
    <p:sp><p:nvSpPr><p:cNvPr id="3" name="Body"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:txBody><a:bodyPr/><a:lstStyle/>{bullet_paragraphs}</p:txBody></p:sp>
  </p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>'''


def _content_types_xml(slides: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  {slides}
</Types>'''


def _root_rels_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>'''


def _presentation_xml(slides: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rIdMaster"/></p:sldMasterIdLst>
  <p:sldIdLst>{slides}</p:sldIdLst>
  <p:sldSz cx="12192000" cy="6858000" type="screen16x9"/>
</p:presentation>'''


def _presentation_rels_xml(slides: str) -> str:
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rIdMaster" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>
  <Relationship Id="rIdTheme" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>
  {slides}
</Relationships>'''


def _theme_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Hawk Executive"><a:themeElements><a:clrScheme name="Hawk"><a:dk1><a:srgbClr val="0B1020"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:accent1><a:srgbClr val="3EE7F2"/></a:accent1><a:accent2><a:srgbClr val="FF7A1A"/></a:accent2><a:accent3><a:srgbClr val="7CFFB2"/></a:accent3><a:accent4><a:srgbClr val="FFD966"/></a:accent4><a:accent5><a:srgbClr val="B794F6"/></a:accent5><a:accent6><a:srgbClr val="F87171"/></a:accent6><a:hlink><a:srgbClr val="3EE7F2"/></a:hlink><a:folHlink><a:srgbClr val="B794F6"/></a:folHlink></a:clrScheme><a:fontScheme name="Aptos"><a:majorFont><a:latin typeface="Aptos Display"/></a:majorFont><a:minorFont><a:latin typeface="Aptos"/></a:minorFont></a:fontScheme><a:fmtScheme name="default"><a:fillStyleLst/><a:lnStyleLst/><a:effectStyleLst/><a:bgFillStyleLst/></a:fmtScheme></a:themeElements></a:theme>'''


def _empty_master_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld><p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></p:sldLayoutIdLst></p:sldMaster>'''


def _empty_layout_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/></p:spTree></p:cSld></p:sldLayout>'''


def _master_rels_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/></Relationships>'''
