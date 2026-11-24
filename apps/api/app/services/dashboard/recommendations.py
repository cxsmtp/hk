from __future__ import annotations

from typing import Any


def _severity_rank(value: str) -> int:
    normalized = str(value or "").strip().lower()
    return {
        "low": 1,
        "med": 2,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(normalized, 1)


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "med"
    return "low"


def _priority_score(*, base: int, severity: str = "low", multiplier: int = 1) -> int:
    score = int(base) + (_severity_rank(severity) * 10 * max(1, int(multiplier)))
    return max(1, min(100, score))


def generate_dashboard_recommendations(
    *,
    violations: dict[str, Any],
    risk_trend: dict[str, Any],
    simulations: dict[str, Any],
    cve_exposure: dict[str, Any],
    shadow_ai_summary: dict[str, Any],
    remediation_actions: dict[str, Any],
    sla_metrics: dict[str, Any],
) -> list[dict[str, Any]]:
    recommendations: list[dict[str, Any]] = []

    high_open = int(violations.get("high_critical_open_count") or 0)
    if high_open > 0:
        severity = "critical" if high_open >= 10 else "high"
        recommendations.append(
            {
                "title": "High-severity incident backlog requires triage",
                "severity": severity,
                "action_type": "route_to_governance",
                "affected_system": "multi-system",
                "reasoning": f"{high_open} high/critical violations are still open.",
                "priority_score": _priority_score(base=45, severity=severity, multiplier=max(1, high_open // 5 or 1)),
                "module_route": "/discovery/findings",
            }
        )

    simulation_fail_rate = float(simulations.get("fail_rate_percent") or 0.0)
    if simulation_fail_rate >= 30:
        severity = "high" if simulation_fail_rate < 55 else "critical"
        recommendations.append(
            {
                "title": "Simulation failure trend indicates control degradation",
                "severity": severity,
                "action_type": "run_validation_pack",
                "affected_system": "control_validation",
                "reasoning": f"Simulation fail rate is {simulation_fail_rate:.1f}%. Tighten controls and rerun targeted packs.",
                "priority_score": _priority_score(base=40, severity=severity, multiplier=max(1, int(simulation_fail_rate // 20) or 1)),
                "module_route": "/simulations",
            }
        )

    shadow_high_risk = int(shadow_ai_summary.get("high_risk_entities") or 0)
    if shadow_high_risk > 0:
        recommendations.append(
            {
                "title": "Unknown AI adoption requires governance handoff",
                "severity": "high" if shadow_high_risk < 5 else "critical",
                "action_type": "promote_to_trust_center",
                "affected_system": "shadow_ai",
                "reasoning": f"{shadow_high_risk} shadow AI entities are high-risk and should be reviewed for Trust Center promotion.",
                "priority_score": _priority_score(base=35, severity="high", multiplier=max(1, shadow_high_risk // 2 or 1)),
                "module_route": "/shadow-ai",
            }
        )

    cve_critical = int(cve_exposure.get("critical") or 0)
    cve_open = int(cve_exposure.get("open_count") or 0)
    if cve_open > 0:
        severity = "critical" if cve_critical > 0 else "high"
        recommendations.append(
            {
                "title": "CVE-linked AI exposure requires patch/remediation plan",
                "severity": severity,
                "action_type": "ticket_create",
                "affected_system": "cve_ingestion",
                "reasoning": (
                    f"{cve_open} CVE/vulnerability-linked monitoring signals detected."
                    + (f" {cve_critical} are critical." if cve_critical else "")
                ),
                "priority_score": _priority_score(base=50, severity=severity, multiplier=max(1, cve_open // 3 or 1)),
                "module_route": "/monitoring",
            }
        )

    risk_points = list(risk_trend.get("points") or [])
    if len(risk_points) >= 2:
        start = float(risk_points[0].get("risk_score") or 0.0)
        end = float(risk_points[-1].get("risk_score") or 0.0)
        if end - start >= 0.15:
            recommendations.append(
                {
                    "title": "Runtime risk trend is rising",
                    "severity": "high",
                    "action_type": "tighten_policy",
                    "affected_system": "runtime_intelligence",
                    "reasoning": f"Aggregate runtime risk increased from {start:.2f} to {end:.2f} in the selected window.",
                    "priority_score": _priority_score(base=30, severity="high", multiplier=2),
                    "module_route": "/runtime-intelligence/overview",
                }
            )

    pending_remediations = int(remediation_actions.get("status_counts", {}).get("proposed") or 0)
    failed_remediations = int(remediation_actions.get("status_counts", {}).get("failed") or 0)
    if pending_remediations > 0 or failed_remediations > 0:
        severity = "high" if failed_remediations > 0 else "med"
        recommendations.append(
            {
                "title": "Remediation queue needs execution and closure",
                "severity": severity,
                "action_type": "route_to_operations",
                "affected_system": "remediation_workflow",
                "reasoning": (
                    f"{pending_remediations} proposed and {failed_remediations} failed remediation actions detected."
                ),
                "priority_score": _priority_score(base=25, severity=severity, multiplier=max(1, (pending_remediations + failed_remediations) // 4 or 1)),
                "module_route": "/auditor",
            }
        )

    approvals_overdue = int(sla_metrics.get("approval_overdue") or 0)
    if approvals_overdue > 0:
        recommendations.append(
            {
                "title": "Approval SLA breach in governance queue",
                "severity": "high",
                "action_type": "require_step_up",
                "affected_system": "governance_approvals",
                "reasoning": f"{approvals_overdue} approvals exceeded SLA and need immediate owner/admin attention.",
                "priority_score": _priority_score(base=35, severity="high", multiplier=max(1, approvals_overdue // 2 or 1)),
                "module_route": "/agui/governance-approvals",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "title": "Control posture is stable",
                "severity": "low",
                "action_type": "monitor_only",
                "affected_system": "platform",
                "reasoning": "No high-priority risk signals detected in the selected scope. Continue monitoring.",
                "priority_score": 10,
                "module_route": "/dashboard/command-center",
            }
        )

    ordered = sorted(
        recommendations,
        key=lambda item: (int(item.get("priority_score") or 0), _severity_rank(str(item.get("severity") or "low"))),
        reverse=True,
    )
    return [
        {
            **row,
            "severity": str(row.get("severity") or _severity_from_score(int(row.get("priority_score") or 0))).lower(),
            "priority_score": int(row.get("priority_score") or 0),
        }
        for row in ordered
    ][:12]

