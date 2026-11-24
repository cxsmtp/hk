from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.evidence import (
    DecisionReceipt,
    EvidenceNode,
    ExecutionIntegrityResult,
    ExecutionReceipt,
)
from app.db.models.finding import Finding


CoverageStatus = Literal["covered", "not_covered", "unknown", "not_applicable"]
TimelineState = Literal["observed", "pending", "blocked", "unknown"]


@dataclass(frozen=True)
class BankingCoverageDimension:
    """Evidence-backed state for one coverage dimension; never an averaged score."""

    status: CoverageStatus
    reason: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {
            "covered",
            "not_covered",
            "unknown",
            "not_applicable",
        }:
            raise ValueError("banking coverage status is invalid")
        if not self.reason or len(self.reason) > 512:
            raise ValueError("banking coverage reason is invalid")


@dataclass(frozen=True)
class BankingTimelineEvent:
    """One privacy-safe event in the canonical AI transaction chain."""

    stage: str
    state: TimelineState
    occurred_at: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.stage or len(self.stage) > 64:
            raise ValueError("banking timeline stage is invalid")
        if self.state not in {"observed", "pending", "blocked", "unknown"}:
            raise ValueError("banking timeline state is invalid")


class BankingTransactionProjection(BaseModel):
    """Read-only projection over Hawk's existing receipts and EvidenceNodes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    ai_transaction_id: str
    subject_reference: str
    subject_type: str
    agent_chain: tuple[str, ...] = ()
    model: str = "unknown"
    business_purpose: str = "unknown"
    action_class: str = "unknown"
    side_effect_class: str = "unknown"
    tool_reference: str = "unknown"
    tool_fingerprint_reference: str = "unknown"
    policy_version: str = "unknown"
    control_point_reference: str = "unknown"
    action_schema: str = "unknown"
    transport: str = "unknown"
    target_class: str = "unknown"
    destination_class: str = "unknown"
    decision: str = "unknown"
    selected_controls: tuple[str, ...] = ()
    decision_receipt_ids: tuple[str, ...] = ()
    execution_receipt_ids: tuple[str, ...] = ()
    integrity_status: str = "unknown"
    drift_flags: tuple[str, ...] = ()
    finding_ids: tuple[str, ...] = ()
    coverage: dict[str, BankingCoverageDimension]
    coverage_complete: bool
    timeline: tuple[BankingTimelineEvent, ...] = ()


class BankingCisoTransactionSummary(BaseModel):
    """Privacy-safe recent transaction row for the existing CISO Command Center."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ai_transaction_id: str
    agent_reference: str
    tool_reference: str
    transport: str
    decision: str
    integrity_status: str
    coverage_complete: bool


class BankingCisoSummary(BaseModel):
    """Evidence-backed CISO rollup over a bounded canonical transaction window."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    generated_at: str
    evidence_window: str
    scanned_canonical_node_count: int
    truncated: bool
    observed_transaction_count: int
    customer_facing_agents: tuple[str, ...] = ()
    tool_references: tuple[str, ...] = ()
    data_reach: tuple[str, ...] = ()
    subject_boundary_status: Literal["evidence_backed", "gaps_present", "unknown"]
    inline_blockable_count: int
    observe_only_count: int
    consequential_transaction_count: int
    execution_verified_count: int
    consequential_execution_verified_percent: float | None
    drifted_transaction_count: int
    control_gaps: tuple[str, ...] = ()
    recent_transactions: tuple[BankingCisoTransactionSummary, ...] = ()


class BankingFailSafeContext(BaseModel):
    """Minimum action-specific material for an explicit degraded-mode decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_class: Literal[
        "low_risk_read",
        "sensitive_customer_read",
        "financial_write",
        "persistent_side_effect",
    ]
    subject_binding: bool
    target_binding: bool
    policy_available: bool
    signed_local_policy_available: bool
    mandatory_control_plan_healthy: bool


class BankingFailSafeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal[
        "allow_online_policy",
        "allow_local_policy",
        "control_requirement_unsatisfied",
    ]
    reason_code: str


@dataclass(frozen=True)
class BankingLatencySample:
    latency_ms: float
    outcome: Literal["success", "error", "timeout"]

    def __post_init__(self) -> None:
        if self.latency_ms < 0 or self.latency_ms > 300_000:
            raise ValueError("banking latency sample is outside the accepted range")


@dataclass(frozen=True)
class BankingLatencySummary:
    count: int
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    max_ms: float | None
    error_rate: float
    timeout_count: int


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 4)
    rank = max(0.0, min(1.0, percentile)) * (len(ordered) - 1)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return round(ordered[lower] + (ordered[upper] - ordered[lower]) * weight, 4)


def summarize_banking_latency_samples(
    samples: tuple[BankingLatencySample, ...],
) -> BankingLatencySummary:
    """Summarize measured samples without converting them into assurance claims."""

    values = [float(sample.latency_ms) for sample in samples]
    failures = sum(sample.outcome != "success" for sample in samples)
    return BankingLatencySummary(
        count=len(samples),
        p50_ms=_percentile(values, 0.50),
        p95_ms=_percentile(values, 0.95),
        p99_ms=_percentile(values, 0.99),
        max_ms=round(max(values), 4) if values else None,
        error_rate=round(failures / len(samples), 6) if samples else 0.0,
        timeout_count=sum(sample.outcome == "timeout" for sample in samples),
    )


def resolve_banking_fail_safe(context: BankingFailSafeContext) -> BankingFailSafeDecision:
    """Fail closed unless all action-specific mandatory controls are satisfied."""

    if not context.subject_binding or not context.target_binding:
        return BankingFailSafeDecision(
            decision="control_requirement_unsatisfied",
            reason_code="SUBJECT_OR_TARGET_BINDING_UNAVAILABLE",
        )
    if not context.mandatory_control_plan_healthy:
        return BankingFailSafeDecision(
            decision="control_requirement_unsatisfied",
            reason_code="MANDATORY_CONTROL_PLAN_UNHEALTHY",
        )
    if context.policy_available:
        return BankingFailSafeDecision(
            decision="allow_online_policy",
            reason_code="ONLINE_POLICY_AUTHORIZED",
        )
    if context.action_class == "low_risk_read" and context.signed_local_policy_available:
        return BankingFailSafeDecision(
            decision="allow_local_policy",
            reason_code="SIGNED_LOCAL_POLICY_FALLBACK",
        )
    return BankingFailSafeDecision(
        decision="control_requirement_unsatisfied",
        reason_code="ONLINE_POLICY_REQUIRED",
    )


_ASYNC_TRANSITIONS: dict[str, frozenset[str]] = {
    "proposed": frozenset({"authorized", "blocked"}),
    "authorized": frozenset({"queued", "started", "cancelled"}),
    "queued": frozenset({"started", "failed", "cancelled"}),
    "started": frozenset({"completed", "failed", "cancelled"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "blocked": frozenset(),
    "cancelled": frozenset(),
}


def advance_banking_async_state(current: str, requested: str) -> str:
    """Advance an asynchronous banking action without skipping execution proof."""

    if current == requested and current in _ASYNC_TRANSITIONS:
        return current
    if current not in _ASYNC_TRANSITIONS or requested not in _ASYNC_TRANSITIONS:
        raise ValueError("banking asynchronous state is invalid")
    if requested not in _ASYNC_TRANSITIONS[current]:
        raise ValueError(f"invalid banking asynchronous transition: {current} -> {requested}")
    return requested


def coverage_is_complete(coverage: Mapping[str, BankingCoverageDimension]) -> bool:
    """Require proof for every applicable dimension; no weighted averaging."""

    return bool(coverage) and all(
        dimension.status in {"covered", "not_applicable"}
        for dimension in coverage.values()
    )


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _text(value: Any, *, default: str = "unknown", max_len: int = 256) -> str:
    text = str(value or "").strip()
    return text[:max_len] if text else default


def _utc_iso(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dimension(
    covered: bool,
    *,
    covered_reason: str,
    missing_reason: str,
    evidence_refs: tuple[str, ...] = (),
    missing_status: CoverageStatus = "unknown",
) -> BankingCoverageDimension:
    return BankingCoverageDimension(
        status="covered" if covered else missing_status,
        reason=covered_reason if covered else missing_reason,
        evidence_refs=evidence_refs if covered else (),
    )


def _not_applicable(reason: str) -> BankingCoverageDimension:
    return BankingCoverageDimension("not_applicable", reason, ())


def _transport_coverage_dimensions(
    *,
    transport: str,
    decision_receipt_ids: tuple[str, ...],
    transport_reason: str,
    canonical_refs: tuple[str, ...],
) -> dict[str, BankingCoverageDimension]:
    """Keep an unknown route unknown instead of defaulting it to Function."""

    if transport == "function":
        return {
            "function": _dimension(
                bool(decision_receipt_ids),
                covered_reason="function action was authorized before execution",
                missing_reason="function authorization receipt is unavailable",
                evidence_refs=decision_receipt_ids,
            ),
            "mcp": _not_applicable("MCP/Toolbox transport was not used"),
            "direct_api": _not_applicable("direct API transport was not used"),
        }
    if transport in {"mcp", "toolbox"}:
        return {
            "function": _not_applicable("function transport was not used"),
            "mcp": _dimension(
                bool(
                    decision_receipt_ids
                    and transport_reason == "TRANSPORT_BINDING_VERIFIED"
                ),
                covered_reason="MCP/Toolbox route and inventory fingerprint are bound",
                missing_reason="MCP/Toolbox binding proof is incomplete",
                evidence_refs=decision_receipt_ids,
                missing_status="not_covered",
            ),
            "direct_api": _not_applicable("direct API transport was not used"),
        }
    if transport in {"rest", "openapi", "apim"}:
        return {
            "function": _not_applicable("function transport was not used"),
            "mcp": _not_applicable("MCP/Toolbox transport was not used"),
            "direct_api": _dimension(
                bool(
                    decision_receipt_ids
                    and transport_reason == "TRANSPORT_BINDING_VERIFIED"
                ),
                covered_reason="direct API route is bound to Hawk authorization",
                missing_reason="direct API route binding is incomplete",
                evidence_refs=decision_receipt_ids,
                missing_status="not_covered",
            ),
        }
    return {
        dimension: BankingCoverageDimension(
            "unknown",
            "execution transport is unknown; applicability cannot be proven",
            canonical_refs,
        )
        for dimension in ("function", "mcp", "direct_api")
    }


def _has_bound_model_receipt(
    *,
    model_node_ids: tuple[str, ...],
    decision_node_ids: tuple[str, ...],
) -> bool:
    """Require a Decision Receipt bound to the canonical model-request node."""

    return bool(set(model_node_ids).intersection(decision_node_ids))


def _receipts_bound_to_nodes(
    receipts: list[DecisionReceipt] | tuple[DecisionReceipt, ...],
    *,
    node_ids: tuple[str, ...],
) -> tuple[DecisionReceipt, ...]:
    node_id_set = set(node_ids)
    return tuple(
        receipt
        for receipt in receipts
        if receipt.canonical_action_evidence_node_id in node_id_set
    )


def _versioned_schema_reference(schema_name: Any, schema_version: Any) -> str:
    name = _text(schema_name)
    version = _text(schema_version)
    if "unknown" in {name, version}:
        return "unknown"
    return f"{name}/{version}"


def _canonical_transaction_nodes(
    db: Session,
    *,
    tenant_id: str,
    ai_transaction_id: str,
) -> list[EvidenceNode]:
    candidates = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type == "canonical_ai_action",
        )
        .order_by(EvidenceNode.created_at.asc())
        .limit(2_000)
    ).all()
    matched: list[EvidenceNode] = []
    for node in candidates:
        canonical = _mapping(_mapping(node.payload).get("canonical_action"))
        actor = _mapping(canonical.get("actor"))
        runtime_transaction = _mapping(canonical.get("surface")).get(
            "ai_transaction_id"
        )
        if (
            actor.get("ai_transaction_id") == ai_transaction_id
            or runtime_transaction == ai_transaction_id
        ):
            matched.append(node)
    return matched


def _recent_banking_transaction_ids(
    db: Session,
    *,
    tenant_id: str,
    scan_limit: int = 2_000,
    transaction_limit: int = 25,
) -> tuple[tuple[str, ...], int, bool]:
    nodes = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.node_type == "canonical_ai_action",
        )
        .order_by(EvidenceNode.created_at.desc())
        .limit(scan_limit + 1)
    ).all()
    node_window_truncated = len(nodes) > scan_limit
    scanned = nodes[:scan_limit]
    transaction_ids: list[str] = []
    seen_transaction_ids: set[str] = set()
    distinct_transaction_limit_truncated = False
    for node in scanned:
        canonical = _mapping(_mapping(node.payload).get("canonical_action"))
        actor = _mapping(canonical.get("actor"))
        surface = _mapping(canonical.get("surface"))
        transaction_id = _text(
            actor.get("ai_transaction_id") or surface.get("ai_transaction_id"),
            default="",
            max_len=64,
        )
        if not transaction_id or transaction_id in seen_transaction_ids:
            continue
        seen_transaction_ids.add(transaction_id)
        if len(transaction_ids) < transaction_limit:
            transaction_ids.append(transaction_id)
        else:
            distinct_transaction_limit_truncated = True
    return (
        tuple(transaction_ids),
        len(scanned),
        node_window_truncated or distinct_transaction_limit_truncated,
    )


def build_banking_transaction_projection(
    db: Session,
    *,
    tenant_id: str,
    ai_transaction_id: str,
) -> BankingTransactionProjection | None:
    """Build one transaction view from immutable existing evidence and receipts."""

    canonical_nodes = _canonical_transaction_nodes(
        db,
        tenant_id=tenant_id,
        ai_transaction_id=ai_transaction_id,
    )
    if not canonical_nodes:
        return None

    node_ids = tuple(node.id for node in canonical_nodes)
    canonicals = [
        _mapping(_mapping(node.payload).get("canonical_action"))
        for node in canonical_nodes
    ]
    canonical_pairs = tuple(zip(canonical_nodes, canonicals, strict=True))
    model_nodes = tuple(
        node
        for node, canonical in canonical_pairs
        if _mapping(canonical.get("action")).get("action_type") == "model_request"
    )
    model_node_ids = tuple(node.id for node in model_nodes)
    execution_pairs = tuple(
        (node, canonical)
        for node, canonical in canonical_pairs
        if _mapping(canonical.get("surface")).get("transport")
        in {"function", "mcp", "toolbox", "rest", "openapi", "apim"}
    )
    route_node_ids = tuple(node.id for node, _canonical in execution_pairs)
    _primary_action_node, function_canonical = (
        execution_pairs[0] if execution_pairs else canonical_pairs[-1]
    )
    decisions = db.scalars(
        select(DecisionReceipt)
        .where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.canonical_action_evidence_node_id.in_(node_ids),
        )
        .order_by(DecisionReceipt.issued_at.asc())
    ).all()
    decision_ids = tuple(receipt.receipt_id for receipt in decisions)
    decision_node_ids = tuple(
        receipt.canonical_action_evidence_node_id for receipt in decisions
    )
    route_decisions = _receipts_bound_to_nodes(decisions, node_ids=route_node_ids)
    route_decision_ids = tuple(receipt.receipt_id for receipt in route_decisions)
    model_decisions = _receipts_bound_to_nodes(decisions, node_ids=model_node_ids)
    model_decision_ids = tuple(receipt.receipt_id for receipt in model_decisions)
    executions = (
        db.scalars(
            select(ExecutionReceipt)
            .where(
                ExecutionReceipt.tenant_id == tenant_id,
                ExecutionReceipt.decision_receipt_id.in_(route_decision_ids),
            )
            .order_by(ExecutionReceipt.executed_at.asc())
        ).all()
        if route_decision_ids
        else []
    )
    execution_ids = tuple(receipt.receipt_id for receipt in executions)
    integrity_results = (
        db.scalars(
            select(ExecutionIntegrityResult)
            .where(
                ExecutionIntegrityResult.tenant_id == tenant_id,
                ExecutionIntegrityResult.decision_receipt_id.in_(route_decision_ids),
            )
            .order_by(ExecutionIntegrityResult.evaluated_at.asc())
        ).all()
        if route_decision_ids
        else []
    )
    response_nodes = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.correlation_id == ai_transaction_id,
            EvidenceNode.signal_type == "banking.response_assurance",
        )
        .order_by(EvidenceNode.created_at.asc())
    ).all()

    actor = _mapping(function_canonical.get("actor"))
    authority = _mapping(function_canonical.get("authority"))
    purpose = _mapping(function_canonical.get("purpose"))
    surface = _mapping(function_canonical.get("surface"))
    action = _mapping(function_canonical.get("action"))
    policy = _mapping(function_canonical.get("policy"))
    approval = _mapping(function_canonical.get("approval"))

    transport = _text(surface.get("transport"))
    subject_reference = _text(actor.get("customer_subject_hash"))
    subject_type = _text(actor.get("subject_type"))
    source_agent = _text(actor.get("source_agent_id"), default="")
    delegated_agents = tuple(
        _text(value, default="", max_len=128)
        for value in list(actor.get("delegated_agent_ids") or [])[:32]
        if _text(value, default="", max_len=128)
    )
    agent_chain = tuple(value for value in (source_agent, *delegated_agents) if value)
    model = next(
        (
            _text(_mapping(item.get("surface")).get("model"))
            for item in canonicals
            if _mapping(item.get("action")).get("action_type") == "model_request"
        ),
        _text(surface.get("model")),
    )
    decision = (
        route_decisions[-1].decision
        if route_decisions
        else decisions[-1].decision
        if decisions
        else _text(_mapping(function_canonical.get("policy")).get("decision"))
    )
    integrity_status = (
        integrity_results[-1].result if integrity_results else "unknown"
    )
    drift_flags = tuple(
        sorted(
            {
                _text(field, default="", max_len=128)
                for result in integrity_results
                for field in list(result.drift_fields or [])
                if _text(field, default="", max_len=128)
            }
        )
    )
    action_ids = tuple(
        _text(item.get("action_id"), default="", max_len=64)
        for item in canonicals
        if _text(item.get("action_id"), default="", max_len=64)
    )
    findings = (
        db.scalars(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.canonical_action_id.in_(action_ids),
            )
        ).all()
        if action_ids
        else []
    )
    finding_ids = tuple(sorted({finding.finding_id for finding in findings}))

    canonical_refs = tuple(node.id for node in canonical_nodes)
    transport_reason = _text(surface.get("transport_reason_code"))
    parameter_bound = bool(
        route_decisions
        and all(
            receipt.parameter_hash not in {"", "unknown"}
            for receipt in route_decisions
        )
    )
    target_bound = bool(
        route_decisions
        and all(
            receipt.target_resource_hash not in {"", "unknown"}
            for receipt in route_decisions
        )
    )
    destination_bound = bool(
        route_decisions
        and all(
            receipt.destination_hash not in {"", "unknown"}
            for receipt in route_decisions
        )
    )
    identity_bound = bool(
        authority.get("workload_identity_authoritative") is True
        and authority.get("workload_identity_quality") not in {None, "", "unknown"}
    )
    purpose_bound = purpose.get("purpose_status") == "verified"
    subject_bound = bool(
        subject_reference != "unknown"
        and actor.get("subject_provenance") not in {None, "", "unknown"}
    )
    response_assured = bool(
        response_nodes
        and _mapping(response_nodes[-1].payload).get("assurance")
        in {"structured_verified", "limited_claim_check"}
    )
    has_model_receipt = _has_bound_model_receipt(
        model_node_ids=model_node_ids,
        decision_node_ids=decision_node_ids,
    )
    transport_coverage = _transport_coverage_dimensions(
        transport=transport,
        decision_receipt_ids=route_decision_ids,
        transport_reason=transport_reason,
        canonical_refs=canonical_refs,
    )

    coverage: dict[str, BankingCoverageDimension] = {
        "subject": _dimension(
            subject_bound,
            covered_reason="signed subject context is bound to the transaction",
            missing_reason="signed subject binding evidence is unavailable",
            evidence_refs=canonical_refs,
        ),
        "identity": _dimension(
            identity_bound,
            covered_reason="authoritative workload identity is bound",
            missing_reason="workload identity authority is unknown or shared",
            evidence_refs=canonical_refs,
        ),
        "purpose": _dimension(
            purpose_bound,
            covered_reason="business purpose is verified and receipt-bound",
            missing_reason="verified business purpose evidence is unavailable",
            evidence_refs=canonical_refs,
        ),
        "model": _dimension(
            has_model_receipt,
            covered_reason="model request has a transaction-bound decision receipt",
            missing_reason="no model-request receipt exists in this transaction",
            evidence_refs=decision_ids,
        ),
        **transport_coverage,
        "parameter_binding": _dimension(
            parameter_bound,
            covered_reason="parameters are hash-bound to the decision receipt",
            missing_reason="parameter binding evidence is unavailable",
            evidence_refs=decision_ids,
        ),
        "target_binding": _dimension(
            target_bound,
            covered_reason="target is hash-bound to the decision receipt",
            missing_reason="target binding evidence is unavailable",
            evidence_refs=decision_ids,
        ),
        "destination_binding": _dimension(
            destination_bound,
            covered_reason="destination is hash-bound to the decision receipt",
            missing_reason="destination binding evidence is unavailable",
            evidence_refs=decision_ids,
        ),
        "approval_binding": (
            _dimension(
                True,
                covered_reason="approval is bound to exact canonical action material",
                missing_reason="approval evidence is unavailable",
                evidence_refs=tuple(
                    receipt.approval_binding_id
                    for receipt in route_decisions
                    if receipt.approval_binding_id
                ),
            )
            if approval.get("approval_binding_id")
            else _not_applicable("approval was not required for this action")
        ),
        "execution_visibility": _dimension(
            bool(executions),
            covered_reason="execution receipt is present",
            missing_reason="execution has not been proven",
            evidence_refs=execution_ids,
        ),
        "execution_verification": _dimension(
            bool(integrity_results and integrity_status == "matched"),
            covered_reason="actual execution matches authorization",
            missing_reason="matched execution verification is unavailable",
            evidence_refs=tuple(result.result_id for result in integrity_results),
            missing_status=(
                "not_covered" if integrity_status == "drift_detected" else "unknown"
            ),
        ),
        "response_assurance": _dimension(
            response_assured,
            covered_reason="structured response was deterministically assured",
            missing_reason="response assurance evidence is unavailable",
            evidence_refs=tuple(node.id for node in response_nodes),
        ),
        "bypass": _dimension(
            transport_reason == "TRANSPORT_BINDING_VERIFIED",
            covered_reason="the selected execution route is explicitly bound",
            missing_reason="bypass status cannot be proven for this route",
            evidence_refs=canonical_refs,
            missing_status="unknown",
        ),
    }

    timeline: list[BankingTimelineEvent] = []
    first_node = canonical_nodes[0]
    timeline.extend(
        [
            BankingTimelineEvent(
                "authenticated",
                "observed" if subject_bound else "unknown",
                _utc_iso(first_node.created_at),
                (first_node.id,),
            ),
            BankingTimelineEvent(
                "action_proposed",
                "observed",
                _utc_iso(first_node.created_at),
                (first_node.id,),
            ),
        ]
    )
    if model_nodes:
        timeline.append(
            BankingTimelineEvent(
                "model_request",
                "observed" if has_model_receipt else "unknown",
                _utc_iso(model_nodes[0].created_at),
                model_decision_ids,
            )
        )
    timeline_decisions = route_decisions or tuple(decisions)
    timeline_decision_ids = route_decision_ids or decision_ids
    if timeline_decisions:
        latest_decision = timeline_decisions[-1]
        timeline.append(
            BankingTimelineEvent(
                "hawk_decision",
                "blocked" if latest_decision.decision == "block" else "observed",
                _utc_iso(latest_decision.issued_at),
                timeline_decision_ids,
            )
        )
        if latest_decision.approval_binding_id:
            timeline.append(
                BankingTimelineEvent(
                    "approval",
                    "observed",
                    _utc_iso(latest_decision.issued_at),
                    (latest_decision.approval_binding_id,),
                )
            )
    if executions:
        timeline.append(
            BankingTimelineEvent(
                "execution",
                "observed",
                _utc_iso(executions[-1].executed_at),
                execution_ids,
            )
        )
    if integrity_results:
        timeline.append(
            BankingTimelineEvent(
                "verification",
                "observed" if integrity_status == "matched" else "blocked",
                _utc_iso(integrity_results[-1].evaluated_at),
                tuple(result.result_id for result in integrity_results),
            )
        )
    if response_nodes:
        latest_response = response_nodes[-1]
        response_state: TimelineState = (
            "blocked"
            if _mapping(latest_response.payload).get("decision") == "block"
            else "observed"
        )
        timeline.extend(
            [
                BankingTimelineEvent(
                    "response_assurance",
                    response_state,
                    _utc_iso(latest_response.created_at),
                    (latest_response.id,),
                ),
                BankingTimelineEvent(
                    "customer_response",
                    response_state,
                    _utc_iso(latest_response.created_at),
                    (latest_response.id,),
                ),
            ]
        )

    route_dimension = (
        "mcp"
        if transport in {"mcp", "toolbox"}
        else "direct_api" if transport in {"rest", "openapi", "apim"} else transport
    )
    selected_controls = tuple(
        sorted(
            {
                *(
                    (f"runtime_control:{transport}",)
                    if route_dimension in coverage
                    and coverage[route_dimension].status == "covered"
                    else ()
                ),
                *(
                    ("model_request_control",)
                    if coverage["model"].status == "covered"
                    else ()
                ),
                *(
                    ("response_assurance",)
                    if coverage["response_assurance"].status == "covered"
                    else ()
                ),
                *(
                    ("execution_verification",)
                    if coverage["execution_verification"].status == "covered"
                    else ()
                ),
            }
        )
    )
    destination_class = _text(surface.get("destination_class"))
    return BankingTransactionProjection(
        tenant_id=tenant_id,
        ai_transaction_id=ai_transaction_id,
        subject_reference=subject_reference,
        subject_type=subject_type,
        agent_chain=agent_chain,
        model=model,
        business_purpose=_text(purpose.get("purpose_id")),
        action_class=_text(action.get("action_type")),
        side_effect_class=_text(action.get("side_effect_class")),
        tool_reference=_text(action.get("tool_name")),
        tool_fingerprint_reference=_text(action.get("tool_fingerprint_id")),
        policy_version=_text(policy.get("policy_snapshot_id")),
        control_point_reference=_text(policy.get("native_primary_control_point")),
        action_schema=_versioned_schema_reference(
            function_canonical.get("schema_name"),
            function_canonical.get("schema_version"),
        ),
        transport=transport,
        target_class=(
            "banking_resource"
            if route_decisions and target_bound
            else "unknown"
        ),
        destination_class=destination_class,
        decision=decision,
        selected_controls=selected_controls,
        decision_receipt_ids=decision_ids,
        execution_receipt_ids=execution_ids,
        integrity_status=integrity_status,
        drift_flags=drift_flags,
        finding_ids=finding_ids,
        coverage=coverage,
        coverage_complete=coverage_is_complete(coverage),
        timeline=tuple(timeline),
    )


def build_banking_ciso_summary(
    db: Session,
    *,
    tenant_id: str,
    transaction_limit: int = 25,
) -> BankingCisoSummary:
    """Summarize only observed transaction evidence; never infer estate-wide coverage."""

    if transaction_limit < 1 or transaction_limit > 100:
        raise ValueError("banking CISO transaction limit is invalid")
    transaction_ids, scanned_nodes, truncated = _recent_banking_transaction_ids(
        db,
        tenant_id=tenant_id,
        transaction_limit=transaction_limit,
    )
    projections = tuple(
        projection
        for transaction_id in transaction_ids
        if (
            projection := build_banking_transaction_projection(
                db,
                tenant_id=tenant_id,
                ai_transaction_id=transaction_id,
            )
        )
        is not None
    )
    agents = tuple(
        sorted({agent for projection in projections for agent in projection.agent_chain})
    )
    tools = tuple(
        sorted(
            {
                projection.tool_reference
                for projection in projections
                if projection.tool_reference != "unknown"
            }
        )
    )
    data_reach = tuple(
        sorted(
            {
                f"{projection.target_class} -> {projection.destination_class}"
                for projection in projections
                if projection.target_class != "unknown"
                or projection.destination_class != "unknown"
            }
        )
    )
    subject_statuses = tuple(
        projection.coverage.get("subject") for projection in projections
    )
    subject_boundary_status: Literal[
        "evidence_backed", "gaps_present", "unknown"
    ] = (
        "unknown"
        if not subject_statuses
        else (
            "evidence_backed"
            if all(
                dimension is not None and dimension.status == "covered"
                for dimension in subject_statuses
            )
            else "gaps_present"
        )
    )

    def route_is_inline_bound(projection: BankingTransactionProjection) -> bool:
        dimension_name = (
            "mcp"
            if projection.transport in {"mcp", "toolbox"}
            else (
                "direct_api"
                if projection.transport in {"rest", "openapi", "apim"}
                else "function"
            )
        )
        dimension = projection.coverage.get(dimension_name)
        return bool(dimension and dimension.status == "covered")

    inline_blockable = sum(route_is_inline_bound(item) for item in projections)
    observe_only = sum(
        not route_is_inline_bound(item)
        and bool(
            item.coverage.get("execution_visibility")
            and item.coverage["execution_visibility"].status == "covered"
        )
        for item in projections
    )
    consequential = tuple(
        item
        for item in projections
        if item.side_effect_class not in {"read_only", "unknown"}
    )
    execution_verified = sum(
        bool(
            item.coverage.get("execution_verification")
            and item.coverage["execution_verification"].status == "covered"
        )
        for item in projections
    )
    consequential_verified = sum(
        bool(
            item.coverage.get("execution_verification")
            and item.coverage["execution_verification"].status == "covered"
        )
        for item in consequential
    )
    control_gaps = tuple(
        sorted(
            {
                dimension_name
                for projection in projections
                for dimension_name, dimension in projection.coverage.items()
                if dimension.status in {"unknown", "not_covered"}
            }
        )
    )
    recent = tuple(
        BankingCisoTransactionSummary(
            ai_transaction_id=item.ai_transaction_id,
            agent_reference=item.agent_chain[0] if item.agent_chain else "unknown",
            tool_reference=item.tool_reference,
            transport=item.transport,
            decision=item.decision,
            integrity_status=item.integrity_status,
            coverage_complete=item.coverage_complete,
        )
        for item in projections
    )
    return BankingCisoSummary(
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        evidence_window="latest 2,000 canonical action evidence nodes",
        scanned_canonical_node_count=scanned_nodes,
        truncated=truncated,
        observed_transaction_count=len(projections),
        customer_facing_agents=agents,
        tool_references=tools,
        data_reach=data_reach,
        subject_boundary_status=subject_boundary_status,
        inline_blockable_count=inline_blockable,
        observe_only_count=observe_only,
        consequential_transaction_count=len(consequential),
        execution_verified_count=execution_verified,
        consequential_execution_verified_percent=(
            round((consequential_verified / len(consequential)) * 100.0, 2)
            if consequential
            else None
        ),
        drifted_transaction_count=sum(
            bool(item.drift_flags)
            or item.integrity_status not in {"matched", "unknown"}
            for item in projections
        ),
        control_gaps=control_gaps,
        recent_transactions=recent,
    )


def banking_transaction_siem_event(
    projection: BankingTransactionProjection,
) -> dict[str, Any]:
    """Return one high-quality privacy-safe event for the existing SIEM exporter."""

    return {
        "tenant_id": projection.tenant_id,
        "event_id": f"banking-transaction:{projection.ai_transaction_id}",
        "event_type": "banking_ai_transaction",
        "timestamp": (
            projection.timeline[-1].occurred_at if projection.timeline else "unknown"
        ),
        "source_surface": "runtime_control",
        "control_mode": (
            "inline_prevented"
            if projection.decision == "block"
            else "inline_allowed"
        ),
        "decision": projection.decision,
        "status": projection.integrity_status,
        "severity": "high" if projection.drift_flags else "low",
        "correlation_id": projection.ai_transaction_id,
        "ai_transaction_id": projection.ai_transaction_id,
        "subject_reference": projection.subject_reference,
        "subject_type": projection.subject_type,
        "agent_chain": list(projection.agent_chain),
        "model": projection.model,
        "business_purpose": projection.business_purpose,
        "action_class": projection.action_class,
        "transport": projection.transport,
        "target_class": projection.target_class,
        "destination_class": projection.destination_class,
        "selected_controls": list(projection.selected_controls),
        "decision_receipt_id": (
            projection.decision_receipt_ids[-1]
            if projection.decision_receipt_ids
            else "unknown"
        ),
        "execution_receipt_id": (
            projection.execution_receipt_ids[-1]
            if projection.execution_receipt_ids
            else "unknown"
        ),
        "integrity_status": projection.integrity_status,
        "drift_flags": list(projection.drift_flags),
        "finding_id": projection.finding_ids[-1] if projection.finding_ids else "none",
        "coverage_status": (
            "complete" if projection.coverage_complete else "incomplete"
        ),
    }
