from __future__ import annotations

import hashlib
import json
import logging
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import event, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.observability import get_correlation_id
from app.db.models.policy import ApprovalRequest
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.action_integrity.execution_authority import invoke_final_seam
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError, enforce as enforce_governance
from app.services.mcp.context import MCPExecutionContext
from app.services.mcp.contracts import MCPExecutionObservation, MCPExecutionResult, ToolContract, ToolRegistration


logger = logging.getLogger(__name__)


class MCPToolRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, ToolRegistration] = {}

    def register(self, tool_registration: ToolRegistration) -> None:
        tool_name = tool_registration.contract.tool_name
        if tool_name in self._registry:
            raise ValueError(f"Tool '{tool_name}' is already registered")
        self._registry[tool_name] = tool_registration

    def get(self, tool_name: str) -> ToolRegistration | None:
        return self._registry.get(tool_name)

    def list(self) -> list[dict[str, Any]]:
        items = [row.contract.model_dump() for row in self._registry.values()]
        return sorted(items, key=lambda row: row["tool_name"])

    def validate_input(self, tool_name: str, payload: dict[str, Any]) -> None:
        registration = self.get(tool_name)
        if registration is None:
            raise ValueError(f"Unknown tool '{tool_name}'")
        _validate_against_schema(payload, registration.contract.input_schema, path="input")

    def validate_output(self, tool_name: str, payload: dict[str, Any]) -> None:
        registration = self.get(tool_name)
        if registration is None:
            raise ValueError(f"Unknown tool '{tool_name}'")
        _validate_against_schema(payload, registration.contract.output_schema, path="output")

    def enforce_permissions(
        self,
        *,
        db: Session,
        registration: ToolRegistration,
        context: MCPExecutionContext,
    ) -> None:
        contract = registration.contract
        if contract.tenant_scope_required and not str(context.tenant_id or "").strip():
            raise PermissionError("tenant scope is required for this tool")

        if context.user_role not in contract.required_role:
            raise PermissionError(
                f"Insufficient role for tool '{contract.tool_name}'. "
                f"Required one of: {', '.join(contract.required_role)}"
            )

        if contract.governance_scope_required and not str(context.ai_system_id or "").strip():
            raise PermissionError(f"Tool '{contract.tool_name}' requires ai_system_id governance scope")

        if contract.governance_scope_required:
            try:
                enforce_governance(
                    db,
                    tenant_id=context.tenant_id,
                    ai_system_id=context.ai_system_id,
                    action=f"mcp.tool.{contract.tool_name}",
                    route="/mcp/execute",
                    module=contract.module,
                    tenant_scope=False,
                    commit_logs=False,
                )
            except GovernanceViolationError as exc:
                raise PermissionError(
                    f"Governance context blocked for tool '{contract.tool_name}': {exc.reason_code}"
                ) from exc
            except GovernanceFailSecureError as exc:
                raise RuntimeError(
                    f"Governance unavailable for tool '{contract.tool_name}': {exc.reason_code}"
                ) from exc

        if contract.requires_approval:
            if not str(context.ai_system_id or "").strip():
                raise PermissionError(f"Tool '{contract.tool_name}' requires ai_system_id for approval checks")
            approved_request = db.scalar(
                select(ApprovalRequest.id)
                .where(
                    ApprovalRequest.tenant_id == context.tenant_id,
                    ApprovalRequest.ai_system_id == context.ai_system_id,
                    ApprovalRequest.status == "approved",
                )
                .order_by(ApprovalRequest.updated_at.desc())
                .limit(1)
            )
            if not approved_request:
                raise PermissionError(
                    f"Tool '{contract.tool_name}' requires an approved request for ai_system_id={context.ai_system_id}"
                )

    def execute(
        self,
        *,
        db: Session,
        context: MCPExecutionContext,
        tool_name: str,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        registration = self.get(tool_name)
        if registration is None:
            raise ValueError(f"Unknown tool '{tool_name}'")

        if not isinstance(args, dict):
            raise ValueError("Tool args must be an object")

        effective_ai_system_id = context.ai_system_id or _extract_ai_system_id(args)
        effective_policy_version_id = context.policy_version_id or _extract_policy_version_id(args)
        effective_context = context.model_copy(
            update={
                "ai_system_id": effective_ai_system_id,
                "policy_version_id": effective_policy_version_id,
                "correlation_id": context.correlation_id or get_correlation_id(),
            }
        )

        status = "success"
        error: str | None = None
        result: dict[str, Any] = {}
        authorization_metadata: dict[str, Any] | None = None
        receipt_context: dict[str, Any] | None = None
        execution_observation: MCPExecutionObservation | None = None
        execution_attempt_id = str(uuid4())
        try:
            self.validate_input(tool_name, args)
            self.enforce_permissions(
                db=db,
                registration=registration,
                context=effective_context,
            )
            authorization_metadata, receipt_context = self._enforce_v2_before_handler(
                db=db,
                contract=registration.contract,
                context=effective_context,
                args=args,
            )
            if receipt_context and receipt_context.get("phase5_attempt_id"):
                execution_attempt_id = str(receipt_context["phase5_attempt_id"])
            callback_result = invoke_final_seam(
                db,
                seam_ref="mcp.registered_executor",
                executor=lambda: registration.executor(db, effective_context, args),
            )
            if isinstance(callback_result, MCPExecutionResult):
                result = callback_result.output
                execution_observation = callback_result.observation
            else:
                result = callback_result
                if registration.execution_observer is not None:
                    execution_observation = registration.execution_observer(db, effective_context, result)
            if not isinstance(result, dict):
                raise ValueError(f"Tool '{tool_name}' returned non-object result")
            self.validate_output(tool_name, result)
        except Exception as exc:
            status = "fail"
            error = str(exc)
            self._write_execution_record(
                db=db,
                registration=registration,
                context=effective_context,
                args=args,
                status=status,
                error=error,
                result={},
                authorization_metadata=authorization_metadata,
                receipt_context=receipt_context,
                execution_observation=execution_observation,
                execution_attempt_id=execution_attempt_id,
            )
            raise

        self._write_execution_record(
            db=db,
            registration=registration,
            context=effective_context,
            args=args,
            status=status,
            error=None,
            result=result,
            authorization_metadata=authorization_metadata,
            receipt_context=receipt_context,
            execution_observation=execution_observation,
            execution_attempt_id=execution_attempt_id,
        )
        return result

    @staticmethod
    def _enforce_v2_before_handler(
        *,
        db: Session,
        contract: ToolContract,
        context: MCPExecutionContext,
        args: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        from app.core.config import settings
        from app.core.control_engine.authorization import (
            apply_trusted_pre_action_rollout,
            authorization_rollout_persistence_metadata,
        )

        args_hash = _hash_payload(args)
        action_id = str(context.correlation_id or args_hash)
        policy_snapshot_id = str(context.policy_version_id or "internal-mcp-registry")
        trusted = {
            "action_id": action_id,
            "actor": {
                "identity_id": context.user_id,
                "identity_type": "human",
                "user_id": context.user_id,
                "session_id": context.brain_session_id,
            },
            "authority": {
                "authority_type": "internal_mcp_role",
                "authority_source": "server_tool_registry",
                "verified": True,
            },
            "surface": {
                "application": "hawk_internal_mcp",
                "asset_status": "registered",
                "environment": "internal",
            },
            "action": {
                "action_type": "tool_execution",
                "action_risk": str(context.risk_tier or contract.side_effect_level or "unknown").lower(),
                "tool_name": contract.tool_name,
                "tool_version": contract.version,
                "tool_fingerprint_id": _hash_payload(
                    {"module": contract.module, "name": contract.tool_name, "version": contract.version}
                ),
                "parameter_hash": args_hash,
                "target_resource": contract.module,
                "side_effect_class": contract.side_effect_level,
                "persistent_side_effect": contract.side_effect_level != "read",
            },
            "policy": {"policy_snapshot_id": policy_snapshot_id, "control_ids": []},
        }
        outcome = apply_trusted_pre_action_rollout(
            tenant_id=context.tenant_id,
            surface="internal_mcp",
            action_id=action_id,
            chain_id=str(
                context.brain_plan_id or context.brain_session_id or context.correlation_id or args_hash
            ),
            collector_id="internal-mcp-registry",
            trusted_pre_action_governance_check=trusted,
            legacy_decision="allow",
            legacy_reason="internal_mcp_registry_allow",
            legacy_control_mode="inline_allowed",
            policy_snapshot_id=policy_snapshot_id,
            settings_obj=settings,
        )
        if (
            outcome.enforced
            and settings.native_control_framework
            and settings.trusted_control_selector
        ):
            from app.services.native_control.selection_service import (
                apply_native_selection_to_rollout,
            )

            outcome = apply_native_selection_to_rollout(
                db,
                rollout=outcome,
                settings_obj=settings,
                trusted_provider="hawk",
            )
        if not outcome.enforced:
            return None, None
        response = outcome.v2_response
        receipt_context: dict[str, Any] | None = None
        decision_receipt = None
        if settings.decision_execution_receipts_enabled:
            from app.services.receipt_service import persist_pre_execution_decision_isolated

            if outcome.request is None or response is None:
                raise RuntimeError("selected authorization result lacks receipt material")
            receipt, canonical = persist_pre_execution_decision_isolated(
                db,
                request=outcome.request,
                response=response,
                settings_obj=settings,
            )
            if receipt is not None:
                decision_receipt = receipt
                receipt_context = {
                    "decision_receipt_id": receipt.receipt_id,
                    "canonical_action": canonical,
                }
        if response is None or response.decision not in {"allow", "warn"}:
            reason = response.reason if response is not None else "authorization_evaluation_failed"
            raise PermissionError(f"authorization_kernel_v2:{reason}")
        # This is the production generic-route hand-off to the Phase 5 final
        # seam.  The action is constructed from server-side registry/context
        # material; request payload cannot manufacture a permit handle.
        from app.services.action_integrity.execution_authority import (
            build_trusted_execution_action,
            current_rollout_configuration,
            install_execution_authority,
        )
        from app.services.action_integrity.signing import KmsHsmSigningKeyProvider

        rollout_mode, policy_epoch = current_rollout_configuration(db, tenant_id=context.tenant_id)
        execution_action = build_trusted_execution_action(
            tenant_id=context.tenant_id,
            action_id=action_id,
            chain_id=str(context.brain_plan_id or context.brain_session_id or action_id),
            actor_principal=f"user:{context.user_id}",
            executing_principal="service:internal-mcp-registry",
            operation="tool_execution",
            tool_or_service_ref=contract.tool_name,
            tool_fingerprint=_hash_payload({"module": contract.module, "name": contract.tool_name, "version": contract.version}),
            parameter_hash=args_hash,
            target_ref=contract.module,
            policy_epoch=policy_epoch,
            approval_requirement="required" if contract.requires_approval else "not_required",
            policy_version_id=policy_snapshot_id,
            now=datetime.now(timezone.utc),
        )
        provider = db.info.get("phase5_signing_provider") or KmsHsmSigningKeyProvider()
        if rollout_mode == "AUTHORITATIVE":
            # A permit (or an approval request) is only meaningful after the
            # base receipt and its signed V1 extension are independently
            # durable.  In particular, do not let the permit's independent
            # transaction race ahead of an unflushed decision extension.
            if decision_receipt is None:
                raise PermissionError("authoritative MCP execution requires a durable decision receipt")
            if outcome.request is None:
                raise PermissionError("authoritative MCP execution requires a native authorization request")
            control_selection_id = str(
                outcome.request.path_evidence.get("native_control_selection_id") or ""
            )
            if not control_selection_id:
                raise PermissionError("authoritative MCP execution requires a selected native control path")
            if str(response.decision).lower() not in {"allow", "require_approval"}:
                raise PermissionError("authoritative MCP execution has no eligible authorization decision")
            from app.services.action_integrity.lifecycle_persistence import persist_decision_receipt_v2_extension
            from app.services.action_integrity.stored_authority import (
                require_current_profile_selection_v1,
            )
            from app.db.models.native_control import NativeControlSelection

            profile_selection = require_current_profile_selection_v1(
                db,
                provider=provider,
                tenant_id=context.tenant_id,
                now=decision_receipt.issued_at,
            )
            native_selection = db.scalar(
                select(NativeControlSelection).where(
                    NativeControlSelection.tenant_id == context.tenant_id,
                    NativeControlSelection.selection_id == control_selection_id,
                    NativeControlSelection.action_id == execution_action["action_id"],
                )
            )
            if (
                native_selection is None
                or native_selection.control_requirement_unsatisfied
                or not native_selection.control_plan_id
                or not native_selection.control_plan_digest
            ):
                raise PermissionError("authoritative MCP execution native control selection is unavailable")
            execution_action.update(
                domain_profile_ref=profile_selection.profile_id,
                domain_profile_hash=profile_selection.profile_content_hash,
                control_plan_id=native_selection.control_plan_id,
                control_plan_digest=native_selection.control_plan_digest,
            )

            persist_decision_receipt_v2_extension(
                db,
                provider=provider,
                receipt=decision_receipt,
                action=execution_action,
                profile_selection_id=profile_selection.selection_id,
                profile_selection_hash=profile_selection.selection_hash,
                control_selection_id=native_selection.selection_id,
            )
            db.flush()
            db.commit()
            if receipt_context is None:
                receipt_context = {}
            receipt_context.update(
                profile_selection_id=profile_selection.selection_id,
                profile_selection_hash=profile_selection.selection_hash,
                control_selection_id=native_selection.selection_id,
            )
        handle = install_execution_authority(
            db,
            tenant_id=context.tenant_id,
            action=execution_action,
            seam_ref="mcp.registered_executor",
            signing_provider=provider,
            ai_system_id=context.ai_system_id,
            decision_receipt_id=(receipt_context or {}).get("decision_receipt_id"),
        )
        if receipt_context is not None and handle is not None:
            receipt_context["phase5_v2_action"] = execution_action
            receipt_context["phase5_permit_id"] = handle.permit_id
            receipt_context["phase5_attempt_id"] = handle.attempt_id
            decision_receipt_id = str(receipt_context.get("decision_receipt_id") or "")
            if decision_receipt_id:
                from app.services.instruction_tool_provenance import InstructionToolProvenanceService

                InstructionToolProvenanceService(
                    db,
                    signing_provider=provider,
                ).attach_execution_permit(
                    tenant_id=context.tenant_id,
                    decision_receipt_id=decision_receipt_id,
                    execution_permit_id=handle.permit_id,
                )
        return authorization_rollout_persistence_metadata(outcome), receipt_context

    def _write_execution_record(
        self,
        *,
        db: Session,
        registration: ToolRegistration,
        context: MCPExecutionContext,
        args: dict[str, Any],
        status: str,
        error: str | None,
        result: dict[str, Any],
        authorization_metadata: dict[str, Any] | None,
        receipt_context: dict[str, Any] | None,
        execution_observation: MCPExecutionObservation | None,
        execution_attempt_id: str,
    ) -> None:
        contract = registration.contract
        args_hash = _hash_payload(args)
        result_hash = _hash_payload(result)
        audit = write_audit_log(
            db,
            tenant_id=context.tenant_id,
            actor_user_id=context.user_id,
            actor_type="human",
            action="mcp.tool.execute",
            resource_type="mcp_tool",
            resource_id=contract.tool_name,
            payload={
                "tool_name": contract.tool_name,
                "module": contract.module,
                "version": contract.version,
                "status": status,
                "error": error,
                "side_effect_level": contract.side_effect_level,
                "requires_approval": contract.requires_approval,
                "writes_evidence": contract.writes_evidence,
                "idempotent": contract.idempotent,
                "args_hash": args_hash,
                "result_hash": result_hash,
                "correlation_id": context.correlation_id,
                "ai_system_id": context.ai_system_id,
                "policy_version_id": context.policy_version_id,
                "brain_session_id": context.brain_session_id,
                "brain_plan_id": context.brain_plan_id,
                "platform_mode": context.platform_mode,
                "risk_tier": context.risk_tier,
                "governance_version": context.governance_version,
            },
            correlation_id=context.correlation_id,
        )
        if contract.writes_evidence:
            create_evidence_node(
                db,
                tenant_id=context.tenant_id,
                node_type="mcp_tool_execution",
                signal_type="mcp.tool.execute",
                label=f"MCP tool '{contract.tool_name}' {status}",
                payload={
                    "tool_name": contract.tool_name,
                    "module": contract.module,
                    "version": contract.version,
                    "status": status,
                    "error": error,
                    "side_effect_level": contract.side_effect_level,
                    "requires_approval": contract.requires_approval,
                    "args_hash": args_hash,
                    "result_hash": result_hash,
                    "audit_log_id": audit.id,
                    "correlation_id": context.correlation_id,
                    "ai_system_id": context.ai_system_id,
                    "policy_version_id": context.policy_version_id,
                    "brain_session_id": context.brain_session_id,
                    "brain_plan_id": context.brain_plan_id,
                },
                correlation_id=context.correlation_id,
            )
        self._emit_shadow_runtime_event(
            db=db,
            contract=contract,
            context=context,
            status=status,
            args_hash=args_hash,
            result_hash=result_hash,
            audit_log_id=audit.id,
            authorization_metadata=authorization_metadata,
            receipt_context=receipt_context,
            execution_observation=execution_observation,
            execution_attempt_id=execution_attempt_id,
        )

    @staticmethod
    def _emit_shadow_runtime_event(
        *,
        db: Session,
        contract: ToolContract,
        context: MCPExecutionContext,
        status: str,
        args_hash: str,
        result_hash: str,
        audit_log_id: str,
        authorization_metadata: dict[str, Any] | None,
        receipt_context: dict[str, Any] | None,
        execution_observation: MCPExecutionObservation | None,
        execution_attempt_id: str,
    ) -> None:
        """Queue redacted parity telemetry for an isolated post-commit transaction."""

        from app.core.config import settings

        if not (
            (
                settings.authorization_kernel_v2_enabled
                and settings.authorization_kernel_shadow_compare_enabled
            )
            or (settings.decision_execution_receipts_enabled and receipt_context)
        ):
            return
        queue = db.info.setdefault("internal_mcp_shadow_events", [])
        queue.append(
            {
                "contract": contract,
                "context": context,
                "status": status,
                "args_hash": args_hash,
                "result_hash": result_hash,
                "audit_log_id": audit_log_id,
                "authorization_metadata": dict(authorization_metadata or {}),
                "receipt_context": dict(receipt_context or {}),
                "execution_observation": execution_observation.model_dump() if execution_observation else None,
                "phase5_signing_provider": db.info.get("phase5_signing_provider"),
                "execution_attempt_id": execution_attempt_id,
                "observed_at": datetime.now(timezone.utc),
            }
        )
        if db.info.get("internal_mcp_shadow_listeners_installed"):
            return
        db.info["internal_mcp_shadow_listeners_installed"] = True

        def emit_after_commit(committed_session: Session) -> None:
            pending = list(committed_session.info.pop("internal_mcp_shadow_events", []))
            if not pending:
                return
            isolated_session = sessionmaker(
                bind=committed_session.get_bind(),
                autocommit=False,
                autoflush=False,
            )()
            try:
                for item in pending:
                    MCPToolRegistry._persist_shadow_runtime_event(
                        db=isolated_session,
                        **item,
                    )
                isolated_session.commit()
            except Exception as exc:
                isolated_session.rollback()
                logger.exception(
                    "internal MCP post-commit evidence persistence failed",
                    extra={"pending_event_count": len(pending)},
                )
                from app.services.receipt_service import (
                    ExecutionAttemptConflictError,
                    persist_execution_attempt_conflict_finding_isolated,
                    persist_execution_failure_fallback_isolated,
                )

                if isinstance(exc, ExecutionAttemptConflictError):
                    persisted_conflict = False
                    for item in pending:
                        receipt = dict(item.get("receipt_context") or {})
                        if not receipt:
                            continue
                        try:
                            persist_execution_attempt_conflict_finding_isolated(
                                committed_session,
                                tenant_id=item["context"].tenant_id,
                                decision_receipt_id=receipt["decision_receipt_id"],
                                execution_attempt_id=item["execution_attempt_id"],
                            )
                            persisted_conflict = True
                        except Exception:
                            continue
                    if not persisted_conflict:
                        raise RuntimeError(
                            "internal MCP execution attempt conflict finding could not be persisted"
                        ) from exc
                    raise

                for item in pending:
                    receipt = dict(item.get("receipt_context") or {})
                    if not receipt:
                        continue
                    try:
                        persist_execution_failure_fallback_isolated(
                            committed_session,
                            tenant_id=item["context"].tenant_id,
                            decision_receipt_id=receipt["decision_receipt_id"],
                            settings_obj=settings,
                            evaluated_at=item["observed_at"],
                            execution_attempt_id=item["execution_attempt_id"],
                        )
                    except Exception:
                        continue
            finally:
                isolated_session.close()

        def clear_after_rollback(rolled_back_session: Session) -> None:
            pending = list(rolled_back_session.info.pop("internal_mcp_shadow_events", []))
            if not pending:
                return
            from app.services.receipt_service import persist_execution_receipt_isolated

            for item in pending:
                context = dict(item.get("receipt_context") or {})
                if not context:
                    continue
                try:
                    persist_execution_receipt_isolated(
                        rolled_back_session,
                        tenant_id=item["context"].tenant_id,
                        decision_receipt_id=context["decision_receipt_id"],
                        actual_canonical_action=context["canonical_action"],
                        execution_status=("success" if item["status"] == "success" else "failure"),
                        collector_id="internal-mcp-registry",
                        settings_obj=settings,
                        downstream_objects=[{"type": "mcp_result", "result_hash": item["result_hash"]}],
                        executed_at=item["observed_at"],
                        execution_attempt_id=item["execution_attempt_id"],
                    )
                except Exception:
                    continue

        event.listen(db, "after_commit", emit_after_commit)
        event.listen(db, "after_rollback", clear_after_rollback)

    @staticmethod
    def _persist_shadow_runtime_event(
        *,
        db: Session,
        contract: ToolContract,
        context: MCPExecutionContext,
        status: str,
        args_hash: str,
        result_hash: str,
        audit_log_id: str,
        authorization_metadata: dict[str, Any] | None,
        receipt_context: dict[str, Any] | None,
        execution_observation: dict[str, Any] | None,
        phase5_signing_provider: Any | None,
        execution_attempt_id: str,
        observed_at: datetime,
    ) -> None:
        try:
            from app.core.config import settings
            from app.services.runtime_intelligence.runtime_event_normalizer import ingest_runtime_event
            from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

            decision = "allow" if status == "success" else "block"
            trusted_pre_action = {
                "action_id": str(context.correlation_id or args_hash),
                "authority": {
                    "authority_type": "internal_mcp_role",
                    "authority_source": "server_tool_registry",
                    "verified": True,
                },
                "surface": {
                    "application": "hawk_internal_mcp",
                    "asset_status": "registered",
                },
                "action": {
                    "action_type": "tool_execution",
                    "action_risk": "low" if status == "success" else "high",
                    "tool_name": contract.tool_name,
                    "tool_version": contract.version,
                    "tool_fingerprint_id": _hash_payload(
                        {
                            "module": contract.module,
                            "name": contract.tool_name,
                            "version": contract.version,
                        }
                    ),
                    "parameter_hash": args_hash,
                    "target_resource": contract.module,
                },
                "policy": {
                    "policy_snapshot_id": str(context.policy_version_id or "internal-mcp-registry"),
                    "control_ids": [],
                },
            }
            if authorization_metadata:
                trusted_pre_action["authorization_kernel_v2_precomputed"] = dict(
                    authorization_metadata
                )
            authorized_action = dict((receipt_context or {}).get("phase5_v2_action") or {})
            metadata: dict[str, Any] = {
                "decision": decision,
                "action_type": "tool_execution",
                "tool_name": contract.tool_name,
                "tool_version": contract.version,
                "tool_fingerprint": _hash_payload(
                    {
                        "module": contract.module,
                        "name": contract.tool_name,
                        "version": contract.version,
                    }
                ),
                "target_resource": contract.module,
                "side_effect_class": contract.side_effect_level,
                "args_hash": args_hash,
                "result_hash": result_hash,
                "audit_log_id": audit_log_id,
                "operational_telemetry": True,
                "pre_action_governance_check": {
                    "authority": {
                        "authority_type": "internal_mcp_role",
                        "authority_source": "server_tool_registry",
                        "verified": True,
                    },
                    "surface": {"asset_status": "registered"},
                },
            }
            if authorized_action:
                from app.services.action_integrity.canonical_v2 import canonical_action_hash_v2

                metadata.update(
                    {
                        "action_id": authorized_action["action_id"],
                        "phase5_canonical_action_hash": canonical_action_hash_v2(authorized_action),
                        "phase5_execution_observation_state": "OBSERVED" if execution_observation else "UNKNOWN",
                    }
                )
            runtime_event = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=context.tenant_id,
                    source_surface="internal_mcp",
                    event_type="mcp_tool_execute",
                    ai_system_id=context.ai_system_id,
                    app_id="hawk_internal_mcp",
                    user_id=context.user_id,
                    policy_version_id=context.policy_version_id,
                    governance_version=context.governance_version,
                    severity="low" if status == "success" else "high",
                    correlation_id=context.correlation_id,
                    context_id=context.brain_session_id or context.correlation_id,
                    chain_id=context.brain_plan_id or context.brain_session_id or context.correlation_id,
                    entity_type="tool",
                    entity_id=contract.tool_name,
                    risk_score=0.0 if status == "success" else 1.0,
                    tool_name=contract.tool_name,
                    tool_category="internal_mcp",
                    metadata=metadata,
                ),
                trusted_pre_action_governance_check=trusted_pre_action,
            )
            if settings.decision_execution_receipts_enabled and receipt_context:
                from app.services.receipt_service import create_execution_receipt

                # An AUTHORITATIVE permit without a post-callback observer is
                # deliberately left without a terminal receipt/comparison.  A
                # pre-execution canonical action is not evidence of execution.
                if authorized_action and execution_observation is None:
                    return
                actual_canonical_action = (
                    _observed_receipt_canonical_action(
                        receipt_context["canonical_action"],
                        observation=execution_observation,
                        contract=contract,
                    )
                    if execution_observation is not None
                    else receipt_context["canonical_action"]
                )
                execution_receipt, _ = create_execution_receipt(
                    db,
                    tenant_id=context.tenant_id,
                    decision_receipt_id=receipt_context["decision_receipt_id"],
                    actual_canonical_action=actual_canonical_action,
                    execution_status="success" if status == "success" else "failure",
                    collector_id="internal-mcp-registry",
                    settings_obj=settings,
                    downstream_objects=[{"type": "mcp_result", "result_hash": result_hash}],
                    executed_at=observed_at,
                    execution_attempt_id=execution_attempt_id,
                )
                if phase5_signing_provider is not None and authorized_action and execution_observation:
                    from app.services.action_integrity.lifecycle_persistence import persist_execution_receipt_v2_and_comparison

                    executed_action = _observed_v2_execution_action(
                        authorized_action,
                        observation=execution_observation,
                        contract=contract,
                        observed_at=observed_at,
                    )
                    receipt_extension, comparison = persist_execution_receipt_v2_and_comparison(
                        db,
                        provider=phase5_signing_provider,
                        execution_receipt=execution_receipt,
                        authorized=authorized_action,
                        executed=executed_action,
                        permit_id=receipt_context.get("phase5_permit_id"),
                        issued_at=observed_at,
                    )
                    lifecycle_refs = _persist_observed_mcp_lifecycle(
                        db,
                        provider=phase5_signing_provider,
                        tenant_id=context.tenant_id,
                        action_id=str(authorized_action["action_id"]),
                        attempt_id=execution_receipt.execution_attempt_id,
                        execution_receipt_id=execution_receipt.receipt_id,
                        observation=execution_observation,
                        observed_at=observed_at,
                    )
                    if runtime_event is not None:
                        _bind_action_integrity_refs_to_runtime_event(
                            db,
                            runtime_event=runtime_event,
                            authorized_action=authorized_action,
                            receipt_context=receipt_context,
                            execution_receipt=execution_receipt,
                            receipt_extension=receipt_extension,
                            comparison=comparison,
                            lifecycle_refs=lifecycle_refs,
                        )
        except Exception:
            raise


def _bind_action_integrity_refs_to_runtime_event(
    db: Session,
    *,
    runtime_event: Any,
    authorized_action: Mapping[str, Any],
    receipt_context: Mapping[str, Any],
    execution_receipt: Any,
    receipt_extension: Any,
    comparison: Any,
    lifecycle_refs: Mapping[str, Any],
) -> None:
    """Bind one RuntimeEvent to exact persisted action-integrity authorities."""
    from app.db.models.evidence import DecisionReceipt

    decision_receipt_id = str(receipt_context["decision_receipt_id"])
    decision = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == runtime_event.tenant_id,
            DecisionReceipt.receipt_id == decision_receipt_id,
        )
    )

    def refs(*values: Any) -> list[str]:
        return list(
            dict.fromkeys(
                str(value)
                for value in values
                if isinstance(value, str) and value
            )
        )

    runtime_evidence = refs(*list(runtime_event.evidence_node_ids or []))
    action_evidence = refs(
        getattr(decision, "canonical_action_evidence_node_id", None),
        *runtime_evidence,
    )
    decision_evidence = refs(
        getattr(decision, "evidence_node_id", None),
        getattr(decision, "policy_snapshot_evidence_node_id", None),
        *action_evidence,
    )
    execution_evidence = refs(
        getattr(execution_receipt, "evidence_node_id", None),
        *runtime_evidence,
    )
    effect_evidence = refs(*list(lifecycle_refs.get("persistent_effect_evidence_refs") or []))
    outcome_evidence = refs(*list(lifecycle_refs.get("outcome_evidence_refs") or []))

    metadata = dict(runtime_event.metadata_json or {})
    metadata["canonical_action"] = deepcopy(dict(authorized_action))
    metadata["action_integrity_refs"] = {
        "canonical_action_id": str(authorized_action["action_id"]),
        "control_selection_id": receipt_context.get("control_selection_id"),
        "decision_receipt_id": decision_receipt_id,
        "execution_permit_id": receipt_context.get("phase5_permit_id"),
        "execution_receipt_id": execution_receipt.receipt_id,
        "execution_comparison_id": comparison.id,
        "persistent_effect_id": lifecycle_refs.get("persistent_effect_id"),
        "outcome_verification_id": lifecycle_refs.get("outcome_verification_id"),
        "delegation_context_id": lifecycle_refs.get("delegation_context_id"),
        "evidence_node_ids": {
            "context": runtime_evidence,
            "action": action_evidence,
            "control": decision_evidence,
            "decision": decision_evidence,
            "permit": decision_evidence,
            "execution": execution_evidence,
            "comparison": execution_evidence,
            "persistent_effect": effect_evidence,
            "outcome": outcome_evidence,
        },
    }
    metadata["phase5_execution_receipt_extension_id"] = receipt_extension.receipt_id
    runtime_event.metadata_json = metadata
    db.flush()


def _observed_receipt_canonical_action(
    authorized_canonical_action: Mapping[str, Any],
    *,
    observation: Mapping[str, Any],
    contract: ToolContract,
) -> dict[str, Any]:
    """Project V1 receipt material from post-callback facts, never by reuse."""
    actual = deepcopy(dict(authorized_canonical_action))
    action = dict(actual.get("action") or {})
    tool_ref = str(observation["tool_or_service_ref"])
    target_ref = str(observation["target_ref"])
    tool_fingerprint = str(
        observation.get("tool_fingerprint")
        or _hash_payload({"module": contract.module, "name": tool_ref, "version": contract.version})
    )
    action.update(
        {
            "tool_name": tool_ref,
            "tool_fingerprint_id": tool_fingerprint,
            "parameter_hash": _hash_payload(dict(observation["actual_args"])),
            "target_resource_hash": _hash_payload(target_ref),
        }
    )
    actual["action"] = action
    # The hash commits the authorised projection. Recalculate it from observed
    # material instead of asserting that it remains valid after execution.
    actual.pop("canonical_action_hash", None)
    return actual


def _observed_v2_execution_action(
    authorized_action: Mapping[str, Any],
    *,
    observation: Mapping[str, Any],
    contract: ToolContract,
    observed_at: datetime,
) -> dict[str, Any]:
    """Build V2 executed material from the executor-returned observation."""
    from app.services.action_integrity.execution_authority import build_trusted_execution_action

    tool_ref = str(observation["tool_or_service_ref"])
    return build_trusted_execution_action(
        tenant_id=str(authorized_action["tenant_id"]),
        action_id=str(authorized_action["action_id"]),
        chain_id=str(authorized_action["chain_id"]),
        actor_principal=str(authorized_action["actor_principal"]),
        executing_principal=str(authorized_action["executing_principal"]),
        operation=str(observation["operation"]),
        tool_or_service_ref=tool_ref,
        tool_fingerprint=str(
            observation.get("tool_fingerprint")
            or _hash_payload({"module": contract.module, "name": tool_ref, "version": contract.version})
        ),
        parameter_hash=_hash_payload(dict(observation["actual_args"])),
        target_ref=str(observation["target_ref"]),
        policy_epoch=int(authorized_action["policy_epoch"]),
        approval_requirement=str(authorized_action["approval_requirement"]),
        policy_version_id=str(authorized_action["policy_version_id"]),
        now=observed_at,
    )


def _persist_observed_mcp_lifecycle(
    db: Session,
    *,
    provider: Any,
    tenant_id: str,
    action_id: str,
    attempt_id: str,
    execution_receipt_id: str,
    observation: Mapping[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    """Persist optional child/effect/outcome facts only when the observer has them."""
    from app.services.action_integrity.lifecycle_persistence import (
        persist_expected_outcome_v2,
        persist_outcome_verification_v2,
        persist_persistent_effect_v2,
        register_delegated_child_v2,
    )

    expires_at = observed_at + timedelta(minutes=5)
    persisted: dict[str, Any] = {}
    delegated_child = observation.get("delegated_child")
    if isinstance(delegated_child, Mapping):
        parent_scope = delegated_child.get("parent_scope")
        child_scope = delegated_child.get("child_scope")
        delegated_action_id = delegated_child.get("delegated_action_id")
        parent_context_id = delegated_child.get("parent_delegation_context_id")
        if (
            isinstance(parent_scope, Mapping)
            and isinstance(child_scope, Mapping)
            and isinstance(delegated_action_id, str)
            and delegated_action_id
            and (parent_context_id is None or isinstance(parent_context_id, str))
        ):
            child = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                parent_action_id=action_id,
                delegated_action_id=delegated_action_id,
                parent_delegation_context_id=parent_context_id,
                parent_scope=parent_scope,
                child_scope=child_scope,
                source_principal_ref=str(delegated_child.get("source_principal_ref") or "service:internal-mcp-registry"),
                destination_principal_ref=str(delegated_child.get("destination_principal_ref") or "service:mcp-child"),
                expires_at=expires_at,
                issued_at=observed_at,
            )
            persisted["delegation_context_id"] = child.delegation_context_id

    expected_row = None
    expected = observation.get("expected_outcome")
    if isinstance(expected, Mapping) and expected.get("expected_state_hash") is not None:
        expected_row = persist_expected_outcome_v2(
            db,
            provider=provider,
            tenant_id=tenant_id,
            action_id=action_id,
            expected_state_hash=str(expected["expected_state_hash"]),
            verification_deadline=expires_at,
            issued_at=observed_at,
            evidence_refs=[str(ref) for ref in list(expected.get("evidence_refs") or [])],
        )

    effect = observation.get("persistent_effect")
    if isinstance(effect, Mapping) and effect.get("downstream_object_hash") and effect.get("expected_object_state_hash"):
        effect_evidence_refs = [str(ref) for ref in list(effect.get("evidence_refs") or [])]
        effect_row = persist_persistent_effect_v2(
            db,
            provider=provider,
            tenant_id=tenant_id,
            action_id=action_id,
            attempt_id=attempt_id,
            execution_receipt_id=execution_receipt_id,
            downstream_object_hash=str(effect["downstream_object_hash"]),
            expected_object_state_hash=str(effect["expected_object_state_hash"]),
            state=str(effect.get("state") or "APPLIED"),
            expires_at=expires_at,
            issued_at=observed_at,
            evidence_refs=effect_evidence_refs,
        )
        persisted["persistent_effect_id"] = effect_row.id
        persisted["persistent_effect_evidence_refs"] = effect_evidence_refs

    outcome = observation.get("outcome_verification")
    if isinstance(outcome, Mapping) and expected_row is not None and outcome.get("verification_source_set_hash"):
        outcome_evidence_refs = [str(ref) for ref in list(outcome.get("evidence_refs") or [])]
        outcome_row = persist_outcome_verification_v2(
            db,
            provider=provider,
            tenant_id=tenant_id,
            action_id=action_id,
            attempt_id=attempt_id,
            outcome_contract_id=expected_row.outcome_contract_id,
            execution_receipt_id=execution_receipt_id,
            result=str(outcome.get("result") or "UNKNOWN"),
            verification_source_set_hash=str(outcome["verification_source_set_hash"]),
            evidence_quality=str(outcome.get("evidence_quality") or "UNVERIFIED"),
            evaluated_at=observed_at,
            evidence_refs=outcome_evidence_refs,
        )
        persisted["outcome_verification_id"] = outcome_row.verification_id
        persisted["outcome_evidence_refs"] = outcome_evidence_refs

    return persisted


def _extract_ai_system_id(args: dict[str, Any]) -> str | None:
    for key in ("ai_system_id", "id"):
        value = str(args.get(key) or "").strip()
        if value:
            return value
    return None


def _extract_policy_version_id(args: dict[str, Any]) -> str | None:
    value = str(args.get("policy_version_id") or "").strip()
    return value or None


def _hash_payload(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _validate_against_schema(payload: Any, schema: dict[str, Any], *, path: str) -> None:
    expected_type = schema.get("type")
    if expected_type is not None:
        _validate_type(payload, expected_type, path=path)

    if "enum" in schema:
        allowed = schema.get("enum") or []
        if payload not in allowed:
            raise ValueError(f"{path} must be one of {allowed}")

    if expected_type == "object":
        properties = schema.get("properties") or {}
        required = schema.get("required") or []
        for key in required:
            if key not in payload:
                raise ValueError(f"{path}.{key} is required")
        additional_allowed = schema.get("additionalProperties", True)
        if additional_allowed is False:
            extras = sorted(set(payload.keys()) - set(properties.keys()))
            if extras:
                raise ValueError(f"{path} has unexpected keys: {', '.join(extras)}")
        for key, sub_schema in properties.items():
            if key in payload and isinstance(sub_schema, dict):
                _validate_against_schema(payload[key], sub_schema, path=f"{path}.{key}")

    if expected_type == "array" and "items" in schema:
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(payload):
                _validate_against_schema(item, item_schema, path=f"{path}[{idx}]")

    if expected_type == "string":
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(payload) < min_length:
            raise ValueError(f"{path} must have length >= {min_length}")


def _validate_type(payload: Any, expected_type: Any, *, path: str) -> None:
    if isinstance(expected_type, (list, tuple)):
        for candidate in expected_type:
            try:
                _validate_type(payload, candidate, path=path)
                return
            except ValueError:
                continue
        raise ValueError(f"{path} must match one of types {list(expected_type)}")

    expected = str(expected_type).strip().lower()
    if expected == "object":
        if not isinstance(payload, dict):
            raise ValueError(f"{path} must be an object")
        return
    if expected == "array":
        if not isinstance(payload, list):
            raise ValueError(f"{path} must be an array")
        return
    if expected == "string":
        if not isinstance(payload, str):
            raise ValueError(f"{path} must be a string")
        return
    if expected == "boolean":
        if not isinstance(payload, bool):
            raise ValueError(f"{path} must be a boolean")
        return
    if expected == "integer":
        if isinstance(payload, bool) or not isinstance(payload, int):
            raise ValueError(f"{path} must be an integer")
        return
    if expected == "number":
        if isinstance(payload, bool) or not isinstance(payload, (int, float)):
            raise ValueError(f"{path} must be a number")
        return
    if expected == "null":
        if payload is not None:
            raise ValueError(f"{path} must be null")
        return
    raise ValueError(f"{path} has unsupported schema type '{expected_type}'")


_MCP_REGISTRY: MCPToolRegistry | None = None


def get_mcp_registry() -> MCPToolRegistry:
    global _MCP_REGISTRY
    if _MCP_REGISTRY is None:
        _MCP_REGISTRY = MCPToolRegistry()
    return _MCP_REGISTRY
