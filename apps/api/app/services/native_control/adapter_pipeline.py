from __future__ import annotations

from dataclasses import dataclass, replace
import json
from typing import Any, Callable, Mapping

from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationResponse,
    authorize_ai_action,
)
from app.services.native_control.adapter_contract import (
    AdapterContractError,
    AdapterError,
    AdapterErrorCode,
    AdapterPipelineContext,
    NativeControlAdapter,
    NativeControlEvent,
    stable_hash,
    validate_adapter_contract,
)


MAX_RAW_PROVIDER_EVENT_BYTES = 65_536
MAX_RAW_PROVIDER_EVENT_DEPTH = 12


@dataclass(frozen=True, slots=True)
class AdapterPipelineResult:
    action_id: str
    authorization_request: AuthorizationRequest
    authorization_response: AuthorizationResponse
    provider_response: dict[str, Any]
    normalized_event_hash: str
    evidence_ref: str
    selected_control_point_id: str
    duplicate: bool = False


class HawkCallbackSecurityBoundary:
    """Hawk-owned transport/auth/replay/schema boundary; adapters never receive authority fields."""

    def __init__(self) -> None:
        self._seen: set[tuple[str, str, str, str]] = set()

    def validate(
        self,
        *,
        context: AdapterPipelineContext,
        raw_payload: Mapping[str, Any],
    ) -> bool:
        if not context.transport_authenticated or not context.signature_valid:
            raise AdapterError(AdapterErrorCode.AUTHENTICATION_FAILURE)
        if not context.tenant_id or not context.integration_instance_id or not context.credential_id:
            raise AdapterError(AdapterErrorCode.AUTHENTICATION_FAILURE)
        if not context.provider_event_id or not context.nonce:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        if not isinstance(raw_payload, Mapping):
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)

        def inspect(value: Any, *, depth: int = 0) -> None:
            if depth > MAX_RAW_PROVIDER_EVENT_DEPTH:
                raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if not isinstance(key, str):
                        raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
                    inspect(child, depth=depth + 1)
            elif isinstance(value, list):
                if len(value) > 512:
                    raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
                for child in value:
                    inspect(child, depth=depth + 1)
            elif value is not None and not isinstance(value, (str, int, float, bool)):
                raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)

        inspect(raw_payload)
        try:
            encoded = json.dumps(raw_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED) from exc
        if len(encoded) > MAX_RAW_PROVIDER_EVENT_BYTES:
            raise AdapterError(AdapterErrorCode.EVENT_SCHEMA_UNSUPPORTED)
        key = (
            context.tenant_id,
            context.integration_instance_id,
            context.provider_event_id,
            context.nonce,
        )
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


class NativeControlAdapterPipeline:
    """Provider-neutral pipeline. Hawk owns trust, selection, policy, action and evidence."""

    def __init__(
        self,
        *,
        evidence_sink: Callable[[dict[str, object]], None],
        security_boundary: HawkCallbackSecurityBoundary | None = None,
        control_point_resolver: Callable[[NativeControlAdapter, AuthorizationRequest], str] | None = None,
        policy_evaluator: Callable[[AuthorizationRequest], AuthorizationResponse] = authorize_ai_action,
    ) -> None:
        self._evidence_sink = evidence_sink
        self._security = security_boundary or HawkCallbackSecurityBoundary()
        self._resolve_control_point = control_point_resolver or (
            lambda adapter, _request: f"adapter:{adapter.descriptor.adapter_id}"
        )
        self._policy = policy_evaluator
        self._results: dict[tuple[str, str, str], AdapterPipelineResult] = {}

    def process(
        self,
        *,
        adapter: NativeControlAdapter,
        context: AdapterPipelineContext,
        raw_payload: Mapping[str, Any],
    ) -> AdapterPipelineResult:
        validate_adapter_contract(adapter)
        identity = (
            context.tenant_id,
            context.integration_instance_id,
            context.provider_event_id,
        )
        fresh = self._security.validate(context=context, raw_payload=raw_payload)
        if not fresh:
            cached = self._results.get(identity)
            if cached is None:
                raise AdapterContractError("replay_result_missing")
            return replace(cached, duplicate=True)
        event: NativeControlEvent = adapter.normalize_event(raw_payload, context)
        if event.tenant_id != context.tenant_id:
            raise AdapterContractError("adapter_tenant_override_rejected")
        if event.integration_instance_id != context.integration_instance_id:
            raise AdapterContractError("adapter_integration_override_rejected")
        request = event.to_authorization_request()
        selected_control_point_id = str(self._resolve_control_point(adapter, request) or "").strip()
        if not selected_control_point_id:
            raise AdapterContractError("control_requirement_unsatisfied")
        response = self._policy(request)
        provider_response = adapter.format_decision_response(response)
        if response.decision == "block" and (
            provider_response.get("continue") is not False
            or str(provider_response.get("decision") or "").lower() != "block"
        ):
            raise AdapterContractError("decision_translation_weakened_block")
        if response.decision in {"review", "require_approval", "require_second_approval"} and (
            provider_response.get("continue") is not False
        ):
            raise AdapterContractError("decision_translation_weakened_approval")
        normalized_hash = stable_hash(event)
        evidence_ref = f"native-adapter-evidence:{stable_hash([*identity, normalized_hash])}"
        evidence = {
            "evidence_ref": evidence_ref,
            "tenant_id": context.tenant_id,
            "integration_instance_id": context.integration_instance_id,
            "action_id": request.action_id,
            "provider_event_id_hash": stable_hash(context.provider_event_id),
            "normalized_event_hash": normalized_hash,
            "decision": response.decision,
            "control_mode": response.control_mode,
            "selected_control_point_id": selected_control_point_id,
            "raw_payload_retained": False,
        }
        self._evidence_sink(evidence)
        result = AdapterPipelineResult(
            action_id=request.action_id,
            authorization_request=request,
            authorization_response=response,
            provider_response=dict(provider_response),
            normalized_event_hash=normalized_hash,
            evidence_ref=evidence_ref,
            selected_control_point_id=selected_control_point_id,
        )
        self._results[identity] = result
        return result
