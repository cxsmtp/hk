from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import EndpointPrimitive, EndpointPrimitiveContext


class FastPathAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_PREAUTHORIZED_PERMIT = "require_preauthorized_permit"
    REQUIRE_REMOTE_DECISION = "require_remote_decision"
    REQUIRE_USER_RETRY_AFTER_APPROVAL = "require_user_retry_after_approval"
    ALLOW_WITH_EVIDENCE = "allow_with_evidence"

    # Source compatibility only. Enum iteration and all new policy bundles use
    # the canonical Phase 3 actions above.
    LOCAL_ESCALATION_REQUIRED = REQUIRE_USER_RETRY_AFTER_APPROVAL
    REMOTE_ENRICHMENT_ALLOWED = ALLOW_WITH_EVIDENCE

    @classmethod
    def _missing_(cls, value: object) -> "FastPathAction | None":
        legacy = {
            "local_escalation_required": cls.REQUIRE_USER_RETRY_AFTER_APPROVAL,
            "remote_enrichment_allowed": cls.ALLOW_WITH_EVIDENCE,
        }
        return legacy.get(str(value or "").strip().lower())


@dataclass(frozen=True, slots=True)
class FastPathDecision:
    action: FastPathAction
    reason: str
    policy_version: str
    rule_id: str | None
    cache_key: str
    policy_epoch: int | None = None
    cache_hit: bool = False
    remote_lookup_performed: bool = False


@dataclass(frozen=True, slots=True)
class PolicyLoadResult:
    accepted: bool
    fast_path: "EndpointPolicyFastPath | None"
    failures: tuple[str, ...]


def canonical_policy_bytes(policy: Mapping[str, Any]) -> bytes:
    return json.dumps(
        policy,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _utc(value: Any) -> datetime:
    rendered = str(value or "").strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(rendered)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def _canonical_primitive(value: Any) -> str:
    return EndpointPrimitive(str(value or "").strip().lower()).value


def _canonical_action(value: Any) -> str:
    return FastPathAction(str(value or "").strip().lower()).value


_V1_POLICY_FIELDS = {
    "schema",
    "version",
    "tenant_id",
    "device_id",
    "policy_version",
    "policy_sequence",
    "issued_at",
    "expires_at",
    "rules",
    "degradation",
}
_V2_POLICY_FIELDS = _V1_POLICY_FIELDS | {
    "policy_epoch",
    "rollback_version",
    "user_group_scope",
    "supported_primitives",
    "classification_rules",
    "destination_rules",
    "business_purpose_references",
    "exception_references",
    "supported_predicates",
    "omitted_predicates",
    "required_remote_context",
    "platform_capability_requirements",
}
_ALLOWED_MATCH_FIELDS = {
    "primitives",
    "resource_classifications",
    "destination_classifications",
    "binary_identities",
    "users",
    "business_purposes",
    "application_assets",
    "ai_assets",
}
_REQUIRED_DEGRADATION = {
    "low_risk_read",
    "sensitive_file_read",
    "file_write",
    "process_exec",
    "known_approved_destination",
    "unknown_external_destination",
    "sensitive_external_transfer",
    "mcp_local_connection",
}
_DEGRADATION_VALUES = {
    "fail_closed",
    "local_policy_only",
    "allow_with_evidence",
    "require_exception",
}


class EndpointPolicyFastPath:
    def __init__(self, policy: dict[str, Any], *, cache_limit: int = 2048) -> None:
        self._policy = policy
        normalized_rules: list[dict[str, Any]] = []
        for source_rule in policy["rules"]:
            rule = dict(source_rule)
            match = dict(rule["match"])
            if "primitives" in match:
                match["primitives"] = [
                    _canonical_primitive(value) for value in match["primitives"]
                ]
            rule["match"] = match
            rule["action"] = _canonical_action(rule["action"])
            normalized_rules.append(rule)
        self._rules = tuple(
            sorted(
                normalized_rules,
                key=lambda row: (int(row["priority"]), str(row["rule_id"])),
            )
        )
        self._degradation = dict(policy["degradation"])
        self._cache_limit = max(1, min(int(cache_limit), 8192))
        self._cache: OrderedDict[str, FastPathDecision] = OrderedDict()

    @property
    def policy_version(self) -> str:
        return str(self._policy["policy_version"])

    @property
    def policy_epoch(self) -> int | None:
        value = self._policy.get("policy_epoch")
        return int(value) if value is not None else None

    def invalidate_for_policy_epoch(self, active_epoch: int) -> bool:
        """Keep cached authority only when it is bound to the active epoch."""

        if self.policy_epoch == int(active_epoch):
            return True
        self._cache.clear()
        return False

    @classmethod
    def load_signed(
        cls,
        envelope: Mapping[str, Any],
        *,
        trusted_public_keys: Mapping[str, bytes],
        expected_tenant_id: str,
        expected_device_id: str,
        now: datetime | None = None,
        cache_limit: int = 2048,
    ) -> "EndpointPolicyFastPath":
        result = cls.try_load_signed(
            envelope,
            trusted_public_keys=trusted_public_keys,
            expected_tenant_id=expected_tenant_id,
            expected_device_id=expected_device_id,
            now=now,
            cache_limit=cache_limit,
        )
        if result.fast_path is None:
            raise ValueError("signed endpoint policy rejected: " + ", ".join(result.failures))
        return result.fast_path

    @classmethod
    def try_load_signed(
        cls,
        envelope: Mapping[str, Any],
        *,
        trusted_public_keys: Mapping[str, bytes],
        expected_tenant_id: str,
        expected_device_id: str,
        now: datetime | None = None,
        cache_limit: int = 2048,
    ) -> PolicyLoadResult:
        failures: list[str] = []
        if not isinstance(envelope, Mapping) or set(envelope) != {
            "key_id",
            "algorithm",
            "policy",
            "signature",
        }:
            return PolicyLoadResult(False, None, ("invalid_envelope_schema",))
        key_id = str(envelope.get("key_id") or "")
        if envelope.get("algorithm") != "Ed25519":
            failures.append("unsupported_algorithm")
        key = trusted_public_keys.get(key_id)
        if key is None:
            failures.append("untrusted_key")
        policy = envelope.get("policy")
        if not isinstance(policy, dict):
            failures.append("invalid_policy")
        else:
            failures.extend(
                cls._validate_policy(
                    policy,
                    expected_tenant_id=expected_tenant_id,
                    expected_device_id=expected_device_id,
                    now=now or datetime.now(UTC),
                )
            )
        if key is not None and isinstance(policy, dict):
            try:
                signature = base64.b64decode(str(envelope.get("signature") or ""), validate=True)
                Ed25519PublicKey.from_public_bytes(bytes(key)).verify(
                    signature,
                    canonical_policy_bytes(policy),
                )
            except (ValueError, TypeError, InvalidSignature, binascii.Error):
                failures.append("signature_invalid")
        failures = list(dict.fromkeys(failures))
        if failures:
            return PolicyLoadResult(False, None, tuple(failures))
        return PolicyLoadResult(True, cls(dict(policy), cache_limit=cache_limit), ())

    @staticmethod
    def _validate_policy(
        policy: dict[str, Any],
        *,
        expected_tenant_id: str,
        expected_device_id: str,
        now: datetime,
    ) -> list[str]:
        failures: list[str] = []
        version = policy.get("version")
        allowed_field_sets = (
            {
                frozenset(_V1_POLICY_FIELDS),
                frozenset(_V1_POLICY_FIELDS - {"policy_sequence"}),
            }
            if version == 1
            else {frozenset(_V2_POLICY_FIELDS)}
        )
        if frozenset(policy) not in allowed_field_sets:
            failures.append("invalid_policy_fields")
        if (
            policy.get("schema") != "hawk.endpoint-fast-path-policy"
            or type(version) is not int
            or version not in {1, 2}
        ):
            failures.append("unsupported_policy_schema")
        if policy.get("tenant_id") != expected_tenant_id:
            failures.append("tenant_binding_invalid")
        if policy.get("device_id") != expected_device_id:
            failures.append("device_binding_invalid")
        if not str(policy.get("policy_version") or "").strip():
            failures.append("policy_version_missing")
        if "policy_sequence" in policy:
            policy_sequence = policy.get("policy_sequence")
            if type(policy_sequence) is not int or policy_sequence <= 0:
                failures.append("policy_sequence_invalid")
        if version == 2:
            policy_epoch = policy.get("policy_epoch")
            if type(policy_epoch) is not int or policy_epoch <= 0:
                failures.append("policy_epoch_invalid")
            rollback_version = policy.get("rollback_version")
            if rollback_version is not None and not str(rollback_version).strip():
                failures.append("rollback_version_invalid")
            scope = policy.get("user_group_scope")
            if not isinstance(scope, dict) or set(scope) != {"users", "groups"}:
                failures.append("user_group_scope_invalid")
            elif any(
                not isinstance(scope.get(field), list)
                or len(scope[field]) > 4096
                or any(not str(value).strip() for value in scope[field])
                for field in ("users", "groups")
            ):
                failures.append("user_group_scope_invalid")
            list_fields = {
                "supported_primitives": 256,
                "classification_rules": 4096,
                "destination_rules": 4096,
                "business_purpose_references": 4096,
                "exception_references": 4096,
                "supported_predicates": 256,
                "omitted_predicates": 256,
                "required_remote_context": 256,
                "platform_capability_requirements": 256,
            }
            for field, maximum in list_fields.items():
                values = policy.get(field)
                if not isinstance(values, list) or len(values) > maximum:
                    failures.append(f"{field}_invalid")
            supported_primitives = policy.get("supported_primitives")
            if isinstance(supported_primitives, list):
                try:
                    for primitive in supported_primitives:
                        _canonical_primitive(primitive)
                except ValueError:
                    failures.append("supported_primitives_invalid")
        try:
            issued_at = _utc(policy.get("issued_at"))
            expires_at = _utc(policy.get("expires_at"))
            if expires_at <= issued_at or now < issued_at or now >= expires_at:
                failures.append("policy_not_current")
        except (ValueError, TypeError):
            failures.append("policy_time_invalid")
        rules = policy.get("rules")
        if not isinstance(rules, list) or len(rules) > 4096:
            failures.append("rules_invalid")
        else:
            seen: set[str] = set()
            for rule in rules:
                if not isinstance(rule, dict) or set(rule) != {"rule_id", "priority", "match", "action"}:
                    failures.append("rule_schema_invalid")
                    continue
                rule_id = str(rule.get("rule_id") or "")
                if not rule_id or rule_id in seen:
                    failures.append("rule_id_invalid")
                seen.add(rule_id)
                try:
                    priority = int(rule.get("priority"))
                    if not 0 <= priority <= 1_000_000:
                        failures.append("rule_priority_invalid")
                except (TypeError, ValueError):
                    failures.append("rule_priority_invalid")
                match = rule.get("match")
                if not isinstance(match, dict) or not set(match).issubset(_ALLOWED_MATCH_FIELDS):
                    failures.append("rule_match_invalid")
                elif any(
                    not isinstance(values, list) or len(values) > 1024
                    for values in match.values()
                ):
                    failures.append("rule_match_values_invalid")
                elif "primitives" in match:
                    try:
                        for primitive in match["primitives"]:
                            _canonical_primitive(primitive)
                    except ValueError:
                        failures.append("rule_primitive_invalid")
                try:
                    _canonical_action(rule.get("action"))
                except ValueError:
                    failures.append("rule_action_invalid")
        degradation = policy.get("degradation")
        if not isinstance(degradation, dict) or set(degradation) != _REQUIRED_DEGRADATION:
            failures.append("degradation_invalid")
        elif any(value not in _DEGRADATION_VALUES for value in degradation.values()):
            failures.append("degradation_value_invalid")
        return failures

    def evaluate(
        self,
        context: EndpointPrimitiveContext,
        *,
        now_monotonic_ns: int,
        now: datetime | None = None,
    ) -> FastPathDecision:
        # Signed UTC bounds are authoritative for every evaluation.  Checking
        # before the cache prevents a cached allow from surviving policy expiry.
        observed_now = now or datetime.now(UTC)
        try:
            expires_at = _utc(self._policy.get("expires_at"))
            issued_at = _utc(self._policy.get("issued_at"))
        except (TypeError, ValueError):
            expires_at = issued_at = None
        if (
            expires_at is None
            or issued_at is None
            or observed_now.astimezone(UTC) < issued_at
            or observed_now.astimezone(UTC) >= expires_at
        ):
            self._cache.clear()
            mode = self._degradation[self._degradation_class(context)]
            return self._decision(
                self._degradation_action(mode),
                "policy_not_current",
                context,
                rule_id=None,
            )
        if context.tenant_id != self._policy["tenant_id"] or context.device_id != self._policy["device_id"]:
            return self._decision(
                FastPathAction.BLOCK,
                "context_binding_invalid",
                context,
                rule_id=None,
            )
        if context.policy_version != self.policy_version:
            return self._decision(
                FastPathAction.BLOCK,
                "policy_version_mismatch",
                context,
                rule_id=None,
            )
        if self.policy_epoch is not None and context.policy_epoch != self.policy_epoch:
            return self._decision(
                FastPathAction.BLOCK,
                "policy_epoch_mismatch",
                context,
                rule_id=None,
            )
        if context.deadline_monotonic_ns is not None and now_monotonic_ns >= context.deadline_monotonic_ns:
            mode = self._degradation[self._degradation_class(context)]
            action = self._degradation_action(mode)
            return self._decision(action, f"deadline_exhausted:{mode}", context, rule_id=None)

        cache_key = self._cache_key(context)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            return FastPathDecision(
                action=cached.action,
                reason=cached.reason,
                policy_version=cached.policy_version,
                rule_id=cached.rule_id,
                cache_key=cached.cache_key,
                policy_epoch=cached.policy_epoch,
                cache_hit=True,
                remote_lookup_performed=False,
            )

        for rule in self._rules:
            if self._matches(rule["match"], context):
                decision = self._decision(
                    FastPathAction(rule["action"]),
                    f"rule:{rule['rule_id']}",
                    context,
                    rule_id=str(rule["rule_id"]),
                    cache_key=cache_key,
                )
                self._remember(decision)
                return decision

        mode = self._degradation[self._degradation_class(context)]
        decision = self._decision(
            self._degradation_action(mode),
            f"no_matching_rule:{mode}",
            context,
            rule_id=None,
            cache_key=cache_key,
        )
        self._remember(decision)
        return decision

    def _decision(
        self,
        action: FastPathAction,
        reason: str,
        context: EndpointPrimitiveContext,
        *,
        rule_id: str | None,
        cache_key: str | None = None,
    ) -> FastPathDecision:
        return FastPathDecision(
            action=action,
            reason=reason,
            policy_version=self.policy_version,
            rule_id=rule_id,
            cache_key=cache_key or self._cache_key(context),
            policy_epoch=self.policy_epoch,
        )

    def _remember(self, decision: FastPathDecision) -> None:
        self._cache[decision.cache_key] = decision
        self._cache.move_to_end(decision.cache_key)
        while len(self._cache) > self._cache_limit:
            self._cache.popitem(last=False)

    @staticmethod
    def _cache_key(context: EndpointPrimitiveContext) -> str:
        material = {
            "tenant_id": context.tenant_id,
            "device_id": context.device_id,
            "process_identity": context.process.canonical_identity,
            "binary_identity": {
                "signature": context.process.binary_signature,
                "hash": context.process.binary_hash_reference,
                "path": context.process.binary_path,
            },
            "primitive": context.primitive.value,
            "resource_reference": context.resource_reference,
            "resource_classification": context.resource_classification,
            "destination_reference": context.destination_reference,
            "destination_classification": context.destination_classification,
            "policy_version": context.policy_version,
            "policy_epoch": context.policy_epoch,
            "business_purpose_reference": context.business_purpose_reference,
            "user_id": context.process.user_id,
            "application_asset_id": context.application_asset_id,
            "ai_asset_id": context.ai_asset_id,
        }
        raw = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _matches(match: Mapping[str, Any], context: EndpointPrimitiveContext) -> bool:
        checks = {
            "primitives": context.primitive.value,
            "resource_classifications": context.resource_classification,
            "destination_classifications": context.destination_classification,
            "binary_identities": context.process.binary_hash_reference or context.process.binary_signature,
            "users": context.process.user_id,
            "business_purposes": context.business_purpose_reference,
            "application_assets": context.application_asset_id or context.process.application_asset_id,
            "ai_assets": context.ai_asset_id or context.process.ai_asset_id,
        }
        for field, allowed in match.items():
            if checks[field] not in {str(value) for value in allowed}:
                return False
        return True

    @staticmethod
    def _degradation_class(context: EndpointPrimitiveContext) -> str:
        if context.primitive in {EndpointPrimitive.FILE_OPEN, EndpointPrimitive.FILE_READ}:
            return "low_risk_read" if context.resource_classification in {"public", "low"} else "sensitive_file_read"
        if context.primitive in {
            EndpointPrimitive.FILE_WRITE,
            EndpointPrimitive.FILE_CREATE,
            EndpointPrimitive.FILE_RENAME,
            EndpointPrimitive.FILE_DELETE,
        }:
            return "file_write"
        if context.primitive in {EndpointPrimitive.PROCESS_EXEC, EndpointPrimitive.PROCESS_CHILD_CREATE}:
            return "process_exec"
        if context.primitive is EndpointPrimitive.MCP_LOCAL_CONNECTION:
            return "mcp_local_connection"
        if context.primitive in {EndpointPrimitive.UPLOAD, EndpointPrimitive.EXTERNAL_TRANSFER}:
            return "sensitive_external_transfer"
        if context.primitive in {
            EndpointPrimitive.NETWORK_CONNECT,
            EndpointPrimitive.NETWORK_SEND,
            EndpointPrimitive.NETWORK_RECEIVE,
            EndpointPrimitive.NETWORK_LISTEN,
            EndpointPrimitive.DOWNLOAD,
            EndpointPrimitive.LOCAL_SERVICE_ACCESS,
        }:
            if context.destination_classification in {"enterprise_approved", "internal", "known_approved"}:
                return "known_approved_destination"
            return "unknown_external_destination"
        return "sensitive_external_transfer"

    @staticmethod
    def _degradation_action(mode: str) -> FastPathAction:
        if mode == "allow_with_evidence":
            return FastPathAction.ALLOW_WITH_EVIDENCE
        if mode == "require_exception":
            return FastPathAction.REQUIRE_USER_RETRY_AFTER_APPROVAL
        # `local_policy_only` with no decisive local rule must not become an
        # implicit allow. It blocks until a signed local policy authorizes it.
        return FastPathAction.BLOCK
