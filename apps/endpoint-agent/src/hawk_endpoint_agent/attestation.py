"""Fail-closed evidence contracts for bank-mode endpoint readiness.

This module validates the shape and binding of evidence returned by trusted
external systems.  It deliberately does not parse or cryptographically verify
Apple attestation assertions; that work must be performed by a configured
remote verifier whose bounded result is checked here.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .macos_native import (
    EXTENSION_BUNDLE_IDS, HOST_BUNDLE_ID, macos_component_set_digest,
)


REMOTE_HARDWARE_ATTESTATION_SCHEMA = "hawk.remote-hardware-attestation"
BANK_READINESS_SCHEMA = "hawk.bank-macos-readiness"
MDM_ENDPOINT_TRUST_PIN_SCHEMA = "hawk.mdm-endpoint-trust-pin"
_SUPPORTED_ATTESTATION_FORMATS = frozenset(
    {"apple-managed-device-attestation-v1"}
)
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class AttestationExpectations:
    """Values a remote attestation result must be bound to."""

    issuer: str
    audience: str
    nonce: str
    device_id: str
    endpoint_public_key_sha256: str
    trusted_verifier_public_keys: Mapping[str, bytes | str]
    trusted_readiness_signer_public_keys: Mapping[str, bytes | str]
    trusted_edr_certifier_public_keys: Mapping[str, bytes | str]
    now: datetime
    maximum_age: timedelta = timedelta(minutes=10)
    clock_skew: timedelta = timedelta(seconds=30)


@dataclass(frozen=True, slots=True)
class RemoteAttestationResult:
    accepted: bool
    failures: tuple[str, ...]
    external_verification_accepted: bool
    cryptographic_verification_performed: bool = False
    verifier_receipt_signature_verified: bool = False


@dataclass(frozen=True, slots=True)
class BankReadinessResult:
    ready: bool
    gates: Mapping[str, bool]
    failures: tuple[str, ...]


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _canonical_bytes(value: object) -> bytes | None:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return None


def _public_key_bytes(value: object) -> bytes | None:
    if isinstance(value, bytes):
        return value if len(value) == 32 else None
    if isinstance(value, str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            return None
        return decoded if len(decoded) == 32 else None
    return None


def _verify_ed25519(
    payload: object,
    signature_value: object,
    public_key_value: object,
) -> bool:
    canonical = _canonical_bytes(payload)
    public_key = _public_key_bytes(public_key_value)
    if canonical is None or public_key is None or not isinstance(signature_value, str):
        return False
    try:
        signature = base64.b64decode(signature_value, validate=True)
        if len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, canonical)
    except (ValueError, TypeError, InvalidSignature):
        return False
    return True


def _nonempty(value: object, *, maximum: int = 512) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= maximum
        and value == value.strip()
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
    )


def _parse_utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed.astimezone(UTC)


def _strict_object(
    value: object,
    required: frozenset[str],
    path: str,
    failures: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping):
        failures.append(f"{path}: object required")
        return None
    keys = frozenset(value.keys())
    missing = required - keys
    unknown = keys - required
    if missing:
        failures.append(f"{path}: missing fields: {', '.join(sorted(missing))}")
    if unknown:
        failures.append(f"{path}: unknown fields: {', '.join(sorted(map(str, unknown)))}")
    return value


def _record_equal(
    value: object,
    expected: object,
    path: str,
    failures: list[str],
) -> None:
    if value != expected:
        failures.append(f"{path}: unexpected value")


def verify_remote_attestation(
    evidence: Mapping[str, Any] | None,
    expectations: AttestationExpectations,
) -> RemoteAttestationResult:
    """Validate a trusted remote verifier's result without claiming local crypto.

    The accepted result means the external result is well-formed, current, from
    an explicitly trusted verifier, and bound to the requested device/session.
    ``cryptographic_verification_performed`` is always false because this
    module never verifies opaque Apple attestation formats itself.
    """

    failures: list[str] = []
    expected_fields = frozenset(
        {
            "schema",
            "version",
            "format",
            "status",
            "issuer",
            "audience",
            "nonce",
            "device_id",
            "key_binding",
            "issued_at",
            "expires_at",
            "verification",
        }
    )
    root = _strict_object(evidence, expected_fields, "attestation", failures)
    if root is None:
        return RemoteAttestationResult(False, tuple(failures), False)

    _record_equal(
        root.get("schema"), REMOTE_HARDWARE_ATTESTATION_SCHEMA, "schema", failures
    )
    _record_equal(root.get("version"), 1, "version", failures)
    attestation_format = root.get("format")
    if (
        not isinstance(attestation_format, str)
        or attestation_format not in _SUPPORTED_ATTESTATION_FORMATS
    ):
        failures.append("format: unsupported attestation format")
    _record_equal(root.get("status"), "verified", "status", failures)
    _record_equal(root.get("issuer"), expectations.issuer, "issuer", failures)
    _record_equal(root.get("audience"), expectations.audience, "audience", failures)
    _record_equal(root.get("nonce"), expectations.nonce, "nonce", failures)
    _record_equal(root.get("device_id"), expectations.device_id, "device_id", failures)

    key_binding = _strict_object(
        root.get("key_binding"),
        frozenset({"key_id", "public_key_sha256"}),
        "key_binding",
        failures,
    )
    if key_binding is not None:
        if not _nonempty(key_binding.get("key_id"), maximum=256):
            failures.append("key_binding.key_id: non-empty bounded value required")
        public_key_sha256 = key_binding.get("public_key_sha256")
        if not _is_sha256(public_key_sha256):
            failures.append("key_binding.public_key_sha256: lowercase SHA-256 required")
        elif public_key_sha256 != expectations.endpoint_public_key_sha256:
            failures.append("key_binding.public_key_sha256: key binding mismatch")

    verification = _strict_object(
        root.get("verification"),
        frozenset(
            {
                "status",
                "method",
                "verifier_id",
                "verified_at",
                "assertion_sha256",
                "receipt_signature",
            }
        ),
        "verification",
        failures,
    )
    if verification is not None:
        _record_equal(
            verification.get("status"),
            "verified",
            "verification.status",
            failures,
        )
        _record_equal(
            verification.get("method"),
            "remote-cryptographic-verifier",
            "verification.method",
            failures,
        )
        verifier_id = verification.get("verifier_id")
        if (
            not isinstance(verifier_id, str)
            or verifier_id not in expectations.trusted_verifier_public_keys
        ):
            failures.append("verification.verifier_id: verifier is not trusted")
        if not _is_sha256(verification.get("assertion_sha256")):
            failures.append("verification.assertion_sha256: lowercase SHA-256 required")

    now = expectations.now
    if now.tzinfo is None or now.utcoffset() != timedelta(0):
        failures.append("expectations.now: timezone-aware UTC time required")
        now = now.replace(tzinfo=UTC)
    else:
        now = now.astimezone(UTC)
    if expectations.maximum_age <= timedelta(0):
        failures.append("expectations.maximum_age: positive duration required")
    if expectations.clock_skew < timedelta(0):
        failures.append("expectations.clock_skew: non-negative duration required")

    issued_at = _parse_utc_timestamp(root.get("issued_at"))
    expires_at = _parse_utc_timestamp(root.get("expires_at"))
    verified_at = (
        _parse_utc_timestamp(verification.get("verified_at"))
        if verification is not None
        else None
    )
    if issued_at is None:
        failures.append("issued_at: RFC3339 UTC timestamp required")
    if expires_at is None:
        failures.append("expires_at: RFC3339 UTC timestamp required")
    if verified_at is None:
        failures.append("verification.verified_at: RFC3339 UTC timestamp required")
    if issued_at is not None:
        if issued_at > now + expectations.clock_skew:
            failures.append("issued_at: evidence was issued in the future")
        if now - issued_at > expectations.maximum_age + expectations.clock_skew:
            failures.append("issued_at: evidence is too old")
    if expires_at is not None and expires_at <= now - expectations.clock_skew:
        failures.append("expires_at: evidence is expired")
    if issued_at is not None and expires_at is not None and issued_at >= expires_at:
        failures.append("expires_at: must be after issued_at")
    if verified_at is not None:
        if verified_at > now + expectations.clock_skew:
            failures.append("verification.verified_at: verification is in the future")
        if issued_at is not None and verified_at < issued_at:
            failures.append("verification.verified_at: precedes issuance")
        if expires_at is not None and verified_at >= expires_at:
            failures.append("verification.verified_at: outside validity period")

    receipt_signature_verified = False
    if verification is not None:
        verifier_id = verification.get("verifier_id")
        trusted_key = (
            expectations.trusted_verifier_public_keys.get(verifier_id)
            if isinstance(verifier_id, str)
            else None
        )
        unsigned = dict(root)
        unsigned_verification = dict(verification)
        signature = unsigned_verification.pop("receipt_signature", None)
        unsigned["verification"] = unsigned_verification
        receipt_signature_verified = _verify_ed25519(unsigned, signature, trusted_key)
        if not receipt_signature_verified:
            failures.append(
                "verification.receipt_signature: trusted verifier receipt signature invalid"
            )

    accepted = not failures and receipt_signature_verified
    return RemoteAttestationResult(
        accepted=accepted,
        failures=tuple(failures),
        external_verification_accepted=accepted,
        cryptographic_verification_performed=False,
        verifier_receipt_signature_verified=receipt_signature_verified,
    )


def _current_window(
    value: Mapping[str, Any] | None,
    now: datetime,
    *,
    issued_field: str = "issued_at",
    expires_field: str = "expires_at",
) -> bool:
    if value is None:
        return False
    issued_at = _parse_utc_timestamp(value.get(issued_field))
    expires_at = _parse_utc_timestamp(value.get(expires_field))
    return bool(
        issued_at is not None
        and expires_at is not None
        and issued_at <= now < expires_at
    )


def _validate_macos_release_evidence_v2(
    build: object, notarization: object, *, now: datetime | None = None,
) -> dict[str, str]:
    """Validate exact four-component build and notarization v2 evidence.

    Existing readiness-v1 gates remain separate; v1 cannot serve as endpoint
    OS-control acceptance material.
    """
    observed = now or datetime.now(UTC)
    if observed.tzinfo is None:
        raise ValueError("verification time must be UTC-aware")
    if not isinstance(build, dict) or set(build) != {
        "schema", "version", "artifact", "signature", "components",
        "component_set_digest", "verified_at",
    } or build.get("schema") != "hawk.bank-macos-build-evidence" or build.get("version") != 2:
        raise ValueError("v2 build evidence schema is invalid")
    artifact = build["artifact"]
    signature = build["signature"]
    components = build["components"]
    if (not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "binary_version"} or
            artifact["name"] != "Hawk Endpoint.app" or
            not _is_sha256(artifact["sha256"]) or
            not _nonempty(artifact["binary_version"], maximum=64) or
            not isinstance(signature, dict) or
            set(signature) != {"team_id", "publisher", "hardened_runtime"} or
            not isinstance(signature["team_id"], str) or
            len(signature["team_id"]) != 10 or
            not signature["team_id"].isalnum() or
            not isinstance(signature["publisher"], str) or
            not signature["publisher"].startswith("Developer ID Application:") or
            signature["hardened_runtime"] is not True or
            not isinstance(components, list) or len(components) != 4):
        raise ValueError("v2 build identity or component count is invalid")
    ids = {HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS}
    requirements = {
        HOST_BUNDLE_ID: "com.apple.developer.system-extension.install",
        EXTENSION_BUNDLE_IDS[0]: "com.apple.developer.endpoint-security.client",
        EXTENSION_BUNDLE_IDS[1]: "com.apple.developer.networking.networkextension",
        EXTENSION_BUNDLE_IDS[2]: "com.apple.developer.networking.networkextension",
    }
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in components:
        if not isinstance(row, dict) or set(row) != {
            "bundle_id", "version", "bundle_version", "team_id", "sha256",
            "entitlement", "provisioning_profile", "hardened_runtime",
        }:
            raise ValueError("v2 component schema is invalid")
        identifier = row["bundle_id"]
        if (not isinstance(identifier, str) or identifier not in ids or identifier in seen or
                row["team_id"] != signature["team_id"] or
                row["version"] != artifact["binary_version"] or
                not _nonempty(row["bundle_version"], maximum=64) or
                not _is_sha256(row["sha256"]) or
                row["entitlement"] != requirements[identifier] or
                not _nonempty(row["provisioning_profile"], maximum=255) or
                row["hardened_runtime"] is not True):
            raise ValueError("v2 component identity is invalid")
        seen.add(identifier)
        records.append({name: row[name] for name in
                        ("bundle_id", "version", "bundle_version", "sha256")})
    if seen != ids or next(row for row in components if row["bundle_id"] == HOST_BUNDLE_ID)["sha256"] != artifact["sha256"]:
        raise ValueError("v2 host artifact binding is invalid")
    component_digest = macos_component_set_digest(records)
    build_time = _parse_utc_timestamp(build["verified_at"])
    if (build["component_set_digest"] != component_digest or
            build_time is None or build_time > observed):
        raise ValueError("v2 component digest or build time is invalid")
    if not isinstance(notarization, dict) or set(notarization) != {
        "schema", "version", "team_id", "build_evidence_sha256",
        "component_evidence_sha256", "submitted_package_sha256",
        "stapled_package_sha256", "status", "submission_id",
        "staple_status", "verified_at",
    } or notarization.get("schema") != "hawk.bank-macos-notarization-evidence" or notarization.get("version") != 2:
        raise ValueError("v2 notarization schema is invalid")
    build_bytes = _canonical_bytes(build)
    components_bytes = _canonical_bytes(components)
    notary_time = _parse_utc_timestamp(notarization["verified_at"])
    if (build_bytes is None or components_bytes is None or
            notarization["team_id"] != signature["team_id"] or
            notarization["build_evidence_sha256"] != hashlib.sha256(build_bytes).hexdigest() or
            notarization["component_evidence_sha256"] != hashlib.sha256(components_bytes).hexdigest() or
            not _is_sha256(notarization["submitted_package_sha256"]) or
            not _is_sha256(notarization["stapled_package_sha256"]) or
            notarization["status"] != "accepted" or
            not _nonempty(notarization["submission_id"], maximum=255) or
            notarization["staple_status"] != "valid" or
            notary_time is None or not build_time <= notary_time <= observed):
        raise ValueError("v2 notarization binding or time is invalid")
    return {
        "component_set_digest": component_digest,
        "team_id": signature["team_id"],
        "artifact_sha256": artifact["sha256"],
        "build_evidence_sha256": hashlib.sha256(build_bytes).hexdigest(),
    }


def validate_macos_release_evidence_v2(
    build: object, notarization: object, *, now: datetime | None = None,
) -> dict[str, str]:
    try:
        return _validate_macos_release_evidence_v2(build, notarization, now=now)
    except (KeyError, TypeError, AttributeError, StopIteration) as exc:
        raise ValueError("v2 release evidence is malformed") from exc


def _valid_build(value: object, now: datetime) -> tuple[bool, bool, Mapping[str, Any] | None]:
    failures: list[str] = []
    build = _strict_object(
        value,
        frozenset({"schema", "version", "artifact", "entitlement", "signature", "verified_at"}),
        "build",
        failures,
    )
    if build is None:
        return False, False, None
    artifact = _strict_object(
        build.get("artifact"),
        frozenset({"name", "sha256", "binary_version"}),
        "build.artifact",
        failures,
    )
    entitlement = _strict_object(
        build.get("entitlement"),
        frozenset({"status", "source", "network_extension_type"}),
        "build.entitlement",
        failures,
    )
    signature = _strict_object(
        build.get("signature"),
        frozenset({"status", "identity_type", "publisher", "team_id", "hardened_runtime"}),
        "build.signature",
        failures,
    )
    build_verified_at = _parse_utc_timestamp(build.get("verified_at"))
    base = (
        not failures
        and build.get("schema") == "hawk.bank-macos-build-evidence"
        and build.get("version") == 1
        and artifact is not None
        and _nonempty(artifact.get("name"), maximum=255)
        and _is_sha256(artifact.get("sha256"))
        and _nonempty(artifact.get("binary_version"), maximum=64)
        and build_verified_at is not None
        and build_verified_at <= now
    )
    entitlement_valid = bool(
        base
        and entitlement is not None
        and entitlement.get("status") == "verified"
        and entitlement.get("source") == "apple-codesign"
        and entitlement.get("network_extension_type") == "transparent-proxy"
    )
    signature_valid = bool(
        base
        and signature is not None
        and signature.get("status") == "verified"
        and signature.get("identity_type") == "developer-id-application"
        and signature.get("hardened_runtime") is True
        and _nonempty(signature.get("publisher"), maximum=255)
        and str(signature.get("publisher", "")).startswith("Developer ID Application:")
        and _nonempty(signature.get("team_id"), maximum=32)
    )
    return entitlement_valid, signature_valid, build if base else None


def _valid_mdm(
    value: object,
    now: datetime,
    build: Mapping[str, Any] | None,
) -> tuple[bool, bool]:
    failures: list[str] = []
    mdm = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "status",
                "managed",
                "routing_authorization",
                "installation_status",
                "configuration_profile_id",
                "system_extension_bundle_id",
                "team_id",
                "issued_at",
                "expires_at",
            }
        ),
        "mdm",
        failures,
    )
    if mdm is None:
        return False, False
    signature = build.get("signature") if build is not None else None
    base = bool(
        not failures
        and mdm.get("schema") == "hawk.mdm-managed-routing-evidence"
        and mdm.get("version") == 1
        and mdm.get("status") == "verified"
        and mdm.get("managed") is True
        and _nonempty(mdm.get("configuration_profile_id"), maximum=255)
        and _nonempty(mdm.get("system_extension_bundle_id"), maximum=255)
        and _nonempty(mdm.get("team_id"), maximum=32)
        and isinstance(signature, Mapping)
        and mdm.get("team_id") == signature.get("team_id")
        and _current_window(mdm, now)
    )
    return (
        base and mdm.get("routing_authorization") == "authorized",
        base and mdm.get("installation_status") == "installed",
    )


def _valid_notarization(
    value: object,
    now: datetime,
    build: Mapping[str, Any] | None,
) -> tuple[bool, bool]:
    failures: list[str] = []
    notarization = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "artifact_sha256",
                "build_evidence_sha256",
                "submission_artifact_sha256",
                "status",
                "submission_id",
                "staple_status",
                "verified_at",
            }
        ),
        "notarization",
        failures,
    )
    if notarization is None:
        return False, False
    artifact = build.get("artifact") if build is not None else None
    build_canonical = _canonical_bytes(build)
    build_digest = (
        hashlib.sha256(build_canonical).hexdigest()
        if build_canonical is not None
        else None
    )
    verified_at = _parse_utc_timestamp(notarization.get("verified_at"))
    base = bool(
        not failures
        and notarization.get("schema") == "hawk.bank-macos-notarization-evidence"
        and notarization.get("version") == 1
        and _is_sha256(notarization.get("artifact_sha256"))
        and isinstance(artifact, Mapping)
        and notarization.get("artifact_sha256") == artifact.get("sha256")
        and notarization.get("build_evidence_sha256") == build_digest
        and _is_sha256(notarization.get("submission_artifact_sha256"))
        and _nonempty(notarization.get("submission_id"), maximum=255)
        and verified_at is not None
        and verified_at <= now
    )
    return (
        base and notarization.get("status") == "accepted",
        base and notarization.get("staple_status") == "valid",
    )


def _valid_edr(
    value: object,
    now: datetime,
    build: Mapping[str, Any] | None,
    expectations: AttestationExpectations,
) -> bool:
    failures: list[str] = []
    edr = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "status",
                "vendor",
                "product",
                "product_version",
                "test_scenario",
                "result",
                "certification_claimed",
                "hawk_binary",
                "build_evidence_sha256",
                "certification",
                "verified_at",
            }
        ),
        "edr",
        failures,
    )
    if edr is None:
        return False
    binary = _strict_object(
        edr.get("hawk_binary"),
        frozenset(
            {
                "name",
                "sha256",
                "signed_publisher",
                "team_identifier",
                "binary_version",
                "signature_verified",
                "hardened_runtime",
            }
        ),
        "edr.hawk_binary",
        failures,
    )
    certification = _strict_object(
        edr.get("certification"),
        frozenset(
            {"status", "algorithm", "certifier_id", "verified_at", "signature"}
        ),
        "edr.certification",
        failures,
    )
    artifact = build.get("artifact") if build is not None else None
    signature = build.get("signature") if build is not None else None
    verified_at = _parse_utc_timestamp(edr.get("verified_at"))
    certification_verified_at = (
        _parse_utc_timestamp(certification.get("verified_at"))
        if certification is not None
        else None
    )
    build_canonical = _canonical_bytes(build)
    expected_build_digest = (
        hashlib.sha256(build_canonical).hexdigest()
        if build_canonical is not None
        else None
    )
    certification_signature_valid = False
    if certification is not None:
        certifier_id = certification.get("certifier_id")
        trusted_key = (
            expectations.trusted_edr_certifier_public_keys.get(certifier_id)
            if isinstance(certifier_id, str)
            else None
        )
        unsigned_edr = dict(edr)
        unsigned_certification = dict(certification)
        receipt_signature = unsigned_certification.pop("signature", None)
        unsigned_edr["certification"] = unsigned_certification
        certification_signature_valid = _verify_ed25519(
            unsigned_edr,
            receipt_signature,
            trusted_key,
        )
    return bool(
        not failures
        and edr.get("schema") == "hawk.edr-coexistence-evidence"
        and edr.get("version") == 1
        and edr.get("status") == "verified"
        and edr.get("result") == "pass"
        and edr.get("certification_claimed") is True
        and all(
            _nonempty(edr.get(field), maximum=512)
            for field in ("vendor", "product", "product_version", "test_scenario")
        )
        and binary is not None
        and binary.get("signature_verified") is True
        and binary.get("hardened_runtime") is True
        and isinstance(artifact, Mapping)
        and isinstance(signature, Mapping)
        and binary.get("name") == artifact.get("name")
        and binary.get("sha256") == artifact.get("sha256")
        and binary.get("binary_version") == artifact.get("binary_version")
        and binary.get("signed_publisher") == signature.get("publisher")
        and binary.get("team_identifier") == signature.get("team_id")
        and edr.get("build_evidence_sha256") == expected_build_digest
        and certification is not None
        and certification.get("status") == "verified"
        and certification.get("algorithm") == "Ed25519"
        and isinstance(certification.get("certifier_id"), str)
        and certification.get("certifier_id")
        in expectations.trusted_edr_certifier_public_keys
        and certification_signature_valid
        and verified_at is not None
        and verified_at <= now
        and certification_verified_at is not None
        and verified_at <= certification_verified_at <= now
    )


def _valid_managed_pin(
    value: object,
    now: datetime,
    expectations: AttestationExpectations,
) -> bool:
    failures: list[str] = []
    pin = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "status",
                "managed",
                "management_source",
                "configuration_profile_id",
                "device_id",
                "endpoint_public_key_sha256",
                "session_receipt_verifier_public_key_sha256",
                "issued_at",
                "expires_at",
            }
        ),
        "ipc_trust_pin",
        failures,
    )
    return bool(
        pin is not None
        and not failures
        and pin.get("schema") == MDM_ENDPOINT_TRUST_PIN_SCHEMA
        and pin.get("version") == 1
        and pin.get("status") == "installed"
        and pin.get("managed") is True
        and pin.get("management_source") == "mdm"
        and _nonempty(pin.get("configuration_profile_id"), maximum=255)
        and pin.get("device_id") == expectations.device_id
        and pin.get("endpoint_public_key_sha256")
        == expectations.endpoint_public_key_sha256
        and _is_sha256(pin.get("session_receipt_verifier_public_key_sha256"))
        and _current_window(pin, now)
    )


def _valid_functional_relay(
    value: object,
    now: datetime,
    build: Mapping[str, Any] | None,
) -> bool:
    failures: list[str] = []
    relay = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "status",
                "provider_type",
                "relay_implemented",
                "artifact_sha256",
                "binary_version",
                "tcp_scenario_result",
                "udp_scenario_result",
                "failure_recovery_result",
                "rollback_result",
                "validated_at",
            }
        ),
        "functional_relay",
        failures,
    )
    validated_at = (
        _parse_utc_timestamp(relay.get("validated_at"))
        if relay is not None
        else None
    )
    artifact = build.get("artifact") if build is not None else None
    return bool(
        relay is not None
        and not failures
        and relay.get("schema") == "hawk.network-extension-relay-evidence"
        and relay.get("version") == 1
        and relay.get("status") == "verified"
        and relay.get("provider_type") == "transparent-proxy"
        and relay.get("relay_implemented") is True
        and isinstance(artifact, Mapping)
        and relay.get("artifact_sha256") == artifact.get("sha256")
        and relay.get("binary_version") == artifact.get("binary_version")
        and relay.get("tcp_scenario_result") == "pass"
        and relay.get("udp_scenario_result") == "pass"
        and relay.get("failure_recovery_result") == "pass"
        and relay.get("rollback_result") == "pass"
        and validated_at is not None
        and validated_at <= now
    )


def _valid_local_broker_authentication(
    value: object,
    now: datetime,
    expectations: AttestationExpectations,
    pin_value: object,
    build: Mapping[str, Any] | None,
) -> bool:
    failures: list[str] = []
    broker = _strict_object(
        value,
        frozenset(
            {
                "schema",
                "version",
                "status",
                "implementation",
                "artifact_sha256",
                "binary_version",
                "endpoint_public_key_sha256",
                "session_receipt_verifier_public_key_sha256",
                "client_version",
                "same_uid_result",
                "response_signature_result",
                "session_receipt_result",
                "replay_resistance_result",
                "validated_at",
            }
        ),
        "local_broker_authentication",
        failures,
    )
    validated_at = (
        _parse_utc_timestamp(broker.get("validated_at"))
        if broker is not None
        else None
    )
    artifact = build.get("artifact") if build is not None else None
    pin = pin_value if isinstance(pin_value, Mapping) else None
    return bool(
        broker is not None
        and not failures
        and broker.get("schema") == "hawk.local-broker-authentication-evidence"
        and broker.get("version") == 1
        and broker.get("status") == "verified"
        and broker.get("implementation")
        == "signed-response-and-receipt-verification"
        and isinstance(artifact, Mapping)
        and broker.get("artifact_sha256") == artifact.get("sha256")
        and broker.get("binary_version") == artifact.get("binary_version")
        and broker.get("endpoint_public_key_sha256")
        == expectations.endpoint_public_key_sha256
        and isinstance(pin, Mapping)
        and broker.get("endpoint_public_key_sha256")
        == pin.get("endpoint_public_key_sha256")
        and _is_sha256(broker.get("session_receipt_verifier_public_key_sha256"))
        and broker.get("session_receipt_verifier_public_key_sha256")
        == pin.get("session_receipt_verifier_public_key_sha256")
        and _nonempty(broker.get("client_version"), maximum=128)
        and broker.get("same_uid_result") == "pass"
        and broker.get("response_signature_result") == "pass"
        and broker.get("session_receipt_result") == "pass"
        and broker.get("replay_resistance_result") == "pass"
        and validated_at is not None
        and validated_at <= now
    )


def _valid_readiness_envelope(
    root: Mapping[str, Any],
    now: datetime,
    expectations: AttestationExpectations,
) -> tuple[bool, bool]:
    failures: list[str] = []
    required_root_fields = frozenset(
        {
            "schema",
            "version",
            "managed_routing_enabled",
            "functional_relay",
            "local_broker_authentication",
            "build",
            "mdm",
            "notarization",
            "attestation",
            "edr",
            "ipc_trust_pin",
            "envelope",
        }
    )
    checked_root = _strict_object(root, required_root_fields, "readiness", failures)
    envelope = _strict_object(
        root.get("envelope"),
        frozenset({"algorithm", "signer_id", "signed_at", "signature"}),
        "readiness.envelope",
        failures,
    )
    structural_valid = bool(
        checked_root is not None
        and not failures
        and root.get("schema") == BANK_READINESS_SCHEMA
        and root.get("version") == 1
        and isinstance(root.get("managed_routing_enabled"), bool)
        and envelope is not None
        and envelope.get("algorithm") == "Ed25519"
    )
    if not structural_valid or envelope is None:
        return False, False

    signed_at = _parse_utc_timestamp(envelope.get("signed_at"))
    signer_id = envelope.get("signer_id")
    time_valid = bool(
        signed_at is not None
        and signed_at <= now + expectations.clock_skew
        and now - signed_at <= expectations.maximum_age + expectations.clock_skew
    )
    unsigned_evidence = dict(root)
    unsigned_envelope = dict(envelope)
    signature = unsigned_envelope.pop("signature", None)
    unsigned_evidence.pop("envelope", None)
    payload = {"evidence": unsigned_evidence, "envelope": unsigned_envelope}
    trusted_key = (
        expectations.trusted_readiness_signer_public_keys.get(signer_id)
        if isinstance(signer_id, str)
        else None
    )
    signature_valid = _verify_ed25519(payload, signature, trusted_key)
    return structural_valid, bool(
        time_valid
        and isinstance(signer_id, str)
        and signer_id in expectations.trusted_readiness_signer_public_keys
        and signature_valid
    )


def evaluate_bank_readiness(
    evidence: Mapping[str, Any] | None,
    expectations: AttestationExpectations,
) -> BankReadinessResult:
    """Evaluate all bank-mode gates; absent or malformed evidence stays false."""

    root = evidence if isinstance(evidence, Mapping) else {}
    now = expectations.now.astimezone(UTC) if expectations.now.tzinfo else expectations.now.replace(tzinfo=UTC)
    root_valid, envelope_valid = _valid_readiness_envelope(root, now, expectations)
    trusted_bundle = root_valid and envelope_valid
    entitlement_ok, signature_ok, build = _valid_build(root.get("build"), now)
    mdm_authorized, mdm_installed = _valid_mdm(root.get("mdm"), now, build)
    notarized, stapled = _valid_notarization(root.get("notarization"), now, build)
    attestation = verify_remote_attestation(root.get("attestation"), expectations)

    gates = {
        "managed_routing_opt_in": trusted_bundle
        and root.get("managed_routing_enabled") is True,
        "signed_readiness_envelope": trusted_bundle,
        "functional_network_relay": trusted_bundle
        and _valid_functional_relay(root.get("functional_relay"), now, build),
        "local_broker_cryptographically_authenticated": trusted_bundle
        and _valid_local_broker_authentication(
            root.get("local_broker_authentication"),
            now,
            expectations,
            root.get("ipc_trust_pin"),
            build,
        ),
        "signed_network_extension_entitlement": trusted_bundle and entitlement_ok,
        "mdm_routing_authorized": trusted_bundle and mdm_authorized,
        "mdm_network_extension_installed": trusted_bundle and mdm_installed,
        "hardened_developer_id_signature": trusted_bundle and signature_ok,
        "notarization_accepted": trusted_bundle and notarized,
        "staple_valid": trusted_bundle and stapled,
        "remote_hardware_attestation": trusted_bundle and attestation.accepted,
        "edr_coexistence": trusted_bundle
        and _valid_edr(root.get("edr"), now, build, expectations),
        "managed_ipc_trust_pin": trusted_bundle
        and _valid_managed_pin(root.get("ipc_trust_pin"), now, expectations),
    }
    failures = [
        f"{gate}: required external evidence is absent or invalid"
        for gate, passed in gates.items()
        if not passed
    ]
    if not root_valid:
        failures.insert(0, "readiness: unsupported, missing, or non-strict schema")
    elif not envelope_valid:
        failures.insert(0, "readiness: trusted evidence-envelope signature required")
    failures.extend(
        f"remote_hardware_attestation: {failure}"
        for failure in attestation.failures
    )
    return BankReadinessResult(
        ready=all(gates.values()),
        gates=MappingProxyType(gates),
        failures=tuple(failures),
    )


__all__ = [
    "AttestationExpectations",
    "BANK_READINESS_SCHEMA",
    "BankReadinessResult",
    "MDM_ENDPOINT_TRUST_PIN_SCHEMA",
    "REMOTE_HARDWARE_ATTESTATION_SCHEMA",
    "RemoteAttestationResult",
    "evaluate_bank_readiness",
    "validate_macos_release_evidence_v2",
    "verify_remote_attestation",
]
