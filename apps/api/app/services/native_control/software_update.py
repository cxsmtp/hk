from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError("update_timestamp_invalid")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class SoftwareUpdateVerificationKey:
    key_id: str
    key_role: str
    public_key_pem: str


@dataclass(frozen=True, slots=True)
class SoftwareUpdateArtifact:
    product: str
    version: str
    artifact_sha256: str
    sbom_sha256: str
    provenance_sha256: str
    rollout_channel: str
    rollback_version: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature_algorithm: str
    signature: str

    def as_dict(self, *, include_signature: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "product": self.product,
            "version": self.version,
            "artifact_sha256": self.artifact_sha256,
            "sbom_sha256": self.sbom_sha256,
            "provenance_sha256": self.provenance_sha256,
            "rollout_channel": self.rollout_channel,
            "rollback_version": self.rollback_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
        }
        if include_signature:
            payload["signature"] = self.signature
        return payload


def canonical_update_body(artifact: SoftwareUpdateArtifact) -> bytes:
    payload = artifact.as_dict(include_signature=False)
    payload["issued_at"] = _utc(artifact.issued_at).isoformat()
    payload["expires_at"] = _utc(artifact.expires_at).isoformat()
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def validate_software_update(
    artifact: SoftwareUpdateArtifact,
    *,
    key: SoftwareUpdateVerificationKey,
    now: datetime,
) -> SoftwareUpdateArtifact:
    if key.key_role != "software_update_signing":
        raise ValueError("update_key_role_invalid")
    if key.key_id != artifact.key_id:
        raise ValueError("update_key_binding_invalid")
    if artifact.signature_algorithm != "ES256":
        raise ValueError("update_signature_algorithm_invalid")
    if _utc(artifact.issued_at) > _utc(now) or _utc(artifact.expires_at) < _utc(now):
        raise ValueError("update_time_window_invalid")
    for digest in (artifact.artifact_sha256, artifact.sbom_sha256, artifact.provenance_sha256):
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError("update_digest_invalid")
    if artifact.rollout_channel not in {"canary", "staged", "stable"} or not artifact.rollback_version:
        raise ValueError("update_release_metadata_invalid")
    try:
        public = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            raise ValueError("update_key_invalid")
        signature = base64.urlsafe_b64decode(artifact.signature + ("=" * (-len(artifact.signature) % 4)))
        public.verify(signature, canonical_update_body(artifact), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("update_signature_invalid") from exc
    return artifact
