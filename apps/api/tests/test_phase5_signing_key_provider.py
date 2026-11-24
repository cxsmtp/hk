from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_local_provider_is_scope_isolated_and_rotation_preserves_history_only() -> None:
    from app.services.action_integrity.signing import LocalSigningKeyProvider, sign_object, verify_signed_object

    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="old", secret=b"a" * 32)
    signed = sign_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", key_id="old", value={"tenant_id": "tenant-a", "value": "x"})
    assert verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed)
    assert not verify_signed_object(provider, purpose="approval_binding_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed)
    provider.set_state(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="old", state="verify_only")
    assert verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed)
    assert not verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed, current_authority=True)
    with pytest.raises(ValueError, match="cannot be reused"):
        provider.add_key(purpose="approval_binding_signing", tenant_id="tenant-a", key_id="bad", secret=b"a" * 32)


def test_signature_decoder_rejects_padding_wrong_domain_and_revoked_current_authority() -> None:
    from app.services.action_integrity.signing import LocalSigningKeyProvider, sign_object, verify_signed_object

    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key", secret=b"b" * 32)
    signed = sign_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", key_id="key", value={"tenant_id": "tenant-a", "value": "x"})
    padded = dict(signed)
    padded["signature"] += "="
    assert not verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=padded)
    assert not verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:other:v1", tenant_id="tenant-a", value=signed)
    provider.set_state(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key", state="revoked")
    assert verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed)
    assert not verify_signed_object(provider, purpose="decision_receipt_signing", domain="hawk:test:v1", tenant_id="tenant-a", value=signed, current_authority=True)


def test_kms_hsm_requires_raw_low_s_asymmetric_signatures() -> None:
    from app.services.action_integrity.signing import KmsHsmSigningKeyProvider

    low_s_raw = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    valid = base64.urlsafe_b64encode(low_s_raw).decode().rstrip("=")
    high_s_raw = (1).to_bytes(32, "big") + ((int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16) // 2) + 1).to_bytes(32, "big")
    high_s = base64.urlsafe_b64encode(high_s_raw).decode().rstrip("=")

    class Hsm:
        def metadata(self, **_: str) -> dict[str, str]:
            return {"algorithm": "ES256", "key_id": "key", "state": "active"}

        def sign(self, **_: object) -> str:
            return valid

        def verify(self, *, signature: str, **_: object) -> bool:
            return signature == valid

        def active_key_id(self, **_: str) -> str:
            return "key"

    provider = KmsHsmSigningKeyProvider(Hsm())
    assert provider.verify(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key", payload=b"proof", signature=valid)
    assert not provider.verify(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key", payload=b"proof", signature=high_s)


def test_provider_requires_the_declared_algorithm_and_signature_input_is_exact() -> None:
    from app.services.action_integrity.signing import LocalSigningKeyProvider, sign_hs256, signed_object_bytes

    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key", secret=b"z" * 32)
    payload = signed_object_bytes("hawk:decision-receipt:v2", {"tenant_id": "tenant-a", "signature": "ignored", "a": 1})
    assert payload == b'hawk:decision-receipt:v2\x00{"a":1,"tenant_id":"tenant-a"}'
    assert sign_hs256(
        purpose="decision_receipt_signing", tenant_id="tenant-a", key=b"x" * 32,
        payload=b'hawk:decision-receipt:v2\x00{"a":1}',
    ) == "uSRS7f5XfukNt2ZveITK6DdwKBBCC9n0Qk7LnA_Rmv0"
    with pytest.raises(ValueError, match="algorithm"):
        provider.sign(
            purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="key",
            algorithm="EdDSA", payload=payload,
        )


def test_kms_provider_binds_ed25519_signature_to_explicit_algorithm() -> None:
    from app.services.action_integrity.signing import KmsHsmSigningKeyProvider

    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    class Ed25519Hsm:
        def metadata(self, **_: str) -> dict[str, str]:
            return {"algorithm": "EdDSA", "key_id": "ed-key", "state": "active"}

        def sign(self, *, algorithm: str, payload: bytes, **_: object) -> str:
            assert algorithm == "EdDSA"
            return base64.urlsafe_b64encode(private.sign(payload)).decode().rstrip("=")

        def verify(self, *, algorithm: str, payload: bytes, signature: str, **_: object) -> bool:
            assert algorithm == "EdDSA"
            try:
                private.public_key().verify(base64.urlsafe_b64decode(signature + "=="), payload)
            except Exception:
                return False
            return True

        def active_key_id(self, **_: str) -> str:
            return "ed-key"

    provider = KmsHsmSigningKeyProvider(Ed25519Hsm())
    signature = provider.sign(
        purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="ed-key",
        algorithm="EdDSA", payload=b"exact-input",
    )
    assert signature == "DZ4c8gesuLhIy-eNF-TN-RfnWGmuGN4q4t9YcU0gclcQhUNx_EAvuMS2zNvRYyTD7OKIxAbFZl5Wdlz1UWT4Bw"
    assert provider.verify(
        purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="ed-key",
        algorithm="EdDSA", payload=b"exact-input", signature=signature,
    )
    assert not provider.verify(
        purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="ed-key",
        algorithm="ES256", payload=b"exact-input", signature=signature,
    )


def test_kms_provider_rejects_a_legacy_delegate_without_algorithm_parameter() -> None:
    from app.services.action_integrity.signing import KmsHsmSigningKeyProvider

    class LegacyDelegate:
        def metadata(self, **_: str) -> dict[str, str]:
            return {"algorithm": "EdDSA", "key_id": "legacy", "state": "active"}

        def sign(self, *, purpose: str, tenant_id: str, key_id: str, payload: bytes) -> str:
            return "A" * 86

        def verify(self, *, purpose: str, tenant_id: str, key_id: str, payload: bytes, signature: str) -> bool:
            return True

    provider = KmsHsmSigningKeyProvider(LegacyDelegate())
    with pytest.raises(ValueError, match="signature provider.*explicit algorithm"):
        provider.sign(
            purpose="decision_receipt_signing", tenant_id="tenant-a", key_id="legacy",
            algorithm="EdDSA", payload=b"exact-input",
        )
