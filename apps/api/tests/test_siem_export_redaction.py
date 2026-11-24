from __future__ import annotations

import hashlib
import json
import re
import traceback
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.core.config import settings


@pytest.fixture
def siem_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "siem_export_enabled", True)
    monkeypatch.setattr(
        settings,
        "siem_pseudonymization_key",
        "vJ3nHh4K_r9Q2pLm7Xs5cTa8Wz1Dg6FyB0uE",
    )


def _client_factory_for(*, response=None, error: Exception | None = None, requests=None):
    captured = requests if requests is not None else []

    class FakeClient:
        def __init__(self, *, transport, timeout):
            self.transport = transport
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, url, *, follow_redirects, **kwargs):
            captured.append(
                {
                    "method": method,
                    "url": url,
                    "follow_redirects": follow_redirects,
                    **kwargs,
                }
            )
            if error is not None:
                raise error
            return response

    return FakeClient


def _stub_transport_factory(_destination, *, verify):
    assert verify is True
    return object()


def test_siem_export_defaults_disabled() -> None:
    assert settings.siem_export_enabled is False


@pytest.mark.parametrize(
    "pseudonymization_key",
    [
        "",
        "too-short",
        "jwt-secret-value-that-is-distinct",
        "connector-secret-value-that-is-distinct",
        "bundle-secret-value-that-is-distinct",
    ],
)
def test_settings_require_distinct_siem_pseudonymization_key_when_enabled(
    pseudonymization_key: str,
) -> None:
    from app.core.config import Settings

    with pytest.raises(ValueError, match="SIEM_PSEUDONYMIZATION_KEY"):
        Settings(
            _env_file=None,
            secret_key="jwt-secret-value-that-is-distinct",
            secret_key_lock_enabled=False,
            connector_secrets_key="connector-secret-value-that-is-distinct",
            connector_secrets_kdf_salt="connector-salt-value-that-is-distinct",
            onprem_bundle_signing_secret="bundle-secret-value-that-is-distinct",
            siem_export_enabled=True,
            siem_pseudonymization_key=pseudonymization_key,
        )

    configured = Settings(
        _env_file=None,
        secret_key="jwt-secret-value-that-is-distinct",
        secret_key_lock_enabled=False,
        connector_secrets_key="connector-secret-value-that-is-distinct",
        connector_secrets_kdf_salt="connector-salt-value-that-is-distinct",
        onprem_bundle_signing_secret="bundle-secret-value-that-is-distinct",
        siem_export_enabled=True,
        siem_pseudonymization_key="vJ3nHh4K_r9Q2pLm7Xs5cTa8Wz1Dg6FyB0uE",
    )
    assert configured.siem_pseudonymization_key == "vJ3nHh4K_r9Q2pLm7Xs5cTa8Wz1Dg6FyB0uE"


@pytest.mark.parametrize(
    "weak_key",
    [
        "a" * 32,
        "abcd" * 8,
        "01234567890123456789012345678901",
        "abcdefghijklmnopqrstuvwxyzabcdef",
        "changeme-siem-pseudonymization-key",
        "replace-with-a-secure-random-value",
    ],
)
def test_settings_reject_obviously_predictable_siem_keys(weak_key: str) -> None:
    from app.core.config import Settings

    with pytest.raises(ValueError, match="predictable"):
        Settings(
            _env_file=None,
            secret_key="jwt-secret-value-that-is-distinct",
            secret_key_lock_enabled=False,
            connector_secrets_key="connector-secret-value-that-is-distinct",
            connector_secrets_kdf_salt="connector-salt-value-that-is-distinct",
            onprem_bundle_signing_secret="bundle-secret-value-that-is-distinct",
            siem_export_enabled=True,
            siem_pseudonymization_key=weak_key,
        )


@pytest.mark.parametrize(
    "weak_key",
    [
        "a" * 32,
        "abcd" * 8,
        "01234567890123456789012345678901",
        "abcdefghijklmnopqrstuvwxyzabcdef",
        "changeme-siem-pseudonymization-key",
    ],
)
def test_build_rejects_obviously_predictable_runtime_siem_key(
    siem_enabled,
    monkeypatch: pytest.MonkeyPatch,
    weak_key: str,
) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    monkeypatch.setattr(settings, "siem_pseudonymization_key", weak_key)
    with pytest.raises(SIEMExportError, match="predictable"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-weak-key"}],
        )


def test_build_siem_export_refuses_when_disabled() -> None:
    from app.services.siem_export_service import SIEMExportDisabledError, build_siem_export

    with pytest.raises(SIEMExportDisabledError, match="SIEM export is disabled"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            enabled=False,
        )


def test_enabled_argument_cannot_bypass_disabled_configuration() -> None:
    from app.services.siem_export_service import SIEMExportDisabledError, build_siem_export

    with pytest.raises(SIEMExportDisabledError, match="SIEM export is disabled"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            enabled=True,
        )


def test_generic_export_is_deterministic_redacted_and_monitoring_honest(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    generated_at = datetime(2026, 7, 22, 12, 1, tzinfo=timezone.utc)
    event = {
        "tenant_id": "tenant-a",
        "event_id": "evt-1",
        "event_type": "policy.violation",
        "severity": "high",
        "created_at": "2026-07-22T12:00:00Z",
        "decision": "block",
        "status": "open",
        "control_mode": "detected_only",
        "source_surface": "browser",
        "correlation_id": "corr-1",
        "url": "https://ai.example/chat?token=url-secret&prompt=private",
        "recommended_action": "Review owner alice@example.com and rotate token=supersecret",
        "raw_prompt": "never export this prompt",
        "response_text": "never export this response",
        "authorization": "Bearer raw-authorization-token",
        "receipt_signature": "do-not-export-signature",
        "metadata_json": {"secret": "do-not-export", "unbounded": ["x"] * 1000},
    }

    first = build_siem_export(
        tenant_id="tenant-a",
        events=[event],
        generated_at=generated_at,
    )
    second = build_siem_export(
        tenant_id="tenant-a",
        events=[event],
        generated_at=generated_at,
    )

    assert first == second
    assert first.metadata == {
        "adapter": "generic",
        "content_type": "application/x-ndjson",
        "delivery_attempted": False,
        "delivery_status": "not_attempted",
        "event_count": 1,
        "generated_at": "2026-07-22T12:01:00Z",
        "health_status": "ready",
        "lag_seconds": 60.0,
        "latest_event_at": "2026-07-22T12:00:00Z",
        "schema": "ocsf-1.1.0-aligned",
    }
    assert first.ndjson.endswith("\n")
    exported = json.loads(first.ndjson)
    assert exported["category_uid"] == 2
    assert exported["class_uid"] == 2001
    assert exported["type_uid"] == 200100
    assert exported["activity_name"] == "policy.violation"
    assert exported["severity"] == "High"
    assert exported["tenant_uid"] == "tenant-a"
    assert exported["event_uid"] == "evt-1"
    assert exported["actor_uid"] == "unknown"
    assert exported["resource_url"] == "https://ai.example/chat"
    assert exported["decision"] == "block"
    assert exported["control_mode"] == "detected_only"
    assert exported["enforcement"] == "monitor_only"
    assert exported["recommended_action"] == "Review owner [email] and rotate [secret]"
    assert "prompt" not in first.ndjson.lower()
    assert "response" not in first.ndjson.lower()
    assert "authorization" not in first.ndjson.lower()
    assert "signature" not in first.ndjson.lower()
    assert "url-secret" not in first.ndjson
    assert "do-not-export" not in first.ndjson


def test_generic_export_pseudonymizes_sensitive_identifiers_and_strips_url_credentials(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    event = {
        "tenant_id": "tenant-a",
        "event_id": "evt-opaque-123",
        "ai_system_id": "system-opaque-456",
        "user_id": "alice@example.com",
        "account_id": "account-raw-789",
        "account_email": "billing@example.com",
        "correlation_id": "token=correlation-secret-987654",
        "url": "https://url-user:url-password@ai.example/chat/path?sig=query-secret#fragment-secret",
    }

    first = build_siem_export(tenant_id="tenant-a", events=[event])
    second = build_siem_export(tenant_id="tenant-a", events=[event])
    exported = json.loads(first.ndjson)

    assert first.ndjson == second.ndjson
    assert exported["event_uid"] == "evt-opaque-123"
    assert exported["ai_system_uid"] == "system-opaque-456"
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", exported["actor_uid"])
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", exported["correlation_uid"])
    assert exported["resource_url"] == "https://ai.example/chat/path"
    for forbidden in (
        "alice@example.com",
        "billing@example.com",
        "account-raw-789",
        "correlation-secret-987654",
        "url-user",
        "url-password",
        "query-secret",
        "fragment-secret",
    ):
        assert forbidden not in first.ndjson


def test_actor_identifier_aliases_share_one_tenant_scoped_pseudonym(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    actor_aliases = (
        "user_id",
        "actor_user_id",
        "actor_id",
        "user_email",
        "account_id",
        "account_user_id",
        "account_email",
    )
    rows = []
    for index, alias in enumerate(actor_aliases):
        result = build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": f"evt-alias-{index}",
                    alias: "alice@example.com",
                }
            ],
        )
        rows.append(json.loads(result.ndjson))

    assert len({row["actor_uid"] for row in rows}) == 1
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", rows[0]["actor_uid"])


def test_opaque_actor_identifier_aliases_are_always_pseudonymized(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    opaque_actor_id = "opaque-actor-42"
    actor_aliases = (
        "user_id",
        "actor_user_id",
        "actor_id",
        "user_email",
        "actor_email",
        "account_id",
        "account_user_id",
        "account_actor_id",
        "account_email",
    )
    actor_uids = []
    for index, alias in enumerate(actor_aliases):
        result = build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": f"evt-opaque-alias-{index}",
                    alias: opaque_actor_id,
                }
            ],
        )
        actor_uids.append(json.loads(result.ndjson)["actor_uid"])
        assert opaque_actor_id not in result.ndjson

    assert len(set(actor_uids)) == 1
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", actor_uids[0])


def test_pseudonym_is_not_an_unkeyed_dictionary_digest(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-dictionary-check",
                "user_id": "alice@example.com",
            }
        ],
    )
    actor_uid = json.loads(result.ndjson)["actor_uid"]
    predictable_digest = hashlib.sha256(
        b"tenant-a:user_id:alice@example.com"
    ).hexdigest()[:32]

    assert actor_uid != f"hawk-pseudo:{predictable_digest}"


def test_pseudonyms_are_tenant_domain_and_key_separated(
    siem_enabled,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.siem_export_service import build_siem_export

    def export_for(tenant_id: str) -> dict[str, object]:
        return json.loads(
            build_siem_export(
                tenant_id=tenant_id,
                events=[
                    {
                        "tenant_id": tenant_id,
                        "event_id": f"evt-{tenant_id}",
                        "user_id": "alice@example.com",
                        "correlation_id": "alice@example.com",
                    }
                ],
            ).ndjson
        )

    tenant_a = export_for("tenant-a")
    tenant_b = export_for("tenant-b")
    assert tenant_a["actor_uid"] != tenant_b["actor_uid"]
    assert tenant_a["actor_uid"] != tenant_a["correlation_uid"]

    monkeypatch.setattr(
        settings,
        "siem_pseudonymization_key",
        "Qm8_Rt2vK5xN9cL4pW7gH1yF6dS3jB0zUeAa",
    )
    rotated = export_for("tenant-a")
    assert rotated["actor_uid"] != tenant_a["actor_uid"]


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "/chat/token=path-token-secret-123456",
        "/chat/secret=path-secret-123456",
        "/users/alice@example.com/activity",
        "/authorization/Bearer%20eyJhbGciOiJIUzI1NiJ9.sensitive-token",
        "/callbacks/signature=receipt-signature-123456",
        "/credentials/credential=private-credential-123456",
        "/accounts/account=acct-sensitive-123456",
        "/cards/4111111111111111",
    ],
)
def test_generic_export_omits_unsafe_url_paths(
    siem_enabled,
    unsafe_path: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-unsafe-url",
                "url": f"https://ai.example{unsafe_path}?query_token=query-secret#fragment-secret",
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == "https://ai.example/"


def test_export_normalizes_encoded_and_unicode_sensitive_values_before_redaction(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-encoded",
                "user_id": "alice%2540example.com",
                "correlation_id": "token%253Dencoded-secret-123456",
            },
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-unicode",
                "user_id": "ａｌｉｃｅ＠ｅｘａｍｐｌｅ．ｃｏｍ",
            },
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-path",
                "url": "https://ai.example/users/alice%252540example.com",
            },
        ],
    )

    rows = {
        row["event_uid"]: row
        for row in (json.loads(line) for line in result.ndjson.splitlines())
    }
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", rows["evt-encoded"]["actor_uid"])
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", rows["evt-encoded"]["correlation_uid"])
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", rows["evt-unicode"]["actor_uid"])
    assert rows["evt-path"]["resource_url"] == "https://ai.example/"
    assert "%25" not in result.ndjson
    assert "ａｌｉｃｅ" not in result.ndjson


def test_export_redacts_unicode_email_from_scalars_actor_and_url_path(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    unicode_email = "álîçé@例え.テスト"
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-unicode-email",
                "user_id": unicode_email,
                "recommended_action": f"Contact {unicode_email} before escalation",
                "url": f"https://ai.example/users/{unicode_email}/activity",
            }
        ],
    )

    exported = json.loads(result.ndjson)
    assert exported["recommended_action"] == "Contact [email] before escalation"
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", exported["actor_uid"])
    assert exported["resource_url"] == "https://ai.example/"
    assert unicode_email not in result.ndjson


def test_export_redacts_devanagari_eai_for_every_actor_alias_and_url_path(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    unicode_email = "उपयोगकर्ता@उदाहरण.भारत"
    actor_aliases = (
        "user_id",
        "actor_user_id",
        "actor_id",
        "user_email",
        "actor_email",
        "account_id",
        "account_user_id",
        "account_actor_id",
        "account_email",
    )
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": f"evt-devanagari-{index}",
                alias: unicode_email,
                "recommended_action": f"Contact {unicode_email} before escalation",
                "url": f"https://ai.example/users/{unicode_email}/activity",
            }
            for index, alias in enumerate(actor_aliases)
        ],
    )

    rows = [json.loads(line) for line in result.ndjson.splitlines()]
    assert len({row["actor_uid"] for row in rows}) == 1
    assert all(
        re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", row["actor_uid"])
        for row in rows
    )
    assert all(
        row["recommended_action"] == "Contact [email] before escalation"
        for row in rows
    )
    assert all(row["resource_url"] == "https://ai.example/" for row in rows)
    assert unicode_email not in result.ndjson


@pytest.mark.parametrize(
    "unicode_email",
    [
        "उपयोगकर्ता!टैग@उदाहरण.भारत",
        "john#smith@例え.テスト",
        "customer+tag@example.com",
        "name/scope@example.com",
        "owner=ops@example.com",
    ],
)
def test_export_redacts_maximal_rfc_eai_dot_atom_local_parts(
    siem_enabled,
    unicode_email: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-rfc-atext",
                "recommended_action": f"Contact {unicode_email} now",
            }
        ],
    )

    assert json.loads(result.ndjson)["recommended_action"] == "Contact [email] now"
    assert unicode_email not in result.ndjson


def test_export_redacts_rfc6531_utf8_symbol_local_part_and_pseudonymizes_actor(
    siem_enabled,
) -> None:
    from app.services.siem_export_service import build_siem_export

    unicode_email = "用户☃@example.com"
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-rfc6531-symbol",
                "user_id": unicode_email,
                "recommended_action": f"Contact {unicode_email} now",
            }
        ],
    )

    exported = json.loads(result.ndjson)
    assert exported["recommended_action"] == "Contact [email] now"
    assert re.fullmatch(r"hawk-pseudo:[0-9a-f]{32}", exported["actor_uid"])
    assert unicode_email not in result.ndjson


@pytest.mark.parametrize(
    ("source_text", "expected"),
    [
        ("Contact 用户☃@example.com.", "Contact [email]."),
        ("Contact 用户☃@example.com。", "Contact [email]。"),
        ("Contact 用户☃@sub。example.com.", "Contact [email]."),
        ("Contact 用户☃@sub．example｡com。", "Contact [email]。"),
    ],
)
def test_export_redacts_longest_valid_idna_domain_and_preserves_terminal_dot(
    siem_enabled,
    source_text: str,
    expected: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-domain-tail-dot",
                "recommended_action": source_text,
            }
        ],
    )

    assert json.loads(result.ndjson)["recommended_action"] == expected


@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        ("a!b@example.com※", "[email]※"),
        ("用户☃@例え.テスト،", "[email]،"),
        ("alice@example.com-", "[email]-"),
        ("用户☃@例え.テスト€", "[email]€"),
        ('"用户☃@例え.テスト"', '"[email]"'),
        ("[用户☃@例え.テスト]", "[[email]]"),
        ("用户☃@sub.example.com.", "[email]."),
        ("用户☃@sub。example.com。", "[email]。"),
        ("用户☃@sub．example｡com．", "[email]."),
    ],
)
def test_export_redacts_boundary_matrix_and_preserves_terminal_punctuation(
    siem_enabled,
    candidate: str,
    expected: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-email-boundary-matrix",
                "recommended_action": candidate,
            }
        ],
    )

    assert json.loads(result.ndjson)["recommended_action"] == expected


@pytest.mark.parametrize("encoding_depth", range(5))
def test_export_redacts_boundary_email_through_four_percent_encoding_depths(
    siem_enabled,
    encoding_depth: int,
) -> None:
    from urllib.parse import quote

    from app.services.siem_export_service import build_siem_export

    encoded_candidate = "a!b@example.com※"
    for _ in range(encoding_depth):
        encoded_candidate = quote(encoded_candidate, safe="")
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": f"evt-email-depth-{encoding_depth}",
                "recommended_action": encoded_candidate,
            }
        ],
    )

    assert json.loads(result.ndjson)["recommended_action"] == "[email]※"


@pytest.mark.parametrize(
    "utf8_atext",
    [
        "€",  # Sc
        "∑",  # Sm
        "☃",  # So
        "‿",  # Pc
        "—",  # Pd
        "※",  # Po
    ],
)
def test_export_redacts_representative_rfc6531_utf8_atext_categories(
    siem_enabled,
    utf8_atext: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    unicode_email = f"user{utf8_atext}tag@example.com"
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-rfc6531-category",
                "recommended_action": unicode_email,
            }
        ],
    )

    assert json.loads(result.ndjson)["recommended_action"] == "[email]"
    assert unicode_email not in result.ndjson


@pytest.mark.parametrize(
    "invalid_local_character",
    [
        "\u2003",  # whitespace
        "\u0007",  # control
        "\u200d",  # format
        "\ue000",  # private use
        "\u0378",  # unassigned
    ],
)
def test_export_does_not_treat_invalid_utf8_local_characters_as_email(
    siem_enabled,
    invalid_local_character: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    invalid_candidate = f"user{invalid_local_character}@example.com"
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-invalid-rfc6531-local",
                "recommended_action": invalid_candidate,
            }
        ],
    )

    exported_action = json.loads(result.ndjson)["recommended_action"]
    assert "[email]" not in exported_action
    assert "@example.com" in exported_action


@pytest.mark.parametrize(
    ("encoded_local", "domain"),
    [
        ("john%23smith", "例え.テスト"),
        (
            "%E0%A4%89%E0%A4%AA%E0%A4%AF%E0%A5%8B%E0%A4%97%E0%A4%95%E0%A4%B0%E0%A5%8D"
            "%E0%A4%A4%E0%A4%BE%21%E0%A4%9F%E0%A5%88%E0%A4%97",
            "उदाहरण.भारत",
        ),
    ],
)
def test_export_detects_percent_encoded_atext_email_in_raw_url_path(
    siem_enabled,
    encoded_local: str,
    domain: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-encoded-atext-path",
                "url": (
                    f"https://ai.example/users/{encoded_local}@{domain}/activity"
                    "?token=query-secret#fragment-secret"
                ),
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == "https://ai.example/"


def test_export_detects_percent_encoded_rfc6531_symbol_email_in_raw_url_path(
    siem_enabled,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-encoded-rfc6531-symbol-path",
                "url": (
                    "https://ai.example/users/"
                    "%E7%94%A8%E6%88%B7%E2%98%83@example.com/activity"
                ),
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == "https://ai.example/"


@pytest.mark.parametrize(
    "encoded_email_with_terminal_dot",
    [
        "%E7%94%A8%E6%88%B7%E2%98%83@example.com%2E",
        "%E7%94%A8%E6%88%B7%E2%98%83@example.com%E3%80%82",
        "%E7%94%A8%E6%88%B7%E2%98%83@sub%E3%80%82example.com%2E",
    ],
)
def test_export_detects_percent_encoded_email_with_terminal_domain_punctuation(
    siem_enabled,
    encoded_email_with_terminal_dot: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-encoded-domain-tail-dot",
                "url": (
                    "https://ai.example/users/"
                    f"{encoded_email_with_terminal_dot}/activity"
                ),
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == "https://ai.example/"


@pytest.mark.parametrize("encoding_depth", range(5))
def test_export_collapses_boundary_email_url_path_through_four_encoding_depths(
    siem_enabled,
    encoding_depth: int,
) -> None:
    from urllib.parse import quote

    from app.services.siem_export_service import build_siem_export

    encoded_candidate = "a!b@example.com※"
    for _ in range(encoding_depth):
        encoded_candidate = quote(encoded_candidate, safe="")
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": f"evt-email-path-depth-{encoding_depth}",
                "url": f"https://ai.example/users/{encoded_candidate}/activity",
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == "https://ai.example/"


@pytest.mark.parametrize("safe_path", ["/docs/chapter%23one", "/docs/chapter%3Fone"])
def test_export_preserves_safe_encoded_path_delimiters_while_stripping_credentials_and_query(
    siem_enabled,
    safe_path: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-safe-encoded-path",
                "url": (
                    f"https://url-user:url-password@ai.example{safe_path}"
                    "?token=query-secret#fragment-secret"
                ),
            }
        ],
    )

    assert json.loads(result.ndjson)["resource_url"] == f"https://ai.example{safe_path}"
    assert "url-user" not in result.ndjson
    assert "url-password" not in result.ndjson
    assert "query-secret" not in result.ndjson
    assert "fragment-secret" not in result.ndjson


def test_export_preserves_non_email_mentions_and_overredacts_invalid_ascii_domain(
    siem_enabled,
) -> None:
    from app.services.siem_export_service import build_siem_export

    non_email_text = "Notify @admin or ops@localhost; ignore bad@-example.com"
    invalid_path = "/mentions/@admin/bad@-example.com"
    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-non-email-at",
                "recommended_action": non_email_text,
                "url": f"https://ai.example{invalid_path}",
            }
        ],
    )

    exported = json.loads(result.ndjson)
    assert exported["recommended_action"] == "Notify @admin or ops@localhost; ignore [email]"
    assert exported["resource_url"] == "https://ai.example/"


def test_export_rejects_percent_encoding_that_does_not_stabilize_within_cap(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    with pytest.raises(SIEMExportError, match="percent decode limit"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-over-encoded",
                    "url": "https://ai.example/users/alice%2525252540example.com",
                }
            ],
        )


@pytest.mark.parametrize(
    ("field", "encoded_value"),
    [
        ("user_id", "%FF"),
        ("recommended_action", "review-%FE"),
        ("url", "https://ai.example/users/%FF"),
    ],
)
def test_export_rejects_invalid_percent_utf8_without_collision_or_traceback_leak(
    siem_enabled,
    field: str,
    encoded_value: str,
) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    with pytest.raises(SIEMExportError) as captured:
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": f"evt-invalid-utf8-{field}",
                    field: encoded_value,
                }
            ],
        )

    assert str(captured.value) == "invalid SIEM export text encoding"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert encoded_value not in formatted


def test_generic_export_rejects_foreign_tenant_data(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMTenantScopeError, build_siem_export

    with pytest.raises(SIEMTenantScopeError, match="foreign-tenant event"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-b", "event_id": "evt-foreign"}],
        )


@pytest.mark.parametrize(
    "tenant_id",
    [
        " tenant-a ",
        "tenant/a",
        "tenant%2Da",
        "tenant\r\nx",
        "tenant\x00x",
        "tenant\u202ex",
        "ténant-a",
        "ｔenant-a",
    ],
)
def test_generic_export_rejects_tenant_ids_outside_ascii_grammar(
    siem_enabled,
    tenant_id: str,
) -> None:
    from app.services.siem_export_service import SIEMTenantScopeError, build_siem_export

    with pytest.raises(SIEMTenantScopeError, match="ASCII grammar"):
        build_siem_export(
            tenant_id=tenant_id,
            events=[{"tenant_id": tenant_id, "event_id": "evt-1"}],
        )


@pytest.mark.parametrize(
    "tenant_id",
    [
        "tenant-a",
        "tenant.a:region_1",
        "A0._:-z9",
    ],
)
def test_generic_export_accepts_tenant_ids_in_ascii_grammar(
    siem_enabled,
    tenant_id: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id=tenant_id,
        events=[{"tenant_id": tenant_id, "event_id": "evt-1"}],
    )
    assert json.loads(result.ndjson)["tenant_uid"] == tenant_id


def test_generic_export_rejects_encoded_event_tenant_alias(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMTenantScopeError, build_siem_export

    with pytest.raises(SIEMTenantScopeError, match="ASCII grammar"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant%2Da", "event_id": "evt-1"}],
        )


@pytest.mark.parametrize(
    ("tenant_id", "event"),
    [
        ("", {"tenant_id": "tenant-a", "event_id": "evt-1"}),
        ("   ", {"tenant_id": "tenant-a", "event_id": "evt-1"}),
        ("tenant-a", {"event_id": "evt-missing"}),
        ("tenant-a", {"tenant_id": "   ", "event_id": "evt-blank"}),
        ("tenant-a", {"tenant_id": " tenant-a ", "event_id": "evt-not-exact"}),
        ("tenant-a", {"tenant_id": "tenant-b", "event_id": "evt-foreign"}),
    ],
)
def test_generic_export_requires_explicit_exact_non_empty_tenant(
    siem_enabled,
    tenant_id: str,
    event: dict[str, str],
) -> None:
    from app.services.siem_export_service import SIEMTenantScopeError, build_siem_export

    with pytest.raises(SIEMTenantScopeError):
        build_siem_export(tenant_id=tenant_id, events=[event])


def test_generic_export_rejects_unsupported_adapter(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMUnsupportedAdapterError, build_siem_export

    with pytest.raises(SIEMUnsupportedAdapterError, match="unsupported SIEM adapter"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            adapter="splunk",
        )


@pytest.mark.parametrize(
    ("adapter", "forbidden"),
    [
        ("token=adapter-secret-123456", "adapter-secret-123456"),
        ("alice@example.com", "alice@example.com"),
        ("sentinel\r\nX-Injected: yes", "X-Injected"),
    ],
)
def test_unsupported_adapter_error_never_echoes_caller_input(
    siem_enabled,
    adapter: str,
    forbidden: str,
) -> None:
    from app.services.siem_export_service import SIEMUnsupportedAdapterError, build_siem_export

    with pytest.raises(SIEMUnsupportedAdapterError) as captured:
        build_siem_export(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            adapter=adapter,
        )

    assert str(captured.value) == "unsupported SIEM adapter"
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert forbidden not in formatted


def test_generic_export_rejects_oversized_batch(siem_enabled) -> None:
    from app.services.siem_export_service import MAX_EXPORT_EVENTS, SIEMExportSizeError, build_siem_export

    assert MAX_EXPORT_EVENTS == 500
    events = [
        {"tenant_id": "tenant-a", "event_id": f"evt-{index}"}
        for index in range(501)
    ]

    with pytest.raises(SIEMExportSizeError, match="event limit"):
        build_siem_export(tenant_id="tenant-a", events=events)


def test_generic_export_rejects_empty_batch(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    with pytest.raises(SIEMExportError, match="must not be empty"):
        build_siem_export(tenant_id="tenant-a", events=[])


def test_generic_export_rejects_oversized_event_payload(siem_enabled) -> None:
    from app.services.siem_export_service import MAX_EXPORT_INPUT_BYTES, SIEMExportSizeError, build_siem_export

    assert MAX_EXPORT_INPUT_BYTES == 1_048_576
    with pytest.raises(SIEMExportSizeError, match="input byte limit"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-oversized",
                    "raw_prompt": "x" * 1_048_577,
                }
            ],
        )


def test_generic_export_rejects_non_json_values_without_string_coercion(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    class StatefulString:
        calls = 0

        def __str__(self) -> str:
            self.calls += 1
            return "alice@example.com"

    unsafe = StatefulString()
    with pytest.raises(SIEMExportError, match="JSON-compatible"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-stateful",
                    "recommended_action": unsafe,
                }
            ],
        )

    assert unsafe.calls == 0


@pytest.mark.parametrize(
    "unsafe_value",
    [
        b"binary",
        {"set-is-not-json"},
        float("nan"),
        SimpleNamespace(value="not-json"),
    ],
)
def test_generic_export_rejects_non_json_compatible_payloads(
    siem_enabled,
    unsafe_value: object,
) -> None:
    from app.services.siem_export_service import SIEMExportError, build_siem_export

    with pytest.raises(SIEMExportError, match="JSON-compatible"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-invalid-json",
                    "metadata_json": unsafe_value,
                }
            ],
        )


def test_generic_export_rejects_excessive_json_depth_and_nodes(siem_enabled) -> None:
    from app.services.siem_export_service import (
        MAX_EXPORT_JSON_DEPTH,
        MAX_EXPORT_JSON_NODES,
        SIEMExportSizeError,
        build_siem_export,
    )

    too_deep: object = "leaf"
    for _ in range(MAX_EXPORT_JSON_DEPTH + 1):
        too_deep = {"child": too_deep}
    with pytest.raises(SIEMExportSizeError, match="depth limit"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-deep",
                    "metadata_json": too_deep,
                }
            ],
        )

    with pytest.raises(SIEMExportSizeError, match="node limit"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-nodal",
                    "metadata_json": [None] * (MAX_EXPORT_JSON_NODES + 1),
                }
            ],
        )


def test_generic_export_counts_escape_expansion_in_incremental_input_limit(siem_enabled) -> None:
    from app.services.siem_export_service import SIEMExportSizeError, build_siem_export

    with pytest.raises(SIEMExportSizeError, match="input byte limit"):
        build_siem_export(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-escape-heavy",
                    "metadata_json": '"' * 600_000,
                }
            ],
        )


def test_generic_export_rejects_sub_limit_input_that_expands_past_ndjson_limit(siem_enabled) -> None:
    from app.services.siem_export_service import MAX_EXPORT_INPUT_BYTES, SIEMExportSizeError, build_siem_export

    assert MAX_EXPORT_INPUT_BYTES == 1_048_576
    events = [
        {
            "tenant_id": "tenant-a",
            "event_id": f"evt-{index}-" + ("e" * 240),
            "event_type": "t" * 256,
            "user_id": "u" * 256,
            "ai_system_id": "a" * 256,
            "correlation_id": "c" * 256,
            "recommended_action": "r" * 512,
            "url": "https://example.com/" + ("p" * 480),
            "source_surface": "gateway",
            "status": "s" * 32,
            "decision": "d" * 32,
            "control_mode": "detected_only",
        }
        for index in range(400)
    ]
    encoded_input = json.dumps(
        events,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(encoded_input) == 1_028_291
    assert len(encoded_input) < 1_048_576

    with pytest.raises(SIEMExportSizeError, match="NDJSON byte limit is 1048576"):
        build_siem_export(tenant_id="tenant-a", events=events)


def test_sentinel_adapter_maps_the_redacted_ocsf_projection(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-1",
                "event_type": "policy.violation",
                "created_at": "2026-07-22T12:00:00Z",
                "severity": "critical",
                "decision": "block",
                "control_mode": "telemetry_only",
                "source_surface": "saas",
                "url": "https://copilot.example/chat?sig=credential",
                "raw_prompt": "private customer prompt",
            }
        ],
        adapter="sentinel",
        generated_at=datetime(2026, 7, 22, 12, 2, tzinfo=timezone.utc),
    )

    row = json.loads(result.ndjson)
    assert row == {
        "ActorId": "unknown",
        "AiSystemId": "unknown",
        "ControlMode": "telemetry_only",
        "CorrelationId": "unknown",
        "Decision": "block",
        "Enforcement": "monitor_only",
        "EventId": "evt-1",
        "EventType": "policy.violation",
        "OcsfCategoryUid": 2,
        "OcsfClassUid": 2001,
        "OcsfTypeUid": 200100,
        "RecommendedAction": "unknown",
        "ResourceUrl": "https://copilot.example/chat",
        "Severity": "Critical",
        "SeverityId": 5,
        "SourceSurface": "saas",
        "Status": "unknown",
        "TenantId": "tenant-a",
        "TimeGenerated": "2026-07-22T12:00:00Z",
        "Vendor": "Hawk",
    }
    assert result.metadata["adapter"] == "sentinel"
    assert result.metadata["schema"] == "microsoft-sentinel-custom-log-v1+ocsf-1.1.0-aligned"
    assert result.metadata["lag_seconds"] == 120.0
    assert "prompt" not in result.ndjson.lower()
    assert "credential" not in result.ndjson


def test_sentinel_adapter_preserves_safe_banking_transaction_fields(siem_enabled) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "banking-transaction:txn-001",
                "event_type": "banking_ai_transaction",
                "timestamp": "2026-08-14T10:00:00Z",
                "severity": "low",
                "decision": "allow",
                "control_mode": "inline_allowed",
                "source_surface": "runtime_control",
                "status": "matched",
                "correlation_id": "txn-001",
                "ai_transaction_id": "txn-001",
                "subject_reference": "hmac-sha256:" + "1" * 64,
                "subject_type": "customer",
                "agent_chain": ["bank-agent", "summary-agent"],
                "model": "gpt-4.1",
                "business_purpose": "own-account-summary",
                "action_class": "tool_execution",
                "transport": "function",
                "target_class": "banking_resource",
                "destination_class": "internal",
                "selected_controls": [
                    "runtime_control:function",
                    "execution_verification",
                ],
                "decision_receipt_id": "decision-001",
                "execution_receipt_id": "execution-001",
                "integrity_status": "matched",
                "drift_flags": [],
                "finding_id": "none",
                "coverage_status": "incomplete",
                "customer_id": "customer-001",
                "account_id": "acct-001",
            }
        ],
        adapter="sentinel",
    )

    row = json.loads(result.ndjson)
    assert row["AiTransactionId"] == "txn-001"
    assert row["SubjectReference"].startswith("hawk-pseudo:")
    assert row["SubjectType"] == "customer"
    assert row["AgentChain"] == ["bank-agent", "summary-agent"]
    assert row["Model"] == "gpt-4.1"
    assert row["BusinessPurpose"] == "own-account-summary"
    assert row["ActionClass"] == "tool_execution"
    assert row["Transport"] == "function"
    assert row["TargetClass"] == "banking_resource"
    assert row["DestinationClass"] == "internal"
    assert row["SelectedControls"] == [
        "runtime_control:function",
        "execution_verification",
    ]
    assert row["DecisionReceiptId"] == "decision-001"
    assert row["ExecutionReceiptId"] == "execution-001"
    assert row["IntegrityStatus"] == "matched"
    assert row["DriftFlags"] == []
    assert row["FindingId"] == "none"
    assert row["CoverageStatus"] == "incomplete"
    assert "customer-001" not in result.ndjson
    assert "acct-001" not in result.ndjson


@pytest.mark.parametrize(
    ("surface", "claimed_mode"),
    [
        ("browser", "inline_prevented"),
        ("browser", "inline_allowed"),
        ("browser_extension", "inline_prevented"),
        ("browser_extension", "inline_allowed"),
        ("sdk", "inline_prevented"),
        ("sdk", "inline_allowed"),
    ],
)
def test_post_action_surfaces_cannot_claim_inline_enforcement(
    siem_enabled,
    surface: str,
    claimed_mode: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": f"evt-{surface}-{claimed_mode}",
                "source_surface": surface,
                "control_mode": claimed_mode,
                "decision": "block",
            }
        ],
    )

    exported = json.loads(result.ndjson)
    assert exported["control_mode"] == "detected_only"
    assert exported["enforcement"] == "monitor_only"


@pytest.mark.parametrize(
    ("surface", "claimed_mode"),
    [
        ("unknown", "inline_prevented"),
        ("gateway", "inline_allowed"),
        ("custom_collector", "inline"),
        ("gateway", "inline_blocked"),
        ("custom_collector", "inline_prevention"),
    ],
)
def test_unverified_surfaces_cannot_forge_inline_enforcement(
    siem_enabled,
    surface: str,
    claimed_mode: str,
) -> None:
    from app.services.siem_export_service import build_siem_export

    result = build_siem_export(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": f"evt-forged-{surface}-{claimed_mode}",
                "source_surface": surface,
                "control_mode": claimed_mode,
                "decision": "block",
            }
        ],
    )

    exported = json.loads(result.ndjson)
    assert exported["control_mode"] == "unknown"
    assert exported["enforcement"] == "unknown"


def test_webhook_delivery_rejects_invalid_destination_before_transport(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMInvalidDestinationError, deliver_siem_webhook

    requests = []

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    with pytest.raises(SIEMInvalidDestinationError, match="invalid SIEM webhook destination"):
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="http://hooks.example/events",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(
                response=SimpleNamespace(status_code=200, headers={}),
                requests=requests,
            ),
            transport_factory=_stub_transport_factory,
        )

    assert requests == []


def test_initial_destination_policy_failure_does_not_retain_raw_exception(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicyError
    from app.services.siem_export_service import SIEMInvalidDestinationError, deliver_siem_webhook

    class SecretBearingInitialPolicy:
        def validate(self, _url: str, *, source: str):
            assert source == "siem_export"
            raise OutboundDestinationPolicyError(
                "token=initial-policy-secret-that-must-not-escape"
            )

    with pytest.raises(SIEMInvalidDestinationError) as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=SecretBearingInitialPolicy(),
            client_factory=_client_factory_for(
                response=SimpleNamespace(status_code=200, headers={})
            ),
            transport_factory=_stub_transport_factory,
        )

    assert str(captured.value) == "invalid SIEM webhook destination"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "initial-policy-secret-that-must-not-escape" not in formatted


def test_request_destination_policy_failure_does_not_retain_raw_exception(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicyError
    from app.services.siem_export_service import SIEMInvalidDestinationError, deliver_siem_webhook

    class SecretBearingRedirectPolicy:
        calls = 0

        def validate(self, _url: str, *, source: str):
            assert source == "siem_export"
            self.calls += 1
            if self.calls == 1:
                return SimpleNamespace(origin="https://hooks.example")
            raise OutboundDestinationPolicyError(
                "credential=redirect-policy-secret-that-must-not-escape"
            )

    with pytest.raises(SIEMInvalidDestinationError) as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=SecretBearingRedirectPolicy(),
            client_factory=_client_factory_for(
                response=SimpleNamespace(status_code=200, headers={})
            ),
            transport_factory=_stub_transport_factory,
        )

    assert str(captured.value) == "invalid SIEM webhook destination"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "redirect-policy-secret-that-must-not-escape" not in formatted


@pytest.mark.parametrize("redirect_status", [307, 308])
def test_webhook_delivery_owns_pinned_post_and_redirect_validation(
    siem_enabled,
    redirect_status: int,
) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import deliver_siem_webhook

    responses = iter(
        [
            SimpleNamespace(status_code=redirect_status, headers={"Location": "/final"}),
            SimpleNamespace(status_code=201, headers={}),
        ]
    )
    requests = []
    pinned_destinations = []

    class FakeClient:
        def __init__(self, *, transport, timeout):
            self.transport = transport
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, url, *, follow_redirects, **kwargs):
            requests.append(
                {
                    "method": method,
                    "url": url,
                    "follow_redirects": follow_redirects,
                    "content": kwargs.get("content"),
                }
            )
            return next(responses)

    def transport_factory(destination, *, verify):
        pinned_destinations.append(
            (destination.hostname, destination.approved_address, verify)
        )
        return object()

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    result = deliver_siem_webhook(
        tenant_id="tenant-a",
        events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
        destination_url="https://hooks.example/ingest",
        destination_policy=destination_policy,
        client_factory=FakeClient,
        transport_factory=transport_factory,
    )

    assert pinned_destinations == [
        ("hooks.example", "93.184.216.34", True),
        ("hooks.example", "93.184.216.34", True),
    ]
    assert [request["method"] for request in requests] == ["POST", "POST"]
    assert [request["url"] for request in requests] == [
        "https://hooks.example/ingest",
        "https://hooks.example/final",
    ]
    assert all(request["follow_redirects"] is False for request in requests)
    assert all(request["content"] == result.ndjson.encode("utf-8") for request in requests)


def test_webhook_delivery_rejects_method_switching_redirect(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMInvalidDestinationError, deliver_siem_webhook

    responses = iter(
        [
            SimpleNamespace(status_code=302, headers={"Location": "/final"}),
            SimpleNamespace(status_code=200, headers={}),
        ]
    )
    requests = []

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, url, *, follow_redirects, **kwargs):
            requests.append(
                {
                    "method": method,
                    "url": url,
                    "follow_redirects": follow_redirects,
                    **kwargs,
                }
            )
            return next(responses)

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    with pytest.raises(SIEMInvalidDestinationError):
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=destination_policy,
            client_factory=FakeClient,
            transport_factory=_stub_transport_factory,
        )

    assert len(requests) == 1
    assert requests[0]["method"] == "POST"

def test_webhook_delivery_reports_observed_success_and_safe_health_metadata(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import deliver_siem_webhook

    requests = []

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    result = deliver_siem_webhook(
        tenant_id="tenant-a",
        events=[
            {
                "tenant_id": "tenant-a",
                "event_id": "evt-1",
                "created_at": "2026-07-22T12:00:00Z",
            }
        ],
        destination_url="https://hooks.example/ingest?sig=destination-secret",
        destination_policy=destination_policy,
        client_factory=_client_factory_for(
            response=SimpleNamespace(status_code=201, headers={}),
            requests=requests,
        ),
        transport_factory=_stub_transport_factory,
        generated_at=datetime(2026, 7, 22, 12, 2, tzinfo=timezone.utc),
        delivered_at=datetime(2026, 7, 22, 12, 2, 1, tzinfo=timezone.utc),
    )

    assert len(requests) == 1
    request = requests[0]
    assert request["content"] == result.ndjson.encode("utf-8")
    assert request["headers"] == {
        "Content-Type": "application/x-ndjson",
        "X-Hawk-Schema": "ocsf-1.1.0-aligned",
        "X-Hawk-Tenant": "tenant-a",
    }
    assert request["method"] == "POST"
    assert request["follow_redirects"] is False
    assert "Authorization" not in request["headers"]
    assert result.metadata["delivery_attempted"] is True
    assert result.metadata["delivery_status"] == "delivered"
    assert result.metadata["health_status"] == "healthy"
    assert result.metadata["delivery_http_status"] == 201
    assert result.metadata["delivered_at"] == "2026-07-22T12:02:01Z"
    assert result.metadata["destination_origin"] == "https://hooks.example"
    assert "destination-secret" not in json.dumps(result.metadata, sort_keys=True)


@pytest.mark.parametrize("status_code", [200, 201, 204])
def test_webhook_delivery_only_marks_terminal_success_codes_delivered(
    siem_enabled,
    status_code: int,
) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import deliver_siem_webhook

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    result = deliver_siem_webhook(
        tenant_id="tenant-a",
        events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
        destination_url="https://hooks.example/ingest",
        destination_policy=destination_policy,
        client_factory=_client_factory_for(
            response=SimpleNamespace(status_code=status_code, headers={})
        ),
        transport_factory=_stub_transport_factory,
        delivered_at=datetime(2026, 7, 22, 12, 2, 1, tzinfo=timezone.utc),
    )

    assert result.metadata["delivery_http_status"] == status_code
    assert result.metadata["delivery_status"] == "delivered"
    assert result.metadata["health_status"] == "healthy"
    assert result.metadata["delivered_at"] == "2026-07-22T12:02:01Z"


def test_webhook_delivery_reports_202_as_accepted_pending(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import deliver_siem_webhook

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    result = deliver_siem_webhook(
        tenant_id="tenant-a",
        events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
        destination_url="https://hooks.example/ingest",
        destination_policy=destination_policy,
        client_factory=_client_factory_for(
            response=SimpleNamespace(status_code=202, headers={})
        ),
        transport_factory=_stub_transport_factory,
        delivered_at=datetime(2026, 7, 22, 12, 2, 1, tzinfo=timezone.utc),
    )

    assert result.metadata["delivery_http_status"] == 202
    assert result.metadata["delivery_status"] == "accepted_pending"
    assert result.metadata["health_status"] == "pending"
    assert result.metadata["accepted_at"] == "2026-07-22T12:02:01Z"
    assert "delivered_at" not in result.metadata


@pytest.mark.parametrize("status_code", [203, 205, 206, 207, 226, 299])
def test_webhook_delivery_rejects_unrecognized_2xx_statuses(
    siem_enabled,
    status_code: int,
) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMDeliveryError, deliver_siem_webhook

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    with pytest.raises(SIEMDeliveryError, match=f"status {status_code}") as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(
                response=SimpleNamespace(status_code=status_code, headers={})
            ),
            transport_factory=_stub_transport_factory,
        )

    assert captured.value.metadata["delivery_http_status"] == status_code
    assert captured.value.metadata["delivery_status"] == "failed"
    assert captured.value.metadata["health_status"] == "failed"


def test_webhook_delivery_suppresses_raw_transport_failure_and_reports_safe_reason(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMDeliveryError, deliver_siem_webhook

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    with pytest.raises(SIEMDeliveryError, match="SIEM webhook transport failed") as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(
                error=TimeoutError("collector timeout with token=do-not-echo")
            ),
            transport_factory=_stub_transport_factory,
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert captured.value.metadata["delivery_error_class"] == "TimeoutError"
    assert captured.value.metadata["delivery_error_reason"] == "timeout"
    assert "do-not-echo" not in str(captured.value)
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "do-not-echo" not in formatted


def test_webhook_delivery_does_not_expose_unknown_exception_class_or_message(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMDeliveryError, deliver_siem_webhook

    class SecretBearingCollectorFailure(Exception):
        pass

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    with pytest.raises(SIEMDeliveryError) as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(
                error=SecretBearingCollectorFailure(
                    "credential=collector-secret-that-must-not-escape"
                )
            ),
            transport_factory=_stub_transport_factory,
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert captured.value.metadata["delivery_error_class"] == "TransportError"
    assert captured.value.metadata["delivery_error_reason"] == "request_failed"
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "collector-secret-that-must-not-escape" not in formatted
    assert "SecretBearingCollectorFailure" not in formatted


def test_webhook_delivery_suppresses_failure_while_reading_response_status(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMDeliveryError, deliver_siem_webhook

    class SecretBearingStatusFailure(Exception):
        pass

    class StatefulResponse:
        headers: dict[str, str] = {}
        reads = 0

        @property
        def status_code(self) -> int:
            self.reads += 1
            if self.reads == 1:
                return 200
            raise SecretBearingStatusFailure(
                "token=response-status-secret-that-must-not-escape"
            )

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )
    with pytest.raises(SIEMDeliveryError) as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[{"tenant_id": "tenant-a", "event_id": "evt-1"}],
            destination_url="https://hooks.example/ingest",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(response=StatefulResponse()),
            transport_factory=_stub_transport_factory,
        )

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert captured.value.metadata["delivery_error_class"] == "TransportError"
    assert captured.value.metadata["delivery_error_reason"] == "request_failed"
    formatted = "".join(
        traceback.format_exception(
            type(captured.value),
            captured.value,
            captured.value.__traceback__,
        )
    )
    assert "response-status-secret-that-must-not-escape" not in formatted
    assert "SecretBearingStatusFailure" not in formatted


def test_webhook_delivery_non_2xx_error_has_failure_health_metadata(siem_enabled) -> None:
    from app.services.outbound_destination_policy import OutboundDestinationPolicy
    from app.services.siem_export_service import SIEMDeliveryError, deliver_siem_webhook

    destination_policy = OutboundDestinationPolicy(
        {"siem_export": {"https://hooks.example"}},
        resolver=lambda _host, _port: ["93.184.216.34"],
    )

    with pytest.raises(SIEMDeliveryError, match="status 503") as captured:
        deliver_siem_webhook(
            tenant_id="tenant-a",
            events=[
                {
                    "tenant_id": "tenant-a",
                    "event_id": "evt-1",
                    "created_at": "2026-07-22T12:00:00Z",
                }
            ],
            destination_url="https://hooks.example/ingest?sig=destination-secret",
            destination_policy=destination_policy,
            client_factory=_client_factory_for(
                response=SimpleNamespace(status_code=503, headers={})
            ),
            transport_factory=_stub_transport_factory,
            generated_at=datetime(2026, 7, 22, 12, 2, tzinfo=timezone.utc),
            delivered_at=datetime(2026, 7, 22, 12, 2, 1, tzinfo=timezone.utc),
        )

    assert captured.value.metadata["delivery_attempted"] is True
    assert captured.value.metadata["delivery_status"] == "failed"
    assert captured.value.metadata["health_status"] == "failed"
    assert captured.value.metadata["delivery_http_status"] == 503
    assert captured.value.metadata["lag_seconds"] == 120.0
    assert captured.value.metadata["destination_origin"] == "https://hooks.example"
    assert "destination-secret" not in json.dumps(captured.value.metadata, sort_keys=True)
