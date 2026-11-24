from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.session import Base
from app.services.activity_audit_service import _resolve_prompt_storage_mode
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.privacy_sanitizer import redact_sensitive_text, sanitize_privacy_payload, strip_url_query
from app.services.snapshot_service import _safe_prompt_for_export
from app.db.models.activity_audit import PromptPayload


def test_high_sensitivity_overrides_requested_full_prompt_storage() -> None:
    mode = _resolve_prompt_storage_mode(
        requested_mode="full",
        sensitivity_score=0.91,
        pii_detected=True,
    )

    assert mode == "hashed_only"


def test_privacy_redaction_preserves_iso_timestamps_while_redacting_phones() -> None:
    redacted = redact_sensitive_text(
        "created_at=2026-05-01T02:00:00Z contact=+1 415 555 1234"
    )

    assert "2026-05-01T02:00:00Z" in redacted
    assert "+1 415 555 1234" not in redacted
    assert "[phone]" in redacted

    payload = sanitize_privacy_payload(
        {
            "created_at": "2026-05-01T02:00:00",
            "updated_at": "2026-05-01 03:04:05+00:00",
        }
    )

    assert payload["created_at"] == "2026-05-01T02:00:00"
    assert payload["updated_at"] == "2026-05-01 03:04:05+00:00"


def test_privacy_redaction_preserves_chatgpt_desktop_version_metadata() -> None:
    payload = sanitize_privacy_payload(
        {
            "chatgpt_desktop": {
                "version": "26.715.72359",
                "build": "5718",
                "support_note": "contact +1 415 555 1234",
            },
            "unscoped_text": "26.715.72359",
        }
    )

    assert payload["chatgpt_desktop"]["version"] == "26.715.72359"
    assert payload["chatgpt_desktop"]["build"] == "5718"
    assert payload["chatgpt_desktop"]["support_note"] == "contact [phone]"
    assert payload["unscoped_text"] == "[phone]"


def test_receipt_projection_preserves_valid_plural_digests_without_card_redaction() -> None:
    from app.services.receipt_service import _receipt_canonical_projection

    account_hash = (
        "hmac-sha256:"
        + "a" * 8
        + "0123456789012345"
        + "b" * 40
    )

    payload = _receipt_canonical_projection(
        {
            "actor": {"identity_id": "customer-subject"},
            "authority": {
                "approved_account_hashes": [account_hash, "4111 1111 1111 1111"],
                "permission_scope": [account_hash],
            },
            "action": {"tool_fingerprint_id": account_hash},
        }
    )

    assert payload["authority"]["approved_account_hashes"] == [
        account_hash,
        "[phone]",
    ]
    assert payload["authority"]["permission_scope"] == [account_hash]


def test_url_sanitizer_removes_userinfo_query_and_fragment_and_handles_ipv6() -> None:
    sanitized = strip_url_query(
        "https://collector-user:must-not-persist@[2001:db8::1]:8443/runtime/events"
        "?api_key=must-not-persist#must-not-persist"
    )

    assert sanitized == "https://[2001:db8::1]:8443/runtime/events"
    assert "collector-user" not in sanitized
    assert "must-not-persist" not in sanitized
    assert strip_url_query("https://collector-user:must-not-persist@example.com:not-a-port/events") == "[redacted]"


def test_generic_prompt_and_argument_containers_are_never_retained() -> None:
    raw_prompt = "summarize customer account material exactly"
    raw_argument = "customer-account-argument-must-not-persist"
    camel_prompt = "camel-case-prompt-must-not-persist"
    dotted_argument = "dotted-argument-must-not-persist"

    sanitized = sanitize_privacy_payload(
        {
            "nested": {
                "prompt": raw_prompt,
                "arguments": {"account": raw_argument},
                "tool_arguments": [raw_argument],
                "rawPrompt": camel_prompt,
                "promptText": camel_prompt,
                "toolArguments": {"account": raw_argument},
                "gen_ai.tool.call.arguments": {"account": dotted_argument},
                "gen_ai.prompt": camel_prompt,
            }
        }
    )

    assert sanitized["nested"] == {
        "prompt": "[hashed_only]",
        "arguments": "[hashed_only]",
        "tool_arguments": "[hashed_only]",
        "rawPrompt": "[hashed_only]",
        "promptText": "[hashed_only]",
        "toolArguments": "[hashed_only]",
        "gen_ai.tool.call.arguments": "[hashed_only]",
        "gen_ai.prompt": "[hashed_only]",
    }
    assert raw_prompt not in repr(sanitized)
    assert raw_argument not in repr(sanitized)
    assert camel_prompt not in repr(sanitized)
    assert dotted_argument not in repr(sanitized)


def test_audit_and_evidence_payloads_are_sanitized_before_storage(tmp_path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'privacy.sqlite3'}")
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        payload = {
            "raw_prompt": "Customer email jane@clientcorp.com and api_key sk-live-1234567890abcdef",
            "content_b64": "QUJDREVGR0g=",
            "url": "https://chatgpt.com/?prompt=secret&token=abc",
            "target_node_label": "https://www.google.com/search?q=secret+api+key&token=abc",
            "nested": {
                "extracted_text": "Card 4111 1111 1111 1111 belongs to jane@clientcorp.com",
            },
        }

        audit = write_audit_log(
            db,
            tenant_id="tenant-privacy",
            actor_user_id=None,
            actor_type="system",
            action="privacy.test",
            resource_type="unit",
            resource_id="privacy",
            payload=payload,
        )
        evidence = create_evidence_node(
            db,
            tenant_id="tenant-privacy",
            node_type="privacy",
            signal_type="privacy.test",
            label="Privacy Test",
            payload=payload,
        )
        db.commit()

        stored_audit = db.get(AuditLog, audit.id)
        stored_evidence = db.get(EvidenceNode, evidence.id)
        combined = f"{stored_audit.payload} {stored_evidence.payload}"

        assert "sk-live" not in combined
        assert "jane@clientcorp.com" not in combined
        assert "4111 1111 1111 1111" not in combined
        assert "QUJDREVGR0g" not in combined
        assert "prompt=secret" not in combined
        assert "q=secret" not in combined
        assert stored_audit.payload["content_b64"] == "[omitted:binary]"
        assert stored_audit.payload["url"] == "https://chatgpt.com/"
        assert stored_audit.payload["target_node_label"] == "https://www.google.com/search"
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_export_prompt_hides_raw_when_storage_is_not_full() -> None:
    row = PromptPayload(
        action_id="act-privacy",
        raw_prompt="Customer email jane@clientcorp.com and api_key sk-live-1234567890abcdef",
        redacted_prompt="Customer email [email] and api_key [secret]",
        pii_detected=True,
        sensitive_entities=["email", "api_key"],
        storage_mode="hashed_only",
        prompt_hash="abc123",
    )

    exported = _safe_prompt_for_export(row)

    assert exported is not None
    assert exported["storage_mode"] == "hashed_only"
    assert exported["raw_prompt"] is None
    assert exported["prompt"] == "[hashed_only]"
    assert exported["redacted_prompt"] == "[hashed_only]"
    assert exported["prompt_hash"] == "abc123"
