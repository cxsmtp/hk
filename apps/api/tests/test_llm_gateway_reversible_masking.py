from __future__ import annotations

import pytest

from app.services.llm_gateway_secure.data_minimizer import (
    MaskingError,
    MaskingSession,
    ReversibleMaskingPolicy,
)
from app.services.llm_gateway_secure.gateway import prepare_provider_payload
from app.services.llm_gateway_secure.schemas import SecureCallContext


def test_multiline_repeated_name_stays_one_person_token_and_round_trips() -> None:
    original = "Name: Alice Smith\nPassport: P12345678\nAccount: 123456789012\nName: Alice Smith"
    session = MaskingSession(ReversibleMaskingPolicy(enabled=True))
    masked = session.mask(original)
    assert masked.count("[[HAWK_PERSON_") == 2
    assert masked.count("[[HAWK_PASSPORT_") == 1
    assert masked.count("[[HAWK_BANK_ACCOUNT_") == 1
    assert masked.splitlines()[0].split("Name: ", 1)[1] == masked.splitlines()[3].split("Name: ", 1)[1]
    assert masked.splitlines()[1].startswith("Passport: [[HAWK_PASSPORT_")
    assert session.metadata()["entity_type_counts"] == {"person": 1, "passport": 1, "bank_account": 1}
    assert session.restore(masked) == original


def test_masking_repeats_are_typed_consistent_and_restored_only_for_current_session() -> None:
    policy = ReversibleMaskingPolicy.from_scope({"enabled": True})
    session = MaskingSession(policy)
    source = "Name: Alice Smith, passport: P12345678, account: 123456789012, alice@example.com"
    masked = session.mask(source)
    again = session.mask("| Name: Alice Smith | passport: P12345678 |")
    assert "Alice Smith" not in masked
    assert "P12345678" not in masked
    assert "123456789012" not in masked
    assert "alice@example.com" not in masked
    for category in ("PERSON", "PASSPORT", "BANK_ACCOUNT", "EMAIL"):
        assert f"[[HAWK_{category}_" in masked
    assert masked.split("Name: ")[1].split(",")[0] in again
    assert session.restore(masked) == source
    with pytest.raises(MaskingError):
        MaskingSession(policy).restore(masked)
    session.destroy()
    with pytest.raises(MaskingError):
        session.restore(masked)


def test_reserved_namespace_and_repeated_output_fail_closed() -> None:
    session = MaskingSession(ReversibleMaskingPolicy.from_scope({"enabled": True}))
    with pytest.raises(MaskingError):
        session.mask("[[HAWK_PERSON_fake_0001]]")
    masked = session.mask("Name: Alice Smith")
    token = masked.split("Name: ")[1]
    with pytest.raises(MaskingError):
        session.restore(token * 100)


def test_invalid_enabled_policy_rejects_and_limits_are_clamped() -> None:
    with pytest.raises(MaskingError):
        ReversibleMaskingPolicy.from_scope({"enabled": True, "mapping_ttl_seconds": "bad"})
    policy = ReversibleMaskingPolicy.from_scope({"enabled": True, "mapping_ttl_seconds": 999, "max_text_chars": 1})
    assert policy.mapping_ttl_seconds == 300
    assert policy.max_text_chars == 1000


def test_prepared_payload_binds_masked_bytes_without_serializing_map() -> None:
    context = SecureCallContext(task_type="test", customer_policy_profile={"reversible_masking": {"enabled": True}})
    prepared = prepare_provider_payload(
        system_prompt="Name: Alice Smith",
        user_prompt="Name: Alice Smith, passport: P12345678",
        context=context,
        provider="openai",
        model="test",
    )
    assert prepared.masking_session is not None
    assert "Alice Smith" not in prepared.system_prompt + prepared.user_prompt
    assert prepared.system_prompt.split("Name: ")[1] in prepared.user_prompt
    assert "Alice Smith" not in repr(prepared)
    assert "Alice Smith" not in repr(prepared.call_material)
    assert prepared.masking_session.restore(prepared.user_prompt).endswith("passport: P12345678")


def test_reversible_preparation_rejects_full_payload_over_limit() -> None:
    context = SecureCallContext(task_type="test", customer_policy_profile={"reversible_masking": {"enabled": True, "max_text_chars": 1000}})
    with pytest.raises(MaskingError, match="masking_text_limit"):
        prepare_provider_payload(system_prompt="x" * 600, user_prompt="y" * 600, context=context, provider="openai", model="test")


def test_table_label_masks_adjacent_account_cell() -> None:
    session = MaskingSession(ReversibleMaskingPolicy.from_scope({"enabled": True}))
    prompt = '{"rows":[["Account","123456789012"]]}'
    masked = session.mask(prompt)
    assert "123456789012" not in masked
    assert "[[HAWK_BANK_ACCOUNT_" in masked
    assert session.restore(masked) == prompt


def test_table_name_and_passport_cells_are_typed() -> None:
    session = MaskingSession(ReversibleMaskingPolicy.from_scope({"enabled": True}))
    prompt = '{"rows":[["Name","Alice Smith"],["Passport","P12345678"]]}'
    masked = session.mask(prompt)
    assert "Alice Smith" not in masked and "P12345678" not in masked
    assert "[[HAWK_PERSON_" in masked and "[[HAWK_PASSPORT_" in masked


def test_known_value_is_masked_in_unlabelled_field() -> None:
    session = MaskingSession(ReversibleMaskingPolicy.from_scope({"enabled": True}))
    session.discover("Name: Alice Smith")
    assert session.mask("Welcome Alice Smith") == f"Welcome {session.mask('Name: Alice Smith').split('Name: ')[1]}"


def test_expired_mapping_is_destroyed_before_restoration(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.llm_gateway_secure import data_minimizer

    now = [100.0]
    monkeypatch.setattr(data_minimizer.time, "monotonic", lambda: now[0])
    session = MaskingSession(ReversibleMaskingPolicy.from_scope({"enabled": True, "mapping_ttl_seconds": 30}))
    masked = session.mask("Name: Alice Smith")
    now[0] = 131.0
    with pytest.raises(MaskingError, match="masking_session_expired"):
        session.restore(masked)
    assert session.metadata()["mapping_destroyed"] is True
