from __future__ import annotations

import io
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.__main__ import read_prompt_from_stdin
from hawk_desktop_guard.api import HawkApiClient
from hawk_desktop_guard.config import DesktopGuardConfig
from hawk_desktop_guard.local_policy import evaluate_local_precheck
from hawk_desktop_guard.models import PromptSnapshot
from hawk_desktop_guard.redaction import PREVIEW_MAX_CHARS, TRUNCATION_MARKER, redact_prompt, redact_text


SENSITIVE_PROMPT = (
    "Email jane.doe@example.com or call +971 50 123 4567. "
    "Card 4111 1111 1111 1111, IBAN AE070331234567890123456, Emirates ID 784-1987-1234567-1. "
    "api_key=abcd1234efgh5678 and token ghp_abcdefghijklmnopqrstuvwxyz0123 and "
    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9abcdef"
)
SECRET_VALUES = [
    "jane.doe@example.com",
    "123 4567",
    "4111 1111 1111 1111",
    "AE070331234567890123456",
    "784-1987-1234567-1",
    "abcd1234efgh5678",
    "ghp_abcdefghijklmnopqrstuvwxyz0123",
    "eyJhbGciOiJIUzI1NiJ9abcdef",
]


def _snapshot(text: str) -> PromptSnapshot:
    return PromptSnapshot(application="Claude Desktop", desktop_app="Claude", prompt_text=text, capture_method="test")


def test_redaction_removes_every_sensitive_value_and_names_its_type() -> None:
    redacted, types = redact_text(SENSITIVE_PROMPT)
    for value in SECRET_VALUES:
        assert value not in redacted, value
    assert set(types) == {"email", "phone", "credit_card", "bank_account", "emirates_id", "api_key"}
    assert "[REDACTED:EMAIL]" in redacted and "[REDACTED:CARD]" in redacted
    # Labels stay readable for the reviewer; values do not.
    assert "api_key=[REDACTED:SECRET]" in redacted
    assert "Authorization: Bearer [REDACTED:TOKEN]" in redacted


def test_redaction_keeps_ordinary_text_dates_and_non_card_numbers() -> None:
    text = "Summarize the 2026-11-25 meeting notes; order 12345 shipped."
    assert redact_text(text) == (text, ())
    # Not a valid card number (Luhn): kept as it is, not taken for a card.
    assert "[REDACTED:CARD]" not in redact_text("ref 1234 5678 9012 3456")[0]


def test_private_key_blocks_are_redacted_whole() -> None:
    text = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----\nthanks"
    redacted, types = redact_text(text)
    assert "MIIEow" not in redacted and "[REDACTED:PRIVATE_KEY]" in redacted
    assert types == ("api_key",)


def test_preview_is_redacted_before_it_is_shortened() -> None:
    secret_at_the_cut = "x" * (PREVIEW_MAX_CHARS - 5) + " jane.doe@example.com tail"
    result = redact_prompt(secret_at_the_cut)
    assert result.truncated
    assert result.preview.endswith(TRUNCATION_MARKER)
    assert len(result.preview) == PREVIEW_MAX_CHARS + len(TRUNCATION_MARKER)
    assert "jane" not in result.preview
    assert result.entity_types == ("email",)
    assert result.length == len(secret_at_the_cut)


def test_snapshot_preview_is_redacted_even_when_captured_raw() -> None:
    snapshot = _snapshot(SENSITIVE_PROMPT)
    for value in SECRET_VALUES:
        assert value not in snapshot.prompt_preview_redacted
    assert snapshot.prompt_text == SENSITIVE_PROMPT


def test_api_payload_has_no_raw_prompt_by_default() -> None:
    payload = _snapshot(SENSITIVE_PROMPT).to_api_payload()
    assert "raw_prompt" not in payload
    assert payload["prompt_storage_mode"] == "redacted_preview_only"
    assert payload["redacted_entity_types"] == ["api_key", "bank_account", "credit_card", "email", "emirates_id", "phone"]
    serialized = json.dumps(payload)
    for value in SECRET_VALUES:
        assert value not in serialized, value


def test_full_prompt_capture_is_an_explicit_opt_in_and_labelled() -> None:
    payload = _snapshot(SENSITIVE_PROMPT).to_api_payload(full_prompt_capture=True)
    assert payload["raw_prompt"] == SENSITIVE_PROMPT
    assert payload["prompt_storage_mode"] == "full"


def test_api_client_sends_no_raw_prompt_unless_configured(monkeypatch) -> None:
    sent: list[dict] = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self) -> bytes:
            return json.dumps({"decision": "allow", "tier": "clear_negative", "reason_codes": []}).encode("utf-8")

    def fake_urlopen(req, timeout):
        sent.append(json.loads(req.data.decode("utf-8")))
        return Response()

    monkeypatch.setattr("hawk_desktop_guard.api.request.urlopen", fake_urlopen)
    HawkApiClient(api_url="http://hawk.test", access_token="t").evaluate_prompt(_snapshot("mail a@b.co please"))
    HawkApiClient(api_url="http://hawk.test", access_token="t", full_prompt_capture=True).evaluate_prompt(
        _snapshot("mail a@b.co please")
    )
    assert "raw_prompt" not in sent[0] and sent[0]["prompt_storage_mode"] == "redacted_preview_only"
    assert sent[1]["raw_prompt"] == "mail a@b.co please" and sent[1]["prompt_storage_mode"] == "full"


def test_full_prompt_capture_setting_defaults_off(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("HAWK_DESKTOP_FULL_PROMPT_CAPTURE", raising=False)
    missing = tmp_path / "none.json"
    assert DesktopGuardConfig.from_file_and_env(config_path=missing).full_prompt_capture is False
    configured = tmp_path / "guard.json"
    configured.write_text(json.dumps({"full_prompt_capture": True}), encoding="utf-8")
    assert DesktopGuardConfig.from_file_and_env(config_path=configured).full_prompt_capture is True
    monkeypatch.setenv("HAWK_DESKTOP_FULL_PROMPT_CAPTURE", "false")
    assert DesktopGuardConfig.from_file_and_env(config_path=configured).full_prompt_capture is False


def test_local_checks_still_see_the_whole_prompt() -> None:
    # The secret sits past the preview's limit and would be redacted from it anyway.
    snapshot = _snapshot("a" * (PREVIEW_MAX_CHARS + 200) + "\nOPENAI_API_KEY=sk-live-1234567890abcdef")
    assert "sk-live" not in snapshot.prompt_preview_redacted
    decision = evaluate_local_precheck(snapshot)
    assert decision is not None and decision.decision == "block"


def test_prompt_hash_covers_the_whole_prompt() -> None:
    first = _snapshot("a" * (PREVIEW_MAX_CHARS + 10) + "one")
    second = _snapshot("a" * (PREVIEW_MAX_CHARS + 10) + "two")
    assert first.prompt_preview_redacted == second.prompt_preview_redacted
    assert first.prompt_hash != second.prompt_hash


def test_prompt_is_read_from_stdin() -> None:
    assert read_prompt_from_stdin(io.StringIO("typed prompt\nsecond line")) == "typed prompt\nsecond line"


def test_macos_return_guard_passes_the_prompt_on_stdin_not_argv() -> None:
    source = (Path(__file__).resolve().parents[1] / "native" / "macos" / "HawkEnterGuard.m").read_text(encoding="utf-8")
    start = source.index("- (void)reportInterceptedPrompt:")
    body = source[start : source.index("@end", start)]
    assert "--evaluate-text" not in body
    assert "--evaluate-stdin" in body
    assert "task.standardInput" in body
    arguments = body[body.index("task.arguments") : body.index("];", body.index("task.arguments"))]
    assert "text" not in arguments.replace("--evaluate-", "").replace("macos_enter_intercept", "")
