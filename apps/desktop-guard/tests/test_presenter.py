from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.models import GuardDecision, PromptSnapshot
from hawk_desktop_guard.presenter import MacDialogPresenter


def _snapshot() -> PromptSnapshot:
    return PromptSnapshot(
        application="Claude Desktop",
        desktop_app="Claude",
        prompt_text="secret",
        capture_method="macos_accessibility",
    )


def _decision(decision: str) -> GuardDecision:
    return GuardDecision(
        decision=decision,
        tier="clear_positive",
        reason_codes=["sensitive_data_pattern"],
        runtime_event_id="evt",
        finding_id="find",
    )


def test_mac_dialog_presenter_shows_block_dialog() -> None:
    commands: list[list[str]] = []
    presenter = MacDialogPresenter(shell=lambda command: commands.append(command) or "")

    presenter.show(_decision("block"), _snapshot())

    command_text = " ".join(commands[0])
    assert "display dialog" in command_text
    assert "BLOCK" in command_text
    assert "Claude Desktop" in command_text


def test_mac_dialog_presenter_suppresses_backend_error_dialog() -> None:
    commands: list[list[str]] = []
    presenter = MacDialogPresenter(shell=lambda command: commands.append(command) or "")

    presenter.show_error(TimeoutError("timed out"), _snapshot())

    assert commands == []
