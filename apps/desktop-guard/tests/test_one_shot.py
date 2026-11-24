from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.models import GuardDecision, PromptSnapshot
from hawk_desktop_guard.one_shot import evaluate_text_once


class FakeApi:
    def __init__(self) -> None:
        self.snapshots: list[PromptSnapshot] = []

    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision:
        self.snapshots.append(snapshot)
        return GuardDecision(
            decision="block",
            tier="clear_positive",
            reason_codes=["sensitive_data_pattern"],
            runtime_event_id="evt_1",
            finding_id="find_1",
        )


class FakePresenter:
    def __init__(self) -> None:
        self.decisions: list[GuardDecision] = []

    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None:
        self.decisions.append(decision)

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None:
        raise AssertionError(str(error))


def test_evaluate_text_once_records_intercepted_prompt_with_backend() -> None:
    api = FakeApi()
    presenter = FakePresenter()

    decision = evaluate_text_once(
        text="please analyse my api key 17269712",
        application="Claude Desktop",
        desktop_app="Claude",
        machine_id="macbook-claude-01",
        capture_method="macos_enter_intercept",
        api=api,
        presenter=presenter,
    )

    assert decision.decision == "block"
    assert api.snapshots[0].capture_method == "macos_enter_intercept"
    assert api.snapshots[0].application == "Claude Desktop"
    assert api.snapshots[0].machine_id == "macbook-claude-01"
    assert presenter.decisions[0].decision == "block"
