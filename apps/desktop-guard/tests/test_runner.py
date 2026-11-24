from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_desktop_guard.models import GuardDecision, PromptSnapshot
from hawk_desktop_guard.runner import DesktopGuardRunner


class FakeCollector:
    def __init__(self, snapshots: list[PromptSnapshot], events: list[str] | None = None) -> None:
        self._snapshots = snapshots
        self.clear_calls = 0
        self.events = events

    def collect(self) -> PromptSnapshot | None:
        return self._snapshots.pop(0) if self._snapshots else None

    def clear_prompt(self) -> None:
        if self.events is not None:
            self.events.append("clear")
        self.clear_calls += 1


class FakeApi:
    def __init__(self, decision: GuardDecision) -> None:
        self.decision = decision
        self.payloads: list[dict] = []

    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision:
        self.payloads.append(snapshot.to_api_payload())
        return self.decision


class FailingApi:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision:
        self.payloads.append(snapshot.to_api_payload())
        raise TimeoutError("timed out")


class FakePresenter:
    def __init__(self, events: list[str] | None = None) -> None:
        self.decisions: list[GuardDecision] = []
        self.errors: list[str] = []
        self.events = events

    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None:
        if self.events is not None:
            self.events.append(f"show:{decision.decision}")
        self.decisions.append(decision)

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None:
        self.errors.append(str(error))


def _snapshot(text: str) -> PromptSnapshot:
    return PromptSnapshot(
        application="Claude Desktop",
        desktop_app="Claude",
        prompt_text=text,
        prompt_preview_redacted=text,
        capture_method="accessibility_api",
        machine_id="macbook-claude-01",
        os_type="macos",
        active_window_title="Claude",
    )


def test_runner_blocks_and_clears_prompt_when_api_blocks() -> None:
    events: list[str] = []
    collector = FakeCollector([_snapshot("Summarize confidential roadmap")], events)
    api = FakeApi(
        GuardDecision(
            decision="block",
            tier="clear_positive",
            reason_codes=["sensitive_data_pattern"],
            runtime_event_id="evt_1",
            finding_id="find_1",
        )
    )
    presenter = FakePresenter(events)
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    processed = runner.tick()

    assert processed is True
    assert collector.clear_calls == 1
    assert presenter.decisions[0].decision == "block"
    assert events == ["clear", "show:block"]
    assert api.payloads[0]["application"] == "Claude Desktop"
    assert api.payloads[0]["machine_id"] == "macbook-claude-01"
    assert api.payloads[0]["capture_method"] == "accessibility_api"


def test_runner_dedupes_repeated_prompt_snapshot() -> None:
    snapshot = _snapshot("Summarize this public release note")
    collector = FakeCollector([snapshot, snapshot])
    api = FakeApi(
        GuardDecision(
            decision="allow",
            tier="clear_negative",
            reason_codes=[],
            runtime_event_id=None,
            finding_id=None,
        )
    )
    presenter = FakePresenter()
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    assert runner.tick() is True
    assert runner.tick() is False
    assert len(api.payloads) == 1
    assert collector.clear_calls == 0
    assert presenter.decisions == []


def test_runner_suppresses_backend_timeout_dialog_for_nonlocal_prompt() -> None:
    snapshot = _snapshot("Summarize public release notes")
    collector = FakeCollector([snapshot, snapshot])
    api = FailingApi()
    presenter = FakePresenter()
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    assert runner.tick() is False
    assert runner.tick() is False
    assert len(api.payloads) == 1
    assert collector.clear_calls == 0
    assert presenter.errors == []


def test_runner_locally_blocks_code_snippet_even_when_api_would_timeout() -> None:
    snapshot = _snapshot(
        "Analyze this code:\n\n"
        "def test_data_transfer_sensitive_file_upload_external_ai_blocks_via_guardian_contract() -> None:\n"
        "    decision = evaluate_data_transfer_policy(\n"
        "        source_classification=\"protected\",\n"
        "        source_surface=\"document\",\n"
        "    )"
    )
    collector = FakeCollector([snapshot])
    api = FailingApi()
    presenter = FakePresenter()
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    assert runner.tick() is True
    assert len(api.payloads) == 0
    assert collector.clear_calls == 1
    assert presenter.decisions[0].decision == "block"
    assert "source_code_snippet" in presenter.decisions[0].reason_codes


def test_runner_locally_blocks_obvious_api_key_before_api_call() -> None:
    events: list[str] = []
    collector = FakeCollector([_snapshot("please analyse my api key 17269712")], events)
    api = FakeApi(
        GuardDecision(
            decision="allow",
            tier="clear_negative",
            reason_codes=[],
            runtime_event_id=None,
            finding_id=None,
        )
    )
    presenter = FakePresenter(events)
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    assert runner.tick() is True
    assert len(api.payloads) == 0
    assert collector.clear_calls == 1
    assert presenter.decisions[0].decision == "block"
    assert presenter.decisions[0].reason_codes == ["local_api_key_pattern"]
    assert events == ["clear", "show:block"]


def test_runner_suppresses_domain_warn_noise_while_typing() -> None:
    collector = FakeCollector([_snapshot("please anan")])
    api = FakeApi(
        GuardDecision(
            decision="warn",
            tier="ambiguous",
            reason_codes=["domain_warn", "intent_unknown"],
            runtime_event_id="evt",
            finding_id=None,
        )
    )
    presenter = FakePresenter()
    runner = DesktopGuardRunner(collector=collector, api=api, presenter=presenter)

    assert runner.tick() is False
    assert len(api.payloads) == 1
    assert collector.clear_calls == 0
    assert presenter.decisions == []
