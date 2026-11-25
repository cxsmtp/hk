from __future__ import annotations

import time
from typing import Protocol

from .models import GuardDecision, PromptSnapshot
from .local_policy import evaluate_local_precheck


class Collector(Protocol):
    def collect(self) -> PromptSnapshot | None: ...

    def clear_prompt(self) -> None: ...


class ApiClient(Protocol):
    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision: ...


class Presenter(Protocol):
    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None: ...

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None: ...


class DesktopGuardRunner:
    def __init__(self, *, collector: Collector, api: ApiClient, presenter: Presenter, poll_seconds: float = 1.0) -> None:
        self.collector = collector
        self.api = api
        self.presenter = presenter
        self.poll_seconds = max(0.1, float(poll_seconds))
        self._last_prompt_hash: str | None = None

    def tick(self) -> bool:
        snapshot = self.collector.collect()
        if snapshot is None:
            return False
        if not snapshot.prompt_text.strip():
            return False
        if snapshot.prompt_hash == self._last_prompt_hash:
            return False

        self._last_prompt_hash = snapshot.prompt_hash
        local_decision = evaluate_local_precheck(snapshot)
        if local_decision is not None:
            self.collector.clear_prompt()
            self.presenter.show(local_decision, snapshot)
            return True
        try:
            decision = self.api.evaluate_prompt(snapshot)
        except Exception:
            self._last_prompt_hash = snapshot.prompt_hash
            return False
        if decision.decision == "warn" and _is_weak_warn(decision):
            return False
        if decision.decision == "block":
            self.collector.clear_prompt()
        if decision.decision in {"warn", "block"}:
            self.presenter.show(decision, snapshot)
        return True

    def run_forever(self) -> None:
        while True:
            self.tick()
            time.sleep(self.poll_seconds)


def _is_weak_warn(decision: GuardDecision) -> bool:
    weak_reasons = {"domain_warn", "intent_unknown"}
    reasons = {str(item).strip().lower() for item in decision.reason_codes if str(item).strip()}
    return bool(reasons) and reasons.issubset(weak_reasons)
