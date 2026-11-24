from __future__ import annotations

from .local_policy import evaluate_local_precheck
from .models import GuardDecision, PromptSnapshot


class ApiClient:
    def evaluate_prompt(self, snapshot: PromptSnapshot) -> GuardDecision: ...


class Presenter:
    def show(self, decision: GuardDecision, snapshot: PromptSnapshot) -> None: ...

    def show_error(self, error: Exception, snapshot: PromptSnapshot) -> None: ...


def evaluate_text_once(
    *,
    text: str,
    application: str,
    desktop_app: str,
    machine_id: str | None,
    capture_method: str,
    api: ApiClient,
    presenter: Presenter | None = None,
) -> GuardDecision:
    snapshot = PromptSnapshot(
        application=application,
        desktop_app=desktop_app,
        prompt_text=text,
        prompt_preview_redacted=text,
        capture_method=capture_method,
        machine_id=machine_id,
        os_type="macos",
        active_window_title=application,
        input_signal_types=["desktop_enter_intercept"],
    )
    local_decision = evaluate_local_precheck(snapshot)
    try:
        decision = api.evaluate_prompt(snapshot)
    except Exception as exc:
        if local_decision is None:
            if presenter is not None:
                presenter.show_error(exc, snapshot)
            raise
        decision = local_decision
    if presenter is not None and decision.decision in {"warn", "block"}:
        presenter.show(decision, snapshot)
    return decision
