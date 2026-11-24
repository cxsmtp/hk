from pathlib import Path


SERVICE_ROOT = Path(__file__).parents[1] / "app" / "services"


def test_native_selector_is_bound_to_each_existing_pre_action_surface() -> None:
    for relative_path in (
        "llm_gateway_service.py",
        "gateway_service.py",
        "runtime_control_agent_action_service.py",
    ):
        source = (SERVICE_ROOT / relative_path).read_text(encoding="utf-8")
        assert "apply_native_selection_to_rollout" in source, relative_path
        assert "settings.native_control_framework" in source, relative_path
        assert "settings.trusted_control_selector" in source, relative_path
        assert source.index("apply_native_selection_to_rollout(") < source.index(
            "authorization_rollout_persistence_metadata(v2_rollout)"
        ), relative_path


def test_llm_chat_completion_and_request_only_paths_both_apply_native_selection() -> None:
    source = (SERVICE_ROOT / "llm_gateway_service.py").read_text(encoding="utf-8")

    assert source.count("apply_native_selection_to_rollout(") >= 2
