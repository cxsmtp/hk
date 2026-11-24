from app.services.native_control.claude_surfaces import claude_surface_control, claude_surface_controls


def test_every_claude_surface_has_a_truthful_control_route() -> None:
    rows = {row.surface: row for row in claude_surface_controls()}

    assert set(rows) == {
        "code_cli",
        "code_desktop_local",
        "code_ide",
        "code_remote_control",
        "code_web_or_desktop_remote",
        "desktop_chat",
        "web_chat",
        "mobile_chat",
        "direct_api",
    }
    assert rows["code_cli"].native_hook_capable is True
    assert rows["code_desktop_local"].control_method == "native_hook"
    assert rows["code_web_or_desktop_remote"].enrollment_scope == "server_managed_or_repository"
    assert rows["code_remote_control"].verification_requirement == "local_runtime_callback"
    assert rows["code_web_or_desktop_remote"].verification_requirement == "fresh_server_managed_callback"
    assert rows["desktop_chat"].native_hook_capable is False
    assert rows["desktop_chat"].control_method == "mcp_gateway_and_endpoint"
    assert rows["web_chat"].control_method == "browser_companion_and_mcp_gateway"
    assert rows["mobile_chat"].control_method == "mcp_gateway"
    assert rows["direct_api"].control_method == "llm_gateway_or_bound_sdk"


def test_non_code_chat_is_never_mislabeled_as_native_hook() -> None:
    for surface in ("desktop_chat", "web_chat", "mobile_chat", "direct_api"):
        row = claude_surface_control(surface)
        assert row.native_hook_capable is False
        assert row.control_method != "native_hook"
        assert row.verification_requirement != "claude_code_native_hook"
