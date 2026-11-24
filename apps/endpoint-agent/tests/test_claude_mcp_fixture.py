from __future__ import annotations

from pathlib import Path

import pytest

from hawk_endpoint_agent.native_control.claude_mcp_fixture import (
    FixtureState,
    handle_request,
)


def test_fixture_initializes_lists_and_calls_bounded_tools(tmp_path: Path) -> None:
    state = FixtureState(marker_path=tmp_path / "marker")

    initialized = handle_request(
        state,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
    )
    listed = handle_request(
        state,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    read = handle_request(
        state,
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_fixture", "arguments": {}},
        },
    )

    assert initialized["result"]["serverInfo"] == {
        "name": "hawk-claude-acceptance",
        "version": "1.0.0",
    }
    assert [row["name"] for row in listed["result"]["tools"]] == [
        "read_fixture",
        "write_marker",
    ]
    assert read["result"]["content"] == [{"type": "text", "text": "hawk-fixture-ok"}]
    assert state.read_calls == 1
    assert not state.marker_path.exists()


def test_fixture_write_is_harmless_bounded_and_unknown_tools_fail(tmp_path: Path) -> None:
    state = FixtureState(marker_path=tmp_path / "marker")
    written = handle_request(
        state,
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "write_marker", "arguments": {"note": "synthetic"}},
        },
    )

    assert written["result"]["content"] == [{"type": "text", "text": "marker-written"}]
    assert state.marker_path.read_text(encoding="utf-8") == "synthetic\n"
    assert state.write_calls == 1

    with pytest.raises(ValueError, match="mcp_fixture_note_too_large"):
        handle_request(
            state,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "write_marker", "arguments": {"note": "x" * 257}},
            },
        )
    with pytest.raises(ValueError, match="mcp_fixture_tool_unknown"):
        handle_request(
            state,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "delete_everything", "arguments": {}},
            },
        )
