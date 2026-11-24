import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hawk_endpoint_agent.collectors.network import list_connections
from hawk_endpoint_agent.metadata_scanner import ScanRoots, collect_endpoint_metadata


def test_network_permission_failure_is_not_an_empty_success():
    class Denied:
        def net_connections(self, **_kwargs):
            raise PermissionError("private path")
    with patch("hawk_endpoint_agent.collectors.network._try_psutil", return_value=Denied()):
        result = list_connections()
    assert result == []
    assert result.collection_status == "unavailable"
    assert result.error_code == "permission_denied"


def test_empty_network_collection_is_successful():
    with patch("hawk_endpoint_agent.collectors.network._try_psutil", return_value=SimpleNamespace(net_connections=lambda **kw: [])):
        result = list_connections()
    assert result.collection_status == "complete"
    assert result.error_code is None


def test_mcp_metadata_keeps_transport_but_not_credentials(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "docs": {"url": "https://name:secret@docs.example.com/mcp?token=secret", "headers": {"Authorization": "secret"}},
        "local": {"command": "/private/home/bin/npx", "args": ["secret"], "env": {"TOKEN": "secret"}},
        "custom": {"command": "private-secret-binary"},
    }}))
    report = collect_endpoint_metadata(roots=ScanRoots(home=home, application_roots=(), executable_roots=()))
    metadata = report["configurations"][0]["metadata"]
    assert "private-secret-binary" not in json.dumps(report)
    assert "token=secret" not in json.dumps(report)
    assert "name:secret" not in json.dumps(report)
    servers = {server["name"]: server for server in metadata["mcp_servers"]}
    assert servers["docs"] == {"name": "docs", "transport": "remote", "destination_host": "docs.example.com"}
    assert servers["local"] == {"name": "local", "transport": "stdio", "executable": "npx"}
    assert servers["custom"] == {"name": "custom", "transport": "stdio"}


def test_desktop_installation_is_presence_not_usage(tmp_path):
    applications = tmp_path / "Applications"
    (applications / "ChatGPT.app").mkdir(parents=True)
    (applications / "Ollama.app").mkdir()
    report = collect_endpoint_metadata(roots=ScanRoots(home=tmp_path, application_roots=(applications,), executable_roots=()))
    products = {product["id"]: product for product in report["products"]}
    assert products["chatgpt_desktop"]["presence"] == "present"
    assert products["ollama"]["presence"] == "present"
    assert products["lm_studio"]["presence"] == "unknown"
    assert products["chatgpt_desktop"]["approval_status"] == "unknown"
    assert report["network_used"] is False


def test_lsof_timeout_reports_unavailable_without_retaining_output():
    import subprocess
    with patch("hawk_endpoint_agent.collectors.network._try_psutil", return_value=None), patch(
        "hawk_endpoint_agent.collectors.network.subprocess.run", side_effect=subprocess.TimeoutExpired("private-command", 5)
    ):
        result = list_connections()
    assert result.collection_status == "unavailable"
    assert result.error_code == "collection_timeout"
