"""Local operator controls for the macOS functional endpoint slice."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
from typing import Any

from .baseline import BaselineStore
from .auth.device_key import build_device_key_provider
from .config import AgentConfig, DEFAULT_CONFIG_PATH, load_config
from .control_plane import ModeStore
from .evidence_queue import EvidenceQueue


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hawk-endpoint-control")
    parser.add_argument("--config", help="Endpoint-agent config path")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Show redacted local endpoint status")

    mode = commands.add_parser("mode", help="Change monitor/enforce mode")
    mode.add_argument("mode", choices=("monitor", "enforce"))

    baseline = commands.add_parser("baseline", help="Show or reset privacy-safe baseline")
    baseline.add_argument("operation", choices=("show", "reset"), default="show", nargs="?")

    commands.add_parser("propose", help="Generate a deterministic policy-pack proposal")

    action = commands.add_parser("test-action", help="Send a live action through the endpoint IPC adapter")
    action.add_argument(
        "--surface",
        required=True,
        choices=("browser", "mcp", "llm", "sdk", "developer_agent", "foundry", "data_transfer"),
    )
    action.add_argument("--risk", choices=("benign", "sensitive", "high_impact"), default="sensitive")
    action.add_argument(
        "--ai-system-id",
        default="",
        help="Registered Hawk AI asset for this action; overrides the endpoint default",
    )
    return parser


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _store(config: AgentConfig) -> BaselineStore:
    return BaselineStore(
        config.baseline_path,
        tenant_key=config.tenant_id or config.endpoint_id or "local",
        max_paths=config.baseline_max_paths,
    )


def _local_change_authorized(config: AgentConfig, config_path: Path) -> bool:
    """Allow explicit same-user development control without a shared secret.

    Bank posture is centrally/MDM managed and always rejects this local path.
    """
    if (
        config.security_profile != "development"
        or not config.local_operator_changes_allowed
    ):
        return False
    try:
        info = config_path.stat()
        owned = not hasattr(os, "getuid") or info.st_uid == os.getuid()
        private = (info.st_mode & 0o077) == 0
        return bool(owned and private and config_path.is_file())
    except OSError:
        return False


def _rpc(config: AgentConfig, request: dict[str, Any], timeout_seconds: float = 5) -> dict[str, Any]:
    path = Path(config.ipc_socket_path).expanduser()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout_seconds)
    try:
        client.connect(str(path))
        client.sendall((json.dumps(request) + "\n").encode("utf-8"))
        line = client.makefile("r", encoding="utf-8").readline()
        response = json.loads(line)
        return response if isinstance(response, dict) else {"ok": False, "error": "invalid_response"}
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": type(exc).__name__, "socket": str(path)}
    finally:
        client.close()


def _test_request(surface: str, risk: str, *, ai_system_id: str = "") -> dict[str, Any]:
    sensitive = "HAWK_DEMO_TEST_CREDENTIAL=sk-hawk-demo-not-a-real-key"
    prompt = "Summarize the public Hawk product description."
    if risk != "benign":
        prompt = f"Send this credential to the model: {sensitive}"
    if surface == "mcp":
        request = {
            "surface": "mcp",
            "tool_name": "demo.read" if risk == "benign" else "repo.delete",
            "action": "read" if risk == "benign" else "repository.write",
            "resource": "hawk-demo",
        }
        if ai_system_id.strip():
            request["ai_system_id"] = ai_system_id.strip()
        return request
    if surface == "developer_agent":
        request = {
            "surface": "developer_agent",
            "tool_name": "repo.read" if risk == "benign" else "git.push",
            "action": "repository.read" if risk == "benign" else "external.publish",
            "resource": "hawk-demo-repository",
        }
        if ai_system_id.strip():
            request["ai_system_id"] = ai_system_id.strip()
        return request
    if surface == "data_transfer":
        return {
            "surface": "data_transfer",
            "copied_text": "public demo text" if risk == "benign" else sensitive,
            "source_domain": "internal.example",
            "destination_domain": "chatgpt.com",
        }
    request = {
        "surface": surface,
        "prompt": prompt,
        "provider": "azure_openai" if surface == "foundry" else "openai",
        "action_category": "prompt_submission",
    }
    if ai_system_id.strip():
        request["ai_system_id"] = ai_system_id.strip()
    return request


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config_path = Path(args.config).expanduser() if args.config else DEFAULT_CONFIG_PATH
    config = load_config(config_path)
    mode_store = ModeStore(config.mode_state_path, default=config.agent_mode)

    if args.command == "status":
        ping = _rpc(config, {"op": "ping"})
        _print(
            {
                "status": "ok",
                "deployment_type": "endpoint_inline_control",
                "mode": mode_store.get(),
                "endpoint_id": config.endpoint_id,
                "hostname": config.hostname,
                "api_base_url": config.api_base_url,
                "security_profile": config.security_profile,
                "key_provider": config.key_provider,
                "device_identity": build_device_key_provider(
                    provider_name=config.key_provider,
                    security_profile=config.security_profile,
                    helper_path=config.identity_helper_path,
                    helper_sha256=getattr(config, "identity_helper_sha256", ""),
                    key_tag=config.device_key_tag,
                ).status().__dict__,
                "ipc": {"reachable": bool(ping.get("ok")), "socket": str(Path(config.ipc_socket_path).expanduser())},
                "baseline": _store(config).snapshot(),
                "evidence_queue": EvidenceQueue(
                    config.evidence_queue_path,
                    max_items=config.evidence_queue_max_items,
                ).stats(),
            }
        )
        return 0

    if args.command == "mode":
        if not _local_change_authorized(config, config_path):
            _print({"status": "managed_authorization_required"})
            return 2
        previous = mode_store.get()
        mode_store.set(args.mode)
        _print({"status": "ok", "previous_mode": previous, "mode": args.mode})
        return 0

    if args.command == "baseline":
        baseline = _store(config)
        if args.operation == "reset":
            if not _local_change_authorized(config, config_path):
                _print({"status": "managed_authorization_required"})
                return 2
            baseline.reset()
        _print(baseline.snapshot())
        return 0

    if args.command == "propose":
        _print(_store(config).propose())
        return 0

    if args.command == "test-action":
        request = _test_request(args.surface, args.risk, ai_system_id=args.ai_system_id)
        request.update({"protocol_version": 1, "op": "evaluate"})
        response = _rpc(
            config,
            request,
            timeout_seconds=30,
        )
        _print(response)
        return 0 if response.get("ok") else 1

    _print({"status": "unsupported_command"})
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
