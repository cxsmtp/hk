"""Command-line runner for the Hawk endpoint agent.

The entry point is intentionally small: it loads config, collects endpoint
signals, asks the Hawk API for policy decisions, and reports only redacted
telemetry. It does not capture raw audio or microphone content.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .collectors.audio import AudioCandidate, collect_platform_audio_candidates
from .collectors.base import Connection, ProcessInfo
from .collectors.meetings import MeetingContext, detect_meeting
from .collectors.network import list_connections
from .collectors.processes import list_processes
from .config import AgentConfig, load_config
from .enroll import enroll, enroll_existing_config
from .auth.session import EnrollmentBundle
from .auth.identity_health import (
    DeviceIdentityHealthError,
    verify_device_identity,
)
from .hawk_client import HawkClient, HawkApiError, HawkUnavailable
from .hmair_snapshot import HMAIRSnapshotError, run_hmair_discovery_snapshot
from .modules.notetaker import NotetakerController
from .policy import PolicyStore
from .runner import AgentRunner


def build_pilot_config(
    *,
    api_url: str,
    tenant_id: str,
    endpoint_id: str = "",
    default_ai_system_id: str = "",
    hostname: str = "",
    fail_secure_mode: str = "warn",
    security_profile: str = "bank",
    key_provider: str = "macos_secure_enclave",
) -> dict[str, Any]:
    """Build a transfer-safe pilot config.

    It contains no bearer, refresh, API, enrollment, or local operator secret.
    """
    cfg = AgentConfig(
        api_base_url=api_url,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id,
        default_ai_system_id=default_ai_system_id,
        hostname=hostname or AgentConfig().hostname,
        fail_secure_mode=fail_secure_mode,
        security_profile=security_profile,
        key_provider=key_provider,
    )
    return {
        "api_base_url": cfg.api_base_url.rstrip("/"),
        "tenant_id": cfg.tenant_id,
        "endpoint_id": cfg.endpoint_id,
        "default_ai_system_id": cfg.default_ai_system_id,
        "hostname": cfg.hostname,
        "security_profile": cfg.security_profile,
        "key_provider": cfg.key_provider,
        "identity_helper_path": cfg.identity_helper_path,
        "device_key_tag": cfg.device_key_tag,
        "poll_interval_seconds": cfg.poll_interval_seconds,
        "policy_ttl_seconds": cfg.policy_ttl_seconds,
        "policy_cache_path": cfg.policy_cache_path,
        "fail_secure_mode": cfg.fail_secure_mode,
        "enabled_modules": cfg.enabled_modules,
        "notetaker_default_action": cfg.notetaker_default_action,
        "notetaker_allow_eviction": cfg.notetaker_allow_eviction,
        "allow_process_termination": cfg.allow_process_termination,
        "allow_mic_revocation": cfg.allow_mic_revocation,
        "allow_network_block": cfg.allow_network_block,
    }


def write_pilot_config(path: Path, config: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def run_once(
    config: AgentConfig,
    *,
    client: Any | None = None,
    policy: PolicyStore | None = None,
    processes: list[ProcessInfo] | None = None,
    connections: list[Connection] | None = None,
    audio_candidates: list[AudioCandidate] | None = None,
    meeting: MeetingContext | None = None,
) -> list[dict[str, Any]]:
    """Collect one snapshot and report endpoint notetaker telemetry."""
    client = client or HawkClient(config)
    policy = policy or PolicyStore(config, client)
    policy.refresh()

    processes = processes if processes is not None else list_processes()
    connections = connections if connections is not None else list_connections()
    audio_candidates = (
        audio_candidates
        if audio_candidates is not None
        else collect_platform_audio_candidates(processes, os_type=config.os_type)
    )
    meeting = meeting if meeting is not None else detect_meeting(processes, connections)

    controller = NotetakerController(config)
    reported: list[dict[str, Any]] = []
    for detected in controller.detect(
        processes=processes,
        connections=connections,
        audio_candidates=audio_candidates,
        meeting=meeting,
    ):
        decision = controller.evaluate(detected, client=client, policy=policy)
        outcome = controller.enforce(detected, decision, mode=config.agent_mode)
        event = detected.to_telemetry_event(config, outcome=outcome)
        try:
            client.report_discovery(event)
        except (HawkApiError, HawkUnavailable):
            continue
        reported.append(event)
    return reported


def run_forever(config: AgentConfig) -> None:
    AgentRunner(config).start()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hawk-endpoint-agent")
    parser.add_argument("--config", help="Path to endpoint-agent JSON config")
    parser.add_argument("--once", action="store_true", help="Collect and report one snapshot, then exit")
    parser.add_argument(
        "--hmair-discovery-snapshot",
        action="store_true",
        help=(
            "Explicitly collect and submit one metadata-only HMAIR lab snapshot, "
            "then exit"
        ),
    )
    parser.add_argument("--print-config", action="store_true", help="Print redacted effective config")
    parser.add_argument("--version", action="store_true", help="Print agent version")
    parser.add_argument("--write-pilot-config", help="Write a transfer-safe pilot config JSON")
    parser.add_argument("--api-url", help="Hawk API base URL for generated pilot config")
    parser.add_argument("--tenant-id", help="Hawk tenant ID for generated pilot config")
    parser.add_argument("--endpoint-id", default="", help="Optional endpoint ID for generated pilot config")
    parser.add_argument("--ai-system-id", default="", help="Registered Hawk AI-system asset ID")
    parser.add_argument("--hostname", default="", help="Optional hostname for generated pilot config")
    parser.add_argument("--fail-secure", default="warn", help="allow | warn | block")
    parser.add_argument("--enroll", action="store_true", help="One-shot: configure the endpoint, CA, service, and browser bridge")
    parser.add_argument(
        "--enroll-existing-config",
        action="store_true",
        help="Enroll a pre-staged managed config without replacing its policy trust pins",
    )
    parser.add_argument(
        "--enrollment-bundle-stdin",
        action="store_true",
        help="Read the one-time enrollment authorization JSON from standard input",
    )
    parser.add_argument(
        "--security-profile", choices=("bank", "development"), default="bank"
    )
    parser.add_argument(
        "--key-provider",
        choices=("macos_secure_enclave", "windows_tpm_cng", "linux_tpm2", "development_ephemeral"),
        default="macos_secure_enclave",
    )
    parser.add_argument(
        "--identity-helper",
        default="~/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity",
    )
    parser.add_argument(
        "--device-key-tag",
        default="com.hawk.endpoint-agent.device-key",
        help="Safe logical tag for the hardware-backed endpoint identity",
    )
    parser.add_argument(
        "--verify-device-identity",
        action="store_true",
        help="Verify the persisted enrolled key without printing key material",
    )
    parser.add_argument(
        "--windows-floor-status",
        action="store_true",
        help="Read the bounded native Windows endpoint-floor status",
    )
    parser.add_argument(
        "--windows-binary-identity",
        help="Resolve a binary to the canonical identity used by the Windows driver",
    )
    parser.add_argument("--enable-proxy", action="store_true", help="Enable the local intercepting proxy")
    parser.add_argument("--enable-tls", action="store_true", help="Enable deep TLS inspection (generates the CA)")
    parser.add_argument("--install-service", action="store_true", help="Install a launch agent / systemd unit to autostart")
    parser.add_argument("--install-bridge", action="store_true", help="Write the browser native-messaging manifests")
    parser.add_argument("--extension-id", action="append", default=[], help="Allowed browser extension id (repeatable)")
    parser.add_argument("--mode", choices=("monitor", "enforce"), default="monitor", help="Initial endpoint mode")
    parser.add_argument(
        "--allow-development-local-control",
        action="store_true",
        help="Development only: allow same-user local mode/baseline changes",
    )
    parser.add_argument("--log-dir", default="", help="Agent log directory for launchd")
    parser.add_argument("--python-path", default="", help="Private package path used by launchd")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        print(__version__)
        return 0

    if args.enroll_existing_config:
        if args.enroll:
            raise SystemExit("choose only one enrollment mode")
        if not args.config or not args.enrollment_bundle_stdin:
            raise SystemExit(
                "--config and --enrollment-bundle-stdin are required with --enroll-existing-config"
            )
        raw_bundle = bytearray(sys.stdin.buffer.read(65537))
        if not raw_bundle or len(raw_bundle) > 65536:
            for index in range(len(raw_bundle)):
                raw_bundle[index] = 0
            raise SystemExit("invalid enrollment bundle")
        decoded_bundle: dict[str, Any] = {}
        try:
            parsed = json.loads(bytes(raw_bundle))
            if not isinstance(parsed, dict):
                raise ValueError("enrollment bundle must be a JSON object")
            decoded_bundle = parsed
            report = enroll_existing_config(
                config_path=Path(args.config).expanduser(),
                enrollment_bundle=EnrollmentBundle.from_mapping(decoded_bundle),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise SystemExit("invalid enrollment bundle") from exc
        finally:
            decoded_bundle.clear()
            for index in range(len(raw_bundle)):
                raw_bundle[index] = 0
        result = report.as_dict()
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    if args.enroll:
        if not args.api_url or not args.tenant_id:
            raise SystemExit("--api-url and --tenant-id are required with --enroll")
        if not args.ai_system_id.strip():
            raise SystemExit(
                "--ai-system-id is required with --enroll and must identify a registered Hawk AI asset"
            )
        if not args.enrollment_bundle_stdin:
            raise SystemExit(
                "--enrollment-bundle-stdin is required; credentials are never accepted in arguments or environment"
            )
        raw_bundle = bytearray(sys.stdin.buffer.read(65537))
        if not raw_bundle or len(raw_bundle) > 65536:
            for index in range(len(raw_bundle)):
                raw_bundle[index] = 0
            raise SystemExit("invalid enrollment bundle")
        decoded_bundle: dict[str, Any] = {}
        try:
            parsed = json.loads(bytes(raw_bundle))
            if not isinstance(parsed, dict):
                raise ValueError("enrollment bundle must be a JSON object")
            decoded_bundle = parsed
            bundle = EnrollmentBundle.from_mapping(decoded_bundle)
            report = enroll(
                api_url=args.api_url,
                tenant_id=args.tenant_id,
                endpoint_id=args.endpoint_id,
                default_ai_system_id=args.ai_system_id,
                config_path=args.config,
                fail_secure=args.fail_secure,
                enable_proxy=args.enable_proxy,
                enable_tls=args.enable_tls,
                install_service=args.install_service,
                install_bridge=args.install_bridge,
                extension_ids=args.extension_id,
                agent_mode=args.mode,
                security_profile=args.security_profile,
                key_provider=args.key_provider,
                identity_helper_path=args.identity_helper,
                device_key_tag=args.device_key_tag,
                local_operator_changes_allowed=args.allow_development_local_control,
                enrollment_bundle=bundle,
                log_dir=args.log_dir or None,
                python_path=args.python_path,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise SystemExit("invalid enrollment bundle") from exc
        finally:
            decoded_bundle.clear()
            for index in range(len(raw_bundle)):
                raw_bundle[index] = 0
        result = report.as_dict()
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    if args.write_pilot_config:
        if not args.api_url or not args.tenant_id:
            raise SystemExit("--api-url and --tenant-id are required with --write-pilot-config")
        pilot_config = build_pilot_config(
            api_url=args.api_url,
            tenant_id=args.tenant_id,
            endpoint_id=args.endpoint_id,
            default_ai_system_id=args.ai_system_id,
            hostname=args.hostname,
            fail_secure_mode=args.fail_secure,
            security_profile=args.security_profile,
            key_provider=args.key_provider,
        )
        write_pilot_config(Path(args.write_pilot_config).expanduser(), pilot_config)
        print(f"wrote {args.write_pilot_config}")
        return 0

    config = load_config(Path(args.config).expanduser() if args.config else None)
    if args.hmair_discovery_snapshot:
        try:
            receipt = run_hmair_discovery_snapshot(config)
        except (HMAIRSnapshotError, HawkApiError, HawkUnavailable):
            print(json.dumps({"ok": False, "reason": "hmair_snapshot_failed"}, sort_keys=True))
            return 1
        print(json.dumps({"ok": True, **receipt}, sort_keys=True))
        return 0 if receipt["status"] in {"complete", "completed"} else 1
    if args.windows_binary_identity:
        try:
            from .windows.policy_compiler import windows_binary_identity

            identity = windows_binary_identity(args.windows_binary_identity)
        except Exception:  # noqa: BLE001 - do not echo customer paths in errors
            print(json.dumps({"ok": False, "reason": "binary_identity_unavailable"}))
            return 1
        print(json.dumps({"ok": True, "binary_identity": identity}, sort_keys=True))
        return 0
    if args.windows_floor_status:
        if config.os_type != "windows":
            print(json.dumps({"ok": False, "reason": "windows_floor_unavailable"}))
            return 1
        try:
            from .windows.kernel_channel import WindowsKernelChannel

            status = WindowsKernelChannel(
                device_path=config.windows_floor_device_path
            ).status()
        except Exception:  # noqa: BLE001 - never expose kernel/device details
            print(json.dumps({"ok": False, "reason": "windows_floor_unavailable"}))
            return 1
        print(json.dumps({
            "ok": True,
            "armed": status.armed,
            "policy_loaded": status.policy_loaded,
            "policy_current": status.policy_current,
            "identity_coverage_ready": status.identity_coverage_ready,
            "wfp_ready": status.wfp_ready,
            "generation": status.generation,
            "policy_sequence": status.policy_sequence,
            "policy_fingerprint": status.policy_fingerprint,
            "allow_count": status.allow_count,
            "block_count": status.block_count,
            "policy_reject_count": status.policy_reject_count,
        }, sort_keys=True))
        return 0
    if args.verify_device_identity:
        try:
            result = verify_device_identity(config)
        except DeviceIdentityHealthError:
            print(json.dumps({
                "ok": False,
                "reason": "device_identity_verification_failed",
            }, sort_keys=True))
            return 1
        print(json.dumps(result.as_dict(), sort_keys=True))
        return 0
    if args.print_config:
        print(json.dumps(config.redacted(), indent=2, sort_keys=True))
        return 0
    if args.once:
        events = run_once(config)
        print(json.dumps({"reported_events": len(events)}, sort_keys=True))
        return 0
    run_forever(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
