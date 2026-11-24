from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import plistlib
import pty
import re
import select
import signal
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.native_control.claude_acceptance import (
    _SignerServer,
    _SignerState,
    _b64url_decode,
    _canonical,
)
from hawk_endpoint_agent.native_control.installer import NativeHookInstaller


_SEMVER = re.compile(r"\b(\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)\b")
_APPROVED_AGENT_VERSION = "2026.08.11-e8db854"
_APPROVED_DESKTOP_VERSION = "3.15.6"
_APPROVED_DESKTOP_COMMIT = "a1f686545fd0ce8917bbd2449f733551a9bce420"


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * quantile)))
    return round(ordered[index], 3)


@dataclass(frozen=True, slots=True)
class CursorBinaryAcceptanceReport:
    binary_available: bool
    provider_version: str
    desktop_version: str
    desktop_commit: str
    exact_version_verified: bool
    desktop_signature_verified: bool
    signed_allow: bool
    allowed_action_executed: bool | None
    signed_block: bool
    blocked_action_executed: bool | None
    forged_callback_rejected: bool
    replay_rejected: bool
    shell_pre_action_verified: bool
    mcp_pre_action_verified: bool
    file_read_pre_action_verified: bool
    prompt_pre_action_verified: bool
    interactive_prompt_allowed: bool
    interactive_prompt_blocked: bool
    interactive_prompt_block_prevented_backend: bool
    subagent_pre_action_verified: bool
    post_action_correlated: bool
    config_tamper_detected: bool
    timeout_failed_closed: bool
    customer_hooks_preserved: bool
    hook_ordering_verified: bool
    input_mutation_verified: bool
    input_mutation_status: str
    endpoint_correlation_verified: bool
    endpoint_correlation_status: str
    mcp_status: str
    managed_hook_status: str
    cloud_execution_verified: bool
    measured_callback_sample_count: int
    measured_callback_p50_ms: float
    measured_callback_p95_ms: float
    measured_callback_p99_ms: float
    diagnostics: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return all(
            (
                self.binary_available,
                self.exact_version_verified,
                self.desktop_signature_verified,
                self.signed_allow,
                self.allowed_action_executed is True,
                self.signed_block,
                self.blocked_action_executed is False,
                self.forged_callback_rejected,
                self.replay_rejected,
                self.shell_pre_action_verified,
                self.file_read_pre_action_verified,
                self.prompt_pre_action_verified,
                self.interactive_prompt_allowed,
                self.interactive_prompt_blocked,
                self.interactive_prompt_block_prevented_backend,
                self.mcp_pre_action_verified,
                self.mcp_status == "verified:read_and_blocked_write",
                self.post_action_correlated,
                self.config_tamper_detected,
                self.timeout_failed_closed,
                self.customer_hooks_preserved,
                self.hook_ordering_verified,
                self.input_mutation_verified,
                self.measured_callback_sample_count > 0,
                self.measured_callback_p95_ms < 4_000,
                not self.diagnostics,
            )
        )


class _CursorCallbackState:
    def __init__(self, signer: _SignerState) -> None:
        self.signer = signer
        self.decision = "allow"
        self.decision_events = frozenset({"before_shell"})
        self.delay_seconds = 0.0
        self.events: list[dict[str, Any]] = []
        self.latencies_ms: list[float] = []
        self.seen_event_ids: set[str] = set()
        self.last_request_body: dict[str, str] | None = None
        self.lock = threading.Lock()

    def reset(
        self,
        *,
        decision: str,
        decision_events: frozenset[str],
        delay_seconds: float = 0.0,
    ) -> None:
        with self.lock:
            self.decision = decision
            self.decision_events = decision_events
            self.delay_seconds = delay_seconds
            self.events.clear()


class _CursorCallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:
        state: _CursorCallbackState = self.server.state  # type: ignore[attr-defined]
        try:
            length = int(self.headers.get("Content-Length") or "0")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("callback_body_invalid")
            envelope = json.loads(base64.b64decode(body["envelope_base64"], validate=True))
            payload_bytes = base64.b64decode(body["payload_base64"], validate=True)
            payload = json.loads(payload_bytes)
            signature = _b64url_decode(str(envelope.pop("signature")))
            state.signer.key.public_key().verify(
                signature,
                _canonical(envelope),
                ec.ECDSA(hashes.SHA256()),
            )
            if hashlib.sha256(payload_bytes).hexdigest() != envelope.get("payload_hash"):
                raise ValueError("payload_hash_mismatch")
            if envelope.get("provider") != "cursor" or envelope.get("product") != "cursor":
                raise ValueError("provider_binding_mismatch")
            event_id = str(envelope.get("event_id") or "")
            with state.lock:
                if not event_id or event_id in state.seen_event_ids:
                    raise ValueError("callback_replay")
                state.seen_event_ids.add(event_id)
            issued_at = datetime.fromisoformat(str(envelope["issued_at"]))
            latency_ms = max(
                0.0,
                (datetime.now(timezone.utc) - issued_at).total_seconds() * 1000,
            )
            event = {
                "signature_valid": True,
                "provider_event_type": envelope.get("provider_event_type"),
                "provider_event_id": envelope.get("provider_event_id"),
                "correlation_id": envelope.get("correlation_id"),
                "parameter_hash": payload.get("parameter_hash"),
                "target_resource_hash": payload.get("target_resource_hash"),
                "provider_tool_use_hash": payload.get("provider_tool_use_hash"),
                "provider_session_hash": payload.get("provider_session_hash"),
                "action_type": payload.get("action_type"),
                "tool_name": payload.get("tool_name"),
                "execution_status": payload.get("execution_status"),
                "evidence_quality": payload.get("evidence_quality"),
                "endpoint_observation_id_hash": payload.get("endpoint_observation_id_hash"),
                "mcp_observation_id_hash": payload.get("mcp_observation_id_hash"),
            }
            with state.lock:
                state.events.append(event)
                state.latencies_ms.append(latency_ms)
                state.last_request_body = {
                    "envelope_base64": str(body["envelope_base64"]),
                    "payload_base64": str(body["payload_base64"]),
                }
                delay = state.delay_seconds
                decision = state.decision
                decision_events = state.decision_events
            if delay:
                time.sleep(delay)
            effective = decision if envelope.get("provider_event_type") in decision_events else "allow"
            encoded = _canonical(
                {
                    "decision": effective,
                    "enforced": True,
                    "reason": "Hawk Cursor exact-version acceptance policy",
                    "evidence_quality": "provider_reported",
                }
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except Exception as exc:
            encoded = _canonical({"detail": type(exc).__name__})
            try:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except (BrokenPipeError, ConnectionResetError):
                return


class _CursorCallbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, state: _CursorCallbackState) -> None:
        self.state = state
        super().__init__(("127.0.0.1", 0), _CursorCallbackHandler)


def _post_raw(port: int, body: dict[str, str]) -> int:
    from urllib import error as urlerror
    from urllib import request as urlrequest

    request = urlrequest.Request(
        f"http://127.0.0.1:{port}/native-controls/callbacks/cursor-acceptance",
        data=_canonical(body),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(request, timeout=5) as response:
            return response.status
    except urlerror.HTTPError as exc:
        return exc.code


def _missing_report(reason: str, *, binary_available: bool = False, version: str = "unknown") -> CursorBinaryAcceptanceReport:
    return CursorBinaryAcceptanceReport(
        binary_available=binary_available,
        provider_version=version,
        desktop_version="unknown",
        desktop_commit="unknown",
        exact_version_verified=False,
        desktop_signature_verified=False,
        signed_allow=False,
        allowed_action_executed=None,
        signed_block=False,
        blocked_action_executed=None,
        forged_callback_rejected=False,
        replay_rejected=False,
        shell_pre_action_verified=False,
        mcp_pre_action_verified=False,
        file_read_pre_action_verified=False,
        prompt_pre_action_verified=False,
        interactive_prompt_allowed=False,
        interactive_prompt_blocked=False,
        interactive_prompt_block_prevented_backend=False,
        subagent_pre_action_verified=False,
        post_action_correlated=False,
        config_tamper_detected=False,
        timeout_failed_closed=False,
        customer_hooks_preserved=False,
        hook_ordering_verified=False,
        input_mutation_verified=False,
        input_mutation_status="not_run",
        endpoint_correlation_verified=False,
        endpoint_correlation_status="not_run",
        mcp_status="not_run",
        managed_hook_status="not_run",
        cloud_execution_verified=False,
        measured_callback_sample_count=0,
        measured_callback_p50_ms=0.0,
        measured_callback_p95_ms=0.0,
        measured_callback_p99_ms=0.0,
        diagnostics=(reason,),
    )


def _version(binary: Path) -> str:
    try:
        result = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    match = _SEMVER.search(f"{result.stdout}\n{result.stderr}")
    return match.group(1) if result.returncode == 0 and match else "unknown"


def _desktop_identity(app: Path) -> tuple[str, str, bool]:
    plist = app / "Contents/Info.plist"
    wrapper = app / "Contents/Resources/app/bin/cursor"
    try:
        with plist.open("rb") as stream:
            version = str(plistlib.load(stream).get("CFBundleShortVersionString") or "unknown")
        result = subprocess.run(
            [str(wrapper), "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        commit = lines[1] if len(lines) > 1 else "unknown"
        signature = subprocess.run(
            ["codesign", "--verify", "--deep", "--strict", str(app)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, plistlib.InvalidFileException, subprocess.SubprocessError):
        return "unknown", "unknown", False
    return version, commit, signature.returncode == 0


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def _write_helper(path: Path) -> None:
    package_root = Path(__file__).resolve().parents[2]
    path.write_text(
        "#!/bin/sh\n"
        + "export PYTHONPATH="
        + shlex.quote(str(package_root))
        + "\nexec "
        + shlex.quote(sys.executable)
        + " -m hawk_endpoint_agent.native_control.hook \"$@\"\n",
        encoding="utf-8",
    )
    path.chmod(0o700)


def _run_agent(
    *,
    binary: Path,
    acceptance_home: Path,
    workspace: Path,
    prompt: str,
    timeout: int = 180,
    approve_mcps: bool = False,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": str(acceptance_home),
            "AGENT_CLI_CREDENTIAL_STORE": "file",
            "NO_COLOR": "1",
        }
    )
    arguments = [
        str(binary),
        "-p",
        "--force",
        "--trust",
        "--output-format",
        "stream-json",
        "--workspace",
        str(workspace),
    ]
    if approve_mcps:
        arguments.append("--approve-mcps")
    arguments.append(prompt)
    return subprocess.run(
        arguments,
        cwd=workspace,
        env=environment,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _run_agent_interactive(
    *,
    binary: Path,
    acceptance_home: Path,
    workspace: Path,
    prompt: str,
    expected_output: str,
    timeout: int = 60,
) -> str:
    """Submit a prompt through Cursor's interactive TUI and return bounded output."""

    environment = dict(os.environ)
    environment.update(
        {
            "HOME": str(acceptance_home),
            "AGENT_CLI_CREDENTIAL_STORE": "file",
            "NO_COLOR": "1",
        }
    )
    master, slave = pty.openpty()
    process: subprocess.Popen[bytes] | None = None
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(
            [str(binary), "--force", "--trust", "--workspace", str(workspace)],
            cwd=workspace,
            env=environment,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave)
        slave = -1

        def collect_until(marker: bytes, *, stop_at: float | None = None) -> bool:
            local_deadline = min(deadline, stop_at) if stop_at is not None else deadline
            while time.monotonic() < local_deadline:
                if marker in output:
                    return True
                ready, _, _ = select.select(
                    [master],
                    [],
                    [],
                    min(0.25, max(0.0, local_deadline - time.monotonic())),
                )
                if not ready:
                    if process is not None and process.poll() is not None:
                        break
                    continue
                try:
                    chunk = os.read(master, 65_536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 1_000_000:
                    del output[:-500_000]
            return marker in output

        if not collect_until(b"Cursor Agent"):
            return output.decode("utf-8", errors="replace")
        time.sleep(0.5)
        os.write(master, prompt.encode("utf-8"))
        time.sleep(0.2)
        os.write(master, b"\r")
        marker = expected_output.encode("utf-8")
        if not collect_until(marker, stop_at=time.monotonic() + 3.0):
            os.write(master, b"\r")
            collect_until(marker)
        return output.decode("utf-8", errors="replace")
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        if slave >= 0:
            os.close(slave)
        os.close(master)


def _correlated(events: list[dict[str, Any]], before: str, after: str) -> bool:
    pres = [row for row in events if row.get("provider_event_type") == before]
    posts = [row for row in events if row.get("provider_event_type") == after]
    return any(
        str(pre.get("parameter_hash") or "")
        and pre.get("parameter_hash") == post.get("parameter_hash")
        for pre in pres
        for post in posts
    )


def run_cursor_binary_acceptance(
    cursor_binary: Path | str,
    *,
    acceptance_home: Path | str | None = None,
    desktop_app: Path | str | None = None,
) -> CursorBinaryAcceptanceReport:
    """Run harmless actions through an exact Cursor binary and signed Hawk hooks.

    This never infers protection from documentation. Missing authentication,
    missing provider events, or an unavailable managed source remain explicit
    unverified results rather than optimistic promotion.
    """

    binary = Path(cursor_binary).expanduser().resolve()
    if not binary.is_file() or binary.is_symlink():
        return _missing_report("cursor_binary_unavailable")
    version = _version(binary)
    if acceptance_home is None or desktop_app is None:
        return _missing_report(
            "cursor_exact_version_real_binary_acceptance_not_recorded",
            binary_available=True,
            version=version,
        )
    home = Path(acceptance_home).expanduser().resolve()
    app = Path(desktop_app).expanduser().resolve()
    if not home.is_dir() or not app.is_dir() or app.is_symlink():
        return _missing_report(
            "cursor_acceptance_environment_unavailable",
            binary_available=True,
            version=version,
        )

    desktop_version, desktop_commit, desktop_signature = _desktop_identity(app)
    exact = (
        version == _APPROVED_AGENT_VERSION
        and desktop_version == _APPROVED_DESKTOP_VERSION
        and desktop_commit == _APPROVED_DESKTOP_COMMIT
        and desktop_signature
    )
    if not exact:
        report = _missing_report(
            "cursor_exact_version_or_signature_mismatch",
            binary_available=True,
            version=version,
        )
        return CursorBinaryAcceptanceReport(
            **{
                **{field: getattr(report, field) for field in report.__dataclass_fields__},
                "desktop_version": desktop_version,
                "desktop_commit": desktop_commit,
                "desktop_signature_verified": desktop_signature,
            }
        )

    diagnostics: list[str] = []
    package_root = Path(__file__).resolve().parents[2]
    settings_path = home / ".cursor/hooks.json"
    prior_settings = settings_path.read_bytes() if settings_path.is_file() else None
    with tempfile.TemporaryDirectory(prefix="hawk-cursor-acceptance-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir(mode=0o700)
        helper = root / "hawk-native-hook"
        config = root / "native-control.json"
        customer_hook = root / "customer-allow.py"
        customer_mutator = root / "customer-mutator.py"
        allow_marker = workspace / "allowed.marker"
        block_marker = workspace / "blocked.marker"
        timeout_marker = workspace / "timeout.marker"
        mutator_first_marker = workspace / "mutator-first.marker"
        mutator_last_marker = workspace / "mutator-last.marker"
        mutation_source_marker = workspace / "mutation-source.marker"
        mutation_target_marker = workspace / "mutation-target.marker"
        mutation_hook_marker = workspace / "mutation-hook-observed.marker"
        mcp_marker = workspace / "mcp.marker"
        input_file = workspace / "input.txt"
        input_file.write_text("synthetic cursor acceptance input\n", encoding="utf-8")
        input_file.chmod(0o600)
        _write_helper(helper)
        customer_hook.write_text(
            "import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'permission':'allow'}))\n",
            encoding="utf-8",
        )
        customer_hook.chmod(0o700)
        mutated_command = f"/usr/bin/printf mutated > {shlex.quote(str(mutation_target_marker))}"
        customer_mutator.write_text(
            "import json\n"
            "from pathlib import Path\n"
            "import sys\n"
            "payload=json.load(sys.stdin)\n"
            "tool_input=payload.get('tool_input') if isinstance(payload.get('tool_input'),dict) else {}\n"
            f"source={str(mutation_source_marker)!r}\n"
            f"target_command={mutated_command!r}\n"
            f"observed={str(mutation_hook_marker)!r}\n"
            "result={'permission':'allow'}\n"
            "if source in str(tool_input.get('command') or ''):\n"
            "    Path(observed).write_text('observed',encoding='utf-8')\n"
            "    result['updated_input']={'command':target_command,'working_directory':str(tool_input.get('working_directory') or '')}\n"
            "print(json.dumps(result))\n",
            encoding="utf-8",
        )
        customer_mutator.chmod(0o700)

        signer_state = _SignerState()
        signer_state.key_reference = "hsm://hawk-acceptance/cursor"
        signer = _SignerServer(root / "signer.sock", signer_state)
        callback_state = _CursorCallbackState(signer_state)
        callback = _CursorCallbackServer(callback_state)
        threads = tuple(
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in (signer, callback)
        )
        for thread in threads:
            thread.start()
        runtime = {
            "api_url": f"http://127.0.0.1:{callback.server_port}",
            "tenant_id": "tenant-cursor-acceptance",
            "integration_id": "cursor-acceptance",
            "credential_id": "cursor-acceptance-hardware-key",
            "provider": "cursor",
            "product": "cursor",
            "provider_version": version,
            "adapter_version": "0.2.0",
            "credential_epoch": 1,
            "environment": "acceptance",
            "key_provider": "kms_hsm_helper",
            "security_profile": "bank",
            "kms_hsm_helper_path": f"unix://{root / 'signer.sock'}",
            "kms_hsm_key_reference": signer_state.key_reference,
        }
        _write_json(config, runtime)
        installer = NativeHookInstaller(
            provider="cursor",
            helper_path=helper,
            runtime_config_path=config,
        )
        original_for_preservation = {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [
                    {"command": shlex.join((sys.executable, str(customer_hook))), "timeout": 5}
                ],
                "preToolUse": [
                    {
                        "command": shlex.join((sys.executable, str(customer_mutator))),
                        "timeout": 5,
                        "matcher": "Shell",
                    }
                ],
            },
        }
        _write_json(settings_path, original_for_preservation)
        install_result = installer.install(settings_path)
        config_tamper_detected = False
        customer_hooks_preserved = False
        signed_allow = False
        allowed_action_executed: bool | None = None
        signed_block = False
        blocked_action_executed: bool | None = None
        forged_callback_rejected = False
        replay_rejected = False
        shell_pre_action_verified = False
        file_read_pre_action_verified = False
        prompt_pre_action_verified = False
        interactive_prompt_allowed = False
        interactive_prompt_blocked = False
        interactive_prompt_block_prevented_backend = False
        post_action_correlated = False
        timeout_failed_closed = False
        hook_ordering_verified = False
        input_mutation_verified = False
        input_mutation_status = "unverified:not_emitted"
        mcp_pre_action_verified = False
        mcp_status = "unverified:model_did_not_call_fixture"
        endpoint_correlation_verified = False
        endpoint_correlation_status = "unverified:external_endpoint_observation_not_in_fixture"
        try:
            callback_state.reset(decision="allow", decision_events=frozenset({"before_shell"}))
            allow_result = _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf allowed > {shlex.quote(str(allow_marker))}"
                ),
            )
            allow_events = list(callback_state.events)
            signed_allow = any(
                row.get("signature_valid") is True
                and row.get("provider_event_type") == "before_shell"
                for row in allow_events
            )
            allowed_action_executed = allow_marker.is_file()
            shell_pre_action_verified = signed_allow
            post_action_correlated = _correlated(allow_events, "before_shell", "after_shell")
            if allow_result.returncode != 0 and not allowed_action_executed:
                diagnostics.append("cursor_allow_action_failed")

            probe_body = dict(callback_state.last_request_body or {})
            replay_rejected = bool(probe_body) and _post_raw(callback.server_port, probe_body) == 401
            if probe_body:
                envelope = json.loads(base64.b64decode(probe_body["envelope_base64"], validate=True))
                envelope["signature"] = "AA"
                forged = {
                    **probe_body,
                    "envelope_base64": base64.b64encode(_canonical(envelope)).decode("ascii"),
                }
                forged_callback_rejected = _post_raw(callback.server_port, forged) == 401

            callback_state.reset(decision="block", decision_events=frozenset({"before_shell"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf blocked > {shlex.quote(str(block_marker))}"
                ),
            )
            block_events = list(callback_state.events)
            signed_block = any(
                row.get("signature_valid") is True
                and row.get("provider_event_type") == "before_shell"
                for row in block_events
            )
            blocked_action_executed = block_marker.exists()

            callback_state.reset(decision="allow", decision_events=frozenset({"before_file_read"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=f"Read {input_file.name} using the file-read tool and report only its first word.",
            )
            file_read_pre_action_verified = any(
                row.get("provider_event_type") == "before_file_read"
                and row.get("signature_valid") is True
                for row in callback_state.events
            )

            callback_state.reset(decision="allow", decision_events=frozenset({"before_model"}))
            allow_prompt_output = _run_agent_interactive(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Return the following two words joined by a hyphen and no other text: "
                    "hawk cursorinteractiveallow"
                ),
                expected_output="hawk-cursorinteractiveallow",
            )
            allow_prompt_events = list(callback_state.events)
            interactive_prompt_allowed = "hawk-cursorinteractiveallow" in allow_prompt_output and any(
                row.get("provider_event_type") == "before_model"
                and row.get("signature_valid") is True
                for row in allow_prompt_events
            )
            callback_state.reset(decision="block", decision_events=frozenset({"before_model"}))
            block_prompt_output = _run_agent_interactive(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt="Respond exactly should-not-reach-cursor-backend and do not use tools.",
                expected_output="Hawk Cursor exact-version acceptance policy",
            )
            block_prompt_events = list(callback_state.events)
            interactive_prompt_blocked = (
                "Hawk Cursor exact-version acceptance policy" in block_prompt_output
                and any(
                    row.get("provider_event_type") == "before_model"
                    and row.get("signature_valid") is True
                    for row in block_prompt_events
                )
            )
            interactive_prompt_block_prevented_backend = interactive_prompt_blocked and not any(
                row.get("provider_event_type") == "after_agent_response"
                for row in block_prompt_events
            )
            prompt_pre_action_verified = interactive_prompt_allowed and interactive_prompt_blocked

            callback_state.reset(
                decision="allow",
                decision_events=frozenset({"before_shell"}),
                delay_seconds=5.0,
            )
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf timeout > {shlex.quote(str(timeout_marker))}"
                ),
            )
            timeout_failed_closed = not timeout_marker.exists() and any(
                row.get("provider_event_type") == "before_shell"
                for row in callback_state.events
            )

            callback_state.reset(decision="block", decision_events=frozenset({"before_shell"}))
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            rows = settings["hooks"]["beforeShellExecution"]
            rows[:] = [rows[-1], rows[0]]
            _write_json(settings_path, settings)
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf first > {shlex.quote(str(mutator_first_marker))}"
                ),
            )
            first_order_events = list(callback_state.events)
            deny_survived_allow_first = not mutator_first_marker.exists() and any(
                row.get("provider_event_type") == "before_shell"
                for row in first_order_events
            )
            installer.install(settings_path)
            callback_state.reset(decision="block", decision_events=frozenset({"before_shell"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf last > {shlex.quote(str(mutator_last_marker))}"
                ),
            )
            last_order_events = list(callback_state.events)
            deny_survived_allow_last = not mutator_last_marker.exists() and any(
                row.get("provider_event_type") == "before_shell"
                for row in last_order_events
            )
            if deny_survived_allow_first and deny_survived_allow_last:
                hook_ordering_verified = True
                input_mutation_status = "verified:deny_precedence_survived"

            installer.install(settings_path)
            callback_state.reset(decision="block", decision_events=frozenset({"before_shell"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                prompt=(
                    "Use the shell exactly once to run this command, then stop: "
                    f"/usr/bin/printf source > {shlex.quote(str(mutation_source_marker))}"
                ),
            )
            mutation_events = list(callback_state.events)
            input_mutation_verified = (
                mutation_hook_marker.is_file()
                and not mutation_source_marker.exists()
                and not mutation_target_marker.exists()
                and any(
                    row.get("provider_event_type") == "before_shell"
                    for row in mutation_events
                )
            )
            if input_mutation_verified:
                input_mutation_status = "verified:mutation_attempt_cannot_override_deny"

            mcp_config = {
                "mcpServers": {
                    "hawkfixture": {
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "hawk_endpoint_agent.native_control.gemini_mcp_fixture",
                            "--marker",
                            str(mcp_marker),
                        ],
                        "env": {"PYTHONPATH": str(package_root)},
                    }
                }
            }
            _write_json(workspace / ".cursor/mcp.json", mcp_config)
            callback_state.reset(decision="allow", decision_events=frozenset({"before_mcp"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                approve_mcps=True,
                prompt="Use only the hawkfixture read_marker MCP tool once, then report its result.",
            )
            read_mcp_events = list(callback_state.events)
            read_mcp = any(
                row.get("provider_event_type") == "before_mcp"
                for row in read_mcp_events
            ) and _correlated(read_mcp_events, "before_mcp", "after_mcp")
            callback_state.reset(decision="block", decision_events=frozenset({"before_mcp"}))
            _run_agent(
                binary=binary,
                acceptance_home=home,
                workspace=workspace,
                approve_mcps=True,
                prompt=(
                    "Use only the hawkfixture write_marker MCP tool with value blocked-cursor-mcp, "
                    "then stop."
                ),
            )
            blocked_mcp_events = list(callback_state.events)
            blocked_mcp = any(
                row.get("provider_event_type") == "before_mcp"
                for row in blocked_mcp_events
            ) and not mcp_marker.exists()
            mcp_pre_action_verified = read_mcp or blocked_mcp
            if read_mcp and blocked_mcp:
                mcp_status = "verified:read_and_blocked_write"

            # Signed native/MCP pre/post correlation is proven above. This
            # fixture does not inject a separate endpoint-agent observation,
            # so cross-surface endpoint correlation remains unverified.

            installed = json.loads(settings_path.read_text(encoding="utf-8"))
            installed["hooks"]["beforeShellExecution"][0]["timeout"] = 4
            _write_json(settings_path, installed)
            config_tamper_detected = bool(
                installer.detect_drift(
                    settings_path,
                    expected_fingerprint=install_result.fingerprint,
                )
            )
            installer.install(settings_path)
            installer.uninstall(settings_path)
            customer_hooks_preserved = (
                json.loads(settings_path.read_text(encoding="utf-8"))
                == original_for_preservation
            )
        except subprocess.TimeoutExpired:
            diagnostics.append("cursor_acceptance_process_timeout")
        except Exception as exc:
            diagnostics.append(f"cursor_acceptance_error:{type(exc).__name__}")
        finally:
            callback.shutdown()
            signer.shutdown()
            callback.server_close()
            signer.server_close()
            for thread in threads:
                thread.join(timeout=2)
            if prior_settings is None:
                if settings_path.exists():
                    settings_path.unlink()
            else:
                settings_path.write_bytes(prior_settings)
                settings_path.chmod(0o600)

        latencies = list(callback_state.latencies_ms)
        if not file_read_pre_action_verified:
            diagnostics.append("cursor_file_read_hook_not_observed")
        if not prompt_pre_action_verified:
            diagnostics.append("cursor_prompt_hook_not_observed")
        if not post_action_correlated:
            diagnostics.append("cursor_post_action_not_correlated")
        return CursorBinaryAcceptanceReport(
            binary_available=True,
            provider_version=version,
            desktop_version=desktop_version,
            desktop_commit=desktop_commit,
            exact_version_verified=exact,
            desktop_signature_verified=desktop_signature,
            signed_allow=signed_allow,
            allowed_action_executed=allowed_action_executed,
            signed_block=signed_block,
            blocked_action_executed=blocked_action_executed,
            forged_callback_rejected=forged_callback_rejected,
            replay_rejected=replay_rejected,
            shell_pre_action_verified=shell_pre_action_verified,
            mcp_pre_action_verified=mcp_pre_action_verified,
            file_read_pre_action_verified=file_read_pre_action_verified,
            prompt_pre_action_verified=prompt_pre_action_verified,
            interactive_prompt_allowed=interactive_prompt_allowed,
            interactive_prompt_blocked=interactive_prompt_blocked,
            interactive_prompt_block_prevented_backend=interactive_prompt_block_prevented_backend,
            subagent_pre_action_verified=False,
            post_action_correlated=post_action_correlated,
            config_tamper_detected=config_tamper_detected,
            timeout_failed_closed=timeout_failed_closed,
            customer_hooks_preserved=customer_hooks_preserved,
            hook_ordering_verified=hook_ordering_verified,
            input_mutation_verified=input_mutation_verified,
            input_mutation_status=input_mutation_status,
            endpoint_correlation_verified=endpoint_correlation_verified,
            endpoint_correlation_status=endpoint_correlation_status,
            mcp_status=mcp_status,
            managed_hook_status="unverified:system_write_requires_mdm_or_admin",
            cloud_execution_verified=False,
            measured_callback_sample_count=len(latencies),
            measured_callback_p50_ms=round(statistics.median(latencies), 3) if latencies else 0.0,
            measured_callback_p95_ms=_percentile(latencies, 0.95),
            measured_callback_p99_ms=_percentile(latencies, 0.99),
            diagnostics=tuple(dict.fromkeys(diagnostics)),
        )
