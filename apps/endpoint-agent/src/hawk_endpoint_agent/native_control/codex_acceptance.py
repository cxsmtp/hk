from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from threading import Thread
from time import perf_counter
from typing import ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.device_key import public_key_thumbprint

from .installer import NativeHookInstaller


_ADAPTER_VERSION = "1.0.0"
_TENANT = "codex-acceptance-tenant"
_INTEGRATION = "codex-native-acceptance"
_CREDENTIAL = "codex-acceptance-credential"
_TESTED_EVENTS = ("session_start", "before_model")


@dataclass(frozen=True, slots=True)
class CodexAcceptanceReport:
    binary: str
    binary_sha256: str
    expected_binary_sha256: str
    version: str
    expected_version: str
    version_command_succeeded: bool
    adapter_version: str
    platform: str
    evidence_timestamp: str
    tested_events: tuple[str, ...]
    hardware_key_provider: str
    key_thumbprint: str
    hardware_backed_key: bool
    hook_installation_observed: bool
    allow_callback_observed: bool
    allow_signature_verified: bool
    prompt_hook_observed: bool
    block_signature_verified: bool
    prompt_blocked_before_model: bool
    raw_prompt_exported: bool
    isolated_hook_trust_bypass: bool
    model_transport_isolated: bool
    model_request_observed: bool
    measured_callback_p95_ms: float
    total_acceptance_runtime_ms: float
    return_code: int
    diagnostic: str

    @property
    def passed(self) -> bool:
        return (
            self.version == self.expected_version
            and self.binary_sha256 == self.expected_binary_sha256
            and self.version_command_succeeded
            and self.hardware_key_provider == "macos_secure_enclave"
            and self.hardware_backed_key
            and self.hook_installation_observed
            and self.allow_callback_observed
            and self.allow_signature_verified
            and self.prompt_hook_observed
            and self.block_signature_verified
            and self.prompt_blocked_before_model
            and not self.raw_prompt_exported
            and self.model_transport_isolated
            and not self.model_request_observed
            and set(self.tested_events) == set(_TESTED_EVENTS)
        )

    def as_evidence_artifact(self) -> dict[str, object]:
        return {
            "schema_version": "hawk.codex.acceptance-result/1.0",
            "classification": "real_binary_isolated_hardware_signed_callback_acceptance",
            "provider": "openai",
            "product": "codex",
            "provider_version": self.version,
            "adapter_version": self.adapter_version,
            "binary_sha256": self.binary_sha256,
            "evidence_timestamp": self.evidence_timestamp,
            "platform": self.platform,
            "scope": {
                "provider_adapter_contract_verified": self.passed,
                "tenant_deployment_accepted": False,
                "live_backend_signature_verified": False,
                "synthetic_fixture": False,
                "limitations": [
                    "The callback verifier is isolated and is not the tenant Hawk API.",
                    "Only SessionStart allow progression and UserPromptSubmit block-before-model are verified.",
                    "Tool, approval, post-execution, hosted, cloud, and remote runtime paths remain unverified.",
                    "The isolated run bypasses Codex workspace hook trust; tenant configuration integrity remains mandatory.",
                ],
            },
            "result": {
                "passed": self.passed,
                "actual_binary_executed": True,
                "binary_hash_verified": self.binary_sha256 == self.expected_binary_sha256,
                "exact_version_verified": self.version == self.expected_version,
                "version_command_succeeded": self.version_command_succeeded,
                "hardware_backed_key": self.hardware_backed_key,
                "hardware_key_provider": self.hardware_key_provider,
                "key_thumbprint": self.key_thumbprint,
                "signature_algorithm": "ES256",
                "hook_installation_observed": self.hook_installation_observed,
                "allow_callback_observed": self.allow_callback_observed,
                "allow_signature_verified": self.allow_signature_verified,
                "prompt_hook_observed": self.prompt_hook_observed,
                "block_signature_verified": self.block_signature_verified,
                "prompt_blocked_before_model": self.prompt_blocked_before_model,
                "raw_prompt_exported": self.raw_prompt_exported,
                "isolated_hook_trust_bypass": self.isolated_hook_trust_bypass,
                "model_transport_isolated": self.model_transport_isolated,
                "model_request_observed": self.model_request_observed,
                "tested_events": list(self.tested_events),
                "measured_callback_p95_ms": self.measured_callback_p95_ms,
                "total_acceptance_runtime_ms": self.total_acceptance_runtime_ms,
                "return_code": self.return_code,
                "diagnostic": self.diagnostic,
            },
        }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _decode_callback(body: dict[str, object]) -> tuple[dict[str, object], bytes]:
    try:
        envelope = json.loads(
            base64.b64decode(str(body["envelope_base64"]), validate=True).decode("utf-8")
        )
        payload = base64.b64decode(str(body["payload_base64"]), validate=True)
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, b""
    return (envelope if isinstance(envelope, dict) else {}, payload)


def _verify_callback(
    body: dict[str, object],
    *,
    public_key_pem: str,
    expected_version: str,
) -> tuple[str, bool, float]:
    envelope, payload = _decode_callback(body)
    signature = str(envelope.pop("signature", ""))
    event = str(envelope.get("provider_event_type") or "")
    try:
        issued_at = datetime.fromisoformat(str(envelope.get("issued_at") or ""))
        if issued_at.tzinfo is None:
            raise ValueError("issued_at_timezone_required")
        latency_ms = max(
            0.0,
            min(300_000.0, (datetime.now(timezone.utc) - issued_at).total_seconds() * 1_000),
        )
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("public_key_invalid")
        key.verify(_b64url_decode(signature), _canonical(envelope), ec.ECDSA(hashes.SHA256()))
        valid = bool(
            event in _TESTED_EVENTS
            and envelope.get("integration_instance_id") == _INTEGRATION
            and envelope.get("tenant_binding") == _TENANT
            and envelope.get("provider") == "openai"
            and envelope.get("product") == "codex"
            and envelope.get("provider_version") == expected_version
            and envelope.get("adapter_version") == _ADAPTER_VERSION
            and envelope.get("credential_id") == _CREDENTIAL
            and envelope.get("credential_epoch") == 1
            and envelope.get("signature_algorithm") == "ES256"
            and envelope.get("payload_hash") == hashlib.sha256(payload).hexdigest()
        )
    except (InvalidSignature, TypeError, ValueError, UnicodeError):
        return event, False, 0.0
    return event, valid, round(latency_ms, 3)


class _DecisionHandler(BaseHTTPRequestHandler):
    requests: ClassVar[list[dict[str, object]]] = []
    observations: ClassVar[list[dict[str, object]]] = []
    unexpected_requests: ClassVar[list[dict[str, object]]] = []
    public_key_pem: ClassVar[str] = ""
    expected_version: ClassVar[str] = ""

    def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
        length = min(131_072, max(0, int(self.headers.get("Content-Length", "0"))))
        body_bytes = self.rfile.read(length)
        if self.path != f"/native-controls/callbacks/{_INTEGRATION}":
            self.unexpected_requests.append(
                {
                    "method": "POST",
                    "path": self.path[:512],
                    "content_type": str(self.headers.get("Content-Type") or "")[:128],
                    "body_sha256": hashlib.sha256(body_bytes).hexdigest(),
                }
            )
            self.send_error(503, "acceptance model transport is intentionally unavailable")
            return
        try:
            body = json.loads(body_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        self.requests.append(body)
        event, signature_verified, latency_ms = _verify_callback(
            body,
            public_key_pem=self.public_key_pem,
            expected_version=self.expected_version,
        )
        decision = "allow" if event == "session_start" and signature_verified else "block"
        self.observations.append(
            {
                "event": event,
                "signature_verified": signature_verified,
                "decision": decision,
                "latency_ms": latency_ms,
            }
        )
        encoded = json.dumps(
            {
                "decision": decision,
                "reason": (
                    "HAWK_CODEX_ACCEPTANCE_ALLOW"
                    if decision == "allow"
                    else "HAWK_CODEX_ACCEPTANCE_BLOCK"
                ),
                "enforced": True,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self.unexpected_requests.append({"method": "GET", "path": self.path[:512]})
        self.send_error(503, "acceptance model transport is intentionally unavailable")

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _prompt_was_blocked_by_codex(output: str) -> bool:
    """Recognize Codex's provider-native terminal state for a blocked prompt."""

    return "hook: UserPromptSubmit Blocked" in str(output or "")


def _platform_name() -> str:
    system = platform.system().strip().lower()
    machine = platform.machine().strip().lower()
    return f"{'macos' if system == 'darwin' else system}-{machine}"


def _identity_status(identity_helper: Path, key_tag: str) -> tuple[str, str, bool]:
    candidate = identity_helper.expanduser()
    if candidate.is_symlink():
        raise ValueError("codex_acceptance_identity_helper_invalid")
    helper = candidate.resolve(strict=True)
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise ValueError("codex_acceptance_identity_helper_invalid")
    result = subprocess.run(
        [str(helper), "status", key_tag],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    try:
        status = json.loads(result.stdout) if result.returncode == 0 else {}
    except json.JSONDecodeError:
        status = {}
    public_key = str(status.get("public_key_pem") or "") if isinstance(status, dict) else ""
    if (
        not isinstance(status, dict)
        or status.get("exists") is not True
        or status.get("hardware_backed") is not True
        or status.get("sealed_reference") is not True
        or status.get("provider") != "macos_secure_enclave"
        or "BEGIN PUBLIC KEY" not in public_key
    ):
        raise ValueError("codex_acceptance_hardware_key_unavailable")
    return public_key, public_key_thumbprint(public_key), True


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)], 3)


def run_codex_binary_acceptance(
    binary: Path,
    *,
    repository_root: Path,
    python_binary: Path,
    expected_version: str,
    expected_binary_sha256: str,
    identity_helper: Path,
    key_tag: str,
) -> CodexAcceptanceReport:
    """Exercise real Codex callbacks without creating tenant acceptance.

    The installed binary advances through an authenticated SessionStart allow
    callback and then terminates at an authenticated UserPromptSubmit block,
    before any model request. The isolated verifier checks the existing
    hardware-backed key's ES256 signatures. The resulting report is an adapter
    contract artifact only; the tenant API must still authenticate its own live
    callback and an administrator must invoke the existing acceptance route.
    """

    expected = str(expected_version or "").strip()
    expected_digest = str(expected_binary_sha256 or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", expected):
        raise ValueError("codex_acceptance_expected_version_invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ValueError("codex_acceptance_expected_binary_sha256_invalid")
    if not str(key_tag or "").strip():
        raise ValueError("codex_acceptance_key_tag_invalid")
    resolved_binary = binary.expanduser().resolve(strict=True)
    binary_sha256 = hashlib.sha256(resolved_binary.read_bytes()).hexdigest()
    if binary_sha256 != expected_digest:
        raise ValueError("codex_acceptance_binary_sha256_mismatch")
    version_result = subprocess.run(
        [str(resolved_binary), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    match = re.search(r"(\d+\.\d+\.\d+)", version_result.stdout)
    version = match.group(1) if match else "unknown"
    if version_result.returncode != 0 or version != expected:
        raise ValueError("codex_acceptance_version_mismatch")
    public_key, key_thumbprint, hardware_backed = _identity_status(identity_helper, key_tag)
    raw_prompt = "HAWK_CODEX_RAW_PROMPT_MUST_NOT_LEAVE_ENDPOINT"
    _DecisionHandler.requests = []
    _DecisionHandler.observations = []
    _DecisionHandler.unexpected_requests = []
    _DecisionHandler.public_key_pem = public_key
    _DecisionHandler.expected_version = expected
    server = ThreadingHTTPServer(("127.0.0.1", 0), _DecisionHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    started = perf_counter()
    hook_installation_observed = False
    try:
        with tempfile.TemporaryDirectory(prefix="hawk-codex-acceptance-") as temporary:
            root = Path(temporary)
            wrapper = root / "hawk-native-hook"
            endpoint_source = repository_root / "apps" / "endpoint-agent" / "src"
            wrapper.write_text(
                "#!/bin/sh\n"
                f"export PYTHONPATH={json.dumps(str(endpoint_source))}\n"
                f"exec {json.dumps(str(python_binary))} -m hawk_endpoint_agent.native_control.hook \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            config = root / "runtime.json"
            config.write_text(
                json.dumps(
                    {
                        "api_url": f"http://127.0.0.1:{server.server_port}",
                        "tenant_id": _TENANT,
                        "integration_id": _INTEGRATION,
                        "credential_id": _CREDENTIAL,
                        "credential_epoch": 1,
                        "provider": "openai",
                        "product": "codex",
                        "provider_version": version,
                        "adapter_version": _ADAPTER_VERSION,
                        "environment": "acceptance",
                        "key_provider": "macos_secure_enclave",
                        "security_profile": "development",
                        "secure_enclave_helper_path": str(identity_helper.expanduser().resolve()),
                        "secure_enclave_key_tag": key_tag,
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            config.chmod(0o600)
            isolated_home = root / "home"
            codex_home = isolated_home / ".codex"
            codex_home.mkdir(parents=True, mode=0o700)
            (codex_home / "config.toml").write_text(
                "model = \"hawk-acceptance-no-model\"\n"
                "model_provider = \"hawk_acceptance_sink\"\n"
                "check_for_update_on_startup = false\n"
                "[analytics]\n"
                "enabled = false\n"
                "[feedback]\n"
                "enabled = false\n"
                "[model_providers.hawk_acceptance_sink]\n"
                "name = \"Hawk acceptance local sink\"\n"
                f"base_url = \"http://127.0.0.1:{server.server_port}/model-sink\"\n"
                "env_key = \"HAWK_CODEX_ACCEPTANCE_DUMMY_TOKEN\"\n"
                "wire_api = \"responses\"\n"
                "requires_openai_auth = false\n",
                encoding="utf-8",
            )
            hooks = codex_home / "hooks.json"
            installed = NativeHookInstaller(
                provider="codex",
                helper_path=wrapper,
                runtime_config_path=config,
            ).install(hooks)
            hook_installation_observed = bool(
                hooks.is_file()
                and {"SessionStart", "UserPromptSubmit"} <= set(installed.events)
                and wrapper.is_file()
                and config.is_file()
            )
            environment = dict(os.environ)
            environment["HOME"] = str(isolated_home)
            environment["CODEX_HOME"] = str(codex_home)
            environment["HAWK_NATIVE_ACCEPTANCE_DEBUG"] = "1"
            environment["HAWK_CODEX_ACCEPTANCE_DUMMY_TOKEN"] = "not-a-real-credential"
            result = subprocess.run(
                [
                    str(resolved_binary),
                    "exec",
                    "--dangerously-bypass-hook-trust",
                    "--enable",
                    "hooks",
                    "--skip-git-repo-check",
                    "--ephemeral",
                    "-C",
                    str(root),
                    raw_prompt,
                ],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env=environment,
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    elapsed_ms = (perf_counter() - started) * 1_000
    observations = list(_DecisionHandler.observations)
    allow = [row for row in observations if row["event"] == "session_start"]
    prompts = [row for row in observations if row["event"] == "before_model"]
    combined_output = f"{result.stdout}\n{result.stderr}"
    blocked = _prompt_was_blocked_by_codex(combined_output)
    model_request_observed = bool(_DecisionHandler.unexpected_requests)
    exported = raw_prompt in json.dumps(_DecisionHandler.requests, sort_keys=True)
    passed_observations = bool(
        allow
        and prompts
        and any(row["signature_verified"] is True and row["decision"] == "allow" for row in allow)
        and any(row["signature_verified"] is True and row["decision"] == "block" for row in prompts)
    )
    diagnostic = "passed" if passed_observations and blocked else combined_output[-500:].replace("\n", " ")
    return CodexAcceptanceReport(
        binary=str(resolved_binary),
        binary_sha256=binary_sha256,
        expected_binary_sha256=expected_digest,
        version=version,
        expected_version=expected,
        version_command_succeeded=True,
        adapter_version=_ADAPTER_VERSION,
        platform=_platform_name(),
        evidence_timestamp=datetime.now(timezone.utc).isoformat(),
        tested_events=tuple(
            event for event in _TESTED_EVENTS if any(row["event"] == event for row in observations)
        ),
        hardware_key_provider="macos_secure_enclave",
        key_thumbprint=key_thumbprint,
        hardware_backed_key=hardware_backed,
        hook_installation_observed=hook_installation_observed,
        allow_callback_observed=bool(allow),
        allow_signature_verified=any(row["signature_verified"] is True for row in allow),
        prompt_hook_observed=bool(prompts),
        block_signature_verified=any(row["signature_verified"] is True for row in prompts),
        prompt_blocked_before_model=blocked,
        raw_prompt_exported=exported,
        isolated_hook_trust_bypass=True,
        model_transport_isolated=True,
        model_request_observed=model_request_observed,
        measured_callback_p95_ms=_p95(
            [float(row["latency_ms"]) for row in observations if row["signature_verified"] is True]
        ),
        total_acceptance_runtime_ms=round(elapsed_ms, 3),
        return_code=result.returncode,
        diagnostic=diagnostic[:500],
    )
