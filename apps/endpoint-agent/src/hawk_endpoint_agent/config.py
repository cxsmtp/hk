"""Agent configuration and enrollment.

Config is layered: built-in defaults < config file (JSON) < environment variables.
It contains only non-secret device identity metadata. Endpoint access is obtained
from a hardware-key challenge and no bearer or refresh credential is accepted.
"""

from __future__ import annotations

import json
import ntpath
import os
import platform
import socket
import uuid
import re
import base64
import binascii
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path(
    os.getenv("HAWK_AGENT_CONFIG", "~/.config/hawk/endpoint-agent.json")
).expanduser()

# Fail-secure posture used when the backend is unreachable *and* no fresh cached
# policy is available. "warn" is the conservative default (surfaces risk without
# locking the user out); high-security fleets set "block".
FAIL_SECURE_MODES = ("allow", "warn", "block")
DEPLOYMENT_MODES = ("manual", "user_pilot", "managed_machine")
AGENT_MODES = ("monitor", "enforce")
SECURITY_PROFILES = ("bank", "development")
KEY_PROVIDERS = (
    "macos_secure_enclave",
    "windows_tpm_cng",
    "linux_tpm2",
    "development_ephemeral",
)
_PROHIBITED_SECRET_FIELDS = frozenset(
    {
        "agent_token",
        "operator_token",
        "refresh_token",
        "access_token",
        "bearer_token",
        "api_key",
        "client_secret",
        "enrollment_code",
        "password",
        "private_key",
        "policy_signing_private_key",
    }
)
_PROHIBITED_SECRET_ENV = (
    "HAWK_AGENT_TOKEN",
    "HAWK_AGENT_OPERATOR_TOKEN",
    "HAWK_AGENT_REFRESH_TOKEN",
    "HAWK_AGENT_ACCESS_TOKEN",
    "HAWK_AGENT_BEARER_TOKEN",
    "HAWK_AGENT_API_KEY",
    "HAWK_AGENT_CLIENT_SECRET",
    "HAWK_AGENT_ENROLLMENT_CODE",
    "HAWK_AGENT_PASSWORD",
    "HAWK_AGENT_PRIVATE_KEY",
    "HAWK_AGENT_POLICY_SIGNING_PRIVATE_KEY",
)


def _default_identity_helper_path() -> str:
    if platform.system().lower() == "windows":
        return r"C:\Program Files\Hawk\EndpointAgent\hawk-device-identity.exe"
    return "~/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity"


def _windows_managed_defaults() -> dict[str, str]:
    program_data = str(os.getenv("PROGRAMDATA") or r"C:\ProgramData").strip()
    program_files = str(os.getenv("ProgramFiles") or r"C:\Program Files").strip()
    if not ntpath.isabs(program_data) or "\x00" in program_data:
        program_data = r"C:\ProgramData"
    if not ntpath.isabs(program_files) or "\x00" in program_files:
        program_files = r"C:\Program Files"
    root = ntpath.join(program_data, "Hawk", "EndpointAgent")
    state = ntpath.join(root, "state")
    return {
        "identity_helper_path": ntpath.join(
            program_files, "Hawk", "EndpointAgent", "hawk-device-identity.exe"
        ),
        "policy_cache_path": ntpath.join(state, "policy-cache.json"),
        "baseline_path": ntpath.join(state, "baseline.json"),
        "evidence_queue_path": ntpath.join(state, "evidence-queue.json"),
        "mode_state_path": ntpath.join(state, "mode.json"),
        "endpoint_floor_receipt_path": ntpath.join(
            state, "endpoint-floor-receipt.json"
        ),
        "legacy_bootstrap_path": ntpath.join(root, "legacy-bootstrap"),
        "windows_state_path": ntpath.join(root, "windows-install-state.json"),
        "windows_floor_policy_path": ntpath.join(root, "endpoint-floor-policy.json"),
        "windows_floor_replay_state_path": ntpath.join(
            state, "windows-floor-replay-state.json"
        ),
        "ipc_socket_path": ntpath.join(state, "agent.sock"),
    }


@dataclass
class AgentConfig:
    api_base_url: str = "http://localhost:8000"
    tenant_id: str = ""
    endpoint_id: str = ""
    # Registered Hawk AI-system asset used when an intercepted adapter does not
    # provide a more specific asset ID. Empty means live gateway calls fail closed.
    default_ai_system_id: str = ""
    hostname: str = field(default_factory=lambda: socket.gethostname())
    os_type: str = field(default_factory=lambda: platform.system().lower())
    os_version: str = field(default_factory=lambda: platform.release())
    deployment_mode: str = "manual"
    agent_mode: str = "monitor"

    # Device-bound authentication. Bank mode requires a hardware-backed key and
    # a properly signed native helper. Development permits an ad-hoc helper only
    # when it is selected explicitly.
    security_profile: str = "bank"
    key_provider: str = "macos_secure_enclave"
    identity_helper_path: str = field(default_factory=_default_identity_helper_path)
    # SHA-256 pin for the installed native helper. Bank-mode Windows endpoints
    # require this in addition to Authenticode so a locally trusted but different
    # binary cannot be substituted after enrollment.
    identity_helper_sha256: str = ""
    device_key_tag: str = "com.hawk.endpoint-agent.device-key"
    auth_renewal_margin_seconds: int = 30

    # AI identity carried on every decision so AI-IAM can bind actions to a human
    # or non-human identity without a separate identity provider on the endpoint.
    user_id: str = ""
    user_email: str = ""

    poll_interval_seconds: float = 5.0
    policy_ttl_seconds: int = 300
    policy_cache_path: str = "~/.config/hawk/policy-cache.json"
    fail_secure_mode: str = "warn"

    # Privacy-safe endpoint state. These files contain aggregate categories,
    # bounded receipts, and posture only; never raw prompts or tool arguments.
    baseline_path: str = "~/Library/Application Support/Hawk/EndpointAgent/state/baseline.json"
    evidence_queue_path: str = "~/Library/Application Support/Hawk/EndpointAgent/state/evidence-queue.json"
    mode_state_path: str = "~/Library/Application Support/Hawk/EndpointAgent/state/mode.json"
    endpoint_floor_receipt_path: str = "~/Library/Application Support/Hawk/EndpointAgent/state/endpoint-floor-receipt.json"
    # Public Ed25519 verification keys only. Native signing keys remain in the
    # signed system extension/driver trust boundary and are never stored here.
    endpoint_floor_receipt_public_keys: dict[str, str] = field(default_factory=dict)
    # Public Ed25519 keys used to verify the short-lived endpoint policy before
    # any policy bytes cross the user/kernel trust boundary. Private signing
    # material belongs in Hawk KMS/HSM infrastructure, never on the endpoint.
    endpoint_floor_policy_public_keys: dict[str, str] = field(default_factory=dict)
    legacy_bootstrap_path: str = "~/Library/Application Support/Hawk/EndpointAgent/bootstrap"
    baseline_max_paths: int = 500
    evidence_queue_max_items: int = 500
    # Local mutations are development-only and additionally require an owned,
    # mode-0600 config. Bank deployments change posture centrally or via MDM.
    local_operator_changes_allowed: bool = False

    idle_rss_limit_mb: float = 100.0
    active_rss_limit_mb: float = 200.0
    idle_cpu_limit_percent: float = 1.0
    active_cpu_limit_percent: float = 5.0
    passive_discovery_cooldown_seconds: float = 60.0

    http_timeout_seconds: float = 8.0
    http_retry_attempts: int = 2

    # Local intercepting proxy is an additive, explicitly routed adapter. It does
    # not replace Hawk gateways or the browser companion and proves only requests
    # that actually traverse it.
    proxy_enabled: bool = False
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    windows_routing_enabled: bool = False
    windows_state_path: str = "~/.config/hawk/windows-install-state.json"
    windows_native_enforcement_enabled: bool = False
    windows_floor_policy_path: str = (
        r"C:\ProgramData\Hawk\EndpointAgent\endpoint-floor-policy.json"
    )
    windows_floor_replay_state_path: str = (
        r"C:\ProgramData\Hawk\EndpointAgent\state\windows-floor-replay-state.json"
    )
    windows_floor_device_path: str = r"\\.\HawkEndpointFloor"

    # Managed macOS native floor.  The package ships disarmed; MDM supplies
    # the signed policy and protected configuration before an explicit host
    # activation request.
    macos_native_enforcement_enabled: bool = False
    macos_managed_policy_path: str = "/Library/Application Support/Hawk/EndpointAgent/endpoint-floor-policy.bin"
    macos_managed_config_path: str = "/Library/Managed Preferences/ai.hawk.endpoint.host.plist"
    macos_host_app_path: str = "/Applications/Hawk Endpoint.app"
    macos_target_acceptance_path: str = "/Library/Application Support/Hawk/EndpointAgent/macos-target-acceptance.json"
    macos_target_acceptance_public_keys: dict[str, str] = field(default_factory=dict)

    # Deep TLS inspection of AI hosts. Requires the optional `cryptography` dep and
    # the agent CA trusted on the endpoint (MDM). Off by default; when off, the proxy
    # does host-level TLS control only. Only AI-classified hosts are ever decrypted.
    tls_intercept_enabled: bool = False
    tls_ca_dir: str = "~/.config/hawk/ca"

    # Local control socket — on-device SDKs / hooks / browser bridges call this for
    # inline decisions instead of reaching the backend directly.
    ipc_enabled: bool = True
    ipc_socket_path: str = "~/.config/hawk/agent.sock"
    ipc_max_request_bytes: int = 256 * 1024
    ipc_read_timeout_seconds: float = 2.0
    ipc_max_workers: int = 16
    # Public, non-secret pin used by local clients to authenticate responses from
    # the enrolled device key. Managed deployments protect the containing config
    # with MDM/service ownership.
    ipc_trusted_device_thumbprint: str = ""
    # Agent-owned native callback registrations. Hook callers cannot choose them.
    native_hook_runtime_configs: dict[str, str] = field(default_factory=dict)

    # Which capability modules are active on this endpoint.
    enabled_modules: list[str] = field(
        default_factory=lambda: [
            "interaction_security",
            "data_transfer",
            "shadow_ai",
            "agent_runtime",
            "notetaker",
            "desktop_native",
        ]
    )

    # Notetaker control default posture (server policy overrides this when present).
    notetaker_default_action: str = "warn"  # allow | warn | block
    notetaker_allow_eviction: bool = False

    # Enforcement capability toggles. Some actions need elevated privileges; the
    # agent will not *claim* to perform an action it is not capable of.
    allow_process_termination: bool = False
    allow_mic_revocation: bool = False   # requires MDM/TCC control on macOS
    allow_network_block: bool = False    # requires root (pf/hosts)

    def redacted(self) -> dict[str, Any]:
        return asdict(self)


def _load_file(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _normalize_ed25519_public_keys(value: object, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError(f"{label} public keys must be a bounded key map")
    normalized: dict[str, str] = {}
    for key_id, encoded_key in value.items():
        if not isinstance(key_id, str) or not re.fullmatch(
            r"[A-Za-z0-9._:-]{1,128}", key_id
        ):
            raise ValueError(f"{label} public keys contain an invalid key id")
        if not isinstance(encoded_key, str) or len(encoded_key) > 128:
            raise ValueError(f"{label} public keys contain an invalid key")
        try:
            raw_key = base64.b64decode(encoded_key, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"{label} public keys contain invalid base64") from exc
        if len(raw_key) != 32:
            raise ValueError(f"{label} public keys must contain raw Ed25519 keys")
        normalized[key_id] = encoded_key
    return normalized


def load_config(path: Path | None = None) -> AgentConfig:
    path = path or DEFAULT_CONFIG_PATH
    fixed = Path("/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json")
    if path == fixed:
        from .macos_native import MacOSNativeFloorManager
        file_data = json.loads(MacOSNativeFloorManager._read_protected_file(fixed, 262144))
        if not isinstance(file_data, dict):
            raise ValueError("bank native agent-config must be an object")
    else:
        file_data = _load_file(path)
    if (str(file_data.get("security_profile", "bank")).casefold() == "bank" and
            file_data.get("macos_native_enforcement_enabled")):
        if path != fixed:
            raise ValueError("bank native requires the fixed protected agent-config path")
        if any(name in os.environ for name in (
            "HAWK_AGENT_TENANT_ID", "HAWK_AGENT_ENDPOINT_ID", "HAWK_AGENT_DEPLOYMENT_MODE",
            "HAWK_AGENT_SECURITY_PROFILE", "HAWK_AGENT_KEY_PROVIDER", "HAWK_AGENT_IDENTITY_HELPER",
        )):
            raise ValueError("bank native agent-config identity overrides are forbidden")
        if (file_data.get("security_profile") != "bank" or file_data.get("deployment_mode") != "managed_machine" or
                file_data.get("macos_native_enforcement_enabled") is not True):
            raise ValueError("bank native agent-config identity is invalid")

    forbidden_file_fields = sorted(
        str(key)
        for key, value in file_data.items()
        if str(key).casefold() in _PROHIBITED_SECRET_FIELDS and value
    )
    if forbidden_file_fields:
        raise ValueError(
            "static endpoint credentials are not supported; re-enroll this endpoint"
        )
    if any(os.getenv(name) for name in _PROHIBITED_SECRET_ENV):
        raise ValueError(
            "static endpoint credential environment variables are not supported"
        )
    if (
        str(file_data.get("security_profile", "bank")).casefold() == "bank"
        and str(file_data.get("deployment_mode", "manual")).casefold()
        == "managed_machine"
    ):
        unknown_fields = sorted(
            str(key)
            for key in file_data
            if key not in AgentConfig.__dataclass_fields__
        )
        if unknown_fields:
            raise ValueError(
                "unknown managed configuration fields are not permitted"
            )

    cfg = AgentConfig()
    for key, value in file_data.items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)

    if cfg.os_type == "windows":
        for key, value in _windows_managed_defaults().items():
            if key not in file_data:
                setattr(cfg, key, value)

    # Environment overrides (HAWK_AGENT_*).
    env_map = {
        "HAWK_AGENT_API_URL": "api_base_url",
        "HAWK_AGENT_TENANT_ID": "tenant_id",
        "HAWK_AGENT_ENDPOINT_ID": "endpoint_id",
        "HAWK_AGENT_AI_SYSTEM_ID": "default_ai_system_id",
        "HAWK_AGENT_FAIL_SECURE": "fail_secure_mode",
        "HAWK_AGENT_USER_ID": "user_id",
        "HAWK_AGENT_USER_EMAIL": "user_email",
        "HAWK_AGENT_DEPLOYMENT_MODE": "deployment_mode",
        "HAWK_AGENT_MODE": "agent_mode",
        "HAWK_AGENT_SECURITY_PROFILE": "security_profile",
        "HAWK_AGENT_KEY_PROVIDER": "key_provider",
        "HAWK_AGENT_IDENTITY_HELPER": "identity_helper_path",
    }
    macos_managed_env = {
        "HAWK_AGENT_MACOS_NATIVE_ENFORCEMENT": "macos_native_enforcement_enabled",
        "HAWK_AGENT_MACOS_POLICY_PATH": "macos_managed_policy_path",
        "HAWK_AGENT_MACOS_CONFIG_PATH": "macos_managed_config_path",
        "HAWK_AGENT_MACOS_HOST_APP": "macos_host_app_path",
        "HAWK_AGENT_MACOS_TARGET_ACCEPTANCE_PATH": "macos_target_acceptance_path",
    }
    if (
        str(file_data.get("security_profile", "bank")).casefold() == "bank"
        and any(os.getenv(name) for name in macos_managed_env)
    ):
        raise ValueError("bank managed macOS configuration rejects environment overrides")
    for env_key, attr in env_map.items():
        if os.getenv(env_key):
            setattr(cfg, attr, os.getenv(env_key))
    for env_key, attr in macos_managed_env.items():
        if os.getenv(env_key):
            value: object = os.getenv(env_key)
            if attr == "macos_native_enforcement_enabled":
                value = str(value).strip().casefold() in {"1", "true", "yes", "on"}
            setattr(cfg, attr, value)

    if cfg.fail_secure_mode not in FAIL_SECURE_MODES:
        cfg.fail_secure_mode = "warn"
    if cfg.deployment_mode not in DEPLOYMENT_MODES:
        cfg.deployment_mode = "manual"
    if cfg.agent_mode not in AGENT_MODES:
        cfg.agent_mode = "monitor"
    if cfg.security_profile not in SECURITY_PROFILES:
        raise ValueError("security_profile must be bank or development")
    if cfg.key_provider not in KEY_PROVIDERS:
        raise ValueError("unsupported endpoint key provider")
    cfg.endpoint_floor_receipt_public_keys = _normalize_ed25519_public_keys(
        cfg.endpoint_floor_receipt_public_keys,
        label="endpoint floor receipt",
    )
    cfg.endpoint_floor_policy_public_keys = _normalize_ed25519_public_keys(
        cfg.endpoint_floor_policy_public_keys,
        label="endpoint floor policy",
    )
    cfg.macos_target_acceptance_public_keys = _normalize_ed25519_public_keys(
        cfg.macos_target_acceptance_public_keys,
        label="macOS target acceptance",
    )
    if cfg.security_profile == "bank" and cfg.key_provider == "development_ephemeral":
        raise ValueError("bank security profile requires a hardware-backed device key")
    if (
        cfg.security_profile == "bank"
        and cfg.os_type == "windows"
        and cfg.key_provider != "windows_tpm_cng"
    ):
        raise ValueError(
            "bank Windows endpoints require the Windows TPM/CNG key provider"
        )
    if cfg.security_profile == "bank" and cfg.os_type == "windows":
        expected_helper = _windows_managed_defaults()["identity_helper_path"]
        if not ntpath.normcase(ntpath.normpath(str(cfg.identity_helper_path))) == ntpath.normcase(
            ntpath.normpath(expected_helper)
        ):
            raise ValueError("bank Windows endpoints require the fixed managed identity helper")
        if not re.fullmatch(r"[0-9a-f]{64}", str(cfg.identity_helper_sha256 or "")):
            raise ValueError("bank Windows endpoints require a pinned identity helper digest")
        if os.getenv("HAWK_AGENT_IDENTITY_HELPER"):
            raise ValueError("bank Windows endpoints reject identity helper environment overrides")
    if (
        cfg.security_profile == "bank"
        and cfg.os_type == "windows"
        and cfg.windows_native_enforcement_enabled
        and not cfg.endpoint_floor_policy_public_keys
    ):
        raise ValueError(
            "bank Windows native enforcement requires a policy verification key"
        )
    if cfg.security_profile == "bank" and not cfg.api_base_url.lower().startswith("https://"):
        raise ValueError("bank security profile requires an HTTPS Hawk API URL")
    if cfg.security_profile == "bank" and cfg.tls_intercept_enabled:
        raise ValueError(
            "bank security profile rejects file-backed TLS inspection keys"
        )
    if (
        cfg.security_profile == "bank"
        and cfg.os_type in {"darwin", "macos"}
        and cfg.macos_native_enforcement_enabled
    ):
        if not cfg.endpoint_floor_policy_public_keys:
            raise ValueError("bank managed macOS requires endpoint-floor policy trust")
        if not cfg.macos_target_acceptance_public_keys:
            raise ValueError("bank managed macOS requires target acceptance verification keys")
        for label, value in (
            ("policy", cfg.macos_managed_policy_path),
            ("managed config", cfg.macos_managed_config_path),
            ("host app", cfg.macos_host_app_path),
            ("target acceptance", cfg.macos_target_acceptance_path),
        ):
            rendered = str(value or "")
            if not rendered.startswith("/") or "\x00" in rendered:
                raise ValueError(f"bank managed macOS {label} path must be absolute")
            expected_path = {
                "policy": "/Library/Application Support/Hawk/EndpointAgent/endpoint-floor-policy.bin",
                "managed config": "/Library/Managed Preferences/ai.hawk.endpoint.host.plist",
                "host app": "/Applications/Hawk Endpoint.app",
                "target acceptance": "/Library/Application Support/Hawk/EndpointAgent/macos-target-acceptance.json",
            }[label]
            if rendered != expected_path:
                raise ValueError(f"bank managed macOS {label} path must be fixed")
            path = Path(rendered)
            if path.is_symlink():
                raise ValueError(f"bank managed macOS {label} path cannot be a symlink")
            candidate = path if path.exists() else path.parent
            try:
                mode = candidate.stat().st_mode
                owner = candidate.stat().st_uid
            except OSError as exc:
                raise ValueError(f"bank managed macOS {label} path is inaccessible") from exc
            if owner != 0 or mode & 0o022:
                raise ValueError(f"bank managed macOS {label} path is not protected")
    if cfg.ipc_trusted_device_thumbprint and not re.fullmatch(
        r"[0-9a-f]{64}", cfg.ipc_trusted_device_thumbprint
    ):
        raise ValueError("invalid endpoint IPC device-key thumbprint")
    cfg.auth_renewal_margin_seconds = max(
        5, min(int(cfg.auth_renewal_margin_seconds), 120)
    )
    if not cfg.endpoint_id:
        cfg.endpoint_id = _stable_endpoint_id(cfg.hostname)
    return cfg


def _stable_endpoint_id(hostname: str) -> str:
    """Deterministic per-host id (stable across restarts, no PII beyond hostname)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"hawk-endpoint:{hostname}"))
