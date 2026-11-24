"""One-shot enrollment / installer.

Provisions an endpoint in a single step:
  1. enrolls a hardware-bound device identity using a one-time authorization,
  2. writes the non-secret agent config (0600),
  2. generates + exports the CA for MDM trust-store distribution (if TLS enabled),
  3. writes a bridge launcher + native-messaging manifests for browsers,
  4. installs a launch agent (macOS) / systemd user unit (linux) to run the agent.

Every step reports ``ok`` / ``skipped`` / ``failed`` with the detail and the exact
follow-up command where a privileged action is required (CA trust, service load) —
the installer never claims it performed a step it could not.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import ssl
import sys
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .auth.device_key import DeviceKeyError, UnsupportedKeyProviderError
from .auth.session import (
    EndpointAuthError, EndpointAuthHttpError, EndpointAuthSession,
    EndpointAuthUnavailable, EnrollmentBundle,
)
from .bridge.manifest import HOST_NAME, chrome_manifest, firefox_manifest, install_location
from .config import DEFAULT_CONFIG_PATH, AgentConfig, _stable_endpoint_id, load_config
from .tls.certs import CertificateAuthority, cryptography_available

LAUNCH_AGENT_LABEL = "com.hawk.endpoint-agent"

_PERSISTED_FIELDS = (
    "api_base_url", "tenant_id", "endpoint_id", "default_ai_system_id", "user_id", "user_email",
    "deployment_mode", "agent_mode", "security_profile", "key_provider",
    "identity_helper_path", "identity_helper_sha256", "device_key_tag", "auth_renewal_margin_seconds",
    "local_operator_changes_allowed",
    "fail_secure_mode", "policy_ttl_seconds", "policy_cache_path",
    "poll_interval_seconds", "passive_discovery_cooldown_seconds",
    "baseline_path", "evidence_queue_path", "mode_state_path",
    "endpoint_floor_receipt_path", "endpoint_floor_receipt_public_keys",
    "endpoint_floor_policy_public_keys",
    "baseline_max_paths", "evidence_queue_max_items",
    "idle_rss_limit_mb", "active_rss_limit_mb",
    "idle_cpu_limit_percent", "active_cpu_limit_percent",
    "http_timeout_seconds", "http_retry_attempts",
    "proxy_enabled", "proxy_host", "proxy_port", "tls_intercept_enabled", "tls_ca_dir",
    "windows_routing_enabled", "windows_state_path",
    "windows_native_enforcement_enabled", "windows_floor_policy_path",
    "windows_floor_replay_state_path",
    "windows_floor_device_path",
    "ipc_enabled", "ipc_socket_path", "ipc_max_request_bytes",
    "ipc_read_timeout_seconds", "ipc_max_workers",
    "ipc_trusted_device_thumbprint", "enabled_modules",
    "notetaker_default_action", "notetaker_allow_eviction",
    "allow_process_termination", "allow_mic_revocation", "allow_network_block",
)


@dataclass
class EnrollmentReport:
    steps: list[dict[str, Any]] = field(default_factory=list)

    def add(self, step: str, status: str, detail: str = "", **extra: Any) -> None:
        self.steps.append({"step": step, "status": status, "detail": detail, **extra})

    def as_dict(self) -> dict[str, Any]:
        return {"ok": all(s["status"] in {"ok", "skipped"} for s in self.steps), "steps": self.steps}


# Exact, static messages only: API validation bodies may echo enrollment codes,
# and helper/transport exceptions may contain signed material or credential URLs.
_SAFE_ENROLLMENT_ERRORS = {
    "Endpoint enrollment authorization is invalid or expired": "authorization_invalid_or_expired",
    "Endpoint already has an active identity": "identity_already_active",
    "Endpoint identity conflicts with an existing device": "identity_conflict",
    "Unsupported endpoint key provider": "unsupported_key_provider",
    "Endpoint public key is too large": "invalid_public_key",
    "Invalid endpoint public key": "invalid_public_key",
    "Endpoint key must be P-256": "invalid_public_key",
    "Endpoint identity verification failed": "identity_verification_failed",
    "helper is unsigned or ad-hoc signed": "identity_helper_untrusted",
    "Secure Enclave helper is not installed": "identity_helper_missing",
    "Secure Enclave helper could not run": "identity_helper_unavailable",
    "Secure Enclave operation failed": "device_key_operation_failed",
    "Secure Enclave operation was not successful": "device_key_operation_failed",
    "Secure Enclave helper returned invalid output": "identity_helper_invalid_response",
    "Secure Enclave helper returned invalid signature": "identity_helper_invalid_signature",
}


def _report_enrollment_failure(
    report: EnrollmentReport, exc: Exception, stage: str,
) -> None:
    """Retain actionable diagnostics without rendering arbitrary exception text."""
    reason = "unexpected_enrollment_error"
    detail = "device enrollment failed; unexpected local error"
    extra: dict[str, Any] = {"failure_stage": stage}
    if stage == "persist_config":
        reason = "config_persistence_failed"
        detail = "server enrollment succeeded but local identity configuration could not be saved"
    elif stage == "validate_response":
        reason = "invalid_enrollment_response"
        detail = "enrollment response did not contain a valid key thumbprint; check server identity before retrying"
    elif isinstance(exc, EndpointAuthHttpError):
        extra["http_status"] = exc.status
        reason = "http_error"
        detail = f"device enrollment failed: HTTP {exc.status}"
        body_detail = exc.body.get("detail") if isinstance(exc.body, dict) else None
        if isinstance(body_detail, str) and body_detail in _SAFE_ENROLLMENT_ERRORS:
            reason = _SAFE_ENROLLMENT_ERRORS[body_detail]
            detail += f"; {body_detail}"
        elif exc.status == 422 and isinstance(body_detail, list):
            reason = "request_validation_failed"
            detail += "; enrollment request failed schema validation"
    elif isinstance(exc, EndpointAuthUnavailable):
        reason = "service_unavailable"
        detail = "enrollment service is unreachable; check API address and connectivity"
        cause = exc.__cause__
        if isinstance(cause, urllib.error.URLError):
            cause = cause.reason
        if isinstance(cause, ssl.SSLCertVerificationError):
            reason = "tls_certificate_verification_failed"
            detail = "enrollment TLS certificate verification failed; check the configured CA trust"
        elif isinstance(cause, TimeoutError):
            reason = "connection_timeout"
            detail = "enrollment request timed out; check server identity before retrying"
    elif isinstance(exc, DeviceKeyError):
        reason = "unsupported_key_provider" if isinstance(exc, UnsupportedKeyProviderError) else "device_key_error"
        detail = "device identity helper or signing operation failed"
        if str(exc) in _SAFE_ENROLLMENT_ERRORS:
            reason = _SAFE_ENROLLMENT_ERRORS[str(exc)]
            detail = str(exc)
    elif isinstance(exc, (EndpointAuthError, json.JSONDecodeError, UnicodeDecodeError)):
        reason = "invalid_enrollment_response"
        detail = "enrollment service returned an invalid response"
    report.add("device_identity", "failed", detail, reason=reason, **extra)


def _write_secure(path: Path, data: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temp_path, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def _persisted_config(cfg: AgentConfig) -> dict[str, Any]:
    return {name: getattr(cfg, name) for name in _PERSISTED_FIELDS}


def enroll_existing_config(
    *,
    config_path: str | Path,
    enrollment_bundle: EnrollmentBundle,
    auth_session: Any | None = None,
) -> EnrollmentReport:
    """Enroll an already validated managed config without replacing its policy pins."""
    report = EnrollmentReport()
    path = Path(config_path).expanduser()
    try:
        cfg = load_config(path)
    except Exception:  # noqa: BLE001 - config may contain customer identifiers
        report.add("config", "failed", "managed endpoint configuration is invalid")
        return report
    if not cfg.default_ai_system_id.strip():
        report.add("device_identity", "failed", "registered default AI system is required")
        return report
    stage = "initialize_session"
    try:
        session = auth_session or EndpointAuthSession(config=cfg)
        stage = "enrollment_exchange"
        response = session.enroll(enrollment_bundle)
        stage = "validate_response"
        key_thumbprint = str(response.get("key_thumbprint") or "").strip().lower()
        if len(key_thumbprint) != 64:
            raise ValueError("invalid enrolled key thumbprint")
        cfg.ipc_trusted_device_thumbprint = key_thumbprint
        stage = "persist_config"
        _write_secure(
            path,
            json.dumps(_persisted_config(cfg), indent=2, sort_keys=True),
        )
    except Exception as exc:  # noqa: BLE001 - diagnostics must never expose enrollment material
        _report_enrollment_failure(report, exc, stage)
        return report
    report.add("config", "ok", "preserved validated managed endpoint configuration")
    report.add(
        "device_identity",
        "ok",
        "hardware-bound endpoint identity enrolled",
        endpoint_id=cfg.endpoint_id,
        identity_id=response.get("identity_id"),
        key_provider=response.get("key_provider") or cfg.key_provider,
        local_broker_authenticated=True,
    )
    return report


def _ca_trust_hint(os_type: str, ca_path: Path) -> str:
    if os_type == "darwin":
        return (f"sudo security add-trusted-cert -d -r trustRoot "
                f"-k /Library/Keychains/System.keychain '{ca_path}'  (or push via MDM profile)")
    if os_type == "linux":
        return (f"sudo cp '{ca_path}' /usr/local/share/ca-certificates/hawk-endpoint-ca.crt "
                f"&& sudo update-ca-certificates")
    return "distribute the CA certificate to the endpoint trust store via MDM"


def _write_bridge_wrapper(config_dir: Path, python_exe: str) -> Path:
    wrapper = config_dir / "hawk-bridge"
    _write_secure(wrapper, f'#!/bin/sh\nexec "{python_exe}" -m hawk_endpoint_agent.bridge "$@"\n', mode=0o755)
    return wrapper


def _render_launch_agent(
    python_exe: str,
    config_path: Path,
    log_dir: Path,
    python_path: str = "",
) -> str:
    python_path_entry = (
        f'<key>PYTHONPATH</key><string>{python_path}</string>' if python_path else ""
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0"><dict>\n'
        f'  <key>Label</key><string>{LAUNCH_AGENT_LABEL}</string>\n'
        '  <key>ProgramArguments</key>\n'
        f'  <array><string>{python_exe}</string><string>-m</string>'
        '<string>hawk_endpoint_agent</string></array>\n'
        '  <key>EnvironmentVariables</key>\n'
        f'  <dict><key>HAWK_AGENT_CONFIG</key><string>{config_path}</string>{python_path_entry}</dict>\n'
        '  <key>ProcessType</key><string>Background</string>\n'
        '  <key>ThrottleInterval</key><integer>10</integer>\n'
        f'  <key>StandardOutPath</key><string>{log_dir / "agent.out.log"}</string>\n'
        f'  <key>StandardErrorPath</key><string>{log_dir / "agent.err.log"}</string>\n'
        '  <key>RunAtLoad</key><true/>\n'
        '  <key>KeepAlive</key><true/>\n'
        '</dict></plist>\n'
    )


def _render_systemd(python_exe: str, config_path: Path) -> str:
    return (
        "[Unit]\nDescription=Hawk Endpoint Agent\nAfter=network-online.target\n\n"
        "[Service]\n"
        f"Environment=HAWK_AGENT_CONFIG={config_path}\n"
        f"ExecStart={python_exe} -m hawk_endpoint_agent\n"
        "Restart=always\nRestartSec=5\n\n"
        "[Install]\nWantedBy=default.target\n"
    )


def enroll(
    *,
    api_url: str,
    tenant_id: str,
    endpoint_id: str = "",
    default_ai_system_id: str = "",
    config_path: str | Path | None = None,
    ca_dir: str | None = None,
    fail_secure: str = "warn",
    enable_proxy: bool = False,
    enable_tls: bool = False,
    install_service: bool = False,
    install_bridge: bool = False,
    extension_ids: list[str] | None = None,
    os_type: str | None = None,
    python_exe: str | None = None,
    agent_mode: str = "monitor",
    security_profile: str = "bank",
    key_provider: str = "macos_secure_enclave",
    identity_helper_path: str = (
        "~/Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity"
    ),
    device_key_tag: str = "com.hawk.endpoint-agent.device-key",
    local_operator_changes_allowed: bool = False,
    enrollment_bundle: EnrollmentBundle | None = None,
    auth_session: Any | None = None,
    log_dir: str | Path | None = None,
    python_path: str = "",
) -> EnrollmentReport:
    report = EnrollmentReport()
    os_type = (os_type or platform.system()).lower()
    python_exe = python_exe or sys.executable
    cfg_path = Path(config_path).expanduser() if config_path else DEFAULT_CONFIG_PATH

    cfg = AgentConfig(
        api_base_url=api_url,
        tenant_id=tenant_id,
        endpoint_id=endpoint_id or _stable_endpoint_id(platform.node()),
        default_ai_system_id=default_ai_system_id,
        fail_secure_mode=fail_secure,
        proxy_enabled=enable_proxy,
        tls_intercept_enabled=enable_tls,
        agent_mode=agent_mode if agent_mode in {"monitor", "enforce"} else "monitor",
        security_profile=security_profile,
        key_provider=key_provider,
        identity_helper_path=identity_helper_path,
        device_key_tag=device_key_tag,
        local_operator_changes_allowed=local_operator_changes_allowed,
    )
    if cfg.security_profile not in {"bank", "development"}:
        raise ValueError("security_profile must be bank or development")
    if cfg.security_profile == "bank" and not cfg.api_base_url.lower().startswith("https://"):
        raise ValueError("bank security profile requires an HTTPS Hawk API URL")
    if cfg.security_profile == "bank" and cfg.key_provider == "development_ephemeral":
        raise ValueError("bank security profile requires a hardware-backed device key")
    if cfg.security_profile == "bank" and enable_tls:
        raise ValueError(
            "bank profile disables file-backed TLS inspection; deploy the approved managed interceptor"
        )
    if enrollment_bundle is not None and not cfg.default_ai_system_id.strip():
        raise ValueError("live enrollment requires a registered default AI system ID")
    state_dir = cfg_path.parent
    cfg.policy_cache_path = str(state_dir / "policy-cache.json")
    cfg.baseline_path = str(state_dir / "baseline.json")
    cfg.evidence_queue_path = str(state_dir / "evidence-queue.json")
    cfg.mode_state_path = str(state_dir / "mode.json")
    if ca_dir:
        cfg.tls_ca_dir = ca_dir

    # 1. Replace any legacy config before network enrollment. This deliberately
    # leaves a stopped endpoint unauthenticated if enrollment fails, rather than
    # preserving an old reusable credential on disk.
    _write_secure(cfg_path, json.dumps(_persisted_config(cfg), indent=2, sort_keys=True))
    report.add(
        "config", "ok", f"wrote non-secret config {cfg_path} (0600)", path=str(cfg_path),
    )

    # 2. Device identity. The bundle exists only in caller memory and is never
    # copied into the config, report, launch arguments, environment, or logs.
    if enrollment_bundle is not None:
        stage = "initialize_session"
        try:
            session = auth_session or EndpointAuthSession(config=cfg)
            stage = "enrollment_exchange"
            response = session.enroll(enrollment_bundle)
            stage = "validate_response"
            key_thumbprint = str(response.get("key_thumbprint") or "").strip().lower()
            if len(key_thumbprint) != 64:
                raise ValueError("device enrollment did not return a valid key thumbprint")
            cfg.ipc_trusted_device_thumbprint = key_thumbprint
            stage = "persist_config"
            _write_secure(
                cfg_path,
                json.dumps(_persisted_config(cfg), indent=2, sort_keys=True),
            )
            report.add(
                "device_identity",
                "ok",
                "hardware-bound endpoint identity enrolled",
                endpoint_id=cfg.endpoint_id,
                identity_id=response.get("identity_id"),
                key_provider=response.get("key_provider") or cfg.key_provider,
                local_broker_authenticated=True,
            )
        except Exception as exc:  # noqa: BLE001 - never echo enrollment/authentication material
            _report_enrollment_failure(report, exc, stage)
            return report
    else:
        report.add(
            "device_identity",
            "skipped",
            "configuration only; live device enrollment was not requested",
        )

    # 3. CA (development-only TLS interception)
    if enable_tls and cryptography_available():
        ca = CertificateAuthority(cfg.tls_ca_dir)
        ca.export_ca_pem()
        report.add("ca", "ok", "CA generated; trust it on the endpoint to enable TLS content inspection",
                   path=str(ca.ca_cert_path), trust_command=_ca_trust_hint(os_type, ca.ca_cert_path))
    elif enable_tls:
        report.add("ca", "skipped", "cryptography not installed; proxy will do host-level TLS control only")
    else:
        report.add("ca", "skipped", "tls_intercept_enabled is false")

    # 4. bridge launcher + browser manifests
    if install_bridge:
        wrapper = _write_bridge_wrapper(cfg_path.parent, python_exe)
        report.add("bridge_launcher", "ok", "wrote bridge launcher", path=str(wrapper))
        eids = extension_ids or []
        for browser in ("chrome", "edge", "firefox"):
            location = install_location(os_type, browser)
            if not location:
                report.add(f"bridge_manifest_{browser}", "skipped", f"no manifest location for {browser} on {os_type}")
                continue
            manifest = firefox_manifest(str(wrapper), eids) if browser == "firefox" else chrome_manifest(str(wrapper), eids)
            manifest_path = Path(location).expanduser() / f"{HOST_NAME}.json"
            try:
                _write_secure(manifest_path, json.dumps(manifest, indent=2), mode=0o644)
                note = "" if eids else " (no --extension-id given; add the extension id and re-run)"
                report.add(f"bridge_manifest_{browser}", "ok", f"wrote manifest{note}", path=str(manifest_path))
            except OSError as exc:
                report.add(f"bridge_manifest_{browser}", "failed", str(exc))
    else:
        report.add("bridge", "skipped", "install_bridge not requested")

    # 5. service (autostart)
    if install_service:
        if os_type == "darwin":
            plist_path = Path("~/Library/LaunchAgents").expanduser() / f"{LAUNCH_AGENT_LABEL}.plist"
            try:
                logs = Path(log_dir).expanduser() if log_dir else cfg_path.parent.parent / "logs"
                logs.mkdir(parents=True, exist_ok=True)
                _write_secure(
                    plist_path,
                    _render_launch_agent(python_exe, cfg_path, logs, python_path),
                    mode=0o644,
                )
                report.add("service", "ok", "launch agent written", path=str(plist_path),
                           start_command=f"launchctl bootstrap gui/$(id -u) '{plist_path}'")
            except OSError as exc:
                report.add("service", "failed", str(exc))
        elif os_type == "linux":
            unit_path = Path("~/.config/systemd/user").expanduser() / "hawk-endpoint-agent.service"
            try:
                _write_secure(unit_path, _render_systemd(python_exe, cfg_path), mode=0o644)
                report.add("service", "ok", "systemd user unit written", path=str(unit_path),
                           start_command="systemctl --user enable --now hawk-endpoint-agent")
            except OSError as exc:
                report.add("service", "failed", str(exc))
        else:
            report.add("service", "skipped", f"no service template for {os_type}")
    else:
        report.add("service", "skipped", "install_service not requested")

    return report
