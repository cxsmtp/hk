#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest
import uuid


os.umask(0o077)

REPO_ROOT = Path(__file__).resolve().parents[2]
STACK = REPO_ROOT / "infra/scripts/hawk_demo_stack.sh"
ENV_FILE = REPO_ROOT / ".env"
API_URL = os.environ.get("HAWK_API", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_EMAIL = os.environ.get("HAWK_DEMO_EMAIL", "owner@acme.ai")

GEMINI_VERSION = "0.54.4"
ADAPTER_VERSION = "1.0.0"
GEMINI_ROOT = Path.home() / f"Library/Application Support/Hawk/Gemini/{GEMINI_VERSION}"
GEMINI_SETTINGS = GEMINI_ROOT / "settings.json"
GEMINI_BINARY = GEMINI_ROOT / "node_modules/@google/gemini-cli/bundle/gemini.js"
GEMINI_PACKAGE = GEMINI_ROOT / "node_modules/@google/gemini-cli/package.json"
GEMINI_LAUNCHER = GEMINI_ROOT / "bin/hawk-gemini"

ENDPOINT_ROOT = Path.home() / "Library/Application Support/Hawk/EndpointAgent"
RUNTIME = ENDPOINT_ROOT / "runtime"
RUNTIME_APP = RUNTIME / "app"
PYTHON = RUNTIME / "venv/bin/python"
HOOK = RUNTIME / "bin/hawk-native-hook"
IDENTITY = RUNTIME / "bin/hawk-device-identity"
EXPECTED_IDENTITY = ENDPOINT_ROOT / "bin/hawk-device-identity"

STATE_DIR = Path.home() / ".hawk/native-control"
STATE_FILE = STATE_DIR / "gemini-demo-enrollment.json"
RUNTIME_CONFIG = STATE_DIR / "gemini-cli.json"
KEY_TAG = "com.hawk.endpoint-agent.native-control.gemini.v1"

EVENTS = (
    "session_start",
    "session_end",
    "before_agent",
    "after_agent",
    "before_model",
    "after_model",
    "before_tool_selection",
    "before_tool",
    "after_tool",
    "pre_compress",
    "notification",
)


class EnrollmentError(RuntimeError):
    pass


class ApiError(EnrollmentError):
    def __init__(self, path: str, status: int, detail: str = "") -> None:
        self.path = path
        self.status = status
        self.detail = detail
        suffix = f": {detail}" if detail else ""
        super().__init__(f"Hawk API rejected {path} with HTTP {status}{suffix}")


def require_regular_file(
    path: Path,
    label: str,
    *,
    executable: bool = False,
    allowed_symlink_root: Path | None = None,
) -> Path:
    is_symlink = path.is_symlink()
    if is_symlink and allowed_symlink_root is None:
        raise EnrollmentError(f"{label} is missing or unsafe: {path}")
    try:
        resolved = path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError) as exc:
        raise EnrollmentError(f"{label} is missing or unsafe: {path}") from exc
    if is_symlink:
        try:
            resolved.relative_to(allowed_symlink_root.resolve(strict=True))
        except (FileNotFoundError, RuntimeError, ValueError) as exc:
            raise EnrollmentError(f"{label} escapes its trusted runtime: {path}") from exc
    if not resolved.is_file():
        raise EnrollmentError(f"{label} is missing or unsafe: {path}")
    if resolved.stat().st_mode & 0o022:
        raise EnrollmentError(f"{label} is group/world writable: {path}")
    if executable and not os.access(resolved, os.X_OK):
        raise EnrollmentError(f"{label} is not executable: {path}")
    return resolved


def run_checked(args: list[str], *, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        args,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip().splitlines()[-1:] or completed.stdout.strip().splitlines()[-1:]
        suffix = f": {diagnostic[0][:240]}" if diagnostic else ""
        raise EnrollmentError(f"Local command failed ({Path(args[0]).name}){suffix}")
    return completed.stdout.strip()


def request_json(
    method: str,
    path: str,
    *,
    payload: dict[str, object] | None = None,
    token: str = "",
    tenant_id: str = "",
) -> dict[str, object]:
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Tenant-ID"] = tenant_id
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urlrequest.Request(f"{API_URL}{path}", data=body, headers=headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=10.0) as response:
            decoded = json.loads(response.read(512_000).decode("utf-8") or "{}")
    except urlerror.HTTPError as exc:
        detail = ""
        try:
            error_payload = json.loads(exc.read(16_384).decode("utf-8") or "{}")
            detail = str(error_payload.get("detail") or "") if isinstance(error_payload, dict) else ""
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        raise ApiError(path, exc.code, detail[:240]) from exc
    except (urlerror.URLError, TimeoutError, OSError) as exc:
        raise EnrollmentError(f"Hawk API is unavailable at {API_URL}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EnrollmentError(f"Hawk API returned invalid JSON for {path}") from exc
    if not isinstance(decoded, dict):
        raise EnrollmentError(f"Hawk API returned an invalid object for {path}")
    return decoded


class SecureApiClient:
    def __init__(self, token: str, tenant_id: str, *, expires_in: int) -> None:
        sys.path.insert(0, str(RUNTIME_APP))
        from hawk_endpoint_agent.auth.memory_vault import MemoryTokenVault

        self.tenant_id = tenant_id
        self.vault = MemoryTokenVault()
        self.vault.store(token, expires_at=time.time() + max(60, min(expires_in, 3600)))

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
    ) -> dict[str, object]:
        with self.vault.use() as token_buffer:
            transient_token = token_buffer.decode("ascii")
            try:
                return request_json(
                    method,
                    path,
                    payload=payload,
                    token=transient_token,
                    tenant_id=self.tenant_id,
                )
            finally:
                transient_token = ""

    def close(self) -> None:
        self.vault.close()


def secure_atomic_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    if path.is_symlink():
        raise EnrollmentError(f"Refusing symlink target: {path}")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.hawk-{os.getpid()}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def secure_atomic_json(path: Path, payload: dict[str, object]) -> None:
    secure_atomic_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError(f"Invalid JSON file: {path}") from exc
    if not isinstance(payload, dict):
        raise EnrollmentError(f"Invalid JSON object: {path}")
    return payload


def bind_secure_enclave_runtime_config(path: Path, *, key_tag: str) -> None:
    payload = load_json(path)
    expected_reference = f"secure-enclave://{key_tag}"
    existing_tag = str(payload.get("secure_enclave_key_tag") or "")
    if (
        payload.get("key_provider") != "macos_secure_enclave"
        or payload.get("kms_hsm_key_reference") != expected_reference
        or existing_tag not in {"", key_tag}
    ):
        raise EnrollmentError("Gemini Secure Enclave runtime key binding is inconsistent")
    payload["secure_enclave_key_tag"] = key_tag
    secure_atomic_json(path, payload)


def env_value(name: str) -> str:
    prefix = f"{name}="
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix) :]
    return ""


def update_env(values: dict[str, str]) -> None:
    original = ENV_FILE.read_text(encoding="utf-8")
    output: list[str] = []
    remaining = dict(values)
    for line in original.splitlines():
        key = line.split("=", 1)[0] if "=" in line else ""
        if key in remaining:
            output.append(f"{key}={remaining.pop(key)}")
        else:
            output.append(line)
    output.extend(f"{key}={value}" for key, value in remaining.items())
    mode = ENV_FILE.stat().st_mode & 0o777
    secure_atomic_text(ENV_FILE, "\n".join(output) + "\n", mode=mode)


def additive_route_json(tenant_id: str, integration_id: str) -> str:
    raw = env_value("NATIVE_CONTROL_ROUTE_BINDINGS_JSON") or "{}"
    try:
        bindings = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnrollmentError("NATIVE_CONTROL_ROUTE_BINDINGS_JSON is invalid") from exc
    if not isinstance(bindings, dict):
        raise EnrollmentError("NATIVE_CONTROL_ROUTE_BINDINGS_JSON must be an object")
    tenant = bindings.setdefault(tenant_id, {})
    if not isinstance(tenant, dict):
        raise EnrollmentError("Existing tenant route binding is invalid")
    existing = tenant.get("runtime_control")
    rows = existing if isinstance(existing, list) else ([existing] if isinstance(existing, dict) else [])
    preserved = [row for row in rows if isinstance(row, dict) and row.get("provider") != "google"]
    preserved.append(
        {
            "integration_instance_ids": [integration_id],
            "provider": "google",
            "provider_version": GEMINI_VERSION,
            "adapter_version": ADAPTER_VERSION,
            "product": "gemini_cli",
        }
    )
    tenant["runtime_control"] = preserved
    return json.dumps(bindings, sort_keys=True, separators=(",", ":"))


def ensure_identity_helper() -> None:
    require_regular_file(IDENTITY, "Hawk Secure Enclave helper", executable=True)
    if EXPECTED_IDENTITY.exists() or EXPECTED_IDENTITY.is_symlink():
        try:
            if EXPECTED_IDENTITY.resolve(strict=True) != IDENTITY.resolve(strict=True):
                raise EnrollmentError("Installed Secure Enclave helper binding is inconsistent")
        except FileNotFoundError as exc:
            raise EnrollmentError("Installed Secure Enclave helper binding is broken") from exc
        return
    EXPECTED_IDENTITY.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    EXPECTED_IDENTITY.symlink_to(IDENTITY)


def write_state(
    *, tenant_id: str, integration_id: str, credential_id: str, registered: bool
) -> None:
    state_payload = {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "integration_id": integration_id,
        "credential_id": credential_id,
        "credential_epoch": 1,
        "credential_registered": registered,
        "provider": "google",
        "product": "gemini_cli",
        "provider_version": GEMINI_VERSION,
        "adapter_version": ADAPTER_VERSION,
    }
    secure_atomic_json(STATE_FILE, state_payload)


def patch_settings() -> None:
    settings = load_json(GEMINI_SETTINGS)
    privacy = settings.setdefault("privacy", {})
    general = settings.setdefault("general", {})
    hooks_config = settings.setdefault("hooksConfig", {})
    if not all(isinstance(value, dict) for value in (privacy, general, hooks_config)):
        raise EnrollmentError("Gemini settings contain incompatible control sections")
    privacy["usageStatisticsEnabled"] = False
    general["enableAutoUpdate"] = False
    general["enableAutoUpdateNotification"] = False
    hooks_config["enabled"] = True
    disabled = hooks_config.get("disabled")
    hooks_config["disabled"] = [
        value for value in disabled if value != "hawk-native-control"
    ] if isinstance(disabled, list) else []
    hooks_config["notifications"] = True
    secure_atomic_json(GEMINI_SETTINGS, settings)


def main() -> int:
    require_regular_file(ENV_FILE, "Hawk Docker environment")
    require_regular_file(STACK, "Hawk Docker launcher", executable=True)
    require_regular_file(
        PYTHON,
        "Hawk private Python runtime",
        executable=True,
        allowed_symlink_root=PYTHON.parent,
    )
    require_regular_file(HOOK, "Hawk native-hook launcher", executable=True)
    require_regular_file(GEMINI_BINARY, "Gemini CLI 0.54.4 entry point", executable=True)
    require_regular_file(GEMINI_PACKAGE, "Gemini CLI package manifest")
    ensure_identity_helper()

    node_candidate = Path(os.environ.get("HAWK_NODE_RUNTIME") or shutil.which("node") or "")
    node_runtime = require_regular_file(node_candidate.resolve(), "Pinned Node runtime", executable=True)
    package = load_json(GEMINI_PACKAGE)
    if package.get("name") != "@google/gemini-cli" or package.get("version") != GEMINI_VERSION:
        raise EnrollmentError("Staged Gemini package identity does not match the reviewed release")
    observed_version = run_checked([str(node_runtime), str(GEMINI_BINARY), "--version"]).splitlines()[-1]
    if observed_version != GEMINI_VERSION:
        raise EnrollmentError(f"Expected Gemini {GEMINI_VERSION}, observed {observed_version}")

    global_gemini_before = shutil.which("gemini")
    run_checked([str(STACK), "up"])
    health = request_json("GET", "/health")
    if health.get("status") != "ok" or health.get("schema_healthy") is not True:
        raise EnrollmentError("Hawk API or PostgreSQL schema is not healthy")

    email = input(f"Hawk owner email [{DEFAULT_EMAIL}]: ").strip() or DEFAULT_EMAIL
    password = getpass.getpass("Hawk owner password: ")
    login = request_json("POST", "/auth/login", payload={"email": email, "password": password})
    password = ""
    token = str(login.pop("access_token", "") or "")
    login.pop("refresh_token", None)
    tenant_id = str(login.get("selected_tenant_id") or "")
    expires_in = int(login.get("expires_in") or 900)
    if not token or not tenant_id:
        token = ""
        login.clear()
        raise EnrollmentError("Owner login did not resolve a selected tenant")
    client = SecureApiClient(token, tenant_id, expires_in=expires_in)
    token = ""
    login.clear()

    try:
        catalog = client.request("GET", "/native-controls/adapters")
        adapters = catalog.get("items") if isinstance(catalog.get("items"), list) else []
        adapter = next(
            (
                row
                for row in adapters
                if isinstance(row, dict)
                and row.get("adapter_id") == "google.gemini-cli.command-hooks"
                and row.get("adapter_version") == ADAPTER_VERSION
            ),
            None,
        )
        versions = (
            adapter.get("provider_version_range", {}).get("exact_verified_versions", [])
            if isinstance(adapter, dict) and isinstance(adapter.get("provider_version_range"), dict)
            else []
        )
        if not isinstance(adapter, dict) or GEMINI_VERSION not in versions:
            raise EnrollmentError("Hawk does not contain the reviewed Gemini 0.54.4 adapter evidence")

        STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        integration_id = ""
        credential_id = ""
        credential_registered = False
        state = load_json(STATE_FILE) if STATE_FILE.is_file() and not STATE_FILE.is_symlink() else None
        if state is not None:
            if state.get("tenant_id") != tenant_id:
                raise EnrollmentError("Existing Gemini enrollment belongs to another tenant")
            integration_id = str(state.get("integration_id") or "")
            credential_id = str(state.get("credential_id") or "")
            credential_registered = state.get("credential_registered") is True
            try:
                client.request("GET", f"/control-points/{integration_id}")
            except ApiError as exc:
                if exc.status != 404:
                    raise
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                STATE_FILE.replace(STATE_FILE.with_name(f"{STATE_FILE.name}.stale-{timestamp}"))
                state = None

        if state is None:
            policy_until = datetime.now(timezone.utc) + timedelta(days=7)
            integration = client.request(
                "POST",
                "/native-controls/integrations",
                {
                    "provider": "google",
                    "product": "gemini_cli",
                    "method": "native_hook",
                    "instance_key": "gemini-cli-local-0-54-4",
                    "display_name": "Gemini CLI - governed Mac",
                    "environment": "production",
                    "deployment_family": "endpoint",
                    "provider_version": GEMINI_VERSION,
                    "adapter_version": ADAPTER_VERSION,
                    "policy_version": "airtel-demo-gemini-v1",
                    "policy_fresh_until": policy_until.isoformat(),
                    "degradation_mode": "monitor_only",
                },
            )
            integration_id = str(integration.get("id") or "")
            credential_id = f"gemini-mac-{uuid.uuid4()}"
            if not integration_id:
                raise EnrollmentError("Hawk did not return a Gemini integration ID")
            write_state(
                tenant_id=tenant_id,
                integration_id=integration_id,
                credential_id=credential_id,
                registered=False,
            )

        identity_payload = json.loads(run_checked([str(IDENTITY), "ensure", KEY_TAG]) or "{}")
        if not isinstance(identity_payload, dict) or identity_payload.get("ok") is not True:
            raise EnrollmentError("Secure Enclave identity enrollment failed")
        if identity_payload.get("hardware_backed") is not True:
            raise EnrollmentError("Gemini workload identity is not hardware-backed")
        public_key = str(identity_payload.get("public_key_pem") or "")
        if len(public_key) < 100:
            raise EnrollmentError("Secure Enclave public key is unavailable")

        if not credential_registered:
            credential_until = datetime.now(timezone.utc) + timedelta(days=30)
            client.request(
                "POST",
                f"/native-controls/integrations/{integration_id}/credentials",
                {
                    "credential_id": credential_id,
                    "credential_epoch": 1,
                    "public_key_pem": public_key,
                    "environment": "production",
                    "allowed_event_types": list(EVENTS),
                    "expires_at": credential_until.isoformat(),
                },
            )
            credential_registered = True
            write_state(
                tenant_id=tenant_id,
                integration_id=integration_id,
                credential_id=credential_id,
                registered=True,
            )
        public_key = ""
        identity_payload.clear()

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        if GEMINI_SETTINGS.is_file() and not GEMINI_SETTINGS.is_symlink():
            settings_backup = GEMINI_SETTINGS.with_name(
                f"{GEMINI_SETTINGS.name}.hawk-backup-{timestamp}"
            )
            shutil.copy2(GEMINI_SETTINGS, settings_backup)
            os.chmod(settings_backup, 0o600)

        runtime_env = {**os.environ, "PYTHONPATH": str(RUNTIME_APP)}
        install_payload = json.loads(
            run_checked(
                [
                    str(PYTHON),
                    "-m",
                    "hawk_endpoint_agent.native_control.cli",
                    "install",
                    "--provider", "gemini_cli",
                    "--settings", str(GEMINI_SETTINGS),
                    "--scope", "user",
                    "--helper", str(HOOK),
                    "--config", str(RUNTIME_CONFIG),
                    "--api-url", API_URL,
                    "--tenant-id", tenant_id,
                    "--integration-id", integration_id,
                    "--credential-id", credential_id,
                    "--credential-epoch", "1",
                    "--provider-family", "google",
                    "--product", "gemini_cli",
                    "--provider-version", GEMINI_VERSION,
                    "--adapter-version", ADAPTER_VERSION,
                    "--environment", "production",
                    "--key-provider", "macos_secure_enclave",
                    "--security-profile", "development",
                    "--kms-key-reference", f"secure-enclave://{KEY_TAG}",
                ],
                env=runtime_env,
            )
            or "{}"
        )
        bind_secure_enclave_runtime_config(RUNTIME_CONFIG, key_tag=KEY_TAG)
        installed_events = install_payload.get("events") if isinstance(install_payload, dict) else []
        expected_provider_events = {
            "SessionStart", "SessionEnd", "BeforeAgent", "AfterAgent", "BeforeTool",
            "AfterTool", "BeforeModel", "AfterModel", "BeforeToolSelection", "PreCompress",
            "Notification",
        }
        if set(installed_events or []) != expected_provider_events:
            raise EnrollmentError("Gemini hook installation did not include the full lifecycle")
        patch_settings()

        render_payload = json.loads(
            run_checked(
                [
                    str(PYTHON),
                    "-m",
                    "hawk_endpoint_agent.native_control.cli",
                    "render-gemini-managed",
                    "--binary", str(GEMINI_BINARY),
                    "--runtime", str(node_runtime),
                    "--settings", str(GEMINI_SETTINGS),
                    "--helper", str(HOOK),
                    "--config", str(RUNTIME_CONFIG),
                    "--expected-version", GEMINI_VERSION,
                    "--output", str(GEMINI_LAUNCHER),
                ],
                env=runtime_env,
            )
            or "{}"
        )
        if render_payload.get("hash_pinned") is not True:
            raise EnrollmentError("Hash-pinned Gemini launcher was not rendered")

        env_backup = ENV_FILE.with_name(f".{ENV_FILE.name}.gemini-{os.getpid()}.backup")
        shutil.copy2(ENV_FILE, env_backup)
        try:
            update_env(
                {
                    "NATIVE_CONTROL_GOOGLE": "true",
                    "NATIVE_CONTROL_ROUTE_BINDINGS_JSON": additive_route_json(
                        tenant_id, integration_id
                    ),
                }
            )
            run_checked([str(STACK), "up"])
            final_health = request_json("GET", "/health")
            if final_health.get("status") != "ok" or final_health.get("schema_healthy") is not True:
                raise EnrollmentError("Hawk stack did not return healthy after Gemini route binding")
        except Exception:
            shutil.copy2(env_backup, ENV_FILE)
            run_checked([str(STACK), "up"])
            raise
        finally:
            try:
                env_backup.unlink()
            except FileNotFoundError:
                pass

        launcher_version = run_checked([str(GEMINI_LAUNCHER), "--version"]).splitlines()[-1]
        if launcher_version != GEMINI_VERSION:
            raise EnrollmentError("Pinned Hawk Gemini launcher failed its exact-version check")
        global_gemini_after = shutil.which("gemini")
        if global_gemini_after != global_gemini_before:
            raise EnrollmentError("Global Gemini launcher changed during isolated enrollment.")

        settings = load_json(GEMINI_SETTINGS)
        hook_events = sorted((settings.get("hooks") or {}).keys()) if isinstance(settings.get("hooks"), dict) else []
        print(
            json.dumps(
                {
                    "status": "ok",
                    "tenant_id": tenant_id,
                    "integration_id": integration_id,
                    "credential_id": credential_id,
                    "provider_version": GEMINI_VERSION,
                    "adapter_version": ADAPTER_VERSION,
                    "adapter_maturity": adapter.get("maturity"),
                    "production_eligible": adapter.get("production_eligible"),
                    "hardware_backed_identity": True,
                    "token_encrypted_in_memory": True,
                    "persistent_secret_material": False,
                    "settings_path": str(GEMINI_SETTINGS),
                    "launcher_path": str(GEMINI_LAUNCHER),
                    "runtime_config_path": str(RUNTIME_CONFIG),
                    "state_path": str(STATE_FILE),
                    "hook_events": hook_events,
                    "global_gemini_unchanged": True,
                    "deployment_state": "configured_for_live_monitoring",
                    "enforce_eligibility": "blocked_pending_external_production_evidence",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EnrollmentError, ApiError) as exc:
        print(json.dumps({"status": "failed", "reason": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
