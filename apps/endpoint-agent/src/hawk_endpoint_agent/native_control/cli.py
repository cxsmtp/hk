from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import secrets
from types import SimpleNamespace

from hawk_endpoint_agent.auth.device_key import CANONICAL_MACOS_IDENTITY_HELPER, build_device_key_provider, validate_macos_identity_helper
from .installer import (
    NativeHookInstaller,
    claude_settings_path,
    codex_managed_requirements_toml,
    codex_settings_path,
    cursor_settings_path,
    gemini_managed_launcher_script,
    gemini_settings_path,
)


_DEFAULT_SETTINGS = {
    "gemini_cli": "~/.gemini/settings.json",
    "claude_code": "~/.claude/settings.json",
    "cursor": "~/.cursor/hooks.json",
    "codex": "~/.codex/hooks.json",
}
_SECURE_ENCLAVE_REFERENCE = re.compile(
    r"^secure-enclave://(?P<tag>[A-Za-z0-9._-]{1,200})$"
)


def _runtime_key_binding(*, key_provider: str, key_reference: str) -> dict[str, str]:
    if str(key_provider or "").strip().lower() != "macos_secure_enclave":
        return {}
    matched = _SECURE_ENCLAVE_REFERENCE.fullmatch(str(key_reference or "").strip())
    if matched is None:
        raise ValueError("invalid Secure Enclave key reference")
    return {"secure_enclave_key_tag": matched.group("tag")}


def _atomic_runtime_config(path: Path, payload: dict[str, object]) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError("runtime configuration symlink refused")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.hawk-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_managed_artifact(path: Path, content: str) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError("managed artifact symlink refused")
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if not existing.startswith("# Hawk managed Codex native-control requirements"):
            raise ValueError("existing managed requirements must be merged by MDM; overwrite refused")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.hawk-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _atomic_managed_launcher(path: Path, content: str) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise ValueError("managed launcher symlink refused")
    if path.exists() and not path.read_text(encoding="utf-8").startswith(
        "#!/bin/sh\n# Hawk managed Gemini CLI launcher"
    ):
        raise ValueError("existing launcher is not Hawk-managed; overwrite refused")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.hawk-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o700)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Install or remove Hawk provider-native control hooks")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    enterprise = subparsers.add_parser("render-claude-enterprise")
    enterprise.add_argument("--org-id", action="append", required=True)
    enterprise.add_argument("--output-directory", required=True)
    endpoint = subparsers.add_parser("install-endpoint")
    endpoint.add_argument("--provider", required=True, choices=("codex", "claude_code"))
    endpoint.add_argument("--endpoint-config", required=True)
    endpoint.add_argument("--helper", required=True)
    endpoint.add_argument("--config", required=True)
    endpoint.add_argument("--settings")
    endpoint.add_argument("--scope", choices=("user", "project"), default="user")
    endpoint.add_argument("--project-root")
    for operation in ("install", "uninstall"):
        command = subparsers.add_parser(operation)
        command.add_argument("--provider", required=True, choices=tuple(_DEFAULT_SETTINGS))
        command.add_argument("--settings")
        command.add_argument(
            "--scope",
            choices=("user", "project", "local_project", "managed", "enterprise"),
            default="user",
        )
        command.add_argument("--project-root")
        command.add_argument("--helper")
        command.add_argument("--config")
        if operation == "install":
            for field in (
                "api-url", "tenant-id", "integration-id", "credential-id", "provider-family",
                "product", "provider-version", "kms-key-reference",
            ):
                command.add_argument(f"--{field}", required=True)
            command.add_argument("--credential-epoch", type=int, default=1)
            command.add_argument("--adapter-version", default="1.0.0")
            command.add_argument("--environment", default="production")
            command.add_argument("--key-provider", default="kms_hsm_helper")
            command.add_argument("--kms-helper-path", default="unix:///var/run/hawk/kms-signer.sock")
            command.add_argument("--security-profile", default="bank")
            command.add_argument("--secure-enclave-helper-path", default=str(CANONICAL_MACOS_IDENTITY_HELPER))
    registration = subparsers.add_parser("registration")
    registration.add_argument("--endpoint-id", required=True)
    registration.add_argument("--key-provider", default="kms_hsm_helper")
    registration.add_argument("--kms-helper-path", default="unix:///var/run/hawk/kms-signer.sock")
    registration.add_argument("--kms-key-reference", required=True)
    registration.add_argument("--security-profile", default="bank")
    validation = subparsers.add_parser("validate-claude")
    validation.add_argument("--binary", default=shutil.which("claude") or "claude")
    codex_validation = subparsers.add_parser("validate-codex")
    codex_validation.add_argument("--binary", default=shutil.which("codex") or "codex")
    codex_validation.add_argument("--repository-root", required=True)
    codex_validation.add_argument("--python-binary", default=sys.executable)
    codex_validation.add_argument("--expected-version", required=True)
    codex_validation.add_argument("--expected-binary-sha256", required=True)
    codex_validation.add_argument("--identity-helper", required=True)
    codex_validation.add_argument("--key-tag", required=True)
    cursor_validation = subparsers.add_parser("validate-cursor")
    cursor_validation.add_argument(
        "--binary",
        default=shutil.which("cursor") or "/Applications/Cursor.app/Contents/MacOS/Cursor",
    )
    cursor_validation.add_argument("--acceptance-home", required=True)
    cursor_validation.add_argument("--desktop-app", required=True)
    gemini_validation = subparsers.add_parser("validate-gemini")
    gemini_validation.add_argument("--binary", default=shutil.which("gemini") or "gemini")
    gemini_validation.add_argument("--runtime")
    gemini_validation.add_argument("--real-model-none", action="store_true")
    codex_managed = subparsers.add_parser("render-codex-managed")
    codex_managed.add_argument("--helper", required=True)
    codex_managed.add_argument("--config", required=True)
    codex_managed.add_argument("--output", required=True)
    gemini_managed = subparsers.add_parser("render-gemini-managed")
    gemini_managed.add_argument("--binary", required=True)
    gemini_managed.add_argument("--settings", required=True)
    gemini_managed.add_argument("--helper", required=True)
    gemini_managed.add_argument("--config", required=True)
    gemini_managed.add_argument("--expected-version", required=True)
    gemini_managed.add_argument("--runtime")
    gemini_managed.add_argument("--output", required=True)
    return parser


def _settings_target(args: argparse.Namespace) -> Path:
    if args.settings:
        return Path(args.settings).expanduser()
    if args.provider == "claude_code":
        scope = "managed" if args.scope == "enterprise" else args.scope
        return claude_settings_path(
            scope,
            project_root=args.project_root,
        )
    if args.provider == "cursor":
        scope = "enterprise" if args.scope == "managed" else args.scope
        if scope == "local_project":
            raise ValueError("cursor_settings_scope_unsupported")
        return cursor_settings_path(
            scope,
            project_root=args.project_root,
        )
    if args.provider == "gemini_cli":
        if args.scope == "local_project":
            raise ValueError("gemini_settings_scope_unsupported")
        return gemini_settings_path(
            args.scope,
            project_root=args.project_root,
        )
    if args.provider == "codex":
        if args.scope == "local_project":
            raise ValueError("codex_settings_scope_unsupported")
        if args.scope in {"managed", "enterprise"}:
            raise ValueError("use render-codex-managed and merge the artifact through MDM")
        return codex_settings_path(
            args.scope,
            project_root=args.project_root,
        )
    raise ValueError("provider_settings_scope_unsupported")


def _verify_endpoint_installation(config, provider: str) -> None:
    from ..bridge.socket_client import query_agent
    from .endpoint_broker import registered_runtime
    registered_runtime(config, provider)
    request_id = secrets.token_hex(24)
    identity = query_agent(
        config.ipc_socket_path,
        {"protocol_version": 1, "op": "identity", "request_id": request_id},
        timeout=3.0, expected_thumbprint=config.ipc_trusted_device_thumbprint,
    )
    if (identity.get("ok") is not True or identity.get("request_id") != request_id
            or not config.endpoint_id or identity.get("endpoint_id") != config.endpoint_id):
        raise ValueError("enrolled endpoint is unavailable; hook installation refused")


def _install_endpoint(args) -> None:
    from .endpoint_broker import PROVIDERS, endpoint_configuration
    path = Path(args.endpoint_config).expanduser()
    if (path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077
            or path.stat().st_uid != os.getuid() or path.stat().st_size > 262144):
        raise ValueError("endpoint configuration is unavailable or insecure")
    config = SimpleNamespace(**json.loads(path.read_text(encoding="utf-8")))
    local = endpoint_configuration({
        "transport": "endpoint", "provider": PROVIDERS[args.provider],
        "socket_path": str(Path(config.ipc_socket_path).expanduser()),
        "endpoint_thumbprint": config.ipc_trusted_device_thumbprint,
    })
    config.ipc_socket_path = local["socket_path"]
    _verify_endpoint_installation(config, args.provider)
    settings = _settings_target(args)
    runtime = Path(args.config).expanduser()
    # Never overwrite the agent's registration or endpoint configuration.
    reserved = [path, settings, Path(args.helper), *[
        Path(value) for value in config.native_hook_runtime_configs.values()
    ]]
    if any(runtime.resolve() == item.resolve() for item in reserved):
        raise ValueError("hook client configuration must have a separate path")
    installer = NativeHookInstaller(provider=args.provider, helper_path=Path(args.helper), runtime_config_path=runtime)
    _atomic_runtime_config(runtime, local)
    result = installer.install(settings)
    print(json.dumps({"provider": result.provider, "settings_path": result.settings_path,
                      "changed": result.changed, "fingerprint": result.fingerprint,
                      "transport": "endpoint", "protection_status": "unverified",
                      "events": list(result.events)}, sort_keys=True))


def main() -> None:
    args = _parser().parse_args()
    if hasattr(args, "key_provider"):
        args.key_provider = str(args.key_provider).strip().lower()
        args.security_profile = str(args.security_profile).strip().lower()
    if args.operation == "render-claude-enterprise":
        from .claude_enterprise import deployment_bundle
        bundle = deployment_bundle(args.org_id)
        output = Path(args.output_directory).expanduser()
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        for name, content in bundle.items():
            with (output / name).open("x", encoding="utf-8") as stream:
                stream.write(content)
        print(json.dumps({"output_directory": str(output), "status": "unverified", "installed": False}))
        return
    if args.operation == "install-endpoint":
        _install_endpoint(args)
        return
    if args.operation == "render-codex-managed":
        output = Path(args.output).expanduser()
        rendered = codex_managed_requirements_toml(
            helper_path=Path(args.helper),
            runtime_config_path=Path(args.config),
        )
        _atomic_managed_artifact(output, rendered)
        print(json.dumps({
            "provider": "codex",
            "artifact": str(output),
            "managed_only": True,
            "mdm_merge_required": True,
        }, sort_keys=True))
        return
    if args.operation == "render-gemini-managed":
        output = Path(args.output).expanduser()
        rendered = gemini_managed_launcher_script(
            binary_path=Path(args.binary),
            system_settings_path=Path(args.settings),
            helper_path=Path(args.helper),
            runtime_config_path=Path(args.config),
            expected_version=args.expected_version,
            runtime_path=Path(args.runtime) if args.runtime else None,
        )
        _atomic_managed_launcher(output, rendered)
        print(json.dumps({
            "provider": "gemini_cli",
            "artifact": str(output),
            "expected_version": args.expected_version,
            "hash_pinned": True,
            "managed_only": True,
            "mdm_deployment_required": True,
        }, sort_keys=True))
        return
    if args.operation == "validate-claude":
        from dataclasses import asdict
        from .claude_acceptance import run_claude_binary_acceptance

        report = run_claude_binary_acceptance(Path(args.binary))
        payload = {**asdict(report), "passed": report.passed}
        print(json.dumps(payload, sort_keys=True))
        if not report.passed:
            raise SystemExit(2)
        return
    if args.operation == "validate-codex":
        from .codex_acceptance import run_codex_binary_acceptance

        report = run_codex_binary_acceptance(
            Path(args.binary),
            repository_root=Path(args.repository_root),
            python_binary=Path(args.python_binary),
            expected_version=args.expected_version,
            expected_binary_sha256=args.expected_binary_sha256,
            identity_helper=Path(args.identity_helper),
            key_tag=args.key_tag,
        )
        payload = report.as_evidence_artifact()
        print(json.dumps(payload, sort_keys=True))
        if not report.passed:
            raise SystemExit(2)
        return
    if args.operation == "validate-cursor":
        from dataclasses import asdict
        from .cursor_acceptance import run_cursor_binary_acceptance

        report = run_cursor_binary_acceptance(
            Path(args.binary),
            acceptance_home=Path(args.acceptance_home),
            desktop_app=Path(args.desktop_app),
        )
        payload = {**asdict(report), "passed": report.passed}
        print(json.dumps(payload, sort_keys=True))
        if not report.passed:
            raise SystemExit(2)
        return
    if args.operation == "validate-gemini":
        from dataclasses import asdict
        from .gemini_acceptance import run_gemini_binary_acceptance

        report = run_gemini_binary_acceptance(
            Path(args.binary),
            binary_runtime_path=Path(args.runtime) if args.runtime else None,
            real_model_none=args.real_model_none,
            real_model_api_key=os.environ.get("GEMINI_API_KEY"),
        )
        payload = {**asdict(report), "passed": report.passed}
        print(json.dumps(payload, sort_keys=True))
        if not report.passed:
            raise SystemExit(2)
        return
    if args.operation == "registration":
        provider = build_device_key_provider(
            provider_name=args.key_provider,
            security_profile=args.security_profile,
            kms_hsm_helper_path=args.kms_helper_path,
            kms_hsm_key_reference=args.kms_key_reference,
        )
        identity = provider.ensure_key(args.endpoint_id)
        print(json.dumps({
            "provider": identity.provider,
            "public_key_pem": identity.public_key_pem,
            "key_thumbprint": identity.key_thumbprint,
            "hardware_backed": identity.hardware_backed,
        }, sort_keys=True))
        return

    settings = _settings_target(args)
    helper = Path(args.helper or shutil.which("hawk-native-hook") or "").expanduser()
    config = Path(args.config or "~/.hawk/native-control/runtime.json").expanduser()
    identity_helper = None
    if args.operation == "install" and args.key_provider == "macos_secure_enclave":
        identity_helper = Path(args.secure_enclave_helper_path).expanduser().absolute()
        if args.security_profile != "development":
            identity_helper = validate_macos_identity_helper(str(identity_helper))
    installer = NativeHookInstaller(
        provider=args.provider,
        helper_path=helper,
        runtime_config_path=config,
    )
    if args.operation == "install":
        runtime_key_binding = _runtime_key_binding(
            key_provider=args.key_provider,
            key_reference=args.kms_key_reference,
        )
        _atomic_runtime_config(
            config,
            {
                "api_url": args.api_url,
                "tenant_id": args.tenant_id,
                "integration_id": args.integration_id,
                "credential_id": args.credential_id,
                "credential_epoch": args.credential_epoch,
                "provider": args.provider_family,
                "product": args.product,
                "provider_version": args.provider_version,
                "adapter_version": args.adapter_version,
                "environment": args.environment,
                "key_provider": args.key_provider,
                "security_profile": args.security_profile,
                "kms_hsm_helper_path": args.kms_helper_path,
                "kms_hsm_key_reference": args.kms_key_reference,
                **runtime_key_binding,
                **({"secure_enclave_helper_path": str(identity_helper)} if identity_helper else {}),
            },
        )
        result = installer.install(settings)
    else:
        result = installer.uninstall(settings)
    print(json.dumps({
        "provider": result.provider,
        "settings_path": result.settings_path,
        "changed": result.changed,
        "fingerprint": result.fingerprint,
        "events": list(result.events),
        "runtime_config_path": str(config),
        "runtime_config_removed": False,
        "scope": args.scope,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
