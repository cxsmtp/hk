"""Build a clean endpoint-agent transfer folder for pilot machines."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

PACKAGE_NAME = "hawk-endpoint-agent-pilot"
EXCLUDED_NAMES = {
    ".pytest_cache",
    "__pycache__",
    ".DS_Store",
}
EXCLUDED_SUFFIXES = {
    ".bak",
    ".orig",
    ".pyc",
    ".pyo",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _agent_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_excluded(path: Path) -> bool:
    return (
        path.name.startswith("._")
        or path.name in EXCLUDED_NAMES
        or path.suffix in EXCLUDED_SUFFIXES
        or ".pytest_cache" in path.parts
        or "__pycache__" in path.parts
    )


def _copy_tree(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if _is_excluded(path):
            continue
        rel = path.relative_to(source)
        target = destination / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest(package_dir: Path) -> dict[str, Any]:
    files: list[dict[str, str | int]] = []
    for path in sorted(package_dir.rglob("*")):
        if _is_excluded(path):
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(package_dir).as_posix()
        if rel == "MANIFEST.json":
            continue
        files.append({"path": rel, "size": path.stat().st_size, "sha256": _sha256(path)})
    return {
        "package": PACKAGE_NAME,
        "file_count": len(files),
        "files": files,
        "notes": [
            "No raw audio capture is included.",
            "Enrollment authorization is accepted only through inherited standard input and is never packaged.",
            "Endpoint authentication uses a hardware-bound identity and short-lived proof-of-possession access.",
            "Production-gate source and validation scripts do not certify signing, notarization, MDM, attestation, or EDR coexistence.",
            "Tests, caches, editor backups, and macOS AppleDouble files are excluded.",
        ],
    }


def _write_runbooks(package_dir: Path) -> None:
    (package_dir / "config").mkdir(parents=True, exist_ok=True)
    (package_dir / "config" / "endpoint-agent.example.json").write_text(
        json.dumps(
            {
                "api_base_url": "https://hawk-api.customer.example",
                "tenant_id": "REPLACE_WITH_TENANT_ID",
                "endpoint_id": "",
                "hostname": "",
                "deployment_mode": "user_pilot",
                "agent_mode": "monitor",
                "security_profile": "bank",
                "key_provider": "macos_secure_enclave",
                "identity_helper_path": "~/Library/Application Support/Hawk/EndpointAgent/runtime/bin/hawk-device-identity",
                "local_operator_changes_allowed": False,
                "fail_secure_mode": "warn",
                "allow_process_termination": True,
                "allow_mic_revocation": False,
                "allow_network_block": False,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (package_dir / "README_PILOT.md").write_text(
        """# Hawk Endpoint Agent Pilot Package

This package detects visible and endpoint-local AI notetakers, including known
local recorder processes. It reports redacted endpoint telemetry to the local
Hawk API and does not capture raw microphone audio or meeting content.

## macOS bank installation

Create a single-use endpoint enrollment authorization in Hawk immediately before
installation. Do not save that JSON to a file or place it in a command argument
or environment variable. Start the installer, paste the JSON when prompted, and
press Control-D. Bank mode is the default and requires HTTPS plus a Developer ID
Application signing identity for the native Secure Enclave helper.

```bash
cd hawk-endpoint-agent-pilot
./scripts/install_macos_user.sh \
  --api-url "https://hawk-api.customer.example" \
  --tenant-id "REPLACE_WITH_TENANT_ID" \
  --codesign-identity "Developer ID Application: YOUR ORGANIZATION (TEAMID)"
```

The installer compiles and installs the native identity helper, installs the
mandatory cryptography runtime in Hawk's private virtual environment, enrolls
the hardware-bound identity, and starts in monitor mode. Existing baseline,
evidence queue, cached policy, and mode state are preserved during upgrades.

## Explicit local-development installation

Local HTTP and an ad-hoc signed helper are accepted only when development mode
is selected explicitly. The one-time enrollment JSON still goes only to standard
input: run the command, paste the JSON, and press Control-D.

```bash
cd hawk-endpoint-agent-pilot
./scripts/install_macos_user.sh \
  --api-url "http://127.0.0.1:8000" \
  --tenant-id "REPLACE_WITH_TENANT_ID" \
  --security-profile development
```

Windows installation is intentionally not claimed by this package until the
TPM-backed native identity provider and signed Windows delivery are included.

## Production gate status

Source availability does not establish bank readiness. The included production
gate scripts fail closed and require external signing, notarization, MDM,
attestation, and EDR evidence from the actual customer build and deployment.
They do not create or substitute for that evidence.

The included NetworkExtension source intentionally refuses activation because
this slice does not yet contain a functional TCP/UDP relay.
Local broker responses are authenticated with a pinned hardware-device public
key and signed payload verification in the endpoint client bindings. The MDM
trust-pin contract remains required for managed bank deployment. This package
is not bank-ready until the external production gates above are satisfied.

## Control-mode honesty

This package can warn on local notetaker processes. Process termination is only
attempted when endpoint policy allows it. Microphone revocation and network
blocking are reported as `external_required` unless an MDM/SWG integration is
configured.

Visible meeting bots are reported separately from hidden/local recorders. For
Microsoft Teams, the package emits Microsoft Graph control intents for
participant removal, transcription disablement, recording disablement, and
meeting-admission hardening. Those actions stay `external_required` until a
backend/platform Graph integration confirms the action was triggered.
""",
        encoding="utf-8",
    )


def _remove_excluded_artifacts(package_dir: Path) -> None:
    for path in sorted(package_dir.rglob("*"), reverse=True):
        if not _is_excluded(path):
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)


def build_package(output_root: Path, *, overwrite: bool = False) -> Path:
    package_dir = output_root / PACKAGE_NAME
    if package_dir.exists():
        if not overwrite:
            raise FileExistsError(f"{package_dir} already exists")
        shutil.rmtree(
            package_dir,
            onexc=lambda func, path, exc: None if isinstance(exc, FileNotFoundError) else (_ for _ in ()).throw(exc),
        )
    package_dir.mkdir(parents=True)

    agent_root = _agent_root()
    shutil.copy2(agent_root / "pyproject.toml", package_dir / "pyproject.toml")
    _copy_tree(agent_root / "src", package_dir / "src")
    (package_dir / "scripts").mkdir(parents=True, exist_ok=True)
    for script_name in (
        "build_macos_identity_helper.sh",
        "build_bank_macos.sh",
        "hawk-endpoint-agent-wrapper.sh",
        "hawk-endpoint-control-wrapper.sh",
        "install_macos_user.sh",
        "notarize_bank_macos.sh",
        "uninstall_macos_user.sh",
        "validate_edr_coexistence.sh",
    ):
        shutil.copy2(
            agent_root / "scripts" / script_name,
            package_dir / "scripts" / script_name,
        )
    native_dir = package_dir / "native" / "macos"
    native_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        agent_root / "native" / "macos" / "HawkDeviceIdentity.swift",
        native_dir / "HawkDeviceIdentity.swift",
    )
    _copy_tree(
        agent_root / "native" / "macos" / "network-extension",
        native_dir / "network-extension",
    )
    _write_runbooks(package_dir)
    _remove_excluded_artifacts(package_dir)

    manifest = _manifest(package_dir)
    (package_dir / "MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    _remove_excluded_artifacts(package_dir)
    return package_dir


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(_repo_root().parent / "hawk-endpoint-agent-transfer"),
        help="Directory where the clean pilot package folder will be written",
    )
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    package_dir = build_package(Path(args.output).expanduser(), overwrite=args.overwrite)
    print(package_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
