"""Read-only assessment of a stapled package and its actual native components."""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import stat
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Callable

from .attestation import validate_macos_release_evidence_v2
from .macos_native import HOST_BUNDLE_ID, EXTENSION_BUNDLE_IDS, macos_component_set_digest

_ROOTS = (
    "Applications/Hawk Endpoint.app",
    "Library/Application Support/Hawk/EndpointAgent/runtime",
    "Library/Application Support/Hawk/EndpointAgent/bin/hawk-device-identity",
    "Library/Application Support/Hawk/EndpointAgent/managed-defaults.json",
    "Library/LaunchAgents/ai.hawk.endpoint-agent.plist",
)
_PARENTS = {str(parent) for root in _ROOTS for parent in PurePosixPath(root).parents}
_REQUIREMENTS = {
    HOST_BUNDLE_ID: ("com.apple.developer.system-extension.install", True),
    EXTENSION_BUNDLE_IDS[0]: ("com.apple.developer.endpoint-security.client", True),
    EXTENSION_BUNDLE_IDS[1]: ("com.apple.developer.networking.networkextension", "content-filter-provider-systemextension"),
    EXTENSION_BUNDLE_IDS[2]: ("com.apple.developer.networking.networkextension", "transparent-proxy-provider"),
}


def _payload_paths(raw: bytes) -> None:
    paths = raw.decode("utf-8", errors="strict").splitlines()
    if not paths:
        raise ValueError("package_payload_empty")
    for original in paths:
        path = original.removeprefix("./").rstrip("/")
        if path == ".":
            continue
        if (not path or original != original.strip() or "\x00" in path or "\\" in path or
                path.startswith("/") or ".." in PurePosixPath(path).parts or
                "endpoint-floor-policy.bin" in path or "ai.hawk.endpoint.host.plist" in path or
                not (path in _PARENTS or any(path == root or path.startswith(root + "/") for root in _ROOTS))):
            raise ValueError("package_payload_path_invalid")


def _safe_tree(root: Path) -> None:
    resolved = root.resolve()
    for path in root.rglob("*"):
        metadata = path.lstat()
        if (not path.resolve().is_relative_to(resolved) or
                not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)) or
                (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)):
            raise ValueError("package_payload_escape_or_special_file")
        if path.name == "Scripts":
            raise ValueError("package_scripts_forbidden")


def verify_macos_package(
    package: Path, build: dict, notarization: dict, *,
    installed_component_digest: str, accepted_component_digest: str,
    run: Callable = subprocess.run, temporary_parent: Path | None = None,
) -> dict[str, str]:
    """Require real Apple assessments and a matching packaged/installed/accepted set.

    The two supplied digests must come from installed signature verification and
    verified signed target acceptance, respectively. Evidence JSON is not a trust
    source by itself. No package or payload executable is ever run.
    """
    release = validate_macos_release_evidence_v2(build, notarization)
    if (release["component_set_digest"] != installed_component_digest or
            release["component_set_digest"] != accepted_component_digest):
        raise ValueError("package_installed_target_binding_invalid")
    package = Path(package).absolute()
    if package.suffix != ".pkg" or package.is_symlink() or not package.is_file():
        raise ValueError("package_path_invalid")

    def checked(args: list[str]) -> bytes:
        try:
            result = run(args, capture_output=True, check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("package_assessment_unavailable") from exc
        if result.returncode != 0:
            raise ValueError("package_assessment_failed")
        return result.stdout if result.stdout else result.stderr

    package_digest = hashlib.sha256(package.read_bytes()).hexdigest()
    if package_digest != notarization["stapled_package_sha256"]:
        raise ValueError("stapled_package_digest_mismatch")
    signature = checked(["/usr/sbin/pkgutil", "--check-signature", str(package)]).decode("utf-8")
    team = release["team_id"]
    if re.search(r"Developer ID Installer: [^\r\n]*\(" + re.escape(team) + r"\)", signature) is None:
        raise ValueError("package_installer_identity_invalid")
    checked(["/usr/bin/xcrun", "stapler", "validate", str(package)])
    checked(["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", str(package)])
    _payload_paths(checked(["/usr/sbin/pkgutil", "--payload-files", str(package)]))

    with tempfile.TemporaryDirectory(prefix="hawk-package-verification-", dir=temporary_parent) as directory:
        work = Path(directory)
        os.chmod(work, 0o700)
        outer = work / "outer"
        checked(["/usr/sbin/pkgutil", "--expand", str(package), str(outer)])
        _safe_tree(outer)
        components = list(outer.glob("*.pkg"))
        if len(components) != 1 or components[0].is_symlink():
            raise ValueError("package_component_structure_ambiguous")
        component = components[0]
        if component.is_file():
            expanded = work / "component"
            checked(["/usr/sbin/pkgutil", "--expand", str(component), str(expanded)])
            component = expanded
        _safe_tree(component)
        payloads = list(outer.rglob("Payload")) if component.is_relative_to(outer) else list(component.rglob("Payload"))
        if len(payloads) != 1 or payloads[0].parent != component or payloads[0].is_symlink() or not payloads[0].is_file():
            raise ValueError("package_payload_structure_ambiguous")
        payload = payloads[0]
        _payload_paths(checked(["/usr/bin/tar", "-tf", str(payload)]))
        extracted = work / "extracted"
        extracted.mkdir(mode=0o700)
        # BSD tar defaults reject '..' and intervening symlinks. Never use -P
        # or -U: either would disable that protection. No shell is involved.
        checked(["/usr/bin/tar", "-xf", str(payload), "-C", str(extracted),
                 "--no-same-owner", "--no-same-permissions", "--safe-writes"])
        _safe_tree(extracted)
        _payload_paths("\n".join(str(path.relative_to(extracted)) for path in extracted.rglob("*")).encode())
        launch_path = extracted / "Library/LaunchAgents/ai.hawk.endpoint-agent.plist"
        if not launch_path.is_file() or launch_path.is_symlink():
            raise ValueError("packaged_launch_agent_missing")
        launch = plistlib.loads(launch_path.read_bytes())
        if launch.get("EnvironmentVariables", {}).get("HAWK_AGENT_CONFIG") != "/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json":
            raise ValueError("packaged_agent_config_path_invalid")
        app = extracted / "Applications/Hawk Endpoint.app"
        if list(extracted.rglob("*.app")) != [app] or app.is_symlink():
            raise ValueError("packaged_application_ambiguous")
        bundles = {HOST_BUNDLE_ID: app}
        for extension in (app / "Contents/Library/SystemExtensions").glob("*.systemextension"):
            info = plistlib.loads((extension / "Contents/Info.plist").read_bytes())
            identifier = info.get("CFBundleIdentifier")
            if extension.is_symlink() or identifier not in EXTENSION_BUNDLE_IDS or identifier in bundles:
                raise ValueError("packaged_component_identity_invalid")
            bundles[identifier] = extension
        if set(bundles) != set(_REQUIREMENTS):
            raise ValueError("packaged_component_set_invalid")
        expected = {row["bundle_id"]: row for row in build["components"]}
        records = []
        for identifier, bundle in bundles.items():
            info = plistlib.loads((bundle / "Contents/Info.plist").read_bytes())
            executable_name = info.get("CFBundleExecutable")
            if (not isinstance(executable_name, str) or not executable_name or
                    Path(executable_name).name != executable_name or executable_name in {".", ".."}):
                raise ValueError("packaged_executable_invalid")
            executable = bundle / "Contents/MacOS" / executable_name
            row = {"bundle_id": info.get("CFBundleIdentifier"), "version": info.get("CFBundleShortVersionString"),
                   "bundle_version": info.get("CFBundleVersion"), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
            if executable.is_symlink() or row != {key: expected[identifier][key] for key in row}:
                raise ValueError("packaged_component_bytes_or_version_mismatch")
            checked(["/usr/bin/codesign", "--verify", "--strict", str(bundle)])
            detail = checked(["/usr/bin/codesign", "-dv", "--verbose=4", str(bundle)]).decode("utf-8")
            lines = detail.splitlines()
            if (f"Identifier={identifier}" not in lines or f"TeamIdentifier={team}" not in lines or
                    "Authority=" + build["signature"]["publisher"] not in lines or
                    re.search(r"flags=.*\(runtime\)", detail) is None):
                raise ValueError("packaged_component_signature_invalid")
            entitlements = plistlib.loads(checked(["/usr/bin/codesign", "-d", "--entitlements", "-", str(bundle)]))
            entitlement, value = _REQUIREMENTS[identifier]
            def permits(values):
                actual = values.get(entitlement)
                return actual is True if value is True else isinstance(actual, list) and value in actual
            if not permits(entitlements):
                raise ValueError("packaged_component_entitlement_invalid")
            profile_path = bundle / "Contents/embedded.provisionprofile"
            if not profile_path.is_file() or profile_path.is_symlink():
                raise ValueError("packaged_component_profile_missing")
            profile = plistlib.loads(checked(["/usr/bin/security", "cms", "-D", "-i", str(profile_path)]))
            profile_entitlements = profile.get("Entitlements", {})
            expiration = profile.get("ExpirationDate")
            if (team not in profile.get("TeamIdentifier", []) or
                    profile.get("Name") != expected[identifier]["provisioning_profile"] or
                    (profile_entitlements.get("com.apple.application-identifier") or
                     profile_entitlements.get("application-identifier")) != f"{team}.{identifier}" or
                    not permits(profile_entitlements) or not isinstance(expiration, datetime) or
                    expiration.replace(tzinfo=UTC) <= datetime.now(UTC)):
                raise ValueError("packaged_component_profile_invalid")
            records.append(row)
        if macos_component_set_digest(records) != release["component_set_digest"]:
            raise ValueError("packaged_component_digest_mismatch")
    if hashlib.sha256(package.read_bytes()).hexdigest() != package_digest:
        raise ValueError("package_changed_during_verification")
    return release
