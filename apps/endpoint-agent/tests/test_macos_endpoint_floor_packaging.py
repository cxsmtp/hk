from __future__ import annotations

import json
import hashlib
import plistlib
import subprocess
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
import pytest


ROOT = Path(__file__).resolve().parents[1]
MACOS = ROOT / "native" / "macos"


def _text(relative: str) -> str:
    return (MACOS / relative).read_text(encoding="utf-8")


def test_macos_host_and_system_extension_project_has_explicit_targets() -> None:
    project = _text("HawkEndpointFloor.xcodeproj/project.pbxproj")
    host_entitlements = _text("host/HawkEndpointHost.entitlements")
    host_info = _text("host/Info.plist")
    endpoint_info = _text("endpoint-security/Info.plist")

    assert "HawkEndpointHost" in project
    assert "HawkEndpointSecurityExtension" in project
    assert "HawkNetworkFilterExtension" in project
    assert "HawkManagedRoutingExtension" in project
    assert "SystemExtensions.framework" in project
    assert "libEndpointSecurity.tbd" in project
    assert "NetworkExtension.framework" in project
    assert "com.apple.developer.system-extension.install" in host_entitlements
    assert "ai.hawk.endpoint.host" in host_info
    assert "NSSystemExtensionUsageDescription" in endpoint_info


def test_macos_capabilities_remain_unverified_until_target_host_receipts() -> None:
    contracts = [
        json.loads(_text("endpoint-security/build-contract.json")),
        json.loads(_text("content-filter/build-contract.json")),
        json.loads(_text("network-extension/build-contract.json")),
    ]
    for contract in contracts:
        assert contract["source_ready_is_runtime_ready"] is False
        assert contract["verification_status"] == "unverified"
        assert contract["activation_default"] == "off"
        assert "signed_artifact" in contract["runtime_evidence_required"]
        assert "target_os_acceptance" in contract["runtime_evidence_required"]


def test_endpoint_security_policy_delivery_uses_os_peer_pin_and_detached_signature() -> None:
    source = _text("endpoint-security/HawkEndpointPolicyXPCService.m")
    info = _text("endpoint-security/Info.plist")

    assert "setConnectionCodeSigningRequirement" in source
    assert "HawkMacVerifyAndInstallPolicyEnvelope" in source
    assert "HawkPolicySigningPublicKeyX963Base64" in source
    assert "HawkMacCopyPolicyHealth" in source
    assert "NSEndpointSecurityMachServiceName" in info
    assert "HawkPolicyPeerRequirement" in info
    assert "HawkPolicySigningPublicKeyX963Base64" in info
    assert not any(token in source for token in ("system(", "popen(", "NSTask", "curl"))


def test_read_only_verifier_defaults_to_needs_attention_without_artifacts() -> None:
    script = ROOT / "scripts" / "verify_managed_macos.sh"
    run = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["display_state"] == "Needs attention"
    assert "missing_package" in result["reason_codes"]


@pytest.mark.parametrize("name", [
    "build_bank_macos.sh", "package_managed_macos.sh", "notarize_bank_macos.sh",
])
def test_release_scripts_reject_missing_inputs_without_side_effects(name: str) -> None:
    script = ROOT / "scripts" / name
    syntax = subprocess.run(["/bin/sh", "-n", str(script)], capture_output=True, text=True)
    assert syntax.returncode == 0, syntax.stderr
    run = subprocess.run(["/bin/sh", str(script)], capture_output=True, text=True, check=False)
    assert run.returncode == 2


def test_routing_extension_bundle_identifier_matches_project_target() -> None:
    metadata = plistlib.loads((MACOS / "network-extension/Info.plist").read_bytes())
    assert metadata["CFBundleIdentifier"] == "ai.hawk.endpoint.managed-routing"
    assert "PRODUCT_BUNDLE_IDENTIFIER = ai.hawk.endpoint.managed-routing" in _text(
        "HawkEndpointFloor.xcodeproj/project.pbxproj"
    )


def test_extension_copy_phase_resolves_to_outer_app_contents_and_routing_executable() -> None:
    project_path = MACOS / "HawkEndpointFloor.xcodeproj/project.pbxproj"
    converted = subprocess.run(
        ["/usr/bin/plutil", "-convert", "json", "-o", "-", str(project_path)],
        capture_output=True, text=True, check=False,
    )
    assert converted.returncode == 0, converted.stderr
    objects = json.loads(converted.stdout)["objects"]
    copy_phase = objects["D00100000000000000000004"]
    assert copy_phase["dstSubfolderSpec"] == "1" or copy_phase["dstSubfolderSpec"] == 1
    assert str(Path("HawkEndpointHost.app") / copy_phase["dstPath"]) == (
        "HawkEndpointHost.app/Contents/Library/SystemExtensions"
    )
    assert len(copy_phase["files"]) == 3
    routing = objects["E00400000000000000000001"]
    routing_info = plistlib.loads((MACOS / "network-extension/Info.plist").read_bytes())
    assert routing["productName"] == "HawkManagedRoutingExtension"
    assert routing_info["CFBundleExecutable"] == "$(EXECUTABLE_NAME)"


def test_read_only_verifier_rejects_unsigned_or_incomplete_v2_evidence(tmp_path: Path) -> None:
    build = tmp_path / "build.json"
    notary = tmp_path / "notary.json"
    build.write_text('{"schema":"hawk.bank-macos-build-evidence","version":2}', encoding="utf-8")
    notary.write_text('{"schema":"hawk.bank-macos-notarization-evidence","version":2}', encoding="utf-8")
    script = ROOT / "scripts/verify_managed_macos.sh"
    run = subprocess.run([
        "/bin/sh", str(script), "--build-evidence", str(build),
        "--notarization-evidence", str(notary),
    ], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result["display_state"] == "Needs attention"
    assert "v2_release_evidence_invalid" in result["reason_codes"]


def _release_fixture(tmp_path: Path, mutation: str = ""):
    from hawk_endpoint_agent.macos_native import HOST_BUNDLE_ID, EXTENSION_BUNDLE_IDS, macos_component_set_digest
    source = tmp_path / "source" / "Applications" / "Hawk Endpoint.app"
    records = []
    requirement = [
        ("com.apple.developer.system-extension.install", True),
        ("com.apple.developer.endpoint-security.client", True),
        ("com.apple.developer.networking.networkextension", ["content-filter-provider-systemextension"]),
        ("com.apple.developer.networking.networkextension", ["transparent-proxy-provider"]),
    ]
    for index, identifier in enumerate([HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS]):
        bundle = source if index == 0 else source / "Contents/Library/SystemExtensions" / f"extension-{index}.systemextension"
        (bundle / "Contents/MacOS").mkdir(parents=True)
        (bundle / "Contents/MacOS/main").write_bytes(identifier.encode())
        (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": identifier, "CFBundleExecutable": "main",
            "CFBundleShortVersionString": "1.2.3", "CFBundleVersion": "9",
        }))
        (bundle / "Contents/embedded.provisionprofile").write_bytes(b"profile")
        records.append({"bundle_id": identifier, "version": "1.2.3", "bundle_version": "9",
            "team_id": "ABCDEFGHIJ", "sha256": hashlib.sha256(identifier.encode()).hexdigest(),
            "entitlement": requirement[index][0], "provisioning_profile": identifier,
            "hardened_runtime": True})
    stamp = (datetime.now(UTC) - timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    build = {"schema": "hawk.bank-macos-build-evidence", "version": 2,
        "artifact": {"name": "Hawk Endpoint.app", "sha256": records[0]["sha256"], "binary_version": "1.2.3"},
        "signature": {"team_id": "ABCDEFGHIJ", "publisher": "Developer ID Application: Hawk", "hardened_runtime": True},
        "components": records, "verified_at": stamp,
        "component_set_digest": macos_component_set_digest([{k: row[k] for k in ("bundle_id", "version", "bundle_version", "sha256")} for row in records])}
    package = tmp_path / "release.pkg"
    package.write_bytes(b"signed-and-stapled-test-package")
    notary = {"schema": "hawk.bank-macos-notarization-evidence", "version": 2,
        "team_id": "ABCDEFGHIJ", "build_evidence_sha256": hashlib.sha256(canonical(build)).hexdigest(),
        "component_evidence_sha256": hashlib.sha256(canonical(records)).hexdigest(),
        "submitted_package_sha256": "a" * 64, "stapled_package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
        "status": "accepted", "submission_id": "test-submission", "staple_status": "valid", "verified_at": stamp}
    if mutation == "package_bytes":
        package.write_bytes(b"substituted")
    extension = source / "Contents/Library/SystemExtensions/extension-3.systemextension"
    if mutation == "executable":
        (extension / "Contents/MacOS/main").write_bytes(b"substituted")
    if mutation == "version":
        info = plistlib.loads((extension / "Contents/Info.plist").read_bytes())
        info["CFBundleVersion"] = "10"
        (extension / "Contents/Info.plist").write_bytes(plistlib.dumps(info))
    if mutation == "extra_extension":
        shutil.copytree(extension, extension.with_name("extra.systemextension"))
    calls = []
    def command(args, **kwargs):
        calls.append(args)
        output = b""
        if args[:3] == ["/usr/bin/xcrun", "stapler", "validate"] and mutation == "stapler":
            return subprocess.CompletedProcess(args, 1, b"", b"invalid")
        if args[0] == "/usr/sbin/spctl" and mutation == "gatekeeper":
            return subprocess.CompletedProcess(args, 1, b"", b"rejected")
        if "--check-signature" in args:
            output = b"Developer ID Installer: Hawk (ABCDEFGHIJ)"
        elif "--payload-files" in args:
            output = b"Applications/Hawk Endpoint.app/Contents/Info.plist\n"
            if mutation == "unsafe_path":
                output += b"../../escape\n"
        elif "--expand" in args:
            target = Path(args[-1])
            target.mkdir()
            component = target / "component.pkg"
            component.mkdir()
            (component / "Payload").write_bytes(b"payload")
            if mutation == "multiple_components":
                (target / "second.pkg").mkdir()
            if mutation == "scripts":
                (component / "Scripts").write_bytes(b"script")
        elif args[0] == "/usr/bin/tar":
            if "-tf" in args:
                output = b"Applications/Hawk Endpoint.app/Contents/Info.plist\n"
            else:
                target = Path(args[args.index("-C") + 1])
                shutil.copytree(source.parent, target / "Applications")
                launch = target / "Library/LaunchAgents/ai.hawk.endpoint-agent.plist"
                launch.parent.mkdir(parents=True)
                launch.write_bytes(plistlib.dumps({"EnvironmentVariables": {"HAWK_AGENT_CONFIG":
                    "/tmp/hostile.json" if mutation == "launch_config" else "/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json"}}))
                if mutation == "symlink_escape":
                    (target / "escape").symlink_to(tmp_path)
        elif args[0] == "/usr/bin/codesign" and "-dv" in args:
            info = plistlib.loads((Path(args[-1]) / "Contents/Info.plist").read_bytes())
            team = "ZZZZZZZZZZ" if mutation == "team" else "ABCDEFGHIJ"
            output = f"Identifier={info['CFBundleIdentifier']}\nTeamIdentifier={team}\nAuthority=Developer ID Application: Hawk\nflags=0x10000(runtime)\n".encode()
        elif args[0] == "/usr/bin/codesign" and "--entitlements" in args:
            info = plistlib.loads((Path(args[-1]) / "Contents/Info.plist").read_bytes())
            index = [HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS].index(info["CFBundleIdentifier"])
            output = plistlib.dumps({} if mutation == "entitlement" else dict([requirement[index]]))
        elif args[0] == "/usr/bin/security":
            info = plistlib.loads((Path(args[-1]).parent / "Info.plist").read_bytes())
            identifier = info["CFBundleIdentifier"]
            index = [HOST_BUNDLE_ID, *EXTENSION_BUNDLE_IDS].index(identifier)
            output = plistlib.dumps({"Name": "wrong" if mutation == "profile" else identifier,
                "TeamIdentifier": ["ABCDEFGHIJ"], "ExpirationDate": datetime.now() + timedelta(days=1),
                "Entitlements": {"com.apple.application-identifier": "ABCDEFGHIJ." + identifier, **dict([requirement[index]])}})
        return subprocess.CompletedProcess(args, 0, output, b"")
    return package, build, notary, command, calls


def test_release_verifier_binds_actual_apple_assessment_and_packaged_components(tmp_path: Path) -> None:
    from hawk_endpoint_agent.macos_release import verify_macos_package
    package, build, notary, command, calls = _release_fixture(tmp_path)
    result = verify_macos_package(package, build, notary,
        installed_component_digest=build["component_set_digest"],
        accepted_component_digest=build["component_set_digest"], run=command, temporary_parent=tmp_path)
    assert result["component_set_digest"] == build["component_set_digest"]
    assert ["/usr/bin/xcrun", "stapler", "validate", str(package)] in calls
    assert ["/usr/sbin/spctl", "--assess", "--type", "install", "--verbose=4", str(package)] in calls
    assert any(args[0] == "/usr/bin/tar" and "-xf" in args for args in calls)


@pytest.mark.parametrize("mutation", [
    "stapler", "gatekeeper", "package_bytes", "unsafe_path", "multiple_components", "scripts",
    "symlink_escape", "executable", "version", "team", "entitlement", "profile", "extra_extension",
    "installed_digest", "acceptance_digest", "launch_config",
])
def test_release_verifier_rejects_forged_or_substituted_artifacts(tmp_path: Path, mutation: str) -> None:
    from hawk_endpoint_agent.macos_release import verify_macos_package
    package, build, notary, command, calls = _release_fixture(tmp_path, mutation)
    with pytest.raises(ValueError):
        verify_macos_package(package, build, notary,
            installed_component_digest="0" * 64 if mutation == "installed_digest" else build["component_set_digest"],
            accepted_component_digest="0" * 64 if mutation == "acceptance_digest" else build["component_set_digest"],
            run=command, temporary_parent=tmp_path)
    if mutation == "unsafe_path":
        assert not any(args[0] == "/usr/bin/tar" and "-xf" in args for args in calls)
