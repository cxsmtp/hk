from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib
import subprocess

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import pytest

import hawk_endpoint_agent.auth.device_key as device_key_module
from hawk_endpoint_agent.auth.device_key import (
    DeviceKeyError,
    EphemeralDeviceKeyProvider,
    MacSecureEnclaveProvider,
    UnsupportedKeyProviderError,
    build_device_key_provider,
)
from hawk_endpoint_agent.auth.linux_tpm2 import LinuxTpm2Provider
from hawk_endpoint_agent.auth.windows_tpm import WindowsTpmCngProvider
import hawk_endpoint_agent.auth.windows_tpm as windows_tpm_module


def test_ephemeral_provider_signs_without_private_key_export() -> None:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("test-endpoint")
    signature = provider.sign(b"hawk bank proof")
    public_key = serialization.load_pem_public_key(identity.public_key_pem.encode())

    assert identity.provider == "development_ephemeral"
    assert identity.hardware_backed is False
    assert "PRIVATE" not in identity.public_key_pem
    assert not hasattr(provider, "export_private_key")
    public_key.verify(signature, b"hawk bank proof", ec.ECDSA(hashes.SHA256()))


def test_bank_profile_rejects_ephemeral_provider() -> None:
    with pytest.raises(UnsupportedKeyProviderError):
        build_device_key_provider(
            provider_name="development_ephemeral",
            security_profile="bank",
        )


def test_development_profile_allows_process_only_provider() -> None:
    provider = build_device_key_provider(
        provider_name="development_ephemeral",
        security_profile="development",
    )
    assert provider.status().provider == "development_ephemeral"

    assert provider.status().hardware_backed is False


def test_macos_provider_allows_cold_secure_enclave_operation(monkeypatch, tmp_path) -> None:
    helper = tmp_path / "hawk-device-identity"
    helper.write_bytes(b"signed-helper-placeholder")
    observed_timeouts: list[float] = []

    def fake_run(argv, **kwargs):
        if argv[0] == "/usr/bin/codesign":
            return SimpleNamespace(
                returncode=0,
                stdout="",
                stderr="Signature=adhoc\nTeamIdentifier=not set",
            )
        observed_timeouts.append(kwargs["timeout"])
        return SimpleNamespace(
            returncode=0,
            stdout=b'{"ok":true,"exists":true,"hardware_backed":true}',
            stderr=b"",
        )

    monkeypatch.setattr(device_key_module.subprocess, "run", fake_run)
    provider = MacSecureEnclaveProvider(
        helper_path=str(helper),
        key_tag="com.hawk.endpoint-agent.test",
        require_signed=False,
    )

    assert provider._run("status")["exists"] is True
    assert observed_timeouts == [45.0]


def test_macos_provider_does_not_claim_hardware_when_helper_is_missing(
    tmp_path,
) -> None:
    provider = MacSecureEnclaveProvider(
        helper_path=str(tmp_path / "missing-helper"),
        key_tag="com.hawk.endpoint-agent.test",
    )

    status = provider.status()

    assert status.available is False
    assert status.hardware_backed is False


@pytest.mark.parametrize(
    "provider",
    [
        WindowsTpmCngProvider(platform_name="darwin"),
        LinuxTpm2Provider(platform_name="darwin"),
    ],
)
def test_hardware_provider_is_unavailable_and_fails_closed_off_platform(provider) -> None:
    status = provider.status()

    assert status.available is False
    assert status.hardware_backed is False
    with pytest.raises(DeviceKeyError):
        provider.ensure_key("test-endpoint")
    with pytest.raises(DeviceKeyError):
        provider.sign(b"hawk bank proof")
    with pytest.raises(DeviceKeyError):
        provider.destroy()


def test_windows_tpm_does_not_trust_an_unsubstantiated_hardware_claim(
    monkeypatch, tmp_path
) -> None:
    powershell = tmp_path / "powershell.exe"
    powershell.write_bytes(b"placeholder")

    observed_commands: list[list[str]] = []

    def fake_run(argv, **kwargs):
        observed_commands.append(argv)
        return SimpleNamespace(
            returncode=0,
            stdout=b'{"ok":true,"available":true,"hardware_backed":true}',
            stderr=b"",
        )

    monkeypatch.setattr("hawk_endpoint_agent.auth.windows_tpm.subprocess.run", fake_run)
    provider = WindowsTpmCngProvider(
        platform_name="win32",
        powershell_path=str(powershell),
    )

    status = provider.status()

    assert status.available is False
    assert status.hardware_backed is False
    assert observed_commands[0][-2:] == ["status", "HawkEndpointAgentDeviceKey"]
    assert observed_commands[0][-3].startswith("& {")
    with pytest.raises(DeviceKeyError):
        provider.ensure_key("test-endpoint")


def test_windows_tpm_identity_is_machine_scoped_for_local_system_service() -> None:
    assert "CngKeyCreationOptions]::MachineKey" in windows_tpm_module._CNG_SCRIPT
    assert "CngKeyOpenOptions]::MachineKey" in windows_tpm_module._CNG_SCRIPT


def test_windows_tpm_uses_signed_native_helper_without_powershell(
    monkeypatch, tmp_path
) -> None:
    helper = tmp_path / "hawk-device-identity.exe"
    helper.write_bytes(b"signed-native-helper")
    calls: list[tuple[list[str], bytes]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs["input"]))
        return SimpleNamespace(
            returncode=0,
            stdout=(
                b'{"ok":true,"available":true,"hardware_backed":true,'
                b'"tpm_present":true,"tpm_ready":true,'
                b'"provider":"Microsoft Platform Crypto Provider",'
                b'"signature":"' + __import__("base64").b64encode(bytes(range(64))) + b'"}'
            ),
            stderr=b"",
        )

    monkeypatch.setattr("hawk_endpoint_agent.auth.windows_tpm.subprocess.run", fake_run)
    provider = WindowsTpmCngProvider(
        platform_name="win32",
        helper_path=str(helper),
        expected_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
        require_signed_helper=True,
        signature_verifier=lambda _path: True,
    )

    provider.sign(b"hawk bank proof")

    assert calls == [
        ([str(helper), "sign", "HawkEndpointAgentDeviceKey"], b"hawk bank proof")
    ]
    assert "powershell" not in " ".join(calls[0][0]).lower()


def test_windows_native_helper_requires_signature_validation_by_default(
    tmp_path,
) -> None:
    helper = tmp_path / "hawk-device-identity.exe"
    helper.write_bytes(b"substituted-helper")
    provider = WindowsTpmCngProvider(
        platform_name="win32",
        helper_path=str(helper),
        expected_helper_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
        signature_verifier=lambda _path: False,
    )

    assert provider.status().available is False
    with pytest.raises(DeviceKeyError, match="signature"):
        provider.sign(b"bank-proof")


def test_windows_native_helper_rejects_digest_substitution(tmp_path) -> None:
    helper = tmp_path / "hawk-device-identity.exe"
    helper.write_bytes(b"substituted-helper")
    provider = WindowsTpmCngProvider(
        platform_name="win32",
        helper_path=str(helper),
        expected_helper_sha256="0" * 64,
        signature_verifier=lambda _path: True,
    )

    assert provider.status().available is False
    with pytest.raises(DeviceKeyError, match="digest"):
        provider.sign(b"bank-proof")


def test_windows_native_identity_helper_uses_platform_provider_and_bounded_stdin() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "native/windows/identity/HawkDeviceIdentity.cpp"
    ).read_text(encoding="utf-8")

    for token in (
        "MS_PLATFORM_CRYPTO_PROVIDER",
        "NCryptOpenStorageProvider",
        "NCryptCreatePersistedKey",
        "NCRYPT_MACHINE_KEY_FLAG",
        "NCRYPT_ALLOW_SIGNING_FLAG",
        "NCRYPT_EXPORT_POLICY_PROPERTY",
        "NCRYPT_ALGORITHM_GROUP_PROPERTY",
        "NCRYPT_LENGTH_PROPERTY",
        "ValidMachineKeyProperties",
        "openStatus != NTE_BAD_KEYSET && openStatus != NTE_NOT_FOUND",
        "BCryptFinishHash",
        "HAWK_IDENTITY_MAX_INPUT_BYTES",
    ):
        assert token in source


def test_linux_tpm_requires_platform_and_all_fixed_tpm2_tools(tmp_path) -> None:
    provider = LinuxTpm2Provider(
        platform_name="linux",
        tool_paths={"getcap": str(tmp_path / "missing-tpm2_getcap")},
    )

    assert provider.status().available is False
    assert provider.status().hardware_backed is False
    with pytest.raises(DeviceKeyError):
        provider.sign(b"hawk bank proof")


@pytest.mark.parametrize(
    ("provider_name", "provider_type"),
    [
        ("windows_tpm_cng", WindowsTpmCngProvider),
        ("linux_tpm2", LinuxTpm2Provider),
    ],
)
def test_factory_returns_fail_closed_hardware_provider(
    provider_name: str, provider_type: type
) -> None:
    provider = build_device_key_provider(
        provider_name=provider_name,
        security_profile="bank",
    )

    assert isinstance(provider, provider_type)


def test_linux_tpm_signs_from_stdin_with_fixed_allowlisted_tool(
    monkeypatch, tmp_path
) -> None:
    tools = {}
    for name in ("getcap", "createprimary", "readpublic", "sign", "flushcontext"):
        executable = tmp_path / f"tpm2_{name}"
        executable.write_bytes(b"placeholder")
        tools[name] = str(executable)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "hawk-test.ctx").write_bytes(b"opaque-tpm-context")
    calls: list[tuple[list[str], bytes]] = []
    tpm_device = tmp_path / "tpmrm0"
    tpm_device.write_bytes(b"device-placeholder")

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs["input"]))
        if argv[0] == tools["getcap"]:
            output = b"TPM2_PT_MANUFACTURER\nTPM2_PT_FIRMWARE_VERSION_1\n"
        else:
            output = bytes(range(64))
        return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

    monkeypatch.setattr("hawk_endpoint_agent.auth.linux_tpm2.subprocess.run", fake_run)
    monkeypatch.setattr(
        "hawk_endpoint_agent.auth.linux_tpm2._is_tpm_character_device",
        lambda path: path == tpm_device,
    )
    provider = LinuxTpm2Provider(
        key_name="hawk-test",
        state_dir=str(state_dir),
        platform_name="linux",
        tool_paths=tools,
        device_path=str(tpm_device),
    )
    payload = b"hawk bank proof"

    provider.sign(payload)

    sign_call = next(call for call in calls if call[0][0] == tools["sign"])
    assert sign_call[1] == payload
    assert sign_call[0][1:3] == ["-T", f"device:{tpm_device}"]
    assert sign_call[0][-3:] == ["-o", "-", "-"]
    assert payload not in [part.encode() for part in sign_call[0]]


def test_linux_tpm_destroy_refuses_unprovable_flush_and_retains_context(
    monkeypatch, tmp_path
) -> None:
    tools = {}
    for name in ("getcap", "createprimary", "readpublic", "sign", "flushcontext"):
        executable = tmp_path / f"tpm2_{name}"
        executable.write_bytes(b"placeholder")
        tools[name] = str(executable)
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    context_path = state_dir / "hawk-test.ctx"
    context_path.write_bytes(b"opaque-tpm-context")
    calls: list[list[str]] = []
    tpm_device = tmp_path / "tpmrm0"
    tpm_device.write_bytes(b"device-placeholder")

    def fake_run(argv, **kwargs):
        calls.append(argv)
        output = b""
        if argv[0] == tools["getcap"] and argv[-1] == "properties-fixed":
            output = b"TPM2_PT_MANUFACTURER\nTPM2_PT_FIRMWARE_VERSION_1\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr=b"")

    monkeypatch.setattr("hawk_endpoint_agent.auth.linux_tpm2.subprocess.run", fake_run)
    monkeypatch.setattr(
        "hawk_endpoint_agent.auth.linux_tpm2._is_tpm_character_device",
        lambda path: path == tpm_device,
    )
    provider = LinuxTpm2Provider(
        key_name="hawk-test",
        state_dir=str(state_dir),
        platform_name="linux",
        tool_paths=tools,
        device_path=str(tpm_device),
    )

    with pytest.raises(DeviceKeyError, match="single-process TPM helper"):
        provider.destroy()

    assert not any(call[0] == tools["flushcontext"] for call in calls)
    assert context_path.exists() is True


@pytest.mark.parametrize('kind,expected', [('missing','device_key_helper_missing'),('unsigned','device_key_helper_unsigned'),('operation','device_key_operation_failed')])
def test_macos_failures_have_safe_fixed_codes(monkeypatch, tmp_path, kind, expected):
    helper = tmp_path / 'identity'
    if kind != 'missing':
        helper.write_bytes(b'helper'); helper.chmod(0o700)
    provider = MacSecureEnclaveProvider(helper_path=str(helper), key_tag='synthetic-key')
    monkeypatch.setattr(provider, '_signature_status', lambda: (kind == 'operation', 'private/path token=secret'))
    if kind == 'operation':
        monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 2, b'private-secret', b'private-secret'))
    with pytest.raises(DeviceKeyError) as caught:
        provider.sign(b'private-payload')
    assert caught.value.code == expected


def test_device_error_rejects_unallowlisted_code():
    assert DeviceKeyError('private secret', code='token=private').code == 'device_key_operation_failed'


def test_macos_preflight_rejects_symlink_and_adhoc_before_key_operation(monkeypatch, tmp_path):
    from hawk_endpoint_agent.auth import device_key
    helper=tmp_path/'identity'; helper.write_bytes(b'helper'); helper.chmod(0o700)
    link=tmp_path/'link'; link.symlink_to(helper)
    calls=[]
    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command,0,'','Signature=adhoc\nTeamIdentifier=not set')
    monkeypatch.setattr(subprocess,'run',run)
    with pytest.raises(DeviceKeyError):device_key.validate_macos_identity_helper(str(link))
    assert calls == []
    with pytest.raises(DeviceKeyError) as caught:device_key.validate_macos_identity_helper(str(helper))
    assert caught.value.code == 'device_key_helper_unsigned'
    assert all(command[0]=='/usr/bin/codesign' for command in calls)


def test_macos_developer_signature_requires_verification_and_team_id(monkeypatch,tmp_path):
    helper=tmp_path/'identity';helper.write_bytes(b'helper');helper.chmod(0o700)
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command,0,'','TeamIdentifier=ABCDEFGHIJ\nAuthority=Developer ID Application: Synthetic')
    monkeypatch.setattr(subprocess,'run',run)
    assert device_key_module.validate_macos_identity_helper(str(helper))==helper
    assert [command[1] for command in commands]==['--verify','-dv']
    monkeypatch.setattr(subprocess,'run',lambda command,**kw:subprocess.CompletedProcess(command,1,'','private-secret'))
    with pytest.raises(DeviceKeyError) as caught:device_key_module.validate_macos_identity_helper(str(helper))
    assert caught.value.code=='device_key_helper_unsigned'


def test_legacy_runtime_symlink_resolves_to_signed_regular_helper(monkeypatch,tmp_path):
    helper=tmp_path/'identity';helper.write_bytes(b'helper');helper.chmod(0o700)
    legacy=tmp_path/'legacy-bin';legacy.symlink_to(helper)
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        if command[0]=='/usr/bin/codesign':return subprocess.CompletedProcess(command,0,'','TeamIdentifier=ABCDEFGHIJ')
        return subprocess.CompletedProcess(command,0,b'{"ok":true,"exists":true,"hardware_backed":true}',b'')
    monkeypatch.setattr(subprocess,'run',run)
    provider=MacSecureEnclaveProvider(helper_path=str(legacy),key_tag='synthetic-key')
    assert provider.status().available is True
    assert commands[-1]==[str(helper),'status','synthetic-key']
