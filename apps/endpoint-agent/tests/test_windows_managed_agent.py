from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest

from hawk_endpoint_agent.windows.command import CommandResult
from hawk_endpoint_agent.windows.managed_installer import (
    ManagedInstallRequest,
    WindowsManagedInstaller,
)
from hawk_endpoint_agent.windows.native_driver import (
    WindowsNativeDriver,
    WindowsNativePackage,
)
from hawk_endpoint_agent.windows.state import InstallStateStore
from hawk_endpoint_agent.config import load_config


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native" / "windows"
SCRIPTS = ROOT / "scripts" / "windows"


class FakeRunner:
    def __init__(
        self,
        responses: dict[tuple[str, ...], CommandResult] | None = None,
    ) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.responses = responses or {}

    def run(self, argv, *, timeout: float = 30.0) -> CommandResult:
        del timeout
        command = tuple(str(value) for value in argv)
        self.calls.append(command)
        return self.responses.get(command, CommandResult(command, 0, "", ""))


def _package(tmp_path: Path) -> WindowsNativePackage:
    package = tmp_path / "package"
    package.mkdir()
    for name in (
        "HawkEndpointFloor.inf",
        "HawkEndpointFloor.sys",
        "HawkEndpointService.exe",
        "HawkEndpointCA.cer",
    ):
        (package / name).write_bytes(b"signed-test-artifact")
    return WindowsNativePackage.from_directory(package)


def test_native_source_has_bounded_service_sid_policy_handoff() -> None:
    policy_source = (NATIVE / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    control_source = (NATIVE / "common" / "HawkKernelControl.c").read_text(
        encoding="utf-8"
    )
    ioctl_header = (NATIVE / "include" / "HawkKernelPolicyIoctl.h").read_text(
        encoding="utf-8"
    )

    assert "HawkFloorPublishSnapshot" in policy_source
    assert "HawkFloorEvaluateFile" in policy_source
    assert "HawkFloorEvaluateNetwork" in policy_source
    assert "HawkFloorEvaluateProcess" in policy_source
    assert "FileRenameInformation" in policy_source
    assert "FileEndOfFileInformation" in policy_source
    assert "FILE_DELETE_ON_CLOSE" in policy_source
    assert "FILE_OPEN_IF" in policy_source
    assert "FILE_OVERWRITE_IF" in policy_source
    assert "HawkEvaluateFilePrimitive" in policy_source
    assert "return HAWK_FLOOR_UNKNOWN_ENDPOINT_ACTION" in policy_source
    assert "HAWK_WINDOWS_MAX_POLICY_BYTES" in ioctl_header
    assert "IOCTL_HAWK_POLICY_REPLACE" in ioctl_header
    assert "IOCTL_HAWK_POLICY_ARM" in ioctl_header
    assert "METHOD_BUFFERED" in ioctl_header
    assert "IoCreateDeviceSecure" in control_source
    service_digest = hashlib.sha1(
        "HawkEndpointAgent".upper().encode("utf-16-le")
    ).digest()
    service_sid = "S-1-5-80-" + "-".join(
        str(value) for value in struct.unpack("<5I", service_digest)
    )
    assert service_sid == (
        "S-1-5-80-1135535808-2200536610-2577844612-1285382279-175032405"
    )
    assert service_sid in control_source
    assert "(A;;GA;;;SY)" not in control_source
    assert "(A;;GR;;;BA)" in control_source
    assert "IoValidateDeviceIoControlAccess(irp, FILE_WRITE_DATA)" in control_source
    assert "IoValidateDeviceIoControlAccess(irp, FILE_READ_DATA)" in control_source
    assert "signatureVerified" in control_source
    assert "configurationIntegrityValid" in control_source
    assert not any(
        token in policy_source + control_source
        for token in ("WinHttp", "curl", "http://", "https://", "FltSendMessage")
    )


def test_wdk_project_is_one_lightweight_driver_with_reproducible_inputs() -> None:
    project = (NATIVE / "HawkEndpointFloor" / "HawkEndpointFloor.vcxproj").read_text(
        encoding="utf-8"
    )
    inf_template = (NATIVE / "HawkEndpointFloor" / "HawkEndpointFloor.inf.in").read_text(
        encoding="utf-8"
    )

    for source in (
        r"..\minifilter\HawkMinifilter.c",
        r"..\process-control\HawkProcessControl.c",
        r"..\wfp\HawkWfpCallout.c",
        r"..\common\HawkKernelPolicy.c",
        r"..\common\HawkKernelControl.c",
    ):
        assert source in project
    assert "FltMgr.lib" in project
    assert "Fwpkclnt.lib" in project
    assert "Wdmsec.lib" in project
    assert "__HAWK_MINIFILTER_ALTITUDE__" in inf_template
    assert "HawkEndpointFloor" in inf_template
    assert "FSFilter Activity Monitor" in inf_template


def test_windows_build_and_install_scripts_refuse_unsigned_or_unallocated_builds() -> None:
    build = (SCRIPTS / "build_managed_agent.ps1").read_text(encoding="utf-8")
    install = (SCRIPTS / "install_managed_agent.ps1").read_text(encoding="utf-8")
    enroll = (SCRIPTS / "enroll_managed_agent.ps1").read_text(encoding="utf-8")
    verify = (SCRIPTS / "verify_managed_agent.ps1").read_text(encoding="utf-8")
    uninstall = (SCRIPTS / "uninstall_managed_agent.ps1").read_text(
        encoding="utf-8"
    )

    assert "MinifilterAltitude" in build
    assert "SigningCertificateThumbprint" in build
    assert "signtool.exe" in build.lower()
    assert "verify /kp" in build.lower()
    assert "__HAWK_MINIFILTER_ALTITUDE__" in build
    assert "Get-AuthenticodeSignature" in install
    assert "pnputil.exe" in install.lower()
    assert "HawkEndpointService.exe" in install
    assert "start= demand" in install
    assert "--enroll-existing-config" in enroll
    assert "--enrollment-bundle-stdin" in enroll
    assert 'S-1-5-18' in enroll
    assert "start= auto" in enroll
    for field in (
        "access_token",
        "bearer_token",
        "client_secret",
        "enrollment_code",
        "private_key",
        "policy_signing_private_key",
    ):
        assert field in install
    assert "runtime_entry.py" in build
    assert "--collect-submodules hawk_endpoint_agent" in build
    assert 'pyInstallerVersion -ne "6.21.0"' in build
    assert 'cryptographyVersion -ne "49.0.0"' in build
    assert "microsoft's hardware dev" in install.lower()
    assert "New-FileCatalog" in build
    assert "HawkManagedPackage.cat" in build
    assert "Test-FileCatalog" in install
    assert "showsid HawkEndpointAgent" in install
    assert "sidtype HawkEndpointAgent unrestricted" in install
    assert "depend= HawkEndpointFloor" in install
    assert "Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue" in install
    assert "Refusing to overwrite an existing Hawk managed endpoint" in install
    assert "[StringComparer]::OrdinalIgnoreCase.Equals" in install
    assert "AllowDevelopmentPackage" in install
    assert 'build_profile -ne "production"' in install
    assert "OSArchitecture" in install
    assert "Package architecture does not match" in install
    assert "$administratorsAccess" in install
    assert "Set-HawkProtectedTreeAcl" in install
    assert "Production managed installation must run as LocalSystem" in install
    assert install.rindex("AdministratorsAccess ReadAndExecute") > install.index(
        "managed-install-state.json"
    )
    assert "Reassert protected root ACLs before transactional rollback" in install
    assert "Reassert managed root ACLs for LocalSystem removal" in uninstall
    assert "$administratorsRemovalAccess" in uninstall
    assert "Production managed removal must run as LocalSystem" in uninstall
    assert "EndpointAgentInstallStaging" in install
    assert "Managed package source contains a reparse point" in install
    assert "Get-AuthenticodeSignature $PSCommandPath" in install
    assert install.index("$protectedStaging = Join-Path") < install.index("try {")
    assert install.index("try {") < install.index(
        "New-Item -ItemType Directory -Path $protectedStaging"
    )
    assert install.index("try {") < install.index("$required = @(")
    assert install.rindex("} finally {") > install.index("throw $originalError")
    assert "published_inf_unknown" in install
    assert "Get-HawkPublishedInfSet" in install
    assert "identity_helper_sha256" in install
    assert "ReadToEnd" not in enroll
    assert "[Console]::In.Read($buffer" in enroll
    assert "enrollment_started" in enroll
    assert "WaitForStatus" in enroll
    assert "RequireCurrentPolicy" in verify
    assert "RequireEnforce" in verify
    assert "hawk.windows-managed-removal-recovery" in uninstall
    assert "hawk-device-identity.exe" in uninstall
    assert 'destroy $deviceKeyTag' in uninstall
    assert "TPM identity destruction failed" in uninstall
    assert "transactional-install-state.json" in install
    assert "rollback_failed" in install
    assert "preserving recovery ledger" in install
    assert "Confirm-HawkServiceAbsent" in uninstall
    assert "Confirm-HawkFilterAbsent" in uninstall
    assert "Confirm-HawkDriverPackageAbsent" in uninstall
    assert "recovery ledger was preserved" in uninstall

    service_source = (
        ROOT / "src" / "hawk_endpoint_agent" / "windows" / "service.py"
    ).read_text(encoding="utf-8")
    assert '"depend="' in service_source
    assert '"HawkEndpointFloor"' in service_source
    for target in (
        "10_VB_X64",
        "10_CO_X64",
        "10_NI_X64",
        "10_GE_X64",
        "10_25H2_X64",
        "ServerFE_X64",
        "Server2025_X64",
        "10_VB_ARM64",
        "10_CO_ARM64",
        "10_NI_ARM64",
        "10_GE_ARM64",
        "10_25H2_ARM64",
        "ServerFE_ARM64",
        "Server2025_ARM64",
    ):
        assert target in build
    assert "11_X64" not in build
    assert "Server2022_X64" not in build


def test_windows_managed_deployment_is_crash_recoverable_and_identity_bound() -> None:
    build = (SCRIPTS / "build_managed_agent.ps1").read_text(encoding="utf-8")
    install = (SCRIPTS / "install_managed_agent.ps1").read_text(encoding="utf-8")
    uninstall = (SCRIPTS / "uninstall_managed_agent.ps1").read_text(
        encoding="utf-8"
    )
    deployment = SCRIPTS / "HawkManagedDeployment.psm1"

    assert deployment.is_file()
    helper = deployment.read_text(encoding="utf-8")
    assert "function Assert-HawkNoReparseAncestor" in helper
    assert "function Assert-HawkManagedTreeIntegrity" in helper
    assert "function Set-HawkProtectedTreeAcl" in helper
    assert "function Remove-HawkManagedTree" in helper
    assert "SetOwner($systemSid)" in helper
    assert "function Write-HawkAtomicJson" in helper
    assert "[IO.FileOptions]::WriteThrough" in helper
    assert "function Read-HawkManagedLedger" in helper
    assert "function Get-HawkDriverPackageIdentity" in helper
    assert "function Test-HawkServiceIdentity" in helper
    assert "function Test-HawkKernelServiceIdentity" in helper
    assert "Win32_Service" in helper
    assert "CurrentControlSet\\Services\\HawkEndpointFloor" in helper
    assert "Get-WindowsDriver -Online -Driver" in helper
    assert 'ProviderName -ne "Hawk AI Security"' in helper
    assert 'ClassName -ne "ActivityMonitor"' in helper
    assert 'HawkEndpointFloor.inf' in helper

    assert '"HawkManagedDeployment.psm1"' in build
    assert "Set-AuthenticodeSignature" in build
    for script in (install, uninstall):
        assert "Get-AuthenticodeSignature $deploymentModulePath" in script
        assert "Import-Module $deploymentModulePath" in script
        assert "Assert-HawkManagedTreeIntegrity" in script
        assert "Set-HawkProtectedTreeAcl" in script
        assert "Remove-Item $InstallRoot -Recurse" not in script
        assert "Remove-Item -LiteralPath $InstallRoot -Recurse" not in script

    assert "Production managed installation must run as LocalSystem" in install
    assert 'version = 2' in install
    assert 'driver_store_before = @()' in install
    assert 'Save-TransactionState "driver_staging"' in install
    assert "Assert-HawkDriverPackageEvidence" in install
    assert "expected_driver_provider" in install
    assert "package_manifest_sha256" in install

    assert 'version = 2' in uninstall
    assert "Read-HawkManagedLedger" in uninstall
    assert "Resolve-HawkTransactionPublishedInf" in uninstall
    assert "Save-RemovalRecoveryState" in uninstall
    assert 'Save-RemovalRecoveryState "service_removed"' in uninstall
    assert 'Save-RemovalRecoveryState "driver_unloaded"' in uninstall
    assert 'Save-RemovalRecoveryState "driver_package_removed"' in uninstall
    assert "Assert-HawkDriverPackageEvidence" in uninstall
    assert "Test-HawkServiceIdentity" in uninstall
    assert "Test-HawkKernelServiceIdentity" in uninstall
    assert "Do not trust recovery-ledger completion booleans" in uninstall


def test_windows_managed_deployment_closes_production_recovery_gaps() -> None:
    install = (SCRIPTS / "install_managed_agent.ps1").read_text(encoding="utf-8")
    enroll = (SCRIPTS / "enroll_managed_agent.ps1").read_text(encoding="utf-8")
    uninstall = (SCRIPTS / "uninstall_managed_agent.ps1").read_text(
        encoding="utf-8"
    )
    helper = (SCRIPTS / "HawkManagedDeployment.psm1").read_text(
        encoding="utf-8"
    )

    # Windows PowerShell 5.1 writes a BOM for `-Encoding utf8`; the Python
    # runtime intentionally accepts only ordinary UTF-8 JSON.
    assert "Set-Content $managedConfig -Encoding utf8" not in install
    assert "Set-Content $statePath -Encoding utf8" not in enroll
    assert "Write-HawkAtomicJson -Path $managedConfig" in install
    assert "Write-HawkAtomicJson -Path $statePath" in enroll

    # Strict state validation must still accept every state produced by the
    # signed enrollment lifecycle, including its enrolled_at timestamp.
    for status in (
        "awaiting_enrollment",
        "enrollment_started",
        "enrolled",
        "enrolled_and_started",
    ):
        assert f'"{status}"' in helper
    assert '"enrolled_at"' in helper

    # A protected tree is built from a fresh DACL and verified rather than
    # retaining arbitrary explicit ACEs from a pre-created directory.
    assert "SetAccessRuleProtection($true, $false)" in helper
    assert "GetSecurityDescriptorSddlForm" in helper
    assert "function Assert-HawkProtectedTreeAcl" in helper

    # Recovery is identity-bound to exact package evidence, not only an OEM
    # INF name/provider/class tuple.
    assert "function Assert-HawkDriverPackageEvidence" in helper
    assert "/export-driver" in helper
    assert "package-manifest.json" in install
    assert "DriverEvidence" in install
    assert "Assert-HawkDriverPackageEvidence" in uninstall

    # A durable non-installed transaction is recoverable using the already
    # verified package instead of permanently refusing the next install.
    assert "Recovering an interrupted Hawk managed installation" in install
    assert "Read-HawkManagedLedger -Path $existingTransaction" in install
    guard = install.index("} elseif ($existingService -or $existingBinaries.Count")
    assert install.rfind(
        "$existingService = Get-Service -Name HawkEndpointAgent", 0, guard
    ) >= 0
    assert install.rfind("$existingBinaries = @(", 0, guard) >= 0

    # Purge keeps an independent removal checkpoint until state deletion has
    # completed, so a crash cannot strand the TPM cleanup path.
    assert "install-removal-recovery.json" in uninstall
    assert "identity_destroyed" in uninstall
    assert "$identityProbeAvailable" in uninstall
    assert "$recordedIdentityDestroyed -and -not $identityProbeAvailable" in uninstall
    assert "state_root_removed" in uninstall


def test_runtime_rejects_common_static_secret_aliases(tmp_path: Path) -> None:
    for field in (
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
        "ACCESS_TOKEN",
        "Client_Secret",
    ):
        config = tmp_path / f"{field}.json"
        config.write_text(json.dumps({field: "must-not-persist"}), encoding="utf-8")
        with pytest.raises(ValueError, match="static endpoint credentials"):
            load_config(config)


def test_bank_managed_config_rejects_unknown_persistent_fields(tmp_path: Path) -> None:
    config = tmp_path / "managed.json"
    config.write_text(
        json.dumps(
            {
                "security_profile": "bank",
                "deployment_mode": "managed_machine",
                "unreviewed_extension": {"access_token": "must-not-persist"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unknown managed configuration fields"):
        load_config(config)


def test_driver_uses_documented_process_callbacks_and_normalizes_wfp_paths() -> None:
    policy_source = (NATIVE / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )
    process_source = (
        NATIVE / "process-control" / "HawkProcessControl.c"
    ).read_text(encoding="utf-8")
    wfp_source = (NATIVE / "wfp" / "HawkWfpCallout.c").read_text(
        encoding="utf-8"
    )

    assert "PsSetCreateProcessNotifyRoutineEx" in process_source
    assert "PsGetNextProcess" not in policy_source
    assert "SeLocateProcessImageName" in policy_source
    assert "HawkSeedProcessIdentities" in policy_source
    assert "HawkSha256UnicodeInsensitive(imageFileName" in policy_source
    assert "FileOpenNameAvailable" in process_source
    assert "SeLocateProcessImageName(Process" in process_source
    assert "PCUNICODE_STRING imageName = NULL;" in process_source
    assert "imageName = locatedImageName;" in process_source
    assert process_source.index("SeLocateProcessImageName(Process") < process_source.index(
        "CreateInfo->FileOpenNameAvailable"
    )
    assert "createInfo->CreatingThreadId.UniqueProcess" in policy_source
    assert "createInfo->CreatingThreadId->UniqueProcess" not in policy_source
    assert "const VOID *classifyContext" not in wfp_source
    assert "UNREFERENCED_PARAMETER(classifyContext)" not in wfp_source
    assert "_In_ const FWPS_FILTER0 *filter" in wfp_source
    assert "FwpmBfeStateSubscribeChanges0" in wfp_source
    assert "FwpmBfeStateGet0" in wfp_source
    assert "HawkWfpReady" in wfp_source
    assert "FWP_ACTION_CALLOUT_UNKNOWN" in wfp_source
    assert "FWP_ACTION_CONTINUE" in wfp_source
    assert "FWP_ACTION_PERMIT" not in wfp_source
    assert "FWPS_CLASSIFY_OUT_FLAG_ABSORB" not in wfp_source
    minifilter_source = (NATIVE / "minifilter" / "HawkMinifilter.c").read_text(
        encoding="utf-8"
    )
    assert "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" not in minifilter_source
    assert "IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION" not in policy_source
    assert "IRP_MJ_DIRECTORY_CONTROL" in minifilter_source
    assert "IRP_MJ_SET_SECURITY" in minifilter_source
    assert "if (Data->RequestorMode == KernelMode)" in minifilter_source
    control_source = (NATIVE / "common" / "HawkKernelControl.c").read_text(
        encoding="utf-8"
    )
    assert "EX_RUNDOWN_REF" in control_source
    assert "ExWaitForRundownProtectionRelease" in control_source
    assert "IRP_MJ_CLEANUP" in control_source
    sha_source = (NATIVE / "common" / "HawkSha256.c").read_text(encoding="utf-8")
    assert "RtlUpcaseUnicodeChar(" not in sha_source
    assert "observed >= L'a' && observed <= L'z'" in sha_source


def test_windows_service_fails_closed_when_child_cannot_start_or_be_supervised() -> None:
    service_source = (
        NATIVE / "service" / "HawkEndpointService.cpp"
    ).read_text(encoding="utf-8")

    assert "const DWORD resumeResult = ResumeThread(process.hThread);" in service_source
    assert "resumeResult == static_cast<DWORD>(-1)" in service_source
    assert "TerminateProcess(process.hProcess, error);" in service_source
    assert "result == WAIT_FAILED" in service_source
    assert "const DWORD waitError = result == WAIT_FAILED ? GetLastError()" in service_source
    assert "childExit != NO_ERROR ? childExit : ERROR_PROCESS_ABORTED" in service_source
    assert "Report(SERVICE_STOPPED, serviceError);" in service_source


def test_windows_token_wrapping_key_uses_native_page_locking() -> None:
    vault_source = (
        ROOT / "src" / "hawk_endpoint_agent" / "auth" / "memory_vault.py"
    ).read_text(encoding="utf-8")

    assert 'if os.name == "nt":' in vault_source
    assert "kernel32.VirtualLock" in vault_source
    assert "kernel32.VirtualUnlock" in vault_source


def test_native_callbacks_short_circuit_monitor_and_use_bounded_object_binding() -> None:
    policy_source = (NATIVE / "common" / "HawkKernelPolicy.c").read_text(
        encoding="utf-8"
    )

    assert policy_source.count(
        "if (!HawkPolicyIsArmed()) return HawkKernelAllow;"
    ) == 2
    assert "HawkCaptureArmSessionEpoch(&evaluationArmEpoch)" in policy_source
    assert "HawkArmSessionCurrent(evaluationArmEpoch)" in policy_source
    assert "HawkAcquireControlTransitionLock();" in policy_source
    assert "if (!HawkPolicyIsArmed()) {" in policy_source
    assert "FltGetFileNameInformation" not in policy_source
    assert "HawkBindFileIdentity" in policy_source
    assert "FltQueryInformationFile" in policy_source
    assert "request->stableResourceIdentityHash" in policy_source
    assert "request->destinationReferenceHash" in policy_source
    assert "const BOOLEAN expiredGoverned" in policy_source
    assert "policy->snapshot.expiresAtMonotonicNs <= observedNow" in policy_source
    process_source = (
        NATIVE / "process-control" / "HawkProcessControl.c"
    ).read_text(encoding="utf-8")
    policy_header = (NATIVE / "include" / "HawkKernelPolicy.h").read_text(
        encoding="utf-8"
    )
    assert "BOOLEAN HawkRememberProcessIdentity" in policy_header
    assert "BOOLEAN HawkImageIsGoverned" in policy_header
    assert "SeLocateProcessImageName(Process, &locatedImageName)" in process_source
    assert "const BOOLEAN remembered = HawkRestoreSeededProcessLineage" in policy_source
    assert "HawkRememberProcessIdentity" not in process_source
    assert "const BOOLEAN denyForIdentityFailure = !remembered &&" in policy_source
    assert "HawkImageIsGoverned(targetImageFileName)" in policy_source
    assert "STATUS_ACCESS_DENIED" in process_source


def test_native_driver_install_is_idempotent_and_records_published_inf(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path)
    pnputil = r"C:\Windows\System32\pnputil.exe"
    add = (pnputil, "/add-driver", str(package.inf_path), "/install")
    runner = FakeRunner(
        {add: CommandResult(add, 0, "Published Name: oem42.inf\n", "")}
    )
    driver = WindowsNativeDriver(runner)

    result = driver.install(package)

    assert result.changed is True
    assert result.published_inf == "oem42.inf"
    rendered = [" ".join(call).lower() for call in runner.calls]
    assert any("pnputil.exe /add-driver" in call for call in rendered)
    assert any("fltmc.exe load hawkendpointfloor" in call for call in rendered)


def test_native_driver_rolls_back_package_when_filter_load_fails(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path)
    pnputil = r"C:\Windows\System32\pnputil.exe"
    add = (pnputil, "/add-driver", str(package.inf_path), "/install")
    fltmc = r"C:\Windows\System32\fltMC.exe"
    load = (fltmc, "load", "HawkEndpointFloor")
    runner = FakeRunner(
        {
            add: CommandResult(add, 0, "Published Name: oem42.inf\n", ""),
            load: CommandResult(load, 5, "", "access denied"),
        }
    )

    with pytest.raises(RuntimeError, match="load Hawk endpoint floor"):
        WindowsNativeDriver(runner).install(package)

    assert any(
        call[1:3] == ("/delete-driver", "oem42.inf")
        for call in runner.calls
    )


class FakeStep:
    def __init__(self, name: str, actions: list[str], *, fail: bool = False) -> None:
        self.name = name
        self.actions = actions
        self.fail = fail

    def install(self, *_args, **_kwargs):
        self.actions.append(f"install:{self.name}")
        if self.fail:
            raise RuntimeError(f"{self.name} failed")
        if self.name == "native":
            return type("Result", (), {"published_inf": "oem42.inf"})()
        if self.name == "trust":
            return "AA" * 20
        if self.name == "routing":
            return {"deployment_mode": "managed_machine"}
        return None

    def remove(self, *_args, **_kwargs):
        self.actions.append(f"remove:{self.name}")

    def restore(self, *_args, **_kwargs):
        self.actions.append(f"restore:{self.name}")

    def capture(self, *_args, **_kwargs):
        self.actions.append(f"capture:{self.name}")
        return {"deployment_mode": "managed_machine"}

    def apply(self, *_args, **_kwargs):
        return self.install()


def test_managed_installer_rolls_back_every_completed_step_in_reverse_order(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    installer = WindowsManagedInstaller(
        state_store=InstallStateStore(tmp_path / "state.json"),
        native_driver=FakeStep("native", actions),
        trust=FakeStep("trust", actions),
        service=FakeStep("service", actions),
        routing=FakeStep("routing", actions, fail=True),
    )
    package = _package(tmp_path)

    result = installer.install(
        ManagedInstallRequest(
            package=package,
            config_path=r"C:\ProgramData\Hawk\EndpointAgent\agent.json",
            proxy_host="127.0.0.1",
            proxy_port=8080,
            install_tls_trust=True,
            install_proxy_routing=True,
            development_only=True,
        )
    )

    assert result.ok is False
    assert actions[-3:] == [
        "remove:service",
        "remove:trust",
        "remove:native",
    ]
    assert not (tmp_path / "state.json").exists()


def test_legacy_python_installer_refuses_production_managed_install(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    installer = WindowsManagedInstaller(
        state_store=InstallStateStore(tmp_path / "state.json"),
        native_driver=FakeStep("native", actions),
        trust=FakeStep("trust", actions),
        service=FakeStep("service", actions),
        routing=FakeStep("routing", actions),
    )

    result = installer.install(
        ManagedInstallRequest(
            package=_package(tmp_path),
            config_path=r"C:\ProgramData\Hawk\EndpointAgent\agent.json",
        )
    )

    assert result.ok is False
    assert result.changed is False
    assert "install_managed_agent.ps1" in result.detail
    assert actions == []


def test_managed_installer_persists_no_credentials_and_uninstalls_symmetrically(
    tmp_path: Path,
) -> None:
    actions: list[str] = []
    state_path = tmp_path / "state.json"
    installer = WindowsManagedInstaller(
        state_store=InstallStateStore(state_path),
        native_driver=FakeStep("native", actions),
        trust=FakeStep("trust", actions),
        service=FakeStep("service", actions),
        routing=FakeStep("routing", actions),
    )
    package = _package(tmp_path)

    installed = installer.install(
        ManagedInstallRequest(
            package=package,
            config_path=r"C:\ProgramData\Hawk\EndpointAgent\agent.json",
            proxy_host="127.0.0.1",
            proxy_port=8080,
            install_tls_trust=False,
            install_proxy_routing=True,
            development_only=True,
        )
    )
    removed = installer.uninstall()

    assert installed.ok is True
    assert removed.ok is True
    assert "token" not in installed.state_json.lower()
    assert "secret" not in installed.state_json.lower()
    assert not state_path.exists()
    assert actions[-3:] == [
        "restore:routing",
        "remove:service",
        "remove:native",
    ]
