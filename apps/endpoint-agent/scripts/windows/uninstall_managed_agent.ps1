[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\Hawk\EndpointAgent",
    [string]$StateRoot = "$env:ProgramData\Hawk\EndpointAgent",
    [switch]$PurgeConfiguration,
    [switch]$AllowDevelopmentRemoval
)

$ErrorActionPreference = "Stop"
$fixedInstallRoot = Join-Path $env:ProgramFiles "Hawk\EndpointAgent"
$fixedStateRoot = Join-Path $env:ProgramData "Hawk\EndpointAgent"
if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($InstallRoot), [IO.Path]::GetFullPath($fixedInstallRoot)) -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($StateRoot), [IO.Path]::GetFullPath($fixedStateRoot))) {
    throw "Managed removal is confined to the fixed Hawk installation roots."
}
foreach ($candidate in @($InstallRoot, $StateRoot)) {
    if (Test-Path $candidate) {
        $item = Get-Item $candidate -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Managed removal refuses reparse-point roots."
        }
    }
}
$selfSignature = Get-AuthenticodeSignature $PSCommandPath
if ($selfSignature.Status -ne "Valid" -or -not $selfSignature.SignerCertificate) {
    throw "The managed removal script signature is invalid."
}
$deploymentModulePath = Join-Path (Split-Path -Parent $PSCommandPath) "HawkManagedDeployment.psm1"
$deploymentModuleSignature = Get-AuthenticodeSignature $deploymentModulePath
if ($deploymentModuleSignature.Status -ne "Valid" -or
    -not $deploymentModuleSignature.SignerCertificate -or
    $deploymentModuleSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne
        $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant()) {
    throw "The managed deployment helper publisher does not match this removal package."
}
Import-Module $deploymentModulePath -Force
Assert-HawkManagedTreeIntegrity -Path $InstallRoot -AllowMissingLeaf
Assert-HawkManagedTreeIntegrity -Path $StateRoot -AllowMissingLeaf
function Confirm-HawkServiceAbsent {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (-not (Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Confirm-HawkFilterAbsent {
    $observed = & "$env:SystemRoot\System32\fltMC.exe" filters 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Could not query minifilter state." }
    return (($observed -join "`n") -notmatch '(?m)^HawkEndpointFloor\s')
}
function Confirm-HawkDriverPackageAbsent([string]$PublishedInf) {
    if ($PublishedInf -notmatch '^oem\d+\.inf$') { return $false }
    return ($PublishedInf.ToLowerInvariant() -notin @(Get-HawkPublishedDriverNames))
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell window."
}
if (-not $AllowDevelopmentRemoval -and $identity.User.Value -ne "S-1-5-18") {
    throw "Production managed removal must run as LocalSystem."
}
$administratorsRemovalAccess = if ($identity.User.Value -eq "S-1-5-18") {
    "ReadAndExecute"
} else {
    "FullControl"
}
if ($PurgeConfiguration -and $identity.User.Value -ne "S-1-5-18") {
    throw "Purging the TPM identity and managed configuration must run as LocalSystem."
}

$statePath = Join-Path $StateRoot "managed-install-state.json"
$transactionStatePath = Join-Path $StateRoot "transactional-install-state.json"
$installRecoveryPath = Join-Path $InstallRoot "install-removal-recovery.json"
$state = if (Test-Path -LiteralPath $statePath -PathType Leaf) {
    Read-HawkManagedLedger -Path $statePath -Kind InstallState
} else { $null }
$transactionState = if (Test-Path $transactionStatePath) {
    Read-HawkManagedLedger -Path $transactionStatePath -Kind Auto
} else { $null }
$installRecovery = if (Test-Path -LiteralPath $installRecoveryPath -PathType Leaf) {
    Read-HawkManagedLedger -Path $installRecoveryPath -Kind RemovalRecovery
} else { $null }
if ($transactionState -and $installRecovery -and
    [string]$transactionState.transaction_id -ne
        [string]$installRecovery.transaction_id) {
    throw "Hawk state and install-root recovery ledgers disagree."
}
if (-not $transactionState -and $installRecovery) {
    $transactionState = $installRecovery
}
if ($state -and $transactionState -and
    [string]$transactionState.transaction_id -ne [string]$state.transaction_id) {
    throw "Managed install and transaction ledgers do not describe the same transaction."
}
$installTransaction = if ($transactionState -and
    $transactionState.schema -eq "hawk.windows-managed-install-transaction") {
    $transactionState
} else { $null }
$removalRecovery = if ($transactionState -and
    $transactionState.schema -eq "hawk.windows-managed-removal-recovery") {
    $transactionState
} else { $null }

if (-not $state -and $installTransaction) {
    $recoveredPublishedInf = Resolve-HawkTransactionPublishedInf -Transaction $installTransaction
    $state = [pscustomobject]@{
        transaction_id = [string]$installTransaction.transaction_id
        published_inf = $recoveredPublishedInf
        expected_driver_provider = [string]$installTransaction.expected_driver_provider
        expected_driver_class = [string]$installTransaction.expected_driver_class
        expected_original_inf = [string]$installTransaction.expected_original_inf
        package_manifest_sha256 = [string]$installTransaction.package_manifest_sha256
    }
}
if (-not $state -and $removalRecovery) {
    $state = [pscustomobject]@{
        transaction_id = [string]$removalRecovery.transaction_id
        published_inf = [string]$removalRecovery.published_inf
        expected_driver_provider = [string]$removalRecovery.expected_driver_provider
        expected_driver_class = [string]$removalRecovery.expected_driver_class
        expected_original_inf = [string]$removalRecovery.expected_original_inf
        package_manifest_sha256 = [string]$removalRecovery.package_manifest_sha256
    }
}
$configPath = Join-Path $StateRoot "endpoint-agent.json"
$identityHelper = Join-Path $InstallRoot "hawk-device-identity.exe"
$driverEvidenceRoot = Join-Path $InstallRoot "DriverEvidence"
$recordedIdentityDestroyed = (
    $removalRecovery -and
    $removalRecovery.PSObject.Properties.Name -contains "identity_destroyed" -and
    $removalRecovery.identity_destroyed -eq $true
)
$identityProbeAvailable = (
    (Test-Path -LiteralPath $configPath -PathType Leaf) -and
    (Test-Path -LiteralPath $identityHelper -PathType Leaf)
)

if ($PurgeConfiguration -and -not $identityProbeAvailable -and
    -not $recordedIdentityDestroyed) {
    throw "TPM identity purge requires the managed config and signed identity helper. Reinstall the same trusted package before purging preserved state."
}
if ((Test-Path $InstallRoot) -and -not $state) {
    $unledgeredEntries = @(Get-ChildItem -LiteralPath $InstallRoot -Force)
    if ($unledgeredEntries.Count -eq 0 -and
        -not (Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue)) {
        Remove-Item -LiteralPath $InstallRoot -Force
    } else {
        throw "Managed install state is missing; binaries and recovery data were preserved. Repair the install before removal."
    }
}
if (-not $state -and -not (Test-Path $InstallRoot)) {
    Write-Host "Hawk managed endpoint is already absent. Preserved configuration was not changed."
    return
}

$serviceDeleted = $false
$driverUnloaded = $false
$driverPackageRemoved = $false
# A recovery checkpoint is only authoritative when the files needed to probe
# the TPM have already been removed. If they still exist, re-probe live state
# even when an earlier checkpoint claims success.
$identityDestroyed = ($recordedIdentityDestroyed -and -not $identityProbeAvailable)
$stateRootRemoved = (
    $removalRecovery -and
    $removalRecovery.PSObject.Properties.Name -contains "state_root_removed" -and
    $removalRecovery.state_root_removed -eq $true
)
$removalStartedAt = if ($removalRecovery) {
    [string]$removalRecovery.started_at
} else {
    [DateTimeOffset]::UtcNow.ToString("o")
}
$removalState = [ordered]@{
    schema = "hawk.windows-managed-removal-recovery"
    version = 2
    transaction_id = [string]$state.transaction_id
    status = "removal_started"
    service_deleted = $false
    driver_unloaded = $false
    driver_package_removed = $false
    identity_destroyed = $identityDestroyed
    state_root_removed = $stateRootRemoved
    published_inf = [string]$state.published_inf
    expected_driver_provider = [string]$state.expected_driver_provider
    expected_driver_class = [string]$state.expected_driver_class
    expected_original_inf = [string]$state.expected_original_inf
    package_manifest_sha256 = [string]$state.package_manifest_sha256
    started_at = $removalStartedAt
    updated_at = [DateTimeOffset]::UtcNow.ToString("o")
    failure_class = ""
}
function Save-RemovalRecoveryState([string]$Status) {
    $removalState.status = $Status
    $removalState.service_deleted = $serviceDeleted
    $removalState.driver_unloaded = $driverUnloaded
    $removalState.driver_package_removed = $driverPackageRemoved
    $removalState.identity_destroyed = $identityDestroyed
    $removalState.state_root_removed = $stateRootRemoved
    $removalState.updated_at = [DateTimeOffset]::UtcNow.ToString("o")
    if (Test-Path -LiteralPath $StateRoot -PathType Container) {
        Write-HawkAtomicJson -Path $transactionStatePath -Value $removalState -Depth 5
    }
    if (Test-Path -LiteralPath $InstallRoot -PathType Container) {
        Write-HawkAtomicJson -Path $installRecoveryPath -Value $removalState -Depth 5
    }
}
Save-RemovalRecoveryState "removal_started"
try {
# Do not trust recovery-ledger completion booleans. Reconcile each effect from
# live Windows state before deciding whether a destructive operation remains.
$service = Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue
if ($service) {
    if (-not (Test-HawkServiceIdentity -InstallRoot $InstallRoot -StateRoot $StateRoot)) {
        throw "Hawk service identity could not be proved."
    }
    $serviceBinary = Join-Path $InstallRoot "HawkEndpointService.exe"
    $serviceBinarySignature = Get-AuthenticodeSignature $serviceBinary
    if ($serviceBinarySignature.Status -ne "Valid" -or
        -not $serviceBinarySignature.SignerCertificate -or
        $serviceBinarySignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne
            $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant()) {
        throw "Hawk service binary publisher could not be proved."
    }
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Stop-Service -Name HawkEndpointAgent -Force -ErrorAction Stop
    }
    & "$env:SystemRoot\System32\sc.exe" delete HawkEndpointAgent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not delete the Hawk Endpoint Agent service." }
    if (-not (Confirm-HawkServiceAbsent)) { throw "Hawk Endpoint Agent service deletion did not reach a terminal state." }
}
$serviceDeleted = $true
Save-RemovalRecoveryState "service_removed"
if (-not (Confirm-HawkFilterAbsent)) {
    if (-not (Test-HawkKernelServiceIdentity)) {
        throw "Hawk kernel-service identity could not be proved."
    }
    & "$env:SystemRoot\System32\fltMC.exe" unload HawkEndpointFloor | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not unload the Hawk endpoint-floor driver." }
    if (-not (Confirm-HawkFilterAbsent)) { throw "Hawk endpoint-floor driver remains loaded." }
}
$driverUnloaded = $true
Save-RemovalRecoveryState "driver_unloaded"
if ([string]$state.published_inf -match '^oem\d+\.inf$' -and
    [string]$state.published_inf -in @(Get-HawkPublishedDriverNames)) {
    Assert-HawkDriverPackageEvidence `
        -PublishedInf ([string]$state.published_inf) `
        -EvidenceRoot $driverEvidenceRoot `
        -ExpectedManifestSha256 ([string]$state.package_manifest_sha256) `
        -WorkingRoot $StateRoot | Out-Null
    & "$env:SystemRoot\System32\pnputil.exe" /delete-driver $state.published_inf /uninstall /force | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not remove the Hawk driver package." }
    if (-not (Confirm-HawkDriverPackageAbsent $state.published_inf)) { throw "Hawk driver package remains in the driver store." }
} elseif ([string]$state.published_inf -ne "") {
    if ([string]$state.published_inf -notmatch '^oem\d+\.inf$') {
        throw "The managed recovery ledger has no valid published INF; removal stopped safely."
    }
}
$driverPackageRemoved = $true
Save-RemovalRecoveryState "driver_package_removed"

# Destroy the machine key only after service, filter, and driver-package removal
# are proved. A purge failure leaves all userspace recovery files intact.
if ($PurgeConfiguration -and -not $identityDestroyed) {
    $managedConfig = Get-Content $configPath -Raw | ConvertFrom-Json
    $expectedHelperDigest = [string]$managedConfig.identity_helper_sha256
    if ($expectedHelperDigest -notmatch '^[a-f0-9]{64}$' -or
        (Get-FileHash $identityHelper -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHelperDigest) {
        throw "TPM identity helper digest mismatch; purge stopped safely."
    }
    $helperSignature = Get-AuthenticodeSignature $identityHelper
    if ($helperSignature.Status -ne "Valid" -or -not $helperSignature.SignerCertificate -or
        $helperSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant()) {
        throw "TPM identity helper publisher mismatch; purge stopped safely."
    }
    $deviceKeyTag = [string]$managedConfig.device_key_tag
    if ($deviceKeyTag -notmatch '^[A-Za-z0-9._-]{1,160}$') { throw "Managed TPM key name is invalid." }
    $identityStatus = (& $identityHelper status $deviceKeyTag 2>$null) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "TPM identity status failed; purge stopped safely." }
    $identityState = $identityStatus | ConvertFrom-Json
    if ($identityState.ok -ne $true) { throw "TPM identity status was invalid; purge stopped safely." }
    if ($identityState.exists -eq $true) {
        $destroyOutput = (& $identityHelper destroy $deviceKeyTag 2>$null) -join "`n"
        $destroyExitCode = $LASTEXITCODE
        if ($destroyExitCode -ne 0) { throw "TPM identity destruction failed; purge stopped safely." }
        $destroyed = $destroyOutput | ConvertFrom-Json
        if ($destroyed.ok -ne $true -or $destroyed.exists -ne $false) { throw "TPM identity destruction failed; purge stopped safely." }
    }
    $identityDestroyed = $true
    Save-RemovalRecoveryState "identity_destroyed"
}

# Reassert managed root ACLs for LocalSystem removal. The isolated development
# switch may grant bounded administrator mutation; preserved state is relocked.
if (Test-Path $InstallRoot) {
    Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess $administratorsRemovalAccess -Recurse
}
$stateAclOpened = $false
if (Test-Path $StateRoot) {
    Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess $administratorsRemovalAccess -Recurse
    $stateAclOpened = $true
}
try {
    if ($PurgeConfiguration) {
        if (Test-Path $StateRoot) {
            Assert-HawkManagedTreeIntegrity -Path $StateRoot
            Remove-HawkManagedTree -Path $StateRoot
        }
        $stateRootRemoved = $true
        Save-RemovalRecoveryState "state_root_removed"
        if (Test-Path $InstallRoot) {
            Assert-HawkManagedTreeIntegrity -Path $InstallRoot
            foreach ($entry in @(
                Get-ChildItem -LiteralPath $InstallRoot -Force |
                    Where-Object { $_.Name -ne "install-removal-recovery.json" }
            )) {
                if ($entry.PSIsContainer) {
                    Remove-HawkManagedTree -Path $entry.FullName
                } else {
                    Remove-Item -LiteralPath $entry.FullName -Force
                }
            }
            if (Test-Path -LiteralPath $installRecoveryPath -PathType Leaf) {
                Remove-Item -LiteralPath $installRecoveryPath -Force
            }
            Remove-Item -LiteralPath $InstallRoot -Force
        }
    } else {
        if (Test-Path $InstallRoot) {
            Assert-HawkManagedTreeIntegrity -Path $InstallRoot
            Remove-HawkManagedTree -Path $InstallRoot
        }
        Assert-HawkNoReparseAncestor -Path $statePath
        Assert-HawkNoReparseAncestor -Path $transactionStatePath
        if (Test-Path $statePath) { Remove-Item -LiteralPath $statePath -Force }
        if (Test-Path $transactionStatePath) { Remove-Item -LiteralPath $transactionStatePath -Force }
    }
} finally {
    if (-not $PurgeConfiguration -and $stateAclOpened -and (Test-Path $StateRoot)) {
        Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess ReadAndExecute -Recurse
    }
}
Write-Host "Hawk managed endpoint service, driver, package, and binaries were removed. Configuration was preserved unless -PurgeConfiguration was supplied."
} catch {
    if (Test-Path $StateRoot) {
        Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess $administratorsRemovalAccess -Recurse
    }
    if (Test-Path $InstallRoot) {
        Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess $administratorsRemovalAccess -Recurse
    }
    if ((Test-Path $StateRoot) -or (Test-Path $InstallRoot)) {
        $removalState.failure_class = $_.Exception.GetType().Name
        Save-RemovalRecoveryState "removal_failed"
    }
    if (Test-Path $StateRoot) {
        Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess ReadAndExecute -Recurse
    }
    if (Test-Path $InstallRoot) {
        Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess ReadAndExecute -Recurse
    }
    throw "Managed endpoint removal failed; the recovery ledger was preserved."
}
