[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$PackagePath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ExpectedPublisherThumbprint,
    [switch]$AllowDevelopmentPackage,
    [string]$InstallRoot = "$env:ProgramFiles\Hawk\EndpointAgent",
    [string]$StateRoot = "$env:ProgramData\Hawk\EndpointAgent"
)

$ErrorActionPreference = "Stop"
$fixedInstallRoot = Join-Path $env:ProgramFiles "Hawk\EndpointAgent"
$fixedStateRoot = Join-Path $env:ProgramData "Hawk\EndpointAgent"
if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
    [IO.Path]::GetFullPath($InstallRoot), [IO.Path]::GetFullPath($fixedInstallRoot)
) -or -not [StringComparer]::OrdinalIgnoreCase.Equals(
    [IO.Path]::GetFullPath($StateRoot), [IO.Path]::GetFullPath($fixedStateRoot)
)) {
    throw "Managed installation is confined to the fixed Program Files and ProgramData roots."
}
function Assert-NoReparseAncestor([string]$Path) {
    $cursor = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
    while ($cursor) {
        if ($cursor.Exists -and (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Managed installation refuses reparse-point roots or ancestors."
        }
        $cursor = $cursor.Parent
    }
}
Assert-NoReparseAncestor $InstallRoot
Assert-NoReparseAncestor $StateRoot
function Confirm-HawkServiceAbsent {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (-not (Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}
function Confirm-HawkFilterAbsent {
    $observed = & "$env:SystemRoot\System32\fltMC.exe" filters 2>&1
    if ($LASTEXITCODE -ne 0) { return $false }
    return (($observed -join "`n") -notmatch '(?m)^HawkEndpointFloor\s')
}
function Confirm-HawkDriverPackageAbsent([string]$PublishedInf) {
    if ($PublishedInf -notmatch '^oem\d+\.inf$') { return $false }
    return ($PublishedInf.ToLowerInvariant() -notin @(Get-HawkPublishedDriverNames))
}
function Get-HawkPublishedInfSet {
    return @(Get-HawkPublishedDriverNames)
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this installer from an elevated PowerShell window."
}

$sourcePackage = (Resolve-Path $PackagePath).Path
$config = (Resolve-Path $ConfigPath).Path
$selfSignature = Get-AuthenticodeSignature $PSCommandPath
$expected = $ExpectedPublisherThumbprint.Replace(" ", "").ToUpperInvariant()
if ($selfSignature.Status -ne "Valid" -or -not $selfSignature.SignerCertificate -or
    $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expected) {
    throw "The managed installer itself is not signed by the expected Hawk publisher."
}
$deploymentModulePath = Join-Path (Split-Path -Parent $PSCommandPath) "HawkManagedDeployment.psm1"
$deploymentModuleSignature = Get-AuthenticodeSignature $deploymentModulePath
if ($deploymentModuleSignature.Status -ne "Valid" -or
    -not $deploymentModuleSignature.SignerCertificate -or
    $deploymentModuleSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expected) {
    throw "The managed deployment helper is not signed by the expected Hawk publisher."
}
Import-Module $deploymentModulePath -Force
Assert-HawkNoReparseAncestor -Path $sourcePackage
Assert-HawkManagedTreeIntegrity -Path $sourcePackage
if (-not $AllowDevelopmentPackage -and $identity.User.Value -ne "S-1-5-18") {
    throw "Production managed installation must run as LocalSystem."
}
$administratorsAccess = if ($identity.User.Value -eq "S-1-5-18") {
    "ReadAndExecute"
} else {
    "FullControl"
}
$stagingParent = Join-Path $env:ProgramData "Hawk\EndpointAgentInstallStaging"
New-Item -ItemType Directory -Force -Path $stagingParent | Out-Null
Set-HawkProtectedTreeAcl -Path $stagingParent -AdministratorsAccess $administratorsAccess
$protectedStaging = Join-Path $stagingParent ([Guid]::NewGuid().ToString("N"))
try {
New-Item -ItemType Directory -Path $protectedStaging | Out-Null
Set-HawkProtectedTreeAcl -Path $protectedStaging -AdministratorsAccess $administratorsAccess
$sourcePackageItem = Get-Item -LiteralPath $sourcePackage -Force
if (-not $sourcePackageItem.PSIsContainer -or
    (($sourcePackageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
    @(Get-ChildItem -LiteralPath $sourcePackage -Recurse -Force | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -gt 0) {
    throw "Managed package source contains a reparse point or is not a directory."
}
Get-ChildItem -LiteralPath $sourcePackage -Force | Copy-Item -Destination $protectedStaging -Recurse -Force
Set-HawkProtectedTreeAcl -Path $protectedStaging -AdministratorsAccess ReadAndExecute -Recurse
Assert-HawkManagedTreeIntegrity -Path $protectedStaging
$package = $protectedStaging
$managedConfig = Join-Path $StateRoot "endpoint-agent.json"
$existingService = Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue
$existingState = Join-Path $StateRoot "managed-install-state.json"
$existingTransaction = Join-Path $StateRoot "transactional-install-state.json"
$existingBinaries = @(
    (Join-Path $InstallRoot "HawkEndpointService.exe"),
    (Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"),
    (Join-Path $InstallRoot "hawk-device-identity.exe"),
    (Join-Path $InstallRoot "HawkManagedDeployment.psm1"),
    (Join-Path $InstallRoot "enroll_managed_agent.ps1"),
    (Join-Path $InstallRoot "verify_managed_agent.ps1"),
    (Join-Path $InstallRoot "uninstall_managed_agent.ps1")
) | Where-Object { Test-Path $_ -PathType Leaf }
$required = @(
    "HawkEndpointFloor.inf",
    "HawkEndpointFloor.sys",
    "HawkEndpointFloor.cat",
    "HawkEndpointService.exe",
    "hawk-endpoint-agent-runtime.exe",
    "hawk-device-identity.exe",
    "package-manifest.json",
    "HawkManagedPackage.cat",
    "HawkManagedDeployment.psm1",
    "install_managed_agent.ps1",
    "enroll_managed_agent.ps1",
    "verify_managed_agent.ps1",
    "uninstall_managed_agent.ps1"
)
foreach ($name in $required) {
    if (-not (Test-Path (Join-Path $package $name) -PathType Leaf)) { throw "Package is missing $name" }
}

# Production kernel packages are counter-signed by Microsoft's Hardware Dev
# Center, so their signer is intentionally not required to equal Hawk's
# user-mode publisher. Windows Code Integrity verifies that chain again at load.
foreach ($name in @("HawkEndpointFloor.sys", "HawkEndpointFloor.cat")) {
    $signature = Get-AuthenticodeSignature (Join-Path $package $name)
    if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate) { throw "Invalid signature: $name" }
}
foreach ($name in @("HawkEndpointService.exe", "hawk-endpoint-agent-runtime.exe", "hawk-device-identity.exe", "HawkManagedPackage.cat", "HawkManagedDeployment.psm1", "install_managed_agent.ps1", "enroll_managed_agent.ps1", "verify_managed_agent.ps1", "uninstall_managed_agent.ps1")) {
    $signature = Get-AuthenticodeSignature (Join-Path $package $name)
    if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate) { throw "Invalid signature: $name" }
    if ($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $expected) { throw "Unexpected signer: $name" }
}

$catalogStatus = Test-FileCatalog `
    -CatalogFilePath (Join-Path $package "HawkManagedPackage.cat") `
    -Path $package `
    -FilesToSkip @("HawkManagedPackage.cat")
if ($catalogStatus -ne [System.Management.Automation.CatalogValidationStatus]::Valid) {
    throw "Managed package catalog validation failed."
}

$manifest = Get-Content (Join-Path $package "package-manifest.json") -Raw | ConvertFrom-Json
if ($manifest.schema -ne "hawk.windows-managed-agent-package" -or $manifest.version -ne 1) { throw "Package manifest is invalid." }
$packageManifestSha256 = (Get-FileHash (Join-Path $package "package-manifest.json") -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifest.build_profile -ne "production" -and -not $AllowDevelopmentPackage) {
    throw "Managed installation requires a production Hardware Dev Center package. Use -AllowDevelopmentPackage only on an isolated test host."
}
$osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToUpperInvariant()
$packageArchitecture = ([string]$manifest.platform).ToUpperInvariant()
$expectedPackageArchitecture = if ($osArchitecture -eq "ARM64") { "ARM64" } elseif ($osArchitecture -eq "X64") { "X64" } else { "" }
if (-not $expectedPackageArchitecture -or $packageArchitecture -ne $expectedPackageArchitecture) {
    throw "Package architecture does not match the Windows operating system architecture."
}
foreach ($entry in $manifest.files) {
    if ([IO.Path]::GetFileName([string]$entry.name) -ne [string]$entry.name) {
        throw "Package manifest contains an unsafe artifact name."
    }
    $artifact = Join-Path $package $entry.name
    if (-not (Test-Path $artifact) -or (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.sha256) {
        throw "Package digest mismatch: $($entry.name)"
    }
}

# A signed, durable non-installed transaction is safe to reconcile using the
# already verified package uninstaller. A completed installation or an
# unledgered collision still requires the explicit upgrade/removal workflow.
$existingService = Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue
$existingBinaries = @(
    (Join-Path $InstallRoot "HawkEndpointService.exe"),
    (Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"),
    (Join-Path $InstallRoot "hawk-device-identity.exe"),
    (Join-Path $InstallRoot "HawkManagedDeployment.psm1"),
    (Join-Path $InstallRoot "enroll_managed_agent.ps1"),
    (Join-Path $InstallRoot "verify_managed_agent.ps1"),
    (Join-Path $InstallRoot "uninstall_managed_agent.ps1")
) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
$existingStatePresent = Test-Path -LiteralPath $existingState -PathType Leaf
$existingTransactionLedger = if (
    Test-Path -LiteralPath $existingTransaction -PathType Leaf
) {
    Read-HawkManagedLedger -Path $existingTransaction -Kind Auto
} else { $null }
if ($existingStatePresent -or
    ($existingTransactionLedger -and
        [string]$existingTransactionLedger.status -eq "installed")) {
    throw "Refusing to overwrite an existing Hawk managed endpoint. Uninstall or use the approved upgrade workflow first."
}
if ($existingTransactionLedger) {
    Write-Host "Recovering an interrupted Hawk managed installation before retry."
    $recoveryScript = Join-Path $package "uninstall_managed_agent.ps1"
    $recoveryArguments = @(
        "-InstallRoot", $InstallRoot,
        "-StateRoot", $StateRoot
    )
    if ($AllowDevelopmentPackage) {
        $recoveryArguments += "-AllowDevelopmentRemoval"
    }
    & $recoveryScript @recoveryArguments
    $existingService = Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue
    $existingBinaries = @(
        (Join-Path $InstallRoot "HawkEndpointService.exe"),
        (Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"),
        (Join-Path $InstallRoot "hawk-device-identity.exe")
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }
    if ($existingService -or
        (Test-Path -LiteralPath $existingState -PathType Leaf) -or
        (Test-Path -LiteralPath $existingTransaction -PathType Leaf) -or
        $existingBinaries.Count -gt 0) {
        throw "Interrupted Hawk installation recovery did not reach a clean state."
    }
} elseif ($existingService -or $existingBinaries.Count -gt 0) {
    throw "Refusing an unledgered Hawk installation collision. Repair or remove it with the signed recovery package."
}
if (
    (Test-Path $managedConfig -PathType Leaf) -and
    -not [StringComparer]::OrdinalIgnoreCase.Equals($config, (Resolve-Path $managedConfig).Path)
) {
    throw "A preserved managed config already exists; pass that exact path to reinstall."
}

$installRootExisted = Test-Path $InstallRoot
$stateRootExisted = Test-Path $StateRoot
$publishedInf = ""
$publishedInfUnknown = $false
$driverLoaded = $false
$serviceCreated = $false
$configWasCopied = $false
$driverStoreBefore = @()
$transactionStatePath = Join-Path $StateRoot "transactional-install-state.json"
$installStatePath = Join-Path $StateRoot "managed-install-state.json"
$driverEvidenceRoot = Join-Path $InstallRoot "DriverEvidence"
$transactionId = [Guid]::NewGuid().ToString()
$transactionCreatedAt = [DateTimeOffset]::UtcNow.ToString("o")
$transaction = [ordered]@{
    schema = "hawk.windows-managed-install-transaction"
    version = 2
    transaction_id = $transactionId
    status = "starting"
    published_inf = ""
    published_inf_unknown = $false
    driver_store_before = @()
    driver_loaded = $false
    service_created = $false
    config_was_copied = $false
    rollback_failures = @()
    expected_driver_provider = "Hawk AI Security"
    expected_driver_class = "ActivityMonitor"
    expected_original_inf = "HawkEndpointFloor.inf"
    package_manifest_sha256 = $packageManifestSha256
    created_at = $transactionCreatedAt
    updated_at = $transactionCreatedAt
}
function Save-TransactionState([string]$Status) {
    $transaction.status = $Status
    $transaction.published_inf = $publishedInf
    $transaction.published_inf_unknown = $publishedInfUnknown
    $transaction.driver_store_before = @($driverStoreBefore)
    $transaction.driver_loaded = $driverLoaded
    $transaction.service_created = $serviceCreated
    $transaction.config_was_copied = $configWasCopied
    $transaction.updated_at = [DateTimeOffset]::UtcNow.ToString("o")
    Write-HawkAtomicJson -Path $transactionStatePath -Value $transaction -Depth 5
}
try {
    New-Item -ItemType Directory -Force -Path $InstallRoot, $StateRoot | Out-Null
    Assert-HawkManagedTreeIntegrity -Path $InstallRoot
    Assert-HawkManagedTreeIntegrity -Path $StateRoot
    # Production installation runs as LocalSystem with Administrators read-only.
    # The isolated development switch may grant the invoking administrator
    # temporary mutation rights, which are removed before success is reported.
    Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess $administratorsAccess
    Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess $administratorsAccess
    Save-TransactionState "staging"
    Copy-Item (Join-Path $package "HawkEndpointService.exe") $InstallRoot -Force
    Copy-Item (Join-Path $package "hawk-endpoint-agent-runtime.exe") $InstallRoot -Force
    Copy-Item (Join-Path $package "hawk-device-identity.exe") $InstallRoot -Force
    foreach ($scriptName in @("enroll_managed_agent.ps1", "verify_managed_agent.ps1", "uninstall_managed_agent.ps1")) {
        Copy-Item (Join-Path $package $scriptName) $InstallRoot -Force
    }
    Copy-Item (Join-Path $package "HawkManagedDeployment.psm1") $InstallRoot -Force
    New-Item -ItemType Directory -Path $driverEvidenceRoot | Out-Null
    foreach ($evidenceName in @(
        "HawkEndpointFloor.inf",
        "HawkEndpointFloor.cat",
        "HawkEndpointFloor.sys",
        "package-manifest.json"
    )) {
        Copy-Item (Join-Path $package $evidenceName) $driverEvidenceRoot -Force
    }
    Set-HawkProtectedTreeAcl `
        -Path $driverEvidenceRoot `
        -AdministratorsAccess ReadAndExecute `
        -Recurse
    Assert-HawkManagedTreeIntegrity -Path $InstallRoot
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($config, $managedConfig)) {
        $configWasCopied = $true
        Save-TransactionState "config_copying"
        Copy-Item $config $managedConfig -Force
        Save-TransactionState "config_staged"
    }

    $managedHelper = Join-Path $InstallRoot "hawk-device-identity.exe"
    $managedConfigObject = Get-Content $managedConfig -Raw | ConvertFrom-Json
    if ([string]$managedConfigObject.os_type -ne "windows" -or
        [string]$managedConfigObject.security_profile -ne "bank" -or
        [string]$managedConfigObject.deployment_mode -ne "managed_machine" -or
        [string]::IsNullOrWhiteSpace([string]$managedConfigObject.tenant_id) -or
        [string]::IsNullOrWhiteSpace([string]$managedConfigObject.endpoint_id) -or
        -not ([string]$managedConfigObject.api_base_url).StartsWith("https://", [StringComparison]::OrdinalIgnoreCase) -or
        $managedConfigObject.windows_native_enforcement_enabled -ne $true) {
        throw "Managed Windows installation requires a bank managed_machine configuration."
    }
    foreach ($secretField in @(
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
        "policy_signing_private_key"
    )) {
        if ($managedConfigObject.PSObject.Properties.Name -contains $secretField -and
            -not [string]::IsNullOrWhiteSpace([string]$managedConfigObject.$secretField)) {
            throw "Managed endpoint configuration contains a prohibited static secret."
        }
    }
    $managedConfigObject | Add-Member -NotePropertyName identity_helper_path -NotePropertyValue $managedHelper -Force
    $managedConfigObject | Add-Member -NotePropertyName identity_helper_sha256 -NotePropertyValue ((Get-FileHash $managedHelper -Algorithm SHA256).Hash.ToLowerInvariant()) -Force
    Write-HawkAtomicJson -Path $managedConfig -Value $managedConfigObject -Depth 12

    $managedRuntime = Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"
    & $managedRuntime --config $managedConfig --print-config | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "The managed endpoint configuration failed validation." }

    $pnputil = "$env:SystemRoot\System32\pnputil.exe"
    $driverStoreBefore = @(Get-HawkPublishedDriverNames)
    Save-TransactionState "driver_staging"
    $output = & $pnputil /add-driver (Join-Path $package "HawkEndpointFloor.inf") /install 2>&1
    if ($LASTEXITCODE -ne 0) { throw "pnputil.exe failed to stage the driver package." }
    $driverStoreAfter = @(Get-HawkPublishedDriverNames)
    $newPublishedInfs = @($driverStoreAfter | Where-Object { $_ -notin $driverStoreBefore })
    if ($newPublishedInfs.Count -ne 1) {
        $publishedInfUnknown = $true
        Save-TransactionState "driver_identity_ambiguous"
        throw "Could not prove the single driver-store identity added by this transaction."
    }
    $publishedInf = $newPublishedInfs[0]
    Assert-HawkDriverPackageEvidence `
        -PublishedInf $publishedInf `
        -EvidenceRoot $driverEvidenceRoot `
        -ExpectedManifestSha256 $packageManifestSha256 `
        -WorkingRoot $StateRoot | Out-Null
    Save-TransactionState "driver_staged"

    & "$env:SystemRoot\System32\fltMC.exe" load HawkEndpointFloor
    if ($LASTEXITCODE -ne 0) { throw "The Hawk endpoint floor driver did not load." }
    $driverLoaded = $true
    Save-TransactionState "driver_loaded"

    $serviceExe = Join-Path $InstallRoot "HawkEndpointService.exe"
    $binPath = ('"{0}" --config "{1}"' -f $serviceExe, $managedConfig)
    # Enrollment creates the TPM-bound identity. Keep the service demand-start
    # and stopped until enroll_managed_agent.ps1 proves that identity.
    & "$env:SystemRoot\System32\sc.exe" create HawkEndpointAgent "binPath= $binPath" "start= demand" "obj= LocalSystem" "depend= HawkEndpointFloor" "DisplayName= Hawk Endpoint Agent" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create the Hawk Endpoint Agent service." }
    $serviceCreated = $true
    Save-TransactionState "service_created"
    $expectedServiceSid = "S-1-5-80-1135535808-2200536610-2577844612-1285382279-175032405"
    $serviceSidOutput = & "$env:SystemRoot\System32\sc.exe" showsid HawkEndpointAgent 2>&1
    if ($LASTEXITCODE -ne 0 -or ($serviceSidOutput -join "`n") -notmatch [regex]::Escape($expectedServiceSid)) {
        throw "The Hawk service SID does not match the driver control-channel ACL."
    }
    & "$env:SystemRoot\System32\sc.exe" failure HawkEndpointAgent "reset= 86400" "actions= restart/5000/restart/15000/none/0" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not configure Hawk service recovery." }
    & "$env:SystemRoot\System32\sc.exe" failureflag HawkEndpointAgent 1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not enable Hawk non-crash service recovery." }
    # The kernel policy-mutation device is bound to this service SID. Keep the
    # SID enabled without adding the restricted-token list; administrators have
    # read-only status access and unrelated LocalSystem processes have no access.
    & "$env:SystemRoot\System32\sc.exe" sidtype HawkEndpointAgent unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not enable the Hawk service SID." }
    $installState = [ordered]@{
        schema = "hawk.windows-managed-install-state"
        version = 2
        transaction_id = $transactionId
        published_inf = $publishedInf
        driver_loaded = $true
        service_name = "HawkEndpointAgent"
        service_status = "awaiting_enrollment"
        expected_driver_provider = "Hawk AI Security"
        expected_driver_class = "ActivityMonitor"
        expected_original_inf = "HawkEndpointFloor.inf"
        package_manifest_sha256 = $packageManifestSha256
        installed_at = [DateTimeOffset]::UtcNow.ToString("o")
    }
    Write-HawkAtomicJson -Path $installStatePath -Value $installState -Depth 4
    # This durable, credential-free record is deliberately retained after a
    # successful install as a recovery ledger. If either final ACL transition
    # fails, catch changes its status to rollback_failed.
    Save-TransactionState "installed"
    Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess ReadAndExecute -Recurse
    Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess ReadAndExecute -Recurse
    Write-Host "Hawk managed endpoint installed and stopped pending TPM enrollment. Native enforcement remains disarmed."
} catch {
    $originalError = $_
    $rollbackFailures = [System.Collections.Generic.List[string]]::new()
    # Reassert protected root ACLs before transactional rollback. This also
    # covers a failure between the two final ACL transitions above.
    if (Test-Path $InstallRoot) {
        try {
            Set-HawkProtectedTreeAcl -Path $InstallRoot -AdministratorsAccess $administratorsAccess -Recurse
        } catch { $rollbackFailures.Add("install_acl_unlock_failed") }
    }
    if (Test-Path $StateRoot) {
        try {
            Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess $administratorsAccess -Recurse
        } catch { $rollbackFailures.Add("state_acl_unlock_failed") }
    }
    if ($serviceCreated) {
        $rollbackService = Get-Service -Name HawkEndpointAgent -ErrorAction SilentlyContinue
        if ($rollbackService -and $rollbackService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Stop-Service -Name HawkEndpointAgent -Force -ErrorAction SilentlyContinue
        }
        & "$env:SystemRoot\System32\sc.exe" delete HawkEndpointAgent | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Confirm-HawkServiceAbsent)) {
            $rollbackFailures.Add("service_delete_failed")
        }
    }
    if ($driverLoaded) {
        & "$env:SystemRoot\System32\fltMC.exe" unload HawkEndpointFloor | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Confirm-HawkFilterAbsent)) {
            $rollbackFailures.Add("driver_unload_failed")
        }
    }
    if ($publishedInf) {
        try {
            Assert-HawkDriverPackageEvidence `
                -PublishedInf $publishedInf `
                -EvidenceRoot $driverEvidenceRoot `
                -ExpectedManifestSha256 $packageManifestSha256 `
                -WorkingRoot $StateRoot | Out-Null
            & "$env:SystemRoot\System32\pnputil.exe" /delete-driver $publishedInf /uninstall /force | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not (Confirm-HawkDriverPackageAbsent $publishedInf)) {
                $rollbackFailures.Add("driver_package_delete_failed")
            }
        } catch {
            $rollbackFailures.Add("driver_package_identity_failed")
        }
    }
    if ($publishedInfUnknown) {
        $rollbackFailures.Add("driver_package_identity_unknown")
    }
    if ($rollbackFailures.Count -eq 0) {
        foreach ($path in @(
            (Join-Path $InstallRoot "HawkEndpointService.exe"),
            (Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"),
            (Join-Path $InstallRoot "hawk-device-identity.exe"),
            (Join-Path $InstallRoot "HawkManagedDeployment.psm1"),
            (Join-Path $InstallRoot "enroll_managed_agent.ps1"),
            (Join-Path $InstallRoot "verify_managed_agent.ps1"),
            (Join-Path $InstallRoot "uninstall_managed_agent.ps1")
        )) {
            Assert-HawkNoReparseAncestor -Path $path
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -Force }
        }
        if (Test-Path -LiteralPath $driverEvidenceRoot) {
            Set-HawkProtectedTreeAcl `
                -Path $driverEvidenceRoot `
                -AdministratorsAccess $administratorsAccess `
                -Recurse
            Remove-HawkManagedTree -Path $driverEvidenceRoot
        }
        if ($configWasCopied -and (Test-Path $managedConfig)) { Remove-Item $managedConfig -Force }
        if (Test-Path $installStatePath) { Remove-Item $installStatePath -Force }
        if (Test-Path $transactionStatePath) { Remove-Item $transactionStatePath -Force }
        if (-not $installRootExisted -and (Test-Path $InstallRoot)) {
            Assert-HawkManagedTreeIntegrity -Path $InstallRoot
            Remove-HawkManagedTree -Path $InstallRoot
        }
        if (-not $stateRootExisted -and (Test-Path $StateRoot)) {
            Assert-HawkManagedTreeIntegrity -Path $StateRoot
            Remove-HawkManagedTree -Path $StateRoot
        }
    } else {
        $transaction.rollback_failures = @($rollbackFailures)
        $transaction.status = "rollback_failed"
        $transaction.updated_at = [DateTimeOffset]::UtcNow.ToString("o")
        Write-HawkAtomicJson -Path $transactionStatePath -Value $transaction -Depth 5
        if (Test-Path $StateRoot) {
            Set-HawkProtectedTreeAcl -Path $StateRoot -AdministratorsAccess ReadAndExecute -Recurse
        }
        throw "Managed endpoint installation failed and rollback was incomplete; preserving recovery ledger at $transactionStatePath. Original error: $($originalError.Exception.GetType().Name)"
    }
    throw $originalError
}
} finally {
    if ($protectedStaging -and (Test-Path $protectedStaging)) {
        try {
            Set-HawkProtectedTreeAcl -Path $protectedStaging -AdministratorsAccess $administratorsAccess -Recurse
            Remove-HawkManagedTree -Path $protectedStaging
        } catch {
            Write-Warning "Hawk protected package staging cleanup requires managed recovery."
        }
    }
}
