[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\Hawk\EndpointAgent",
    [string]$StateRoot = "$env:ProgramData\Hawk\EndpointAgent",
    [switch]$RequireCurrentPolicy,
    [switch]$RequireEnforce
)

$ErrorActionPreference = "Stop"
$fixedInstallRoot = Join-Path $env:ProgramFiles "Hawk\EndpointAgent"
$fixedStateRoot = Join-Path $env:ProgramData "Hawk\EndpointAgent"
if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($InstallRoot), [IO.Path]::GetFullPath($fixedInstallRoot)) -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($StateRoot), [IO.Path]::GetFullPath($fixedStateRoot))) {
    throw "Managed verification is confined to the fixed Hawk installation roots."
}
$selfSignature = Get-AuthenticodeSignature $PSCommandPath
if ($selfSignature.Status -ne "Valid" -or -not $selfSignature.SignerCertificate) {
    throw "The managed verification script signature is invalid."
}
$service = Get-Service -Name HawkEndpointAgent -ErrorAction Stop
$filterOutput = & "$env:SystemRoot\System32\fltMC.exe" filters
$filterLoaded = ($filterOutput -match '^HawkEndpointFloor\s')
$configPath = Join-Path $StateRoot "endpoint-agent.json"
$statePath = Join-Path $StateRoot "managed-install-state.json"
$runtimePath = Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"
$floorStatus = $null
if ((Test-Path $runtimePath) -and (Test-Path $configPath)) {
    $floorOutput = & $runtimePath --config $configPath --windows-floor-status 2>$null
    if ($LASTEXITCODE -eq 0) { $floorStatus = ($floorOutput -join "`n") | ConvertFrom-Json }
}
$identityVerified = $false
if ((Test-Path $runtimePath) -and (Test-Path $configPath)) {
    & $runtimePath --config $configPath --verify-device-identity 2>$null | Out-Null
    $identityVerified = $LASTEXITCODE -eq 0
}
$baseReady = (
    $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running -and
    [bool]$filterLoaded -and
    (Test-Path $configPath) -and
    (Test-Path $statePath) -and
    $identityVerified
)
$policyReady = (-not $RequireCurrentPolicy) -or (
    $floorStatus -and [bool]$floorStatus.policy_loaded -and [bool]$floorStatus.policy_current
)
$enforceReady = (-not $RequireEnforce) -or (
    $floorStatus -and [bool]$floorStatus.armed -and
    [bool]$floorStatus.identity_coverage_ready -and [bool]$floorStatus.wfp_ready
)
$overallReady = $baseReady -and $policyReady -and $enforceReady
$verification = [ordered]@{
    schema = "hawk.windows-managed-agent-verification"
    version = 2
    ok = [bool]$overallReady
    service_status = $service.Status.ToString().ToLowerInvariant()
    service_start_type = $service.StartType.ToString().ToLowerInvariant()
    endpoint_floor_loaded = [bool]$filterLoaded
    config_present = Test-Path $configPath
    install_state_present = Test-Path $statePath
    device_identity_verified = [bool]$identityVerified
    policy_loaded = if ($floorStatus) { [bool]$floorStatus.policy_loaded } else { $false }
    policy_current = if ($floorStatus) { [bool]$floorStatus.policy_current } else { $false }
    enforcement_armed = if ($floorStatus) { [bool]$floorStatus.armed } else { $false }
    identity_coverage_ready = if ($floorStatus) { [bool]$floorStatus.identity_coverage_ready } else { $false }
    wfp_ready = if ($floorStatus) { [bool]$floorStatus.wfp_ready } else { $false }
    driver_generation = if ($floorStatus) { [uint64]$floorStatus.generation } else { 0 }
    policy_sequence = if ($floorStatus) { [uint64]$floorStatus.policy_sequence } else { 0 }
    policy_fingerprint = if ($floorStatus) { [string]$floorStatus.policy_fingerprint } else { "" }
    allow_count = if ($floorStatus) { [uint64]$floorStatus.allow_count } else { 0 }
    block_count = if ($floorStatus) { [uint64]$floorStatus.block_count } else { 0 }
    runtime_verification = "requires_signed_policy_and_real_allow_block_receipts"
}
$verification | ConvertTo-Json -Depth 3
if (-not $overallReady) { exit 2 }
