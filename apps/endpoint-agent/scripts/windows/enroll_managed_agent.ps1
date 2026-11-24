[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramFiles\Hawk\EndpointAgent",
    [string]$StateRoot = "$env:ProgramData\Hawk\EndpointAgent"
)

$ErrorActionPreference = "Stop"
$fixedInstallRoot = Join-Path $env:ProgramFiles "Hawk\EndpointAgent"
$fixedStateRoot = Join-Path $env:ProgramData "Hawk\EndpointAgent"
if (-not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($InstallRoot), [IO.Path]::GetFullPath($fixedInstallRoot)) -or
    -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetFullPath($StateRoot), [IO.Path]::GetFullPath($fixedStateRoot))) {
    throw "Managed enrollment is confined to the fixed Hawk installation roots."
}
$selfSignature = Get-AuthenticodeSignature $PSCommandPath
if ($selfSignature.Status -ne "Valid" -or -not $selfSignature.SignerCertificate) {
    throw "The managed enrollment script signature is invalid."
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($identity.User.Value -ne "S-1-5-18") {
    throw "Managed TPM enrollment must run as LocalSystem (for example through MDM/Intune/SCCM)."
}

$runtime = Join-Path $InstallRoot "hawk-endpoint-agent-runtime.exe"
$config = Join-Path $StateRoot "endpoint-agent.json"
$statePath = Join-Path $StateRoot "managed-install-state.json"
foreach ($path in @($runtime, $config, $statePath)) {
    if (-not (Test-Path $path -PathType Leaf)) { throw "Managed endpoint installation is incomplete." }
}
$publisher = $selfSignature.SignerCertificate.Thumbprint.ToUpperInvariant()
foreach ($path in @($runtime, (Join-Path $InstallRoot "hawk-device-identity.exe"))) {
    $signature = Get-AuthenticodeSignature $path
    if ($signature.Status -ne "Valid" -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $publisher) {
        throw "Managed enrollment found an artifact outside the approved publisher boundary."
    }
}
$deploymentModulePath = Join-Path $InstallRoot "HawkManagedDeployment.psm1"
$deploymentModuleSignature = Get-AuthenticodeSignature $deploymentModulePath
if ($deploymentModuleSignature.Status -ne "Valid" -or
    -not $deploymentModuleSignature.SignerCertificate -or
    $deploymentModuleSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne
        $publisher) {
    throw "The managed deployment helper is outside the approved publisher boundary."
}
Import-Module $deploymentModulePath -Force
Assert-HawkManagedTreeIntegrity -Path $InstallRoot
Assert-HawkManagedTreeIntegrity -Path $StateRoot

try {
    $state = Read-HawkManagedLedger -Path $statePath -Kind InstallState
    $identityAlreadyEnrolled = $false
    if ([string]$state.service_status -in @("enrollment_started", "enrolled", "enrolled_and_started")) {
        & $runtime --config $config --verify-device-identity | Out-Null
        $identityAlreadyEnrolled = $LASTEXITCODE -eq 0
    }
    if (-not $identityAlreadyEnrolled) {
        $state.service_status = "enrollment_started"
        Write-HawkAtomicJson -Path $statePath -Value $state -Depth 4
        $builder = [Text.StringBuilder]::new()
        $buffer = [char[]]::new(4096)
        while (($read = [Console]::In.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($builder.Length + $read -gt 65536) {
                $builder.Clear() | Out-Null
                throw "The one-time enrollment authorization exceeds the 64 KiB limit."
            }
            $builder.Append($buffer, 0, $read) | Out-Null
        }
        $bundle = $builder.ToString()
        $builder.Clear() | Out-Null
        if (-not $bundle) {
            throw "A bounded one-time enrollment authorization must be supplied on standard input."
        }
        try {
            $output = $bundle | & $runtime `
                --config $config `
                --enroll-existing-config `
                --enrollment-bundle-stdin 2>$null
            $enrollExitCode = $LASTEXITCODE
        } finally {
            $bundle = $null
        }
        if ($enrollExitCode -ne 0) { throw "TPM-bound endpoint enrollment failed." }
        $result = ($output -join "`n") | ConvertFrom-Json
        if ($result.ok -ne $true) { throw "TPM-bound endpoint enrollment was not accepted." }
        & $runtime --config $config --verify-device-identity | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "The enrolled TPM identity could not be proven." }
        $state = Get-Content $statePath -Raw | ConvertFrom-Json
        $state.service_status = "enrolled"
        $state | Add-Member -NotePropertyName enrolled_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString("o")) -Force
        Write-HawkAtomicJson -Path $statePath -Value $state -Depth 4
    }

    & "$env:SystemRoot\System32\sc.exe" config HawkEndpointAgent "start= auto" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not enable Hawk Endpoint Agent autostart." }
    $service = Get-Service -Name HawkEndpointAgent -ErrorAction Stop
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        Start-Service -Name HawkEndpointAgent -ErrorAction Stop
    }
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $service.Refresh()
    if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "The enrolled Hawk Endpoint Agent service did not reach running state."
    }

    $state = Get-Content $statePath -Raw | ConvertFrom-Json
    $state.service_status = "enrolled_and_started"
    $state | Add-Member -NotePropertyName enrolled_at -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString("o")) -Force
    Write-HawkAtomicJson -Path $statePath -Value $state -Depth 4
} finally {
    Set-HawkProtectedTreeAcl `
        -Path $StateRoot `
        -AdministratorsAccess ReadAndExecute `
        -Recurse
}
Write-Host "Hawk managed endpoint enrolled with its TPM-bound identity and started."
