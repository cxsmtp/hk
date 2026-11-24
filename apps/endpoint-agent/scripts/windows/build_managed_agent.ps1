[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet("x64", "ARM64")][string]$Platform,
    [Parameter(Mandatory=$true)][ValidatePattern('^\d{5,6}(?:\.\d+)?$')][string]$MinifilterAltitude,
    [Parameter(Mandatory=$true)][string]$SigningCertificateThumbprint,
    [Parameter(Mandatory=$true)][switch]$ConfirmMicrosoftAllocatedAltitude,
    [ValidateSet("Development", "Production")][string]$BuildProfile = "Development",
    [string]$MicrosoftSignedDriverDirectory = "",
    [string]$HdcReleaseManifestPath = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$AgentRoot = (Resolve-Path (Join-Path $ScriptRoot "..\..")).Path
$NativeRoot = Join-Path $AgentRoot "native\windows"
$ProjectRoot = Join-Path $NativeRoot "HawkEndpointFloor"
$OutputDirectory = if ($OutputDirectory) { $OutputDirectory } else { Join-Path $AgentRoot "dist\windows-managed-$Platform" }

if (-not $ConfirmMicrosoftAllocatedAltitude) {
    throw "A Microsoft-allocated minifilter altitude must be explicitly confirmed."
}
if ($MinifilterAltitude -eq "__HAWK_MINIFILTER_ALTITUDE__") {
    throw "The minifilter altitude placeholder cannot be packaged."
}
if ($SigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
    throw "SigningCertificateThumbprint must be the exact 40-hex SHA-1 certificate thumbprint used by SignTool."
}
if ($BuildProfile -eq "Production" -and -not $MicrosoftSignedDriverDirectory) {
    throw "Production requires the driver package returned by Microsoft Hardware Dev Center."
}
if ($BuildProfile -eq "Production" -and -not $HdcReleaseManifestPath) {
    $HdcReleaseManifestPath = Join-Path $MicrosoftSignedDriverDirectory "hawk-hdc-release.json"
}

$msbuild = (Get-Command msbuild.exe -ErrorAction Stop).Source
$signtool = (Get-Command signtool.exe -ErrorAction Stop).Source
$inf2cat = (Get-Command Inf2Cat.exe -ErrorAction Stop).Source
$cl = (Get-Command cl.exe -ErrorAction Stop).Source
$python = (Get-Command python.exe -ErrorAction Stop).Source
$expectedDeveloperArchitecture = if ($Platform -eq "ARM64") { "arm64" } else { "x64" }
if ($env:VSCMD_ARG_TGT_ARCH -ne $expectedDeveloperArchitecture) {
    throw "Run this build from the Visual Studio Developer PowerShell configured for $expectedDeveloperArchitecture."
}
$pythonMachine = (& $python -c "import platform; print(platform.machine())").Trim().ToUpperInvariant()
if (
    ($Platform -eq "ARM64" -and $pythonMachine -ne "ARM64") -or
    ($Platform -eq "x64" -and $pythonMachine -notin @("AMD64", "X86_64"))
) {
    throw "The Python/PyInstaller architecture must match the target platform."
}
$pyInstallerVersion = (& $python -c "import PyInstaller; print(PyInstaller.__version__)").Trim()
if ($LASTEXITCODE -ne 0 -or $pyInstallerVersion -ne "6.21.0") {
    throw "Install the pinned Windows build environment with: python -m pip install -e .[windows-build]"
}
$cryptographyVersion = (& $python -c "import cryptography; print(cryptography.__version__)").Trim()
if ($LASTEXITCODE -ne 0 -or $cryptographyVersion -ne "49.0.0") {
    throw "The Windows build requires the reviewed cryptography 49.0.0 runtime."
}
$psutilVersion = (& $python -c "import psutil; print(psutil.__version__)").Trim()
if ($LASTEXITCODE -ne 0 -or $psutilVersion -ne "7.2.2") {
    throw "The Windows build requires the reviewed psutil 7.2.2 runtime for process seeding."
}

if (Test-Path $OutputDirectory) {
    throw "Refusing to overwrite existing output directory: $OutputDirectory"
}
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
$staging = Join-Path $OutputDirectory "staging"
New-Item -ItemType Directory -Path $staging | Out-Null

function Get-PeMachine([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -lt 64) { throw "PE artifact is truncated: $Path" }
        $reader = [IO.BinaryReader]::new($stream)
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw "PE artifact has no DOS signature: $Path" }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) { throw "PE header is outside artifact bounds: $Path" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "PE artifact has no NT signature: $Path" }
        return $reader.ReadUInt16()
    } finally { $stream.Dispose() }
}

function Assert-PeMachine([string]$Path, [string]$ExpectedPlatform) {
    $expected = if ($ExpectedPlatform -eq "ARM64") { 0xAA64 } else { 0x8664 }
    $actual = Get-PeMachine $Path
    if ($actual -ne $expected) {
        throw ("PE machine mismatch for {0}: expected 0x{1:X4}, found 0x{2:X4}" -f $Path, $expected, $actual)
    }
}

& $msbuild (Join-Path $ProjectRoot "HawkEndpointFloor.sln") "/t:Rebuild" "/p:Configuration=Release" "/p:Platform=$Platform" "/m:1"
if ($LASTEXITCODE -ne 0) { throw "WDK driver build failed." }

$driverBuild = Join-Path $ProjectRoot "$Platform\Release\HawkEndpointFloor.sys"
if (-not (Test-Path $driverBuild)) {
    throw "The exact MSBuild target output was not found: $driverBuild"
}

$infTemplate = Get-Content (Join-Path $ProjectRoot "HawkEndpointFloor.inf.in") -Raw
$renderedInf = $infTemplate.Replace("__HAWK_MINIFILTER_ALTITUDE__", $MinifilterAltitude)
if ($renderedInf.Contains("__HAWK_MINIFILTER_ALTITUDE__")) { throw "INF altitude substitution failed." }
Set-Content -Path (Join-Path $staging "HawkEndpointFloor.inf") -Value $renderedInf -Encoding ascii -NoNewline
Copy-Item $driverBuild (Join-Path $staging "HawkEndpointFloor.sys")

$serviceSource = Join-Path $NativeRoot "service\HawkEndpointService.cpp"
$identitySource = Join-Path $NativeRoot "identity\HawkDeviceIdentity.cpp"
Push-Location $staging
try {
    & $cl /nologo /O2 /W4 /WX /MT /std:c++17 /guard:cf /DUNICODE /D_UNICODE /EHsc $serviceSource /Fe:HawkEndpointService.exe /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA advapi32.lib shell32.lib
    if ($LASTEXITCODE -ne 0) { throw "Windows service launcher build failed." }
    & $cl /nologo /O2 /W4 /WX /MT /std:c++17 /guard:cf /DUNICODE /D_UNICODE /EHsc $identitySource /Fe:hawk-device-identity.exe /link /guard:cf /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA bcrypt.lib ncrypt.lib crypt32.lib
    if ($LASTEXITCODE -ne 0) { throw "Native Windows TPM/CNG identity helper build failed." }
} finally { Pop-Location }

$sourceRoot = Join-Path $AgentRoot "src"
$cleanSourceRoot = Join-Path $OutputDirectory "runtime-source"
Get-ChildItem $sourceRoot -Recurse -File | Where-Object {
    $_.Name -notlike "._*" -and $_.FullName -notmatch '[\\/]__pycache__[\\/]'
} | ForEach-Object {
    $relative = $_.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
    $target = Join-Path $cleanSourceRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Copy-Item $_.FullName $target
}
& $python -m PyInstaller --clean --noconfirm --onefile --name hawk-endpoint-agent-runtime --paths $cleanSourceRoot --collect-submodules hawk_endpoint_agent --collect-data hawk_endpoint_agent --distpath $staging --workpath (Join-Path $OutputDirectory "pyinstaller") --specpath $OutputDirectory (Join-Path $ScriptRoot "runtime_entry.py")
if ($LASTEXITCODE -ne 0) { throw "Endpoint runtime packaging failed. Install the pinned build requirements first." }

$managementScripts = @(
    "HawkManagedDeployment.psm1",
    "install_managed_agent.ps1",
    "enroll_managed_agent.ps1",
    "verify_managed_agent.ps1",
    "uninstall_managed_agent.ps1"
)
foreach ($scriptName in $managementScripts) {
    Copy-Item (Join-Path $ScriptRoot $scriptName) (Join-Path $staging $scriptName)
}

if ($BuildProfile -eq "Development") {
    foreach ($artifact in @("HawkEndpointFloor.sys", "HawkEndpointService.exe", "hawk-endpoint-agent-runtime.exe", "hawk-device-identity.exe")) {
        & $signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 (Join-Path $staging $artifact)
        if ($LASTEXITCODE -ne 0) { throw "Signing failed for $artifact" }
    }
    $inf2catTargets = if ($Platform -eq "ARM64") {
        "10_VB_ARM64,10_CO_ARM64,10_NI_ARM64,10_GE_ARM64,10_25H2_ARM64,ServerFE_ARM64,Server2025_ARM64"
    } else {
        "10_VB_X64,10_CO_X64,10_NI_X64,10_GE_X64,10_25H2_X64,ServerFE_X64,Server2025_X64"
    }
    & $inf2cat "/driver:$staging" "/os:$inf2catTargets"
    if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed." }
    & $signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 (Join-Path $staging "HawkEndpointFloor.cat")
    if ($LASTEXITCODE -ne 0) { throw "Catalog signing failed." }
} else {
    if (-not (Test-Path $HdcReleaseManifestPath -PathType Leaf)) {
        throw "Production requires the reviewed Hardware Dev Center release manifest."
    }
    $hdcRelease = Get-Content $HdcReleaseManifestPath -Raw | ConvertFrom-Json
    if (
        $hdcRelease.schema -ne "hawk.windows-hdc-driver-release" -or
        $hdcRelease.version -ne 1 -or
        ([string]$hdcRelease.platform).ToUpperInvariant() -ne $Platform.ToUpperInvariant() -or
        [string]$hdcRelease.submission_id -notmatch '^[A-Za-z0-9._-]{3,128}$' -or
        [string]$hdcRelease.minifilter_altitude -ne $MinifilterAltitude
    ) {
        throw "The Hardware Dev Center release manifest is invalid or does not match this build."
    }
    foreach ($name in @("HawkEndpointFloor.sys", "HawkEndpointFloor.cat", "HawkEndpointFloor.inf")) {
        $sourceArtifact = Join-Path $MicrosoftSignedDriverDirectory $name
        if (-not (Test-Path $sourceArtifact -PathType Leaf)) { throw "Hardware Dev Center package is missing $name" }
        $declared = [string]$hdcRelease.files.$name
        if ($declared -notmatch '^[A-Fa-f0-9]{64}$' -or
            (Get-FileHash $sourceArtifact -Algorithm SHA256).Hash.ToLowerInvariant() -ne $declared.ToLowerInvariant()) {
            throw "Hardware Dev Center release digest mismatch: $name"
        }
        Copy-Item $sourceArtifact (Join-Path $staging $name) -Force
    }
    Copy-Item $HdcReleaseManifestPath (Join-Path $staging "hawk-hdc-release.json")
    $signedInf = Get-Content (Join-Path $staging "HawkEndpointFloor.inf") -Raw
    if ($signedInf.Contains("__HAWK_MINIFILTER_ALTITUDE__") -or $signedInf -notmatch ('InstanceAltitude="' + [regex]::Escape($MinifilterAltitude) + '"')) {
        throw "Microsoft-signed driver package does not contain the approved minifilter altitude."
    }
    foreach ($artifact in @("HawkEndpointService.exe", "hawk-endpoint-agent-runtime.exe", "hawk-device-identity.exe")) {
        & $signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 (Join-Path $staging $artifact)
        if ($LASTEXITCODE -ne 0) { throw "Signing failed for $artifact" }
    }
    $driverCatalogValidation = Join-Path $OutputDirectory "driver-catalog-validation"
    New-Item -ItemType Directory -Path $driverCatalogValidation | Out-Null
    try {
        Copy-Item (Join-Path $staging "HawkEndpointFloor.inf") $driverCatalogValidation
        Copy-Item (Join-Path $staging "HawkEndpointFloor.sys") $driverCatalogValidation
        $driverCatalogStatus = Test-FileCatalog `
            -CatalogFilePath (Join-Path $staging "HawkEndpointFloor.cat") `
            -Path $driverCatalogValidation
        if ($driverCatalogStatus -ne [System.Management.Automation.CatalogValidationStatus]::Valid) {
            throw "The Hardware Dev Center catalog does not bind the exact INF and SYS."
        }
    } finally {
        Remove-Item $driverCatalogValidation -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($peArtifact in @("HawkEndpointFloor.sys", "HawkEndpointService.exe", "hawk-endpoint-agent-runtime.exe", "hawk-device-identity.exe")) {
    Assert-PeMachine (Join-Path $staging $peArtifact) $Platform
}

$signingCertificate = Get-Item "Cert:\LocalMachine\My\$SigningCertificateThumbprint" -ErrorAction SilentlyContinue
if (-not $signingCertificate) {
    $signingCertificate = Get-Item "Cert:\CurrentUser\My\$SigningCertificateThumbprint" -ErrorAction SilentlyContinue
}
if (-not $signingCertificate -or -not $signingCertificate.HasPrivateKey) {
    throw "The exact Hawk code-signing certificate with private key is unavailable."
}
foreach ($scriptName in $managementScripts) {
    $signedScript = Set-AuthenticodeSignature `
        -FilePath (Join-Path $staging $scriptName) `
        -Certificate $signingCertificate `
        -HashAlgorithm SHA256 `
        -TimestampServer $TimestampUrl
    if ($signedScript.Status -ne "Valid") { throw "PowerShell signing failed for $scriptName" }
}

& $signtool verify /kp /v (Join-Path $staging "HawkEndpointFloor.sys")
if ($LASTEXITCODE -ne 0) { throw "Kernel-policy signature verification failed." }
& $signtool verify /kp /v (Join-Path $staging "HawkEndpointFloor.cat")
if ($LASTEXITCODE -ne 0) { throw "Catalog kernel-policy verification failed." }
foreach ($artifact in @("HawkEndpointService.exe", "hawk-endpoint-agent-runtime.exe", "hawk-device-identity.exe")) {
    & $signtool verify /pa /v (Join-Path $staging $artifact)
    if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed for $artifact" }
}
foreach ($scriptName in $managementScripts) {
    $scriptSignature = Get-AuthenticodeSignature (Join-Path $staging $scriptName)
    if ($scriptSignature.Status -ne "Valid" -or
        $scriptSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -ne $SigningCertificateThumbprint.ToUpperInvariant()) {
        throw "Authenticode verification failed for $scriptName"
    }
}

$manifest = Get-ChildItem $staging -File | Sort-Object Name | ForEach-Object {
    [ordered]@{ name = $_.Name; size = $_.Length; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
}
[ordered]@{
    schema = "hawk.windows-managed-agent-package"
    version = 1
    platform = $Platform
    build_profile = $BuildProfile.ToLowerInvariant()
    minifilter_altitude = $MinifilterAltitude
    runtime_verification = "target_os_acceptance_required"
    files = $manifest
} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $staging "package-manifest.json") -Encoding utf8

$packageCatalog = Join-Path $OutputDirectory "HawkManagedPackage.cat"
New-FileCatalog -Path $staging -CatalogFilePath $packageCatalog -CatalogVersion 2.0 | Out-Null
& $signtool sign /sha1 $SigningCertificateThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $packageCatalog
if ($LASTEXITCODE -ne 0) { throw "Managed package catalog signing failed." }
& $signtool verify /pa /v $packageCatalog
if ($LASTEXITCODE -ne 0) { throw "Managed package catalog verification failed." }
Move-Item $packageCatalog (Join-Path $staging "HawkManagedPackage.cat")

Write-Host "Managed Windows package created at $staging"
