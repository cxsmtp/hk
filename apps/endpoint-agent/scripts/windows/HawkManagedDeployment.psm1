Set-StrictMode -Version Latest

$script:HawkDriverProvider = "Hawk AI Security"
$script:HawkDriverClass = "ActivityMonitor"
$script:HawkOriginalInf = "HawkEndpointFloor.inf"

function Assert-HawkNoReparseAncestor {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    $cursor = [IO.DirectoryInfo]::new([IO.Path]::GetFullPath($Path))
    while ($cursor) {
        if ($cursor.Exists -and
            (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Hawk managed deployment refuses reparse-point roots or ancestors."
        }
        $cursor = $cursor.Parent
    }
}

function Assert-HawkManagedTreeIntegrity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [switch]$AllowMissingLeaf
    )

    Assert-HawkNoReparseAncestor -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($AllowMissingLeaf) { return }
        throw "Hawk managed deployment path is missing."
    }
    $root = Get-Item -LiteralPath $Path -Force
    if (-not $root.PSIsContainer -or
        (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw "Hawk managed deployment path is not a regular directory."
    }
    $reparseEntries = @(Get-ChildItem -LiteralPath $Path -Recurse -Force |
        Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        })
    if ($reparseEntries.Count -ne 0) {
        throw "Hawk managed deployment tree contains a reparse point."
    }
}

function New-HawkProtectedSecurityDescriptor {
    param(
        [Parameter(Mandatory=$true)]$Item,
        [Parameter(Mandatory=$true)]
        [ValidateSet("ReadAndExecute", "FullControl")]
        [string]$AdministratorsAccess
    )

    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new(
        "S-1-5-32-544"
    )
    if ($Item.PSIsContainer) {
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $inheritance = (
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        )
    } else {
        $security = [Security.AccessControl.FileSecurity]::new()
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($systemSid)
    $systemRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $administratorRights = if ($AdministratorsAccess -eq "FullControl") {
        [Security.AccessControl.FileSystemRights]::FullControl
    } else {
        [Security.AccessControl.FileSystemRights]::ReadAndExecute
    }
    $administratorRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid,
        $administratorRights,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $security.AddAccessRule($systemRule) | Out-Null
    $security.AddAccessRule($administratorRule) | Out-Null
    return $security
}

function Assert-HawkProtectedTreeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateSet("ReadAndExecute", "FullControl")]
        [string]$AdministratorsAccess = "ReadAndExecute",
        [switch]$Recurse
    )

    Assert-HawkManagedTreeIntegrity -Path $Path
    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add((Get-Item -LiteralPath $Path -Force))
    if ($Recurse) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
            $targets.Add($entry)
        }
    }
    $sections = (
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Access
    )
    foreach ($target in $targets) {
        $expected = New-HawkProtectedSecurityDescriptor `
            -Item $target `
            -AdministratorsAccess $AdministratorsAccess
        $actual = Get-Acl -LiteralPath $target.FullName
        $expectedSddl = $expected.GetSecurityDescriptorSddlForm($sections)
        $actualSddl = $actual.GetSecurityDescriptorSddlForm($sections)
        if ($actualSddl -ne $expectedSddl) {
            throw "Hawk managed-deployment ACL verification failed."
        }
    }
}

function Set-HawkProtectedTreeAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateSet("ReadAndExecute", "FullControl")]
        [string]$AdministratorsAccess = "ReadAndExecute",
        [switch]$Recurse
    )

    Assert-HawkManagedTreeIntegrity -Path $Path
    $targets = [System.Collections.Generic.List[object]]::new()
    $targets.Add((Get-Item -LiteralPath $Path -Force))
    if ($Recurse) {
        foreach ($entry in @(Get-ChildItem -LiteralPath $Path -Recurse -Force)) {
            $targets.Add($entry)
        }
    }
    foreach ($target in $targets) {
        $security = New-HawkProtectedSecurityDescriptor `
            -Item $target `
            -AdministratorsAccess $AdministratorsAccess
        Set-Acl -LiteralPath $target.FullName -AclObject $security
    }
    Assert-HawkManagedTreeIntegrity -Path $Path
    Assert-HawkProtectedTreeAcl `
        -Path $Path `
        -AdministratorsAccess $AdministratorsAccess `
        -Recurse:$Recurse
}

function Remove-HawkManagedTree {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)

    Assert-HawkManagedTreeIntegrity -Path $Path
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Write-HawkAtomicJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]$Value,
        [ValidateRange(2, 32)][int]$Depth = 8
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $directory = [IO.Path]::GetDirectoryName($fullPath)
    Assert-HawkManagedTreeIntegrity -Path $directory
    $leaf = [IO.Path]::GetFileName($fullPath)
    $temporary = Join-Path $directory (".{0}.{1}.tmp" -f $leaf, [Guid]::NewGuid().ToString("N"))
    $backup = Join-Path $directory (".{0}.{1}.bak" -f $leaf, [Guid]::NewGuid().ToString("N"))
    $json = $Value | ConvertTo-Json -Depth $Depth
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = $null
    try {
        $stream = [IO.FileStream]::new(
            $temporary,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        Assert-HawkNoReparseAncestor -Path $fullPath
        if (Test-Path -LiteralPath $fullPath -PathType Leaf) {
            [IO.File]::Replace($temporary, $fullPath, $backup, $true)
            Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
        } else {
            [IO.File]::Move($temporary, $fullPath)
        }
    } finally {
        if ($stream) { $stream.Dispose() }
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue
    }
}

function Assert-HawkLedgerProperties {
    param(
        [Parameter(Mandatory=$true)]$Ledger,
        [Parameter(Mandatory=$true)][string[]]$Required
    )
    $actual = @($Ledger.PSObject.Properties.Name)
    foreach ($name in $Required) {
        if ($name -notin $actual) { throw "Hawk recovery ledger is missing $name." }
    }
    foreach ($name in $actual) {
        if ($name -notin $Required) { throw "Hawk recovery ledger contains an unsupported field." }
    }
}

function Assert-HawkIsoTimestamp([string]$Value) {
    $parsed = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParseExact(
        $Value,
        "o",
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed
    )) {
        throw "Hawk recovery ledger contains an invalid timestamp."
    }
}

function Assert-HawkDriverMetadata($Ledger) {
    if ([string]$Ledger.expected_driver_provider -ne $script:HawkDriverProvider -or
        [string]$Ledger.expected_driver_class -ne $script:HawkDriverClass -or
        [string]$Ledger.expected_original_inf -ne $script:HawkOriginalInf -or
        [string]$Ledger.package_manifest_sha256 -notmatch '^[a-f0-9]{64}$') {
        throw "Hawk recovery ledger driver identity is invalid."
    }
}

function Read-HawkManagedLedger {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Auto", "InstallTransaction", "InstallState", "RemovalRecovery")]
        [string]$Kind
    )

    Assert-HawkNoReparseAncestor -Path $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Hawk recovery ledger is missing."
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 1 -or $item.Length -gt 131072) {
        throw "Hawk recovery ledger file is unsafe."
    }
    try {
        $ledger = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        throw "Hawk recovery ledger is not valid JSON."
    }
    $propertyNames = @($ledger.PSObject.Properties.Name)
    if ("schema" -notin $propertyNames -or "version" -notin $propertyNames) {
        throw "Hawk recovery ledger has no schema header."
    }
    if ($Kind -eq "Auto") {
        $Kind = switch ([string]$ledger.schema) {
            "hawk.windows-managed-install-transaction" { "InstallTransaction" }
            "hawk.windows-managed-install-state" { "InstallState" }
            "hawk.windows-managed-removal-recovery" { "RemovalRecovery" }
            default { throw "Hawk recovery ledger schema is unsupported." }
        }
    }
    $versionIsInteger = (
        $ledger.version -is [int32] -or
        $ledger.version -is [int64] -or
        $ledger.version -is [uint32] -or
        $ledger.version -is [uint64]
    )
    if (-not $versionIsInteger -or [int64]$ledger.version -ne 2) {
        throw "Hawk recovery ledger version is unsupported."
    }

    switch ($Kind) {
        "InstallTransaction" {
            $required = @(
                "schema", "version", "transaction_id", "status", "published_inf",
                "published_inf_unknown", "driver_store_before", "driver_loaded",
                "service_created", "config_was_copied", "rollback_failures",
                "expected_driver_provider", "expected_driver_class",
                "expected_original_inf", "package_manifest_sha256", "created_at",
                "updated_at"
            )
            Assert-HawkLedgerProperties -Ledger $ledger -Required $required
            $allowedStatus = @(
                "starting", "staging", "config_copying", "config_staged",
                "driver_staging", "driver_identity_ambiguous", "driver_staged",
                "driver_loaded", "service_created", "installed", "rollback_failed"
            )
            if ($ledger.schema -ne "hawk.windows-managed-install-transaction" -or
                [string]$ledger.status -notin $allowedStatus) {
                throw "Hawk install transaction ledger is invalid."
            }
            foreach ($field in @(
                "published_inf_unknown", "driver_loaded", "service_created",
                "config_was_copied"
            )) {
                if ($ledger.$field -isnot [bool]) {
                    throw "Hawk install transaction ledger has an invalid Boolean."
                }
            }
            if ([string]$ledger.published_inf -ne "" -and
                [string]$ledger.published_inf -notmatch '^oem\d+\.inf$') {
                throw "Hawk install transaction ledger has an invalid published INF."
            }
            if ($ledger.driver_store_before -isnot [System.Array] -or
                $ledger.rollback_failures -isnot [System.Array]) {
                throw "Hawk install transaction ledger has an invalid array."
            }
            if ([string]$ledger.status -eq "installed" -and
                [string]$ledger.published_inf -notmatch '^oem\d+\.inf$') {
                throw "Hawk installed transaction has no exact driver identity."
            }
            foreach ($entry in @($ledger.driver_store_before)) {
                if ([string]$entry -notmatch '^oem\d+\.inf$') {
                    throw "Hawk install transaction ledger has an invalid driver-store snapshot."
                }
            }
            foreach ($failure in @($ledger.rollback_failures)) {
                if ([string]$failure -notmatch '^[a-z0-9_]{1,80}$') {
                    throw "Hawk install transaction ledger has an invalid failure code."
                }
            }
        }
        "InstallState" {
            $required = @(
                "schema", "version", "transaction_id", "published_inf",
                "driver_loaded", "service_name", "service_status",
                "expected_driver_provider", "expected_driver_class",
                "expected_original_inf", "package_manifest_sha256", "installed_at"
            )
            $allowedServiceStatus = @(
                "awaiting_enrollment", "enrollment_started", "enrolled",
                "enrolled_and_started"
            )
            if ($ledger.PSObject.Properties.Name -contains "enrolled_at") {
                $required += "enrolled_at"
            }
            Assert-HawkLedgerProperties -Ledger $ledger -Required $required
            if ($ledger.schema -ne "hawk.windows-managed-install-state" -or
                [string]$ledger.published_inf -notmatch '^oem\d+\.inf$' -or
                $ledger.driver_loaded -isnot [bool] -or
                [string]$ledger.service_name -ne "HawkEndpointAgent" -or
                [string]$ledger.service_status -notin $allowedServiceStatus -or
                ([string]$ledger.service_status -in @("enrolled", "enrolled_and_started") -and
                    $ledger.PSObject.Properties.Name -notcontains "enrolled_at")) {
                throw "Hawk managed install ledger is invalid."
            }
        }
        "RemovalRecovery" {
            $required = @(
                "schema", "version", "transaction_id", "status",
                "service_deleted", "driver_unloaded", "driver_package_removed",
                "published_inf", "expected_driver_provider", "expected_driver_class",
                "expected_original_inf", "package_manifest_sha256", "started_at",
                "updated_at", "failure_class"
            )
            foreach ($optionalField in @("identity_destroyed", "state_root_removed")) {
                if ($ledger.PSObject.Properties.Name -contains $optionalField) {
                    $required += $optionalField
                }
            }
            Assert-HawkLedgerProperties -Ledger $ledger -Required $required
            $allowedStatus = @(
                "removal_started", "service_removed", "driver_unloaded",
                "driver_package_removed", "identity_destroyed",
                "state_root_removed", "removal_failed"
            )
            if ($ledger.schema -ne "hawk.windows-managed-removal-recovery" -or
                [string]$ledger.status -notin $allowedStatus -or
                ([string]$ledger.published_inf -ne "" -and
                    [string]$ledger.published_inf -notmatch '^oem\d+\.inf$')) {
                throw "Hawk managed removal ledger is invalid."
            }
            foreach ($field in @(
                "service_deleted", "driver_unloaded", "driver_package_removed"
            )) {
                if ($ledger.$field -isnot [bool]) {
                    throw "Hawk removal ledger has an invalid Boolean."
                }
            }
            foreach ($field in @("identity_destroyed", "state_root_removed")) {
                if ($ledger.PSObject.Properties.Name -contains $field -and
                    $ledger.$field -isnot [bool]) {
                    throw "Hawk removal ledger has an invalid recovery Boolean."
                }
            }
            if ([string]$ledger.failure_class -notmatch '^[A-Za-z0-9._-]{0,160}$') {
                throw "Hawk removal ledger has an invalid failure class."
            }
        }
    }

    if ([string]$ledger.transaction_id -notmatch
        '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$') {
        throw "Hawk recovery ledger transaction ID is invalid."
    }
    Assert-HawkDriverMetadata -Ledger $ledger
    foreach ($field in @(
        "created_at", "installed_at", "enrolled_at", "started_at", "updated_at"
    )) {
        if ($ledger.PSObject.Properties.Name -contains $field) {
            Assert-HawkIsoTimestamp -Value ([string]$ledger.$field)
        }
    }
    return $ledger
}

function Get-HawkDriverPackageIdentity {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$PublishedInf)

    if ($PublishedInf -notmatch '^oem\d+\.inf$') {
        throw "Published driver identity is invalid."
    }
    $matches = @(Get-WindowsDriver -Online -Driver $PublishedInf -ErrorAction Stop)
    if ($matches.Count -ne 1) {
        throw "Could not resolve one exact Windows driver package."
    }
    $driver = $matches[0]
    $identity = [pscustomobject]@{
        PublishedInf = ([string]$driver.Driver).ToLowerInvariant()
        ProviderName = [string]$driver.ProviderName
        ClassName = [string]$driver.ClassName
        OriginalInfName = [IO.Path]::GetFileName([string]$driver.OriginalFileName)
    }
    if ($identity.PublishedInf -ne $PublishedInf.ToLowerInvariant() -or
        $identity.ProviderName -ne "Hawk AI Security" -or
        $identity.ClassName -ne "ActivityMonitor" -or
        $identity.OriginalInfName -ne "HawkEndpointFloor.inf") {
        throw "The Windows driver-store entry is not the exact Hawk package."
    }
    return $identity
}

function Get-HawkDriverEvidenceHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$EvidenceRoot,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedManifestSha256
    )

    Assert-HawkManagedTreeIntegrity -Path $EvidenceRoot
    $manifestPath = Join-Path $EvidenceRoot "package-manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
        (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $ExpectedManifestSha256) {
        throw "Hawk driver evidence manifest does not match the recovery ledger."
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ([string]$manifest.schema -ne "hawk.windows-managed-agent-package" -or
        [int64]$manifest.version -ne 1 -or
        $manifest.files -isnot [System.Array]) {
        throw "Hawk driver evidence manifest is invalid."
    }
    $expectedNames = @(
        "HawkEndpointFloor.inf",
        "HawkEndpointFloor.cat",
        "HawkEndpointFloor.sys"
    )
    $hashes = [ordered]@{}
    foreach ($name in $expectedNames) {
        $entries = @($manifest.files | Where-Object {
            [string]$_.name -ceq $name -and [string]$_.sha256 -match '^[a-f0-9]{64}$'
        })
        if ($entries.Count -ne 1) {
            throw "Hawk driver evidence manifest lacks one exact driver artifact."
        }
        $artifact = Join-Path $EvidenceRoot $name
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf) -or
            (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                [string]$entries[0].sha256) {
            throw "Hawk retained driver evidence is incomplete or changed."
        }
        $hashes[$name] = [string]$entries[0].sha256
    }
    return [pscustomobject]$hashes
}

function Assert-HawkDriverPackageEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$PublishedInf,
        [Parameter(Mandatory=$true)][string]$EvidenceRoot,
        [Parameter(Mandatory=$true)]
        [ValidatePattern('^[a-f0-9]{64}$')]
        [string]$ExpectedManifestSha256,
        [Parameter(Mandatory=$true)][string]$WorkingRoot
    )

    $identity = Get-HawkDriverPackageIdentity -PublishedInf $PublishedInf
    $expectedHashes = Get-HawkDriverEvidenceHashes `
        -EvidenceRoot $EvidenceRoot `
        -ExpectedManifestSha256 $ExpectedManifestSha256
    Assert-HawkManagedTreeIntegrity -Path $WorkingRoot
    $exportRoot = Join-Path $WorkingRoot (
        ".driver-export-{0}" -f [Guid]::NewGuid().ToString("N")
    )
    New-Item -ItemType Directory -Path $exportRoot | Out-Null
    Set-HawkProtectedTreeAcl -Path $exportRoot -AdministratorsAccess ReadAndExecute
    try {
        & "$env:SystemRoot\System32\pnputil.exe" `
            /export-driver $PublishedInf $exportRoot | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not export the exact Windows driver package for verification."
        }
        Assert-HawkManagedTreeIntegrity -Path $exportRoot
        foreach ($name in @(
            "HawkEndpointFloor.inf",
            "HawkEndpointFloor.cat",
            "HawkEndpointFloor.sys"
        )) {
            $matches = @(Get-ChildItem -LiteralPath $exportRoot -Recurse -Force -File |
                Where-Object { [string]$_.Name -ceq $name })
            $expectedHash = [string]$expectedHashes.PSObject.Properties[$name].Value
            if ($matches.Count -ne 1 -or
                (Get-FileHash -LiteralPath $matches[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                    $expectedHash) {
                throw "The live driver-store package does not match retained Hawk evidence."
            }
        }
    } finally {
        if (Test-Path -LiteralPath $exportRoot) {
            Set-HawkProtectedTreeAcl `
                -Path $exportRoot `
                -AdministratorsAccess FullControl `
                -Recurse
            Remove-HawkManagedTree -Path $exportRoot
        }
    }
    return $identity
}

function Test-HawkServiceIdentity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$InstallRoot,
        [Parameter(Mandatory=$true)][string]$StateRoot
    )

    $services = @(Get-CimInstance -ClassName Win32_Service -Filter (
        "Name='HawkEndpointAgent'"
    ) -ErrorAction Stop)
    if ($services.Count -eq 0) { return $false }
    if ($services.Count -ne 1) { throw "Hawk service identity is ambiguous." }
    $serviceExecutable = Join-Path $InstallRoot "HawkEndpointService.exe"
    $managedConfig = Join-Path $StateRoot "endpoint-agent.json"
    $expectedPath = ('"{0}" --config "{1}"' -f $serviceExecutable, $managedConfig)
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
        [string]$services[0].PathName, $expectedPath
    ) -or [string]$services[0].StartName -ne "LocalSystem") {
        throw "The Hawk service name belongs to an unexpected executable or account."
    }
    return $true
}

function Test-HawkKernelServiceIdentity {
    [CmdletBinding()]
    param()

    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\HawkEndpointFloor"
    if (-not (Test-Path -LiteralPath $servicePath)) { return $false }
    $service = Get-ItemProperty -LiteralPath $servicePath -ErrorAction Stop
    $allowedImagePaths = @(
        "\SystemRoot\System32\drivers\HawkEndpointFloor.sys",
        "System32\drivers\HawkEndpointFloor.sys"
    )
    if ([int64]$service.Type -ne 2 -or
        [string]$service.ImagePath -notin $allowedImagePaths -or
        [string]$service.Group -ne "FSFilter Activity Monitor") {
        throw "The Hawk kernel-service name belongs to an unexpected driver."
    }
    return $true
}

function Get-HawkPublishedDriverNames {
    $drivers = @(Get-WindowsDriver -Online -All -ErrorAction Stop)
    return @($drivers | ForEach-Object { ([string]$_.Driver).ToLowerInvariant() } |
        Where-Object { $_ -match '^oem\d+\.inf$' } | Sort-Object -Unique)
}

function Resolve-HawkTransactionPublishedInf {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Transaction)

    if ([string]$Transaction.published_inf -match '^oem\d+\.inf$') {
        return (Get-HawkDriverPackageIdentity -PublishedInf ([string]$Transaction.published_inf)).PublishedInf
    }
    $before = @($Transaction.driver_store_before | ForEach-Object {
        ([string]$_).ToLowerInvariant()
    })
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($publishedInf in @(Get-HawkPublishedDriverNames)) {
        if ($publishedInf -in $before) { continue }
        try {
            Get-HawkDriverPackageIdentity -PublishedInf $publishedInf | Out-Null
            $candidates.Add($publishedInf)
        } catch {
            continue
        }
    }
    if ($candidates.Count -gt 1) {
        throw "More than one new Hawk driver package exists; recovery stopped safely."
    }
    if ($candidates.Count -eq 1) { return $candidates[0] }
    return ""
}

Export-ModuleMember -Function @(
    "Assert-HawkNoReparseAncestor",
    "Assert-HawkManagedTreeIntegrity",
    "Assert-HawkProtectedTreeAcl",
    "Set-HawkProtectedTreeAcl",
    "Remove-HawkManagedTree",
    "Write-HawkAtomicJson",
    "Read-HawkManagedLedger",
    "Get-HawkDriverPackageIdentity",
    "Assert-HawkDriverPackageEvidence",
    "Test-HawkServiceIdentity",
    "Test-HawkKernelServiceIdentity",
    "Get-HawkPublishedDriverNames",
    "Resolve-HawkTransactionPublishedInf"
)
