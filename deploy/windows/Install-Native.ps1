[CmdletBinding()]
param(
    [string]$BundleRoot = $PSScriptRoot,
    [string]$InstallRoot = "C:\ProgramData\COE\App",
    [string]$BootstrapPython = "py.exe",
    [switch]$ConfigureOutboundBlock,
    [switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

function Assert-ExactJsonFields {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Object -isnot [PSCustomObject]) {
        throw "$Label must be a JSON object."
    }
    [string[]]$actual = @($Object.PSObject.Properties.Name)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($Expected, [StringComparer]::Ordinal)
    if (($actual -join "`n") -ne ($Expected -join "`n")) {
        throw "$Label fields do not match the supported contract."
    }
}

function Get-BundleApplicationContract {
    param([Parameter(Mandatory = $true)][string]$Root)

    $bundleManifestPath = Join-Path $Root "bundle-manifest.json"
    $runtimeManifestPath = Join-Path $Root "runtime_manifest.json"
    $bundleManifestPresent = Test-Path -LiteralPath $bundleManifestPath -PathType Leaf
    $runtimeManifestPresent = Test-Path -LiteralPath $runtimeManifestPath -PathType Leaf
    if ($bundleManifestPresent -eq $runtimeManifestPresent) {
        throw "The portable bundle must contain exactly one supported runtime manifest."
    }
    $manifestPath = if ($bundleManifestPresent) { $bundleManifestPath } else { $runtimeManifestPath }
    $manifestItem = Get-Item -LiteralPath $manifestPath -Force
    if ($manifestItem -isnot [IO.FileInfo] -or $manifestItem.Length -gt 1048576) {
        throw "The portable bundle runtime manifest exceeds its size boundary."
    }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "The portable bundle runtime manifest is unreadable or malformed."
    }

    if ($bundleManifestPresent) {
        Assert-ExactJsonFields -Object $manifest -Expected @(
            "application_package",
            "application_version",
            "application_wheel",
            "contains_model_weights",
            "contains_patient_data",
            "contains_terminology_payloads",
            "created_at_utc",
            "exact_matching_device",
            "gpu_semantic_stage",
            "portable_bundle_schema_version",
            "run_network_policy"
        ) -Label "The PowerShell portable-bundle manifest"
        Assert-ExactJsonFields `
            -Object $manifest.application_wheel `
            -Expected @("path", "sha256") `
            -Label "The PowerShell application-wheel declaration"
        if (
            $manifest.portable_bundle_schema_version -ne "1.1.0" -or
            $manifest.application_package -cne "coe-corpus-ontology-enricher" -or
            $manifest.exact_matching_device -ne "cpu" -or
            $manifest.gpu_semantic_stage -ne "reserved_not_implemented" -or
            $manifest.run_network_policy -ne "offline-required" -or
            $manifest.contains_patient_data -ne $false -or
            $manifest.contains_terminology_payloads -ne $false -or
            $manifest.contains_model_weights -ne $false
        ) {
            throw "The PowerShell portable-bundle manifest profile is invalid."
        }
        $createdAt = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse([string]$manifest.created_at_utc, [ref]$createdAt)) {
            throw "The PowerShell portable-bundle creation timestamp is invalid."
        }
        $packageName = [string]$manifest.application_package
        $applicationVersion = $manifest.application_version
        $wheelPath = $manifest.application_wheel.path
        $wheelSha256 = $manifest.application_wheel.sha256
        $manifestProfile = "powershell_bundle_manifest_1.1.0"
    }
    else {
        $runtimeFields = @(
            "application_version",
            "bundle_profile",
            "exact_matching_device",
            "patient_data_included",
            "runtime_manifest_schema_version",
            "terminology_payload_included",
            "wheel"
        )
        Assert-ExactJsonFields `
            -Object $manifest `
            -Expected $runtimeFields `
            -Label "The Python runtime manifest"
        Assert-ExactJsonFields `
            -Object $manifest.wheel `
            -Expected @("distribution", "path", "sha256", "version") `
            -Label "The Python runtime wheel declaration"
        if (
            $manifest.runtime_manifest_schema_version -ne "1.0.0" -or
            $manifest.bundle_profile -ne "windows-native-with-conditional-wsl2" -or
            $manifest.exact_matching_device -ne "cpu" -or
            $manifest.patient_data_included -ne $false -or
            $manifest.terminology_payload_included -ne $false -or
            $manifest.wheel.distribution -cne "coe-corpus-ontology-enricher" -or
            $manifest.wheel.version -cne $manifest.application_version
        ) {
            throw "The Python runtime manifest profile is invalid."
        }
        $packageName = [string]$manifest.wheel.distribution
        $applicationVersion = $manifest.application_version
        $wheelPath = $manifest.wheel.path
        $wheelSha256 = $manifest.wheel.sha256
        $manifestProfile = "python_runtime_manifest_1.0.0"
    }

    if (
        $packageName -cne "coe-corpus-ontology-enricher" -or
        $applicationVersion -isnot [string] -or
        [string]$applicationVersion -notmatch '^[0-9][A-Za-z0-9._+!]*$' -or
        $wheelPath -isnot [string] -or
        [string]$wheelPath -notmatch '^app/coe_corpus_ontology_enricher-[0-9][A-Za-z0-9._+!]*-py3-none-any\.whl$' -or
        $wheelSha256 -isnot [string] -or
        [string]$wheelSha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw "The portable bundle application identity is invalid."
    }
    $declaredWheel = Resolve-CoeBundleMember -BundleRoot $Root -RelativePath ([string]$wheelPath)
    if (-not (Test-Path -LiteralPath $declaredWheel -PathType Leaf)) {
        throw "The portable bundle application wheel is missing."
    }
    $wheelIdentity = Get-CoeApplicationWheelIdentity -Path $declaredWheel
    if (
        $wheelIdentity.application_package -cne $packageName -or
        $wheelIdentity.application_version -cne [string]$applicationVersion -or
        ("app/" + $wheelIdentity.filename) -cne [string]$wheelPath -or
        $wheelIdentity.sha256 -cne [string]$wheelSha256
    ) {
        throw "The portable bundle manifest does not match the application wheel."
    }
    return [PSCustomObject]@{
        application_package = $packageName
        application_version = [string]$applicationVersion
        manifest_profile = $manifestProfile
        wheel_path = [string]$wheelPath
        wheel_sha256 = [string]$wheelSha256
    }
}

function Test-BundleChecksums {
    param([Parameter(Mandatory = $true)][string]$Root)

    $checksumPath = Join-Path $Root "checksums.sha256"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw "The portable bundle checksum index is missing."
    }
    $checksumItem = Get-Item -LiteralPath $checksumPath -Force
    if ($checksumItem -isnot [IO.FileInfo] -or $checksumItem.Length -gt 10485760) {
        throw "The portable bundle checksum index exceeds its size boundary."
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($line in Get-Content -LiteralPath $checksumPath -Encoding UTF8) {
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') {
            throw "The portable bundle checksum index is malformed."
        }
        $digest = $Matches[1]
        $relative = $Matches[2]
        if (-not $seen.Add($relative)) {
            throw "The portable bundle checksum index contains a duplicate path."
        }
        $member = Resolve-CoeBundleMember -BundleRoot $Root -RelativePath $relative
        if (-not (Test-Path -LiteralPath $member -PathType Leaf)) {
            throw "A portable bundle member is missing."
        }
        if ((Get-Item -LiteralPath $member -Force) -isnot [IO.FileInfo]) {
            throw "A portable bundle member is not a regular file."
        }
        if ((Get-CoeFileSha256 -Path $member) -ne $digest) {
            throw "A portable bundle member failed checksum verification."
        }
    }
    if ($seen.Count -lt 1) {
        throw "The portable bundle checksum index is empty."
    }
    $rootPrefix = $Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $actualFiles = @(Get-ChildItem -LiteralPath $Root -Force -Recurse -File | Where-Object {
        -not ($_.Name -eq "checksums.sha256" -and $_.DirectoryName -eq $Root)
    })
    if ($actualFiles.Count -ne $seen.Count) {
        throw "The portable bundle contains an undeclared file."
    }
    foreach ($file in $actualFiles) {
        $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        if (-not $seen.Contains($relative)) {
            throw "The portable bundle contains an undeclared file."
        }
    }
}

try {
    $bundle = Resolve-CoePath -Path $BundleRoot -MustExist
    $install = Resolve-CoePath -Path $InstallRoot
    if (
        (Test-CoePathWithin -Path $install -Root $bundle) -or
        (Test-CoePathWithin -Path $bundle -Root $install)
    ) {
        throw "The installation directory and portable bundle must be disjoint."
    }
    $bundleItem = Get-Item -LiteralPath $bundle -Force
    if (-not $bundleItem.PSIsContainer) {
        throw "The portable bundle root must be a directory."
    }
    Assert-CoeNoReparsePoints -Path $bundle -Label "The portable bundle"
    Test-BundleChecksums -Root $bundle
    $applicationContract = Get-BundleApplicationContract -Root $bundle

    $appRoot = Join-Path $bundle "app"
    if (-not (Test-Path -LiteralPath $appRoot -PathType Container)) {
        throw "The portable bundle application directory is missing."
    }
    $appEntries = @(Get-ChildItem -LiteralPath $appRoot -Force)
    $declaredWheel = Resolve-CoeBundleMember `
        -BundleRoot $bundle `
        -RelativePath $applicationContract.wheel_path
    if (
        $appEntries.Count -ne 1 -or
        $appEntries[0] -isnot [IO.FileInfo] -or
        $appEntries[0].FullName -cne $declaredWheel
    ) {
        throw "The portable bundle must contain exactly one COE application wheel."
    }
    $wheelhouse = Join-Path $bundle "wheelhouse"
    if (-not (Test-Path -LiteralPath $wheelhouse -PathType Container)) {
        throw "The portable bundle wheelhouse is missing."
    }
    foreach ($entry in Get-ChildItem -LiteralPath $wheelhouse -Force) {
        if (
            $entry -isnot [IO.FileInfo] -or
            (
                $entry.Name -cne "README.txt" -and
                (
                    $entry.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.]*-[A-Za-z0-9][A-Za-z0-9_.+!]*(?:-[0-9][A-Za-z0-9_]*)?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$' -or
                    $entry.Name -like 'coe_corpus_ontology_enricher-*'
                )
            )
        ) {
            throw "The portable bundle wheelhouse contains an unsafe or ambiguous member."
        }
    }
    if (Test-Path -LiteralPath (Join-Path $bundle ".runtime")) {
        throw "The portable bundle cannot contain a pre-created Python runtime."
    }
    if (Test-Path -LiteralPath $install) {
        if (-not $Overwrite) {
            throw "The installation already exists; explicit overwrite is required."
        }
        $installItem = Get-Item -LiteralPath $install -Force
        if (-not $installItem.PSIsContainer) {
            throw "The existing installation target is not a directory."
        }
        Assert-CoeNoReparsePoints -Path $install -Label "The existing installation"
    }

    $parent = Split-Path -Parent $install
    [void](New-Item -ItemType Directory -Path $parent -Force)
    $temporary = Join-Path $parent (".coe-install-tmp-" + [Guid]::NewGuid().ToString("N"))
    $backup = $null
    [void](New-Item -ItemType Directory -Path $temporary)
    try {
        foreach ($source in Get-ChildItem -LiteralPath $bundle -Force) {
            Copy-Item -LiteralPath $source.FullName -Destination $temporary -Recurse -Force
        }
        Assert-CoeNoReparsePoints -Path $temporary -Label "The staged portable bundle"
        Test-BundleChecksums -Root $temporary
        $stagedContract = Get-BundleApplicationContract -Root $temporary
        if (
            $stagedContract.application_package -cne $applicationContract.application_package -or
            $stagedContract.application_version -cne $applicationContract.application_version -or
            $stagedContract.wheel_path -cne $applicationContract.wheel_path -or
            $stagedContract.wheel_sha256 -cne $applicationContract.wheel_sha256
        ) {
            throw "The portable bundle changed while it was staged for installation."
        }
        $runtime = Join-Path $temporary ".runtime"
        if ([IO.Path]::GetFileName($BootstrapPython).ToLowerInvariant() -eq "py.exe") {
            & $BootstrapPython -3.12 -m venv $runtime
        }
        else {
            & $BootstrapPython -m venv $runtime
        }
        if ($LASTEXITCODE -ne 0) {
            throw "The isolated Python runtime could not be created."
        }
        $runtimePython = Join-Path $runtime "Scripts\python.exe"
        $stagedWheel = Resolve-CoeBundleMember `
            -BundleRoot $temporary `
            -RelativePath $applicationContract.wheel_path
        $stagedWheelhouse = Join-Path $temporary "wheelhouse"
        $savedPipNoIndex = [Environment]::GetEnvironmentVariable("PIP_NO_INDEX", "Process")
        $savedPipVersionCheck = [Environment]::GetEnvironmentVariable("PIP_DISABLE_PIP_VERSION_CHECK", "Process")
        try {
            $env:PIP_NO_INDEX = "1"
            $env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
            & $runtimePython -m pip install --no-index --find-links $stagedWheelhouse $stagedWheel
            if ($LASTEXITCODE -ne 0) {
                throw "The COE wheel could not be installed from the offline bundle."
            }
            $distributionProbe = (
                'import importlib.metadata as m; ' +
                'd=m.distribution("coe-corpus-ontology-enricher"); ' +
                'print(d.metadata["Name"]); print(d.version)'
            )
            $installedMetadata = @(& $runtimePython -c $distributionProbe 2>$null)
            if ($LASTEXITCODE -ne 0 -or $installedMetadata.Count -ne 2) {
                throw "The installed COE distribution metadata could not be verified."
            }
            $installedPackage = ([string]$installedMetadata[0]).Trim()
            $installedVersion = ([string]$installedMetadata[1]).Trim()
            if (
                $installedPackage -cne $applicationContract.application_package -or
                $installedVersion -cne $applicationContract.application_version
            ) {
                throw "The installed COE distribution does not match the portable bundle manifest."
            }
            $versionRaw = & $runtimePython -m coe --version 2>$null
            $versionOutput = ($versionRaw -join " ").Trim()
            if (
                $LASTEXITCODE -ne 0 -or
                $versionOutput -cne ("coe " + $applicationContract.application_version)
            ) {
                throw "The installed COE command version does not match the portable bundle manifest."
            }
        }
        finally {
            [Environment]::SetEnvironmentVariable("PIP_NO_INDEX", $savedPipNoIndex, "Process")
            [Environment]::SetEnvironmentVariable(
                "PIP_DISABLE_PIP_VERSION_CHECK",
                $savedPipVersionCheck,
                "Process"
            )
        }

        if (Test-Path -LiteralPath $install) {
            $backup = Join-Path $parent (".coe-install-backup-" + [Guid]::NewGuid().ToString("N"))
            Move-Item -LiteralPath $install -Destination $backup
        }
        try {
            Move-Item -LiteralPath $temporary -Destination $install
        }
        catch {
            if ($null -ne $backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $install)) {
                Move-Item -LiteralPath $backup -Destination $install
            }
            throw
        }
        $installedPython = Join-Path $install ".runtime\Scripts\python.exe"
        $firewallConfigured = $false
        try {
            $installedMetadata = @(& $installedPython -c $distributionProbe 2>$null)
            if ($LASTEXITCODE -ne 0 -or $installedMetadata.Count -ne 2) {
                throw "The installed COE distribution metadata could not be verified after publication."
            }
            $installedPackage = ([string]$installedMetadata[0]).Trim()
            $installedVersion = ([string]$installedMetadata[1]).Trim()
            if (
                $installedPackage -cne $applicationContract.application_package -or
                $installedVersion -cne $applicationContract.application_version
            ) {
                throw "The published COE distribution does not match the portable bundle manifest."
            }
            $publishedVersionRaw = & $installedPython -m coe --version 2>$null
            $publishedVersion = ($publishedVersionRaw -join " ").Trim()
            if (
                $LASTEXITCODE -ne 0 -or
                $publishedVersion -cne ("coe " + $applicationContract.application_version)
            ) {
                throw "The published COE command version does not match the portable bundle manifest."
            }
            if ($ConfigureOutboundBlock) {
                if ($null -eq (Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue)) {
                    throw "Windows Firewall cmdlets are unavailable; the outbound block was not configured."
                }
                $programHash = Get-CoeFileSha256 -Path $installedPython
                $ruleName = "COE-Protected-Runtime-" + $programHash.Substring(0, 12)
                $existing = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
                if ($null -eq $existing) {
                    [void](New-NetFirewallRule `
                        -Name $ruleName `
                        -DisplayName "COE protected Python runtime outbound block" `
                        -Program $installedPython `
                        -Direction Outbound `
                        -Action Block `
                        -Profile Any `
                        -Enabled True)
                }
                $firewallConfigured = Test-CoeOutboundBlock -ProgramPath $installedPython
                if (-not $firewallConfigured) {
                    throw "The dedicated Python runtime outbound block could not be verified."
                }
            }
        }
        catch {
            if (Test-Path -LiteralPath $install) {
                Remove-Item -LiteralPath $install -Recurse -Force
            }
            if ($null -ne $backup -and (Test-Path -LiteralPath $backup)) {
                Move-Item -LiteralPath $backup -Destination $install
            }
            throw
        }
        if ($null -ne $backup -and (Test-Path -LiteralPath $backup)) {
            Remove-Item -LiteralPath $backup -Recurse -Force
        }

        Write-CoeJson -Value ([PSCustomObject]@{
            windows_install_schema_version = "1.0.0"
            status = "installed"
            application_package = $applicationContract.application_package
            application_version = $applicationContract.application_version
            manifest_profile = $applicationContract.manifest_profile
            application_wheel_sha256 = $applicationContract.wheel_sha256
            offline_install = $true
            bundle_checksums_verified = $true
            contains_patient_data = $false
            contains_terminology_payloads = $false
            outbound_firewall_block_configured = $firewallConfigured
        })
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Recurse -Force
        }
    }
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_install_schema_version = "1.0.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
