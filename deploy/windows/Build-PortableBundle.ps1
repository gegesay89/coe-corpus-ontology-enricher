[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$WheelPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$WheelhousePath,
    [switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

try {
    $wheel = Resolve-CoePath -Path $WheelPath -MustExist
    $sourceWheelIdentity = Get-CoeApplicationWheelIdentity -Path $wheel
    $output = Resolve-CoePath -Path $OutputPath
    $wheelhouse = $null
    if (-not [string]::IsNullOrWhiteSpace($WheelhousePath)) {
        $wheelhouse = Resolve-CoePath -Path $WheelhousePath -MustExist
    }
    $protectedSources = @($PSScriptRoot, $wheel)
    if ($null -ne $wheelhouse) {
        $protectedSources += $wheelhouse
    }
    foreach ($sourceRoot in $protectedSources) {
        if (
            (Test-CoePathWithin -Path $output -Root $sourceRoot) -or
            (Test-CoePathWithin -Path $sourceRoot -Root $output)
        ) {
            throw "The portable bundle output must be disjoint from every packaging input."
        }
    }
    if (Test-Path -LiteralPath $output) {
        if (-not $Overwrite) {
            throw "The portable bundle output already exists; explicit overwrite is required."
        }
        $outputItem = Get-Item -LiteralPath $output -Force
        if (-not $outputItem.PSIsContainer) {
            throw "The existing portable bundle output is not a directory."
        }
        Assert-CoeNoReparsePoints -Path $output -Label "The existing portable bundle output"
    }
    $parent = Split-Path -Parent $output
    [void](New-Item -ItemType Directory -Path $parent -Force)
    $temporary = Join-Path $parent (".coe-bundle-tmp-" + [Guid]::NewGuid().ToString("N"))
    $backup = $null
    [void](New-Item -ItemType Directory -Path $temporary)
    try {
        $deploymentFiles = @(
            "Build-PortableBundle.ps1",
            "Collect-HostFacts.ps1",
            "Common.ps1",
            "config/model_manifest.example.json",
            "config/protected_data_attestation.example.json",
            "config/protected_run.example.json",
            "config/terminology_entitlement.example.json",
            "docker/Dockerfile.gpu",
            "docker/compose.gpu.yaml",
            "docker/run-protected.sh",
            "docker/validate_attestation.py",
            "Inspect-InputLayout.ps1",
            "Install-Native.ps1",
            "Invoke-WslDocker.ps1",
            "Preflight-ProtectedRun.ps1",
            "README-WINDOWS.md",
            "Run-Coe.ps1",
            "Verify-Run.ps1"
        )
        foreach ($name in $deploymentFiles) {
            $source = Join-Path $PSScriptRoot $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "The deployment source is incomplete."
            }
            $sourceItem = Get-Item -LiteralPath $source -Force
            if (
                $sourceItem -isnot [IO.FileInfo] -or
                ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "The deployment source contains an unsafe file."
            }
            $destination = Join-Path $temporary $name
            [void](New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force)
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
        [void](New-Item -ItemType Directory -Path (Join-Path $temporary "app") -Force)
        [void](New-Item -ItemType Directory -Path (Join-Path $temporary "wheelhouse") -Force)
        $copiedWheel = Join-Path (Join-Path $temporary "app") $sourceWheelIdentity.filename
        Copy-Item -LiteralPath $wheel -Destination $copiedWheel -Force
        $copiedWheelIdentity = Get-CoeApplicationWheelIdentity -Path $copiedWheel
        if ($copiedWheelIdentity.sha256 -ne $sourceWheelIdentity.sha256) {
            throw "The COE application wheel changed while the portable bundle was built."
        }
        if ($null -ne $wheelhouse) {
            Assert-CoeNoReparsePoints -Path $wheelhouse -Label "The offline wheelhouse"
            $wheelhouseItem = Get-Item -LiteralPath $wheelhouse -Force
            if (-not $wheelhouseItem.PSIsContainer) {
                throw "The offline wheelhouse must be a directory."
            }
            foreach ($dependency in Get-ChildItem -LiteralPath $wheelhouse -Force) {
                if (
                    $dependency -isnot [IO.FileInfo] -or
                    $dependency.Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.]*-[A-Za-z0-9][A-Za-z0-9_.+!]*(?:-[0-9][A-Za-z0-9_]*)?-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl$' -or
                    $dependency.Name -like 'coe_corpus_ontology_enricher-*'
                ) {
                    throw "The offline wheelhouse contains an unsafe or ambiguous member."
                }
                Copy-Item `
                    -LiteralPath $dependency.FullName `
                    -Destination (Join-Path $temporary "wheelhouse") `
                    -Force
            }
        }

        $manifest = [ordered]@{
            portable_bundle_schema_version = "1.1.0"
            created_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
            application_package = $copiedWheelIdentity.application_package
            application_version = $copiedWheelIdentity.application_version
            application_wheel = [ordered]@{
                path = "app/" + $copiedWheelIdentity.filename
                sha256 = $copiedWheelIdentity.sha256
            }
            exact_matching_device = "cpu"
            gpu_semantic_stage = "reserved_not_implemented"
            contains_patient_data = $false
            contains_terminology_payloads = $false
            contains_model_weights = $false
            run_network_policy = "offline-required"
        }
        Write-CoeUtf8NoBom `
            -Path (Join-Path $temporary "bundle-manifest.json") `
            -Content (($manifest | ConvertTo-Json -Depth 8) + "`n")

        $rootPrefix = $temporary.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        $checksumRows = New-Object System.Collections.Generic.List[string]
        foreach ($file in Get-ChildItem -LiteralPath $temporary -Force -Recurse -File) {
            if ($file.Name -eq "checksums.sha256" -and $file.DirectoryName -eq $temporary) {
                continue
            }
            $relative = $file.FullName.Substring($rootPrefix.Length).Replace('\', '/')
            $checksumRows.Add((Get-CoeFileSha256 -Path $file.FullName) + "  " + $relative)
        }
        $rows = $checksumRows.ToArray()
        [Array]::Sort($rows, [StringComparer]::Ordinal)
        Write-CoeUtf8NoBom -Path (Join-Path $temporary "checksums.sha256") -Content (($rows -join "`n") + "`n")

        if (Test-Path -LiteralPath $output) {
            $backup = Join-Path $parent (".coe-bundle-backup-" + [Guid]::NewGuid().ToString("N"))
            Move-Item -LiteralPath $output -Destination $backup
        }
        try {
            Move-Item -LiteralPath $temporary -Destination $output
        }
        catch {
            if ($null -ne $backup -and (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $output)) {
                Move-Item -LiteralPath $backup -Destination $output
            }
            throw
        }
        if ($null -ne $backup -and (Test-Path -LiteralPath $backup)) {
            Remove-Item -LiteralPath $backup -Recurse -Force
        }
        Write-CoeJson -Value ([PSCustomObject]@{
            portable_bundle_schema_version = "1.1.0"
            status = "created"
            application_package = $copiedWheelIdentity.application_package
            application_version = $copiedWheelIdentity.application_version
            checksum_count = $rows.Count
            contains_patient_data = $false
            contains_terminology_payloads = $false
            contains_model_weights = $false
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
        portable_bundle_schema_version = "1.1.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
