[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\ProgramData\COE\App",
    [Parameter(Mandatory = $true)][string]$CorpusPath,
    [Parameter(Mandatory = $true)][string]$ReferenceSetPath,
    [Parameter(Mandatory = $true)][string]$AttestationPath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')][string]$OutputName = "run",
    [Parameter(Mandatory = $true)]
    [ValidatePattern('@sha256:[0-9a-fA-F]{64}$')]
    [string]$PythonBaseImage,
    [Int64]$MaxFiles,
    [Int64]$MaxTotalBytes,
    [Int64]$MaxTotalTokens,
    [Int64]$MaxTotalNgrams,
    [int]$MaxNgramTokens,
    [int]$MaxCandidatesPerPhraseSystem,
    [switch]$RequireNvidia,
    [switch]$Build,
    [switch]$Overwrite
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")
$suppliedParameters = @{}
foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    $suppliedParameters[$entry.Key] = $entry.Value
}

function Set-CoeOptionalLimit {
    param(
        [Parameter(Mandatory = $true)][string]$ParameterName,
        [Parameter(Mandatory = $true)][string]$EnvironmentName,
        [Parameter(Mandatory = $true)][Int64]$Value,
        [Parameter(Mandatory = $true)][Int64]$Maximum
    )

    if (-not $script:SuppliedParameters.ContainsKey($ParameterName)) {
        [Environment]::SetEnvironmentVariable($EnvironmentName, $null, "Process")
        return
    }
    if ($Value -lt 1 -or $Value -gt $Maximum) {
        throw "A protected-run resource limit is outside its safety boundary."
    }
    [Environment]::SetEnvironmentVariable(
        $EnvironmentName,
        $Value.ToString([Globalization.CultureInfo]::InvariantCulture),
        "Process"
    )
}

function Assert-CoeBidirectionalDisjoint {
    param(
        [Parameter(Mandatory = $true)][string]$First,
        [Parameter(Mandatory = $true)][string]$Second
    )

    if (
        (Test-CoePathWithin -Path $First -Root $Second) -or
        (Test-CoePathWithin -Path $Second -Root $First)
    ) {
        throw "The container output root must be disjoint from every protected input and runtime directory."
    }
}

function Get-CoeDockerImageId {
    param([Parameter(Mandatory = $true)][string]$Reference)

    $raw = @(& docker.exe image inspect --format "{{.Id}}" $Reference 2>$null)
    if ($LASTEXITCODE -ne 0 -or $raw.Count -ne 1) {
        throw "The approved COE container image could not be resolved locally."
    }
    $imageId = ([string]$raw[0]).Trim()
    if ($imageId -cnotmatch '^sha256:[0-9a-f]{64}$') {
        throw "The approved COE container image did not resolve to an immutable image ID."
    }
    return $imageId
}

function Remove-CoeOwnedStagingDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OutputRootPath
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $expectedParent = Resolve-CoePath -Path (Split-Path -Parent $Path)
    $expectedRoot = Resolve-CoePath -Path $OutputRootPath
    $leaf = Split-Path -Leaf $Path
    if (
        -not [string]::Equals($expectedParent, $expectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $leaf -notmatch '^\.coe-stage-[0-9a-f]{32}$'
    ) {
        throw "The one-run staging cleanup boundary is invalid."
    }
    $inventory = Get-CoeBoundedTreeInventory `
        -Path $Path `
        -Label "The one-run staging directory" `
        -MaxFiles 6 `
        -MaxBytes 68719476736 `
        -MaxWalkEntries 16
    if ($inventory.walk_entry_count -gt 16) {
        throw "The one-run staging directory exceeds its cleanup boundary."
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

$stagingRoot = $null
$stagedOutput = $null
$backupPath = $null
$publishedOutput = $false
$containerImageId = $null
$outputRootPath = $null

try {
    $script:SuppliedParameters = $suppliedParameters
    [Int64]$corpusDigestMaxFiles = 10000
    [Int64]$corpusDigestMaxBytes = 100000000
    if ($script:SuppliedParameters.ContainsKey("MaxFiles")) {
        if ($MaxFiles -lt 1 -or $MaxFiles -gt 10000) {
            throw "A protected-run resource limit is outside its safety boundary."
        }
        $corpusDigestMaxFiles = $MaxFiles
    }
    if ($script:SuppliedParameters.ContainsKey("MaxTotalBytes")) {
        if ($MaxTotalBytes -lt 1 -or $MaxTotalBytes -gt 100000000) {
            throw "A protected-run resource limit is outside its safety boundary."
        }
        $corpusDigestMaxBytes = $MaxTotalBytes
    }
    if ($null -eq (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
        throw "Docker is unavailable. Use the native Windows route or verify WSL2 Docker support first."
    }
    $null = & docker.exe version --format "{{.Server.Version}}" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The Docker server is unavailable."
    }
    $null = & docker.exe image inspect $PythonBaseImage 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The approved digest-pinned base image is not available locally."
    }

    $corpus = Resolve-CoePath -Path $CorpusPath -MustExist
    $referenceSet = Resolve-CoePath -Path $ReferenceSetPath -MustExist
    $attestation = Resolve-CoePath -Path $AttestationPath -MustExist
    $outputRootPath = Resolve-CoePath -Path $OutputRoot -MustExist
    $output = Join-Path $outputRootPath $OutputName
    $install = Resolve-CoePath -Path $InstallRoot -MustExist
    $python = Resolve-CoePath -Path (Join-Path $install ".runtime\Scripts\python.exe") -MustExist
    $outputRootItem = Get-Item -LiteralPath $outputRootPath -Force
    if (
        -not $outputRootItem.PSIsContainer -or
        ($outputRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "The container output root must be a regular, non-reparse directory."
    }
    $attestationDirectory = Resolve-CoePath -Path (Split-Path -Parent $attestation) -MustExist
    foreach ($protectedRoot in @($corpus, $referenceSet, $attestationDirectory, $install, $PSScriptRoot)) {
        Assert-CoeBidirectionalDisjoint -First $outputRootPath -Second $protectedRoot
    }
    if (Test-Path -LiteralPath $output) {
        if (-not $Overwrite) {
            throw "The protected output already exists; use -Overwrite for an atomic replacement."
        }
        $existingOutput = Get-CoeBoundedTreeInventory `
            -Path $output `
            -Label "The existing protected output" `
            -MaxFiles 3 `
            -MaxBytes 68719476736 `
            -MaxWalkEntries 3
        if ($existingOutput.walk_entry_count -ne $existingOutput.file_count) {
            throw "The existing protected output is not a flat, bounded artifact directory."
        }
    }

    $preflightArguments = @{
        PythonExe = $python
        CorpusPath = $corpus
        ReferenceSetPath = $referenceSet
        AttestationPath = $attestation
        OutputPath = $output
        ContainerReadOnlyMounts = $true
        MaxFiles = $corpusDigestMaxFiles
        MaxTotalBytes = $corpusDigestMaxBytes
    }
    if ($RequireNvidia) {
        $preflightArguments["RequireNvidia"] = $true
    }
    $preflightRaw = & (Join-Path $PSScriptRoot "Preflight-ProtectedRun.ps1") @preflightArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Protected-run host preflight failed closed."
    }
    $preflight = ($preflightRaw -join "`n") | ConvertFrom-Json
    if ($preflight.status -ne "passed") {
        throw "Protected-run host preflight failed closed."
    }

    $environmentNames = @(
        "COE_CORPUS_PATH",
        "COE_REFERENCE_SET_PATH",
        "COE_ATTESTATION_PATH",
        "COE_OUTPUT_STAGING_PATH",
        "COE_REQUIRE_GPU",
        "COE_PYTHON_BASE_IMAGE",
        "COE_IMAGE_NAME",
        "COE_MAX_FILES",
        "COE_MAX_TOTAL_BYTES",
        "COE_MAX_TOTAL_TOKENS",
        "COE_MAX_TOTAL_NGRAMS",
        "COE_MAX_NGRAM_TOKENS",
        "COE_MAX_CANDIDATES_PER_PHRASE_SYSTEM"
    )
    $savedEnvironment = @{}
    foreach ($name in $environmentNames) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
        $env:COE_CORPUS_PATH = $corpus
        $env:COE_REFERENCE_SET_PATH = $referenceSet
        $env:COE_ATTESTATION_PATH = $attestation
        $env:COE_REQUIRE_GPU = if ($RequireNvidia) { "1" } else { "0" }
        $env:COE_PYTHON_BASE_IMAGE = $PythonBaseImage
        $expectedImageTag = "coe-protected-local:0.2.0a1"
        $env:COE_IMAGE_NAME = $expectedImageTag
        Set-CoeOptionalLimit "MaxFiles" "COE_MAX_FILES" $MaxFiles 10000
        Set-CoeOptionalLimit "MaxTotalBytes" "COE_MAX_TOTAL_BYTES" $MaxTotalBytes 100000000
        Set-CoeOptionalLimit "MaxTotalTokens" "COE_MAX_TOTAL_TOKENS" $MaxTotalTokens 5000000
        Set-CoeOptionalLimit "MaxTotalNgrams" "COE_MAX_TOTAL_NGRAMS" $MaxTotalNgrams 10000000
        Set-CoeOptionalLimit "MaxNgramTokens" "COE_MAX_NGRAM_TOKENS" $MaxNgramTokens 8
        Set-CoeOptionalLimit `
            "MaxCandidatesPerPhraseSystem" `
            "COE_MAX_CANDIDATES_PER_PHRASE_SYSTEM" `
            $MaxCandidatesPerPhraseSystem `
            100

        $compose = Join-Path $PSScriptRoot "docker\compose.gpu.yaml"
        if ($Build) {
            & docker.exe compose -f $compose build --pull=false coe *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "The offline COE container build failed."
            }
        }
        $containerImageId = Get-CoeDockerImageId -Reference $expectedImageTag
        $env:COE_IMAGE_NAME = $containerImageId
        if ((Get-CoeDockerImageId -Reference $env:COE_IMAGE_NAME) -cne $containerImageId) {
            throw "The immutable COE container image ID could not be reverified before execution."
        }

        $stagingRoot = Join-Path $outputRootPath (".coe-stage-" + [Guid]::NewGuid().ToString("N"))
        $stagedOutput = Join-Path $stagingRoot "result"
        if (
            (Test-Path -LiteralPath $stagingRoot) -or
            (Test-CoePathWithin -Path $stagingRoot -Root $output) -or
            (Test-CoePathWithin -Path $output -Root $stagingRoot)
        ) {
            throw "The unique one-run staging directory is not disjoint from the publication target."
        }
        [void](New-Item -ItemType Directory -Path $stagingRoot)
        $stagingItem = Get-Item -LiteralPath $stagingRoot -Force
        if (
            -not $stagingItem.PSIsContainer -or
            ($stagingItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        ) {
            throw "The unique one-run staging directory is unsafe."
        }
        $env:COE_OUTPUT_STAGING_PATH = $stagingRoot

        $corpusBefore = Get-CoeTreeDigest `
            -Path $corpus `
            -Label "The protected corpus" `
            -MaxFiles $corpusDigestMaxFiles `
            -MaxBytes $corpusDigestMaxBytes `
            -MaxWalkEntries 50000
        $referenceBefore = Get-CoeTreeDigest `
            -Path $referenceSet `
            -Label "The licensed reference set" `
            -MaxFiles 10 `
            -MaxBytes 68719476736 `
            -MaxWalkEntries 10
        $attestationBefore = Get-CoeFileSha256 -Path $attestation
        & docker.exe compose -f $compose run --rm --no-deps coe *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "The network-isolated COE container run failed closed."
        }
        if ((Get-CoeDockerImageId -Reference $containerImageId) -cne $containerImageId) {
            throw "The immutable COE container image ID could not be reverified after execution."
        }
        $corpusAfter = Get-CoeTreeDigest `
            -Path $corpus `
            -Label "The protected corpus" `
            -MaxFiles $corpusDigestMaxFiles `
            -MaxBytes $corpusDigestMaxBytes `
            -MaxWalkEntries 50000
        $referenceAfter = Get-CoeTreeDigest `
            -Path $referenceSet `
            -Label "The licensed reference set" `
            -MaxFiles 10 `
            -MaxBytes 68719476736 `
            -MaxWalkEntries 10
        $attestationAfter = Get-CoeFileSha256 -Path $attestation
        if (
            $corpusBefore.sha256 -ne $corpusAfter.sha256 -or
            $referenceBefore.sha256 -ne $referenceAfter.sha256 -or
            $attestationBefore -ne $attestationAfter
        ) {
            throw "A protected input changed during the container run."
        }
    }
    finally {
        foreach ($name in $environmentNames) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
        }
    }

    if ($null -eq $stagedOutput -or -not (Test-Path -LiteralPath $stagedOutput -PathType Container)) {
        throw "The container did not produce the fixed staged result directory."
    }
    $stagedVerificationRaw = & (Join-Path $PSScriptRoot "Verify-Run.ps1") `
        -OutputPath $stagedOutput `
        -ReferenceSetPath $referenceSet `
        -PythonExe $python
    if ($LASTEXITCODE -ne 0) {
        throw "Staged container output verification failed closed."
    }
    $stagedVerification = ($stagedVerificationRaw -join "`n") | ConvertFrom-Json
    if ($stagedVerification.status -ne "passed") {
        throw "Staged container output verification failed closed."
    }

    if (Test-Path -LiteralPath $output) {
        if (-not $Overwrite) {
            throw "The protected output appeared before publication and replacement was not approved."
        }
        $replacementOutput = Get-CoeBoundedTreeInventory `
            -Path $output `
            -Label "The protected output selected for replacement" `
            -MaxFiles 3 `
            -MaxBytes 68719476736 `
            -MaxWalkEntries 3
        if ($replacementOutput.walk_entry_count -ne $replacementOutput.file_count) {
            throw "The protected output selected for replacement is not a flat, bounded artifact directory."
        }
        $backupPath = Join-Path $outputRootPath (".coe-backup-" + [Guid]::NewGuid().ToString("N"))
        if (Test-Path -LiteralPath $backupPath) {
            throw "The atomic output rollback path already exists."
        }
        [IO.Directory]::Move($output, $backupPath)
    }
    try {
        [IO.Directory]::Move($stagedOutput, $output)
        $publishedOutput = $true
        $publishedVerificationRaw = & (Join-Path $PSScriptRoot "Verify-Run.ps1") `
            -OutputPath $output `
            -ReferenceSetPath $referenceSet `
            -PythonExe $python
        if ($LASTEXITCODE -ne 0) {
            throw "Published container output verification failed closed."
        }
        $verification = ($publishedVerificationRaw -join "`n") | ConvertFrom-Json
        if (
            $verification.status -ne "passed" -or
            $verification.run_fingerprint -cne $stagedVerification.run_fingerprint -or
            $verification.semantic_output_sha256 -cne $stagedVerification.semantic_output_sha256 -or
            $verification.run_report_sha256 -cne $stagedVerification.run_report_sha256
        ) {
            throw "The published container output does not match the verified staged result."
        }
        if ($null -ne $backupPath) {
            Remove-Item -LiteralPath $backupPath -Recurse -Force
            $backupPath = $null
        }
    }
    catch {
        if ($publishedOutput -and (Test-Path -LiteralPath $output)) {
            Remove-Item -LiteralPath $output -Recurse -Force
            $publishedOutput = $false
        }
        if ($null -ne $backupPath -and (Test-Path -LiteralPath $backupPath)) {
            if (Test-Path -LiteralPath $output) {
                throw "Atomic container-output publication failed and rollback requires operator recovery."
            }
            [IO.Directory]::Move($backupPath, $output)
            $backupPath = $null
        }
        throw "Atomic container-output publication failed and was rolled back."
    }

    Remove-CoeOwnedStagingDirectory -Path $stagingRoot -OutputRootPath $outputRootPath
    $stagingRoot = $null
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_container_run_schema_version = "1.0.0"
        status = "succeeded"
        runtime_profile = "wsl2-docker-protected"
        execution_profile = "protected_phi_local"
        output_classification = "protected_aggregate"
        network_policy = "container_network_none"
        protected_input_write_policy = "container_read_only_bind_mounts"
        protected_output_write_policy = "unique_one_run_staging_then_atomic_publish"
        container_image_id = [string]$containerImageId
        exact_matching_device = "cpu"
        nvidia_preflight = if ($RequireNvidia) { "passed_visibility_only" } else { "not_required" }
        gpu_semantic_stage = "reserved_not_implemented"
        input_integrity_verified_before_and_after = $true
        verification = $verification
    })
}
catch {
    $safeError = Get-CoeSafeError -Exception $_.Exception
    if ($null -ne $stagingRoot -and $null -ne $outputRootPath) {
        try {
            Remove-CoeOwnedStagingDirectory -Path $stagingRoot -OutputRootPath $outputRootPath
            $stagingRoot = $null
        }
        catch {
            $safeError = "The container run failed closed and its one-run staging directory requires local operator cleanup."
        }
    }
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_container_run_schema_version = "1.0.0"
        status = "failed"
        safe_error = $safeError
    })
    exit 1
}
