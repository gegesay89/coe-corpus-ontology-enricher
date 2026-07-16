[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\ProgramData\COE\App",
    [Parameter(Mandatory = $true)][string]$CorpusPath,
    [Parameter(Mandatory = $true)][string]$ReferenceSetPath,
    [Parameter(Mandatory = $true)][string]$AttestationPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Int64]$MaxFiles,
    [Int64]$MaxTotalBytes,
    [Int64]$MaxTotalTokens,
    [Int64]$MaxTotalNgrams,
    [int]$MaxNgramTokens,
    [int]$MaxCandidatesPerPhraseSystem,
    [switch]$RequireNvidia,
    [switch]$Overwrite,
    [switch]$AllowHostNetwork
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")
$suppliedParameters = @{}
foreach ($entry in $PSBoundParameters.GetEnumerator()) {
    $suppliedParameters[$entry.Key] = $entry.Value
}

function Add-CoeBoundedArgument {
    param(
        [Parameter(Mandatory = $true)][string]$ParameterName,
        [Parameter(Mandatory = $true)][string]$CliName,
        [Parameter(Mandatory = $true)][Int64]$Value,
        [Parameter(Mandatory = $true)][Int64]$Maximum,
        [Parameter(Mandatory = $true)]$Arguments
    )

    if (-not $script:SuppliedParameters.ContainsKey($ParameterName)) {
        return
    }
    if ($Value -lt 1 -or $Value -gt $Maximum) {
        throw "A protected-run resource limit is outside its safety boundary."
    }
    $Arguments.Add($CliName)
    $Arguments.Add($Value.ToString([Globalization.CultureInfo]::InvariantCulture))
}

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
    $install = Resolve-CoePath -Path $InstallRoot -MustExist
    $python = Resolve-CoePath -Path (Join-Path $install ".runtime\Scripts\python.exe") -MustExist
    $corpus = Resolve-CoePath -Path $CorpusPath -MustExist
    $referenceSet = Resolve-CoePath -Path $ReferenceSetPath -MustExist
    $attestation = Resolve-CoePath -Path $AttestationPath -MustExist
    $output = Resolve-CoePath -Path $OutputPath

    $preflightArgs = @{
        PythonExe = $python
        CorpusPath = $corpus
        ReferenceSetPath = $referenceSet
        AttestationPath = $attestation
        OutputPath = $output
        MaxFiles = $corpusDigestMaxFiles
        MaxTotalBytes = $corpusDigestMaxBytes
    }
    if ($RequireNvidia) {
        $preflightArgs["RequireNvidia"] = $true
    }
    if ($AllowHostNetwork) {
        $preflightArgs["AllowHostNetwork"] = $true
    }
    $preflightRaw = & (Join-Path $PSScriptRoot "Preflight-ProtectedRun.ps1") @preflightArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Protected-run preflight failed closed."
    }
    $preflight = ($preflightRaw -join "`n") | ConvertFrom-Json
    if ($preflight.status -ne "passed") {
        throw "Protected-run preflight failed closed."
    }

    $indexes = @(
        "cpt",
        "hcpcs",
        "icd10cm",
        "icd10pcs",
        "loinc",
        "rxnorm",
        "snomed"
    ) | ForEach-Object {
        $candidate = Resolve-CoePath -Path (Join-Path $referenceSet ($_ + ".sqlite3")) -MustExist
        if (-not (Test-CoePathWithin -Path $candidate -Root $referenceSet)) {
            throw "A licensed terminology index escapes the verified reference set."
        }
        $candidate
    }
    if ($indexes.Count -ne 7) {
        throw "The protected run requires all seven verified terminology indexes."
    }

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

    $savedEnvironment = @{}
    foreach ($name in @(
        "PIP_NO_INDEX",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "HF_HUB_OFFLINE",
        "HF_HUB_DISABLE_TELEMETRY",
        "TRANSFORMERS_OFFLINE",
        "DO_NOT_TRACK",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "PYTHONHASHSEED"
    )) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, "Process")
    }
    try {
        $env:PIP_NO_INDEX = "1"
        $env:PIP_DISABLE_PIP_VERSION_CHECK = "1"
        $env:HF_HUB_OFFLINE = "1"
        $env:HF_HUB_DISABLE_TELEMETRY = "1"
        $env:TRANSFORMERS_OFFLINE = "1"
        $env:DO_NOT_TRACK = "1"
        $env:HTTP_PROXY = "http://127.0.0.1:9"
        $env:HTTPS_PROXY = "http://127.0.0.1:9"
        $env:ALL_PROXY = "http://127.0.0.1:9"
        $env:NO_PROXY = ""
        $env:PYTHONHASHSEED = "0"

        $arguments = New-Object System.Collections.Generic.List[string]
        foreach ($item in @(
            "-m",
            "coe",
            "protected",
            "run",
            "--corpus",
            $corpus,
            "--attestation",
            $attestation
        )) {
            $arguments.Add($item)
        }
        foreach ($index in $indexes) {
            $arguments.Add("--index")
            $arguments.Add($index)
        }
        $arguments.Add("--output")
        $arguments.Add($output)
        Add-CoeBoundedArgument "MaxFiles" "--max-files" $MaxFiles 10000 $arguments
        Add-CoeBoundedArgument "MaxTotalBytes" "--max-total-bytes" $MaxTotalBytes 100000000 $arguments
        Add-CoeBoundedArgument "MaxTotalTokens" "--max-total-tokens" $MaxTotalTokens 5000000 $arguments
        Add-CoeBoundedArgument "MaxTotalNgrams" "--max-total-ngrams" $MaxTotalNgrams 10000000 $arguments
        Add-CoeBoundedArgument "MaxNgramTokens" "--max-ngram-tokens" $MaxNgramTokens 8 $arguments
        Add-CoeBoundedArgument `
            "MaxCandidatesPerPhraseSystem" `
            "--max-candidates-per-phrase-system" `
            $MaxCandidatesPerPhraseSystem `
            100 `
            $arguments
        if ($RequireNvidia) {
            $arguments.Add("--require-nvidia")
        }
        if ($Overwrite) {
            $arguments.Add("--overwrite")
        }

        $runRaw = & $python @($arguments.ToArray()) 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "The protected COE run failed closed."
        }
        $run = ($runRaw -join "`n") | ConvertFrom-Json
        if ($run.status -ne "succeeded") {
            throw "The protected COE run did not report success."
        }
    }
    finally {
        foreach ($name in $savedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], "Process")
        }
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
    if ($corpusBefore.sha256 -ne $corpusAfter.sha256) {
        throw "The protected corpus changed during the run."
    }
    if ($referenceBefore.sha256 -ne $referenceAfter.sha256) {
        throw "The licensed reference set changed during the run."
    }
    if ($attestationBefore -ne $attestationAfter) {
        throw "The protected-data attestation changed during the run."
    }

    $verificationRaw = & (Join-Path $PSScriptRoot "Verify-Run.ps1") `
        -OutputPath $output `
        -ReferenceSetPath $referenceSet `
        -PythonExe $python
    if ($LASTEXITCODE -ne 0) {
        throw "Post-run artifact verification failed closed."
    }
    $verification = ($verificationRaw -join "`n") | ConvertFrom-Json
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_protected_run_schema_version = "1.0.0"
        status = "succeeded"
        runtime_profile = "native-windows-protected"
        execution_profile = "protected_phi_local"
        output_classification = "protected_aggregate"
        network_policy = [string]$preflight.network_policy
        exact_matching_device = "cpu"
        nvidia_preflight = if ($RequireNvidia) { "passed_visibility_only" } else { "not_required" }
        gpu_semantic_stage = "reserved_not_implemented"
        input_integrity_verified_before_and_after = $true
        run = $run
        verification = $verification
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_protected_run_schema_version = "1.0.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
