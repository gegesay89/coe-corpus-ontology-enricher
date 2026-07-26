[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$ReferenceSetPath,
    [Parameter(Mandatory = $true)][string]$PythonExe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

# This wrapper deliberately delegates semantic verification to the trusted
# `coe protected verify` implementation instead of re-implementing the
# aggregate output contract in PowerShell. One verifier, one contract: the
# wrapper adds only host-side path safety, licensed-reference-set
# verification, and a cross-check that the report on disk is the one the core
# verifier accepted.

function Assert-CoeExactFields {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($Object -isnot [PSCustomObject]) {
        throw "$Label is not a JSON object."
    }
    [string[]]$actual = @($Object.PSObject.Properties.Name)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($Expected, [StringComparer]::Ordinal)
    if (($actual -join "`n") -ne ($Expected -join "`n")) {
        throw "$Label contains an unsupported field."
    }
}

try {
    $output = Resolve-CoePath -Path $OutputPath -MustExist
    $referenceSet = Resolve-CoePath -Path $ReferenceSetPath -MustExist
    $python = Resolve-CoePath -Path $PythonExe -MustExist
    if (
        (Test-CoePathWithin -Path $output -Root $referenceSet) -or
        (Test-CoePathWithin -Path $referenceSet -Root $output)
    ) {
        throw "The protected output and licensed reference set must be disjoint."
    }
    Assert-CoeNoReparsePoints -Path $output -Label "The run output"
    Assert-CoeNoReparsePoints -Path $referenceSet -Label "The licensed reference set"

    $referenceRaw = & $python -m coe reference verify-set $referenceSet 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The licensed reference set failed post-run verification."
    }
    try {
        $referenceReport = ($referenceRaw -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "The licensed reference set returned an invalid verification report."
    }
    if (
        $referenceReport.reference_set_manifest_schema_version -ne "1.0.0" -or
        [int]$referenceReport.index_count -ne 7
    ) {
        throw "The licensed reference set does not contain the required seven verified indexes."
    }

    $referenceIdentities = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $coreVerifyArguments = New-Object System.Collections.Generic.List[string]
    foreach ($argument in @("-m", "coe", "protected", "verify", "--output", $output)) {
        $coreVerifyArguments.Add($argument)
    }
    foreach ($record in @($referenceReport.indexes)) {
        if (-not $referenceIdentities.Add(([string]$record.system_uri) + "`n" + ([string]$record.release_id))) {
            throw "The licensed reference set contains a duplicate release identity."
        }
        $fileName = [string]$record.file_name
        if ([IO.Path]::GetFileName($fileName) -ne $fileName -or $fileName -notmatch '^[a-z0-9]+\.sqlite3$') {
            throw "The licensed reference set contains an unsafe index path."
        }
        $indexPath = Resolve-CoePath -Path (Join-Path $referenceSet $fileName) -MustExist
        if (-not (Test-CoePathWithin -Path $indexPath -Root $referenceSet)) {
            throw "A licensed terminology index escapes the verified reference set."
        }
        $coreVerifyArguments.Add("--index")
        $coreVerifyArguments.Add($indexPath)
    }
    $coreRaw = & $python @($coreVerifyArguments.ToArray()) 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The trusted protected-output verifier failed closed."
    }
    try {
        $coreVerification = ($coreRaw -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "The trusted protected-output verifier returned an invalid result."
    }
    Assert-CoeExactFields -Object $coreVerification -Expected @(
        "ambiguity_row_count",
        "association_row_count",
        "candidate_term_row_count",
        "coding_count_row_count",
        "lexical_form_row_count",
        "run_fingerprint",
        "semantic_output_sha256",
        "status",
        "terminology_count",
        "verification_schema_version"
    ) -Label "The trusted protected-output verification result"
    if (
        $coreVerification.status -ne "passed" -or
        $coreVerification.verification_schema_version -ne "protected-output-verification-1.1.0" -or
        [int]$coreVerification.terminology_count -ne 7
    ) {
        throw "The trusted protected-output verifier did not satisfy its contract."
    }

    $reportPath = Join-Path $output "run_report.json"
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "The protected run report is missing."
    }
    $reportItem = Get-Item -LiteralPath $reportPath -Force
    if ($reportItem -isnot [IO.FileInfo] -or $reportItem.Length -gt 1048576) {
        throw "The protected run report exceeds its size boundary."
    }
    try {
        $report = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "The protected run report is unreadable or malformed."
    }
    if (
        $report.run_report_schema_version -ne "protected-local-1.1.0" -or
        $report.status -ne "succeeded" -or
        $report.execution_profile -ne "protected_phi_local" -or
        $report.attestation.output_classification -ne "protected_aggregate" -or
        [string]$report.run_fingerprint -ne [string]$coreVerification.run_fingerprint -or
        [string]$report.semantic_output_sha256 -ne [string]$coreVerification.semantic_output_sha256
    ) {
        throw "The protected run report does not match the trusted verification result."
    }
    $reportIdentities = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($terminology in @($report.terminologies)) {
        [void]$reportIdentities.Add(([string]$terminology.system_uri) + "`n" + ([string]$terminology.release_id))
    }
    if (-not $reportIdentities.SetEquals($referenceIdentities)) {
        throw "The protected run report is not bound to the verified reference set."
    }

    Write-CoeJson -Value ([PSCustomObject]@{
        windows_run_verification_schema_version = "2.0.0"
        status = "passed"
        execution_profile = "protected_phi_local"
        output_classification = "protected_aggregate"
        run_fingerprint = [string]$report.run_fingerprint
        semantic_output_sha256 = [string]$report.semantic_output_sha256
        run_report_sha256 = Get-CoeFileSha256 -Path $reportPath
        trusted_core_verification_schema_version = [string]$coreVerification.verification_schema_version
        ambiguity_row_count = [Int64]$coreVerification.ambiguity_row_count
        association_row_count = [Int64]$coreVerification.association_row_count
        candidate_term_row_count = [Int64]$coreVerification.candidate_term_row_count
        coding_count_row_count = [Int64]$coreVerification.coding_count_row_count
        lexical_form_row_count = [Int64]$coreVerification.lexical_form_row_count
        terminology_count = [int]$coreVerification.terminology_count
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_run_verification_schema_version = "2.0.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
