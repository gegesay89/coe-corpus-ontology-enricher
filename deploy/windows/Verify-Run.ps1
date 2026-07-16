[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [Parameter(Mandatory = $true)][string]$ReferenceSetPath,
    [Parameter(Mandatory = $true)][string]$PythonExe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

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

function Assert-CoeBoundedInteger {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][Int64]$Minimum,
        [Parameter(Mandatory = $true)][Int64]$Maximum,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $numericType = if ($null -eq $Value) { "" } else { $Value.GetType().Name }
    if ($numericType -notin @("Byte", "Int16", "Int32", "Int64", "UInt16", "UInt32", "UInt64")) {
        throw "$Label is not an integer."
    }
    try {
        [Int64]$integer = [Convert]::ToInt64($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    catch {
        throw "$Label is outside its integer boundary."
    }
    if ($integer -lt $Minimum -or $integer -gt $Maximum) {
        throw "$Label is outside its approved boundary."
    }
}

function Get-ExpectedRowFields {
    param([Parameter(Mandatory = $true)][string]$ArtifactName)

    if ($ArtifactName -eq "coding_counts.jsonl") {
        return @(
            "code",
            "coding_count_schema_version",
            "distinct_matched_form_count",
            "exact_match_document_count",
            "exact_match_occurrence_count",
            "release_id",
            "system_uri"
        )
    }
    if ($ArtifactName -eq "ambiguity_counts.jsonl") {
        return @(
            "ambiguity_count_schema_version",
            "ambiguous_document_count",
            "ambiguous_form_count",
            "ambiguous_occurrence_count",
            "release_id",
            "system_uri"
        )
    }
    throw "The protected run declared an unsupported artifact."
}

function Test-CoeAggregateRow {
    param(
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][string]$ArtifactName
    )

    if ([string]::IsNullOrWhiteSpace($Line)) {
        throw "A protected aggregate artifact contains an empty row."
    }
    try {
        $row = $Line | ConvertFrom-Json
    }
    catch {
        throw "A protected aggregate artifact contains malformed JSON."
    }
    $expectedFields = Get-ExpectedRowFields -ArtifactName $ArtifactName
    $actualFields = @($row.PSObject.Properties.Name)
    [Array]::Sort($actualFields, [StringComparer]::Ordinal)
    if (($actualFields -join "`n") -ne ($expectedFields -join "`n")) {
        throw "A protected aggregate artifact contains an unsupported field."
    }
    if ($ArtifactName -eq "coding_counts.jsonl") {
        if ($row.coding_count_schema_version -ne "1.0.0") {
            throw "A protected aggregate artifact row has an unsupported schema."
        }
        $numericFields = @(
            "distinct_matched_form_count",
            "exact_match_document_count",
            "exact_match_occurrence_count"
        )
        if (
            $row.code -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$row.code) -or
            ([string]$row.code).Length -gt 128 -or
            [string]$row.code -match '[\x00-\x1f]'
        ) {
            throw "A protected coding aggregate contains an invalid terminology code."
        }
    }
    else {
        if ($row.ambiguity_count_schema_version -ne "1.0.0") {
            throw "A protected aggregate artifact row has an unsupported schema."
        }
        $numericFields = @(
            "ambiguous_document_count",
            "ambiguous_form_count",
            "ambiguous_occurrence_count"
        )
    }
    foreach ($name in $numericFields) {
        $value = $row.PSObject.Properties[$name].Value
        Assert-CoeBoundedInteger `
            -Value $value `
            -Minimum 0 `
            -Maximum ([Int64]::MaxValue) `
            -Label "A protected aggregate artifact count"
    }
    foreach ($name in @("release_id", "system_uri")) {
        $value = $row.PSObject.Properties[$name].Value
        if (
            $value -isnot [string] -or
            [string]::IsNullOrWhiteSpace([string]$value) -or
            ([string]$value).Length -gt 2048 -or
            [string]$value -match '[\x00-\x1f]'
        ) {
            throw "A protected aggregate artifact contains an invalid terminology identity."
        }
    }
}

function Test-CoeJsonlArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ArtifactName,
        [Parameter(Mandatory = $true)][Int64]$ExpectedRows
    )

    [Int64]$rows = 0
    $maximumLineCharacters = 16384
    $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
    try {
        $reader = [IO.StreamReader]::new($Path, $strictUtf8, $true)
    }
    catch {
        throw "A protected aggregate artifact is unreadable."
    }
    try {
        $lineBuilder = New-Object Text.StringBuilder
        while (($character = $reader.Read()) -ne -1) {
            if ($character -eq 13) {
                throw "A protected aggregate artifact contains a non-canonical line ending."
            }
            if ($character -eq 10) {
                Test-CoeAggregateRow -Line $lineBuilder.ToString() -ArtifactName $ArtifactName
                $rows += 1
                [void]$lineBuilder.Clear()
                continue
            }
            [void]$lineBuilder.Append([char]$character)
            if ($lineBuilder.Length -gt $maximumLineCharacters) {
                throw "A protected aggregate artifact row exceeds its size boundary."
            }
        }
        if ($lineBuilder.Length -ne 0) {
            throw "A protected aggregate artifact is missing its terminal newline."
        }
    }
    finally {
        $reader.Dispose()
    }
    if ($rows -ne $ExpectedRows) {
        throw "A protected aggregate artifact row count does not match its report."
    }
    return $rows
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
        "coding_count_row_count",
        "run_fingerprint",
        "semantic_output_sha256",
        "status",
        "terminology_count",
        "verification_schema_version"
    ) -Label "The trusted protected-output verification result"
    if (
        $coreVerification.status -ne "passed" -or
        $coreVerification.verification_schema_version -ne "protected-output-verification-1.0.0" -or
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
    Assert-CoeExactFields -Object $report -Expected @(
        "artifacts",
        "attestation",
        "execution_profile",
        "grounding",
        "limitations",
        "matching",
        "processing_totals",
        "resource_limits",
        "run_fingerprint",
        "run_report_schema_version",
        "semantic_output_sha256",
        "status",
        "terminologies",
        "totals"
    ) -Label "The protected run report"
    Assert-CoeExactFields -Object $report.attestation -Expected @(
        "approval_ref_count",
        "approved",
        "attestation_sha256",
        "output_classification",
        "profile",
        "retention_policy_id"
    ) -Label "The protected run attestation summary"
    Assert-CoeExactFields -Object $report.grounding -Expected @(
        "candidate_count_checked",
        "status"
    ) -Label "The protected run grounding summary"
    Assert-CoeExactFields -Object $report.matching -Expected @(
        "device",
        "method",
        "nvidia_preflight"
    ) -Label "The protected run matching summary"
    Assert-CoeExactFields -Object $report.processing_totals -Expected @(
        "corpus_content_set_sha256",
        "file_count",
        "total_bytes",
        "total_characters",
        "total_ngrams",
        "total_tokens",
        "unique_form_count"
    ) -Label "The protected run processing totals"
    Assert-CoeExactFields -Object $report.resource_limits -Expected @(
        "max_candidates_per_phrase_system",
        "max_file_bytes",
        "max_files",
        "max_ngram_tokens",
        "max_ngrams_per_file",
        "max_tokens_per_file",
        "max_total_bytes",
        "max_total_ngrams",
        "max_total_tokens",
        "max_unique_phrases",
        "max_walk_entries"
    ) -Label "The protected run resource limits"
    Assert-CoeExactFields -Object $report.totals -Expected @(
        "ambiguity_row_count",
        "coding_count_row_count"
    ) -Label "The protected run output totals"
    $expectedLimitations = @(
        "aggregate protected output; not de-identified or approved for public release",
        "exact lexical n-grams are not context-qualified or overlap-resolved",
        "coding counts are lexical evidence and not clinical prevalence",
        "ambiguous and unmapped forms do not contribute to coding counts"
    )
    $actualLimitations = @($report.limitations)
    if (
        $actualLimitations.Count -ne $expectedLimitations.Count -or
        ($actualLimitations -join "`n") -cne ($expectedLimitations -join "`n")
    ) {
        throw "The protected run report limitations do not match the approved contract."
    }
    if (
        $report.run_report_schema_version -ne "protected-local-1.0.0" -or
        $report.status -ne "succeeded" -or
        $report.execution_profile -ne "protected_phi_local" -or
        $report.attestation.approved -ne $true -or
        $report.attestation.profile -ne "protected_phi_local" -or
        $report.attestation.output_classification -ne "protected_aggregate" -or
        [string]$report.attestation.attestation_sha256 -notmatch '^[0-9a-f]{64}$' -or
        $report.matching.device -ne "cpu" -or
        $report.matching.method -ne "exact_preferred_and_alias" -or
        $report.matching.nvidia_preflight -notin @("not_required", "passed") -or
        $report.grounding.status -ne "passed"
    ) {
        throw "The protected run report did not satisfy its aggregate-only contract."
    }
    if (
        [string]$report.run_fingerprint -notmatch '^[0-9a-f]{64}$' -or
        [string]$report.semantic_output_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$report.processing_totals.corpus_content_set_sha256 -notmatch '^[0-9a-f]{64}$'
    ) {
        throw "The protected run report contains an invalid digest."
    }
    Assert-CoeBoundedInteger `
        -Value $report.attestation.approval_ref_count `
        -Minimum 2 `
        -Maximum 3 `
        -Label "The protected run approval-reference count"
    $limitMaximums = @{
        max_candidates_per_phrase_system = 100
        max_file_bytes = 10000000
        max_files = 10000
        max_ngram_tokens = 8
        max_ngrams_per_file = 1000000
        max_tokens_per_file = 250000
        max_total_bytes = 100000000
        max_total_ngrams = 10000000
        max_total_tokens = 5000000
        max_unique_phrases = 1000000
        max_walk_entries = 50000
    }
    foreach ($name in $limitMaximums.Keys) {
        Assert-CoeBoundedInteger `
            -Value $report.resource_limits.PSObject.Properties[$name].Value `
            -Minimum 1 `
            -Maximum ([Int64]$limitMaximums[$name]) `
            -Label "A protected run resource limit"
    }
    if (
        [Int64]$report.resource_limits.max_file_bytes -gt [Int64]$report.resource_limits.max_total_bytes -or
        [Int64]$report.resource_limits.max_tokens_per_file -gt [Int64]$report.resource_limits.max_total_tokens -or
        [Int64]$report.resource_limits.max_ngrams_per_file -gt [Int64]$report.resource_limits.max_total_ngrams
    ) {
        throw "The protected run resource-limit relationships are invalid."
    }
    $processingBounds = @{
        file_count = [Int64]$report.resource_limits.max_files
        total_bytes = [Int64]$report.resource_limits.max_total_bytes
        total_characters = [Int64]$report.resource_limits.max_total_bytes
        total_ngrams = [Int64]$report.resource_limits.max_total_ngrams
        total_tokens = [Int64]$report.resource_limits.max_total_tokens
        unique_form_count = [Int64]$report.resource_limits.max_unique_phrases
    }
    foreach ($name in $processingBounds.Keys) {
        $minimum = if ($name -eq "file_count") { 1 } else { 0 }
        Assert-CoeBoundedInteger `
            -Value $report.processing_totals.PSObject.Properties[$name].Value `
            -Minimum $minimum `
            -Maximum ([Int64]$processingBounds[$name]) `
            -Label "A protected run processing total"
    }
    [Int64]$maximumGroundedCandidates = (
        [Int64]$report.resource_limits.max_unique_phrases *
        7 *
        [Int64]$report.resource_limits.max_candidates_per_phrase_system
    )
    Assert-CoeBoundedInteger `
        -Value $report.grounding.candidate_count_checked `
        -Minimum 0 `
        -Maximum $maximumGroundedCandidates `
        -Label "The protected run grounded-candidate count"
    Assert-CoeBoundedInteger `
        -Value $report.totals.ambiguity_row_count `
        -Minimum 0 `
        -Maximum 7 `
        -Label "The protected run ambiguity-row count"
    Assert-CoeBoundedInteger `
        -Value $report.totals.coding_count_row_count `
        -Minimum 0 `
        -Maximum ([Int64]$report.resource_limits.max_unique_phrases * 7) `
        -Label "The protected run coding-row count"
    if (@($report.terminologies).Count -ne 7) {
        throw "The protected run report does not contain all seven terminology releases."
    }
    $terminologyIdentities = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($terminology in @($report.terminologies)) {
        Assert-CoeExactFields `
            -Object $terminology `
            -Expected @("release_id", "system_uri") `
            -Label "A protected run terminology identity"
        if (-not $terminologyIdentities.Add(([string]$terminology.system_uri) + "`n" + ([string]$terminology.release_id))) {
            throw "The protected run report contains a duplicate terminology release."
        }
    }
    if (-not $terminologyIdentities.SetEquals($referenceIdentities)) {
        throw "The protected run terminology identities do not match the verified reference set."
    }

    $expectedNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    [void]$expectedNames.Add("run_report.json")
    [Int64]$verifiedBytes = 0
    [Int64]$verifiedRows = 0
    [int]$verifiedFiles = 0
    $artifactRows = @{}
    foreach ($descriptor in @($report.artifacts)) {
        Assert-CoeExactFields -Object $descriptor -Expected @(
            "byte_count",
            "media_type",
            "path",
            "row_count",
            "schema_version",
            "sha256"
        ) -Label "A protected aggregate artifact descriptor"
        $relative = [string]$descriptor.path
        if ($relative -notin @("ambiguity_counts.jsonl", "coding_counts.jsonl")) {
            throw "The protected run declared an unsupported artifact."
        }
        if (-not $expectedNames.Add($relative)) {
            throw "The protected run declared a duplicate artifact."
        }
        if (
            $descriptor.media_type -ne "application/x-ndjson" -or
            $descriptor.schema_version -ne "1.0.0" -or
            [string]$descriptor.sha256 -notmatch '^[0-9a-f]{64}$'
        ) {
            throw "A protected aggregate artifact descriptor is invalid."
        }
        $maximumRows = if ($relative -eq "ambiguity_counts.jsonl") {
            7
        }
        else {
            [Int64]$report.resource_limits.max_unique_phrases * 7
        }
        Assert-CoeBoundedInteger `
            -Value $descriptor.row_count `
            -Minimum 0 `
            -Maximum $maximumRows `
            -Label "A protected aggregate artifact row count"
        Assert-CoeBoundedInteger `
            -Value $descriptor.byte_count `
            -Minimum 0 `
            -Maximum ([Int64]::MaxValue) `
            -Label "A protected aggregate artifact byte count"
        $artifact = Join-Path $output $relative
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "A declared protected aggregate artifact is missing."
        }
        $item = Get-Item -LiteralPath $artifact -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "A protected aggregate artifact is a reparse point."
        }
        if ([Int64]$descriptor.byte_count -ne $item.Length) {
            throw "A protected aggregate artifact byte count does not match its report."
        }
        if ((Get-CoeFileSha256 -Path $artifact) -ne [string]$descriptor.sha256) {
            throw "A protected aggregate artifact digest does not match its bytes."
        }
        $verifiedRows += Test-CoeJsonlArtifact `
            -Path $artifact `
            -ArtifactName $relative `
            -ExpectedRows ([Int64]$descriptor.row_count)
        $artifactRows[$relative] = [Int64]$descriptor.row_count
        $verifiedBytes += $item.Length
        $verifiedFiles += 1
    }
    if ($expectedNames.Count -ne 3) {
        throw "The protected run report does not declare the exact artifact inventory."
    }
    if (
        [Int64]$report.totals.ambiguity_row_count -ne [Int64]$artifactRows["ambiguity_counts.jsonl"] -or
        [Int64]$report.totals.coding_count_row_count -ne [Int64]$artifactRows["coding_counts.jsonl"]
    ) {
        throw "The protected run output totals do not match its artifact descriptors."
    }

    $actualItems = @(Get-ChildItem -LiteralPath $output -Force)
    if ($actualItems.Count -ne $expectedNames.Count) {
        throw "The protected run output contains an undeclared artifact."
    }
    foreach ($item in $actualItems) {
        if (-not $item.PSIsContainer -and $expectedNames.Contains($item.Name)) {
            continue
        }
        throw "The protected run output contains an undeclared or non-file artifact."
    }

    $catalogProbe = @'
import json
import sys
from contextlib import ExitStack
from pathlib import Path

from coe.terminology.licensed import SQLiteTerminologyIndex
from coe.terminology.licensed_set import verify_licensed_index_set

reference_root = Path(sys.argv[1])
output_root = Path(sys.argv[2])
manifest = verify_licensed_index_set(reference_root)
checked = 0
with ExitStack() as stack:
    indexes = {}
    for record in manifest["indexes"]:
        index = stack.enter_context(SQLiteTerminologyIndex(reference_root / record["file_name"], verify=False))
        identity = (index.reference.system_uri, index.reference.release_id)
        if identity in indexes:
            raise ValueError("duplicate identity")
        indexes[identity] = index
    for artifact_name in ("coding_counts.jsonl", "ambiguity_counts.jsonl"):
        with (output_root / artifact_name).open("r", encoding="utf-8", newline="") as stream:
            for line in stream:
                row = json.loads(line)
                identity = (row["system_uri"], row["release_id"])
                index = indexes.get(identity)
                if index is None:
                    raise ValueError("unknown identity")
                if artifact_name == "coding_counts.jsonl" and row["code"] not in index.reference.code_catalog:
                    raise ValueError("ungrounded code")
                checked += 1
print(json.dumps({"checked_row_count": checked, "status": "passed"}, separators=(",", ":")))
'@
    $catalogRaw = & $python -c $catalogProbe $referenceSet $output 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "A protected aggregate row is not grounded in the verified licensed reference set."
    }
    try {
        $catalogReport = ($catalogRaw -join "`n") | ConvertFrom-Json
    }
    catch {
        throw "The protected aggregate catalog verification returned an invalid result."
    }
    if (
        $catalogReport.status -ne "passed" -or
        [Int64]$catalogReport.checked_row_count -ne $verifiedRows
    ) {
        throw "The protected aggregate catalog verification did not cover every output row."
    }

    Write-CoeJson -Value ([PSCustomObject]@{
        windows_run_verification_schema_version = "1.0.0"
        status = "passed"
        execution_profile = "protected_phi_local"
        output_classification = "protected_aggregate"
        run_fingerprint = [string]$report.run_fingerprint
        semantic_output_sha256 = [string]$report.semantic_output_sha256
        run_report_sha256 = Get-CoeFileSha256 -Path $reportPath
        trusted_core_verification_schema_version = [string]$coreVerification.verification_schema_version
        verified_file_count = $verifiedFiles
        verified_row_count = $verifiedRows
        catalog_grounded_row_count = [Int64]$catalogReport.checked_row_count
        verified_byte_count = $verifiedBytes
        undeclared_file_count = 0
        patient_level_fields_detected = 0
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        windows_run_verification_schema_version = "1.0.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
