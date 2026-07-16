[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [Parameter(Mandatory = $true)][string]$CorpusPath,
    [Parameter(Mandatory = $true)][string]$ReferenceSetPath,
    [Parameter(Mandatory = $true)][string]$AttestationPath,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [ValidateRange(1, 10000)][Int64]$MaxFiles = 10000,
    [ValidateRange(1, 100000000)][Int64]$MaxTotalBytes = 100000000,
    [switch]$RequireNvidia,
    [switch]$AllowHostNetwork,
    [switch]$ContainerReadOnlyMounts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

function Invoke-CoeJson {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$CheckName
    )

    $raw = & $script:ResolvedPython -m coe @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "$CheckName failed closed."
    }
    try {
        return (($raw -join "`n") | ConvertFrom-Json)
    }
    catch {
        throw "$CheckName returned an invalid machine-readable result."
    }
}

function Assert-ApprovalReference {
    param([Parameter(Mandatory = $true)][object]$Value)

    if ($Value -isnot [string]) {
        throw "The protected-data attestation contains an invalid approval reference."
    }
    $text = [string]$Value
    if (
        [string]::IsNullOrWhiteSpace($text) -or
        $text.Length -gt 256 -or
        $text -match '[\x00-\x1f]' -or
        $text -match '^(?i:TEST-ONLY|REPLACE-WITH)'
    ) {
        throw "The protected-data attestation contains an invalid or placeholder approval reference."
    }
}

try {
    $script:ResolvedPython = Resolve-CoePath -Path $PythonExe -MustExist
    $resolvedCorpus = Resolve-CoePath -Path $CorpusPath -MustExist
    $resolvedReferenceSet = Resolve-CoePath -Path $ReferenceSetPath -MustExist
    $resolvedAttestation = Resolve-CoePath -Path $AttestationPath -MustExist
    $resolvedOutput = Resolve-CoePath -Path $OutputPath

    Assert-CoeLocalFixedPath -Path $resolvedCorpus -Label "The protected corpus"
    Assert-CoeLocalFixedPath -Path $resolvedReferenceSet -Label "The licensed reference set"
    Assert-CoeLocalFixedPath -Path $resolvedAttestation -Label "The protected-data attestation"
    Assert-CoeLocalFixedPath -Path $resolvedOutput -Label "The protected output"

    Assert-CoeNoReparsePoints -Path $resolvedAttestation -Label "The protected-data attestation"
    $corpusInventory = Get-CoeBoundedTreeInventory `
        -Path $resolvedCorpus `
        -Label "The protected corpus" `
        -MaxFiles $MaxFiles `
        -MaxBytes $MaxTotalBytes `
        -MaxWalkEntries 50000
    $referenceInventory = Get-CoeBoundedTreeInventory `
        -Path $resolvedReferenceSet `
        -Label "The licensed reference set" `
        -MaxFiles 10 `
        -MaxBytes 68719476736 `
        -MaxWalkEntries 10
    if ($corpusInventory.file_count -lt 1) {
        throw "The protected corpus contains no plaintext files."
    }
    if ($referenceInventory.file_count -ne 10 -or $referenceInventory.walk_entry_count -ne 10) {
        throw "The licensed reference set does not have the exact approved file inventory."
    }
    if ($null -ne (@($corpusInventory.files) | Where-Object { $_.Extension -ne ".txt" } | Select-Object -First 1)) {
        throw "The protected corpus contains an unsupported file type; use an approved plaintext extraction adapter."
    }
    if (-not $ContainerReadOnlyMounts) {
        Assert-CoeReadOnlyAcl -Path $resolvedCorpus -Label "The protected corpus"
        Assert-CoeReadOnlyAcl -Path $resolvedReferenceSet -Label "The licensed reference set"
        Assert-CoeReadOnlyAcl -Path $resolvedAttestation -Label "The protected-data attestation"
    }
    foreach ($inputRoot in @($resolvedCorpus, $resolvedReferenceSet)) {
        if (Test-CoePathWithin -Path $resolvedOutput -Root $inputRoot) {
            throw "The output cannot be placed inside a protected input directory."
        }
    }
    $attestationDirectory = Split-Path -Parent $resolvedAttestation
    if (Test-CoePathWithin -Path $resolvedOutput -Root $attestationDirectory) {
        throw "The output cannot be placed inside the controlled attestation directory."
    }
    if (Test-Path -LiteralPath $resolvedOutput) {
        Assert-CoeNoReparsePoints -Path $resolvedOutput -Label "The protected output"
    }

    $validator = Resolve-CoePath `
        -Path (Join-Path $PSScriptRoot "docker\validate_attestation.py") `
        -MustExist
    $validatorRaw = & $script:ResolvedPython $validator --attestation $resolvedAttestation 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "The protected-data attestation failed closed validation."
    }
    try {
        $validatorReport = ($validatorRaw -join "`n") | ConvertFrom-Json
        if ($validatorReport.status -ne "passed") {
            throw "The protected-data attestation failed closed validation."
        }
        $attestation = Get-Content -LiteralPath $resolvedAttestation -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "The protected-data attestation is unreadable or malformed."
    }
    $expectedAttestationFields = @(
        "approval_refs",
        "approved",
        "attestation_schema_version",
        "output_classification",
        "profile",
        "retention_policy_id"
    )
    $actualAttestationFields = @($attestation.PSObject.Properties.Name)
    [Array]::Sort($actualAttestationFields, [StringComparer]::Ordinal)
    if (($actualAttestationFields -join "`n") -ne ($expectedAttestationFields -join "`n")) {
        throw "The protected-data attestation fields do not match its schema."
    }
    if (
        $attestation.attestation_schema_version -ne "1.0.0" -or
        $attestation.profile -ne "protected_phi_local" -or
        $attestation.approved -ne $true -or
        $attestation.output_classification -ne "protected_aggregate"
    ) {
        throw "The protected-data attestation is not explicitly approved for this run."
    }
    Assert-ApprovalReference -Value $attestation.retention_policy_id
    if ($attestation.approval_refs -isnot [PSCustomObject]) {
        throw "The protected-data attestation approval references are invalid."
    }
    $approvalNames = @($attestation.approval_refs.PSObject.Properties.Name)
    foreach ($required in @("data_owner", "privacy")) {
        if ($required -notin $approvalNames) {
            throw "The protected-data attestation is missing a required approval reference."
        }
    }
    if (@($approvalNames | Where-Object { $_ -notin @("data_owner", "privacy", "security") }).Count -ne 0) {
        throw "The protected-data attestation contains an unsupported approval reference."
    }
    foreach ($property in $attestation.approval_refs.PSObject.Properties) {
        Assert-ApprovalReference -Value $property.Value
    }

    $manifestPath = Join-Path $resolvedReferenceSet "reference_set_manifest.json"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "The licensed reference-set manifest is missing."
    }
    $referenceReport = Invoke-CoeJson `
        -Arguments @("reference", "verify-set", $resolvedReferenceSet) `
        -CheckName "Licensed reference-set verification"
    $expectedTerminologies = @("cpt", "hcpcs", "icd10cm", "icd10pcs", "loinc", "rxnorm", "snomed")
    $actualTerminologies = @($referenceReport.indexes | ForEach-Object { [string]$_.terminology })
    [Array]::Sort($actualTerminologies, [StringComparer]::Ordinal)
    if (
        $referenceReport.reference_set_manifest_schema_version -ne "1.0.0" -or
        [int]$referenceReport.index_count -ne 7 -or
        ($actualTerminologies -join "`n") -ne ($expectedTerminologies -join "`n")
    ) {
        throw "The licensed reference set does not contain the required seven terminology indexes."
    }
    $indexPaths = New-Object System.Collections.Generic.List[string]
    foreach ($record in @($referenceReport.indexes)) {
        $fileName = [string]$record.file_name
        if (
            [string]::IsNullOrWhiteSpace($fileName) -or
            [IO.Path]::GetFileName($fileName) -ne $fileName -or
            $fileName -ne (([string]$record.terminology) + ".sqlite3")
        ) {
            throw "The licensed reference set contains an unsafe index path."
        }
        $indexPath = Resolve-CoePath -Path (Join-Path $resolvedReferenceSet $fileName) -MustExist
        if (-not (Test-CoePathWithin -Path $indexPath -Root $resolvedReferenceSet)) {
            throw "A licensed terminology index escapes the verified reference set."
        }
        $indexPaths.Add($indexPath)
    }

    if ($RequireNvidia) {
        $hardware = Invoke-CoeJson `
            -Arguments @("hardware", "probe", "--require-nvidia") `
            -CheckName "NVIDIA capability preflight"
        if ($hardware.status -ne "passed") {
            throw "NVIDIA capability preflight failed closed."
        }
    }
    if (
        -not $ContainerReadOnlyMounts -and
        -not $AllowHostNetwork -and
        -not (Test-CoeOutboundBlock -ProgramPath $script:ResolvedPython)
    ) {
        throw "The dedicated Python runtime does not have a verified outbound firewall block."
    }

    Write-CoeJson -Value ([PSCustomObject]@{
        protected_preflight_schema_version = "1.0.0"
        status = "passed"
        execution_profile = "protected_phi_local"
        output_classification = "protected_aggregate"
        reference_index_count = $indexPaths.Count
        exact_matching_device = "cpu"
        nvidia_preflight = if ($RequireNvidia) { "passed_visibility_only" } else { "not_required" }
        gpu_semantic_stage = "reserved_not_implemented"
        protected_input_write_policy = if ($ContainerReadOnlyMounts) {
            "container_read_only_bind_mounts"
        }
        else {
            "windows_acl_read_only_verified"
        }
        network_policy = if ($ContainerReadOnlyMounts) {
            "container_network_none"
        }
        elseif ($AllowHostNetwork) {
            "explicit_operator_override"
        }
        else {
            "outbound_block_verified"
        }
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        protected_preflight_schema_version = "1.0.0"
        status = "failed"
        safe_error = Get-CoeSafeError -Exception $_.Exception
    })
    exit 1
}
