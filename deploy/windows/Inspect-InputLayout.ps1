[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PatientDataRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

try {
    $root = Resolve-CoePath -Path $PatientDataRoot -MustExist
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer) {
        throw "The input layout root must be a directory."
    }

    [Int64]$totalFiles = 0
    [Int64]$totalBytes = 0
    [Int64]$reparsePoints = 0
    $extensions = @{}
    $allowedExtensions = @(
        ".7z", ".bmp", ".csv", ".dcm", ".doc", ".docx", ".eml", ".gif", ".gz", ".htm", ".html",
        ".jpeg", ".jpg", ".json", ".jsonl", ".m4a", ".mp3", ".mp4", ".msg", ".pdf", ".png", ".rtf",
        ".tar", ".tif", ".tiff", ".tsv", ".txt", ".wav", ".xls", ".xlsx", ".xml", ".zip"
    )
    $directories = New-Object 'System.Collections.Generic.Queue[string]'
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        $reparsePoints = 1
    }
    else {
        $directories.Enqueue($root)
    }

    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $reparsePoints += 1
                continue
            }
            if ($item.PSIsContainer) {
                $directories.Enqueue($item.FullName)
                continue
            }
            if (-not ($item -is [IO.FileInfo])) {
                continue
            }
            $extension = [IO.Path]::GetExtension($item.Name).ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($extension)) {
                $extension = "<none>"
            }
            elseif ($extension -notin $allowedExtensions) {
                $extension = "<other>"
            }
            if (-not $extensions.ContainsKey($extension)) {
                $extensions[$extension] = [Int64]0
            }
            $extensions[$extension] = [Int64]$extensions[$extension] + 1
            $totalFiles += 1
            $totalBytes += [Int64]$item.Length
        }
    }

    $orderedExtensions = [ordered]@{}
    foreach ($extension in @($extensions.Keys | Sort-Object)) {
        $orderedExtensions[$extension] = [Int64]$extensions[$extension]
    }
    Write-CoeJson -Value ([PSCustomObject]@{
        input_layout_report_schema_version = "1.0.0"
        status = "completed"
        total_files = $totalFiles
        total_bytes = $totalBytes
        reparse_point_count = $reparsePoints
        extension_counts = $orderedExtensions
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        input_layout_report_schema_version = "1.0.0"
        status = "failed"
        safe_error = "The input layout could not be inspected without expanding the collection scope."
    })
    exit 1
}
