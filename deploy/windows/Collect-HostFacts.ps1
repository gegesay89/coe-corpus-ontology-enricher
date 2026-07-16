[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "Common.ps1")

function Get-SafeCommandOutput {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    if ($null -eq (Get-Command $Command -ErrorAction SilentlyContinue)) {
        return $null
    }
    $output = & $Command @Arguments 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ($output -join "`n").Trim()
}

try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $platformKind = if ([int]$os.ProductType -eq 1) { "workstation" } else { "server" }

    $gpus = New-Object System.Collections.Generic.List[object]
    $gpuRows = Get-SafeCommandOutput -Command "nvidia-smi.exe" -Arguments @(
        "--query-gpu=name,memory.total,driver_version,compute_cap",
        "--format=csv,noheader,nounits"
    )
    if ($null -eq $gpuRows) {
        $gpuRows = Get-SafeCommandOutput -Command "nvidia-smi.exe" -Arguments @(
            "--query-gpu=name,memory.total,driver_version",
            "--format=csv,noheader,nounits"
        )
    }
    if (-not [string]::IsNullOrWhiteSpace($gpuRows)) {
        foreach ($line in $gpuRows.Split("`n")) {
            $columns = @($line.Split(',') | ForEach-Object { $_.Trim() })
            if ($columns.Count -ge 3) {
                $memory = 0
                [void][int]::TryParse($columns[1], [ref]$memory)
                $gpus.Add([PSCustomObject]@{
                    name = $columns[0]
                    memory_mib = $memory
                    driver_version = $columns[2]
                    compute_capability = if ($columns.Count -ge 4) { $columns[3] } else { $null }
                })
            }
        }
    }

    $wslVersion = Get-SafeCommandOutput -Command "wsl.exe" -Arguments @("--version")
    $dockerVersion = Get-SafeCommandOutput -Command "docker.exe" -Arguments @(
        "version",
        "--format",
        "{{.Server.Version}}"
    )
    $dockerRuntimes = Get-SafeCommandOutput -Command "docker.exe" -Arguments @(
        "info",
        "--format",
        "{{json .Runtimes}}"
    )
    $pythonVersion = Get-SafeCommandOutput -Command "py.exe" -Arguments @("-3.12", "--version")

    Write-CoeJson -Value ([PSCustomObject]@{
        host_facts_schema_version = "1.0.0"
        generated_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
        operating_system = [PSCustomObject]@{
            caption = [string]$os.Caption
            version = [string]$os.Version
            build_number = [string]$os.BuildNumber
            architecture = [string]$os.OSArchitecture
            platform_kind = $platformKind
        }
        memory = [PSCustomObject]@{
            total_bytes = [Int64]$computer.TotalPhysicalMemory
        }
        nvidia = [PSCustomObject]@{
            detected = $gpus.Count -gt 0
            gpu_count = $gpus.Count
            devices = $gpus.ToArray()
        }
        python = [PSCustomObject]@{
            python_3_12_detected = $null -ne $pythonVersion
            version_output = $pythonVersion
        }
        wsl2 = [PSCustomObject]@{
            detected = $null -ne $wslVersion
            version_output = $wslVersion
        }
        docker = [PSCustomObject]@{
            server_detected = $null -ne $dockerVersion
            server_version = $dockerVersion
            runtimes = $dockerRuntimes
            docker_desktop_supported_by_os_class = $platformKind -eq "workstation"
        }
        coe_execution = [PSCustomObject]@{
            exact_matching_device = "cpu"
            gpu_semantic_stage = "reserved_not_implemented"
            native_windows_first = $true
        }
        privacy = [PSCustomObject]@{
            identifiers_omitted = $true
            patient_paths_collected = $false
        }
    })
}
catch {
    Write-CoeJson -Value ([PSCustomObject]@{
        host_facts_schema_version = "1.0.0"
        status = "failed"
        safe_error = "Host facts could not be collected without expanding the collection scope."
    })
    exit 1
}
