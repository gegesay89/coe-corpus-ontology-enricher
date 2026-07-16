Set-StrictMode -Version Latest

function Resolve-CoePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$MustExist
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "A required path was not supplied."
    }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path)
    $full = [IO.Path]::GetFullPath($expanded)
    if ($MustExist -and -not (Test-Path -LiteralPath $full)) {
        throw "A required protected-run input is missing."
    }
    return $full
}

function Test-CoePathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = (Resolve-CoePath -Path $Path).TrimEnd('\', '/')
    $fullRoot = (Resolve-CoePath -Path $Root).TrimEnd('\', '/')
    if ([string]::Equals($fullPath, $fullRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-CoeLocalFixedPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($env:OS -ne "Windows_NT") {
        throw "Local fixed-drive verification is unavailable on this host."
    }
    $full = Resolve-CoePath -Path $Path
    if ($full.StartsWith('\\') -or $full.StartsWith('//')) {
        throw "$Label must be on a local fixed Windows drive; UNC paths are forbidden."
    }
    $driveRoot = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($driveRoot)) {
        throw "$Label must be on a local fixed Windows drive."
    }
    try {
        $drive = [IO.DriveInfo]::new($driveRoot)
        if (-not $drive.IsReady -or $drive.DriveType -ne [IO.DriveType]::Fixed) {
            throw "$Label must be on a local fixed Windows drive; mapped network drives are forbidden."
        }
    }
    catch {
        if ($_.Exception.Message -match 'local fixed Windows drive') {
            throw
        }
        throw "$Label could not be verified as a local fixed Windows drive."
    }
}

function Assert-CoeNoReparsePoints {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $full = Resolve-CoePath -Path $Path -MustExist
    $rootItem = Get-Item -LiteralPath $full -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label cannot be a symbolic link, junction, or other reparse point."
    }
    if ($rootItem.PSIsContainer) {
        $unsafe = Get-ChildItem -LiteralPath $full -Force -Recurse | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        } | Select-Object -First 1
        if ($null -ne $unsafe) {
            throw "$Label contains a symbolic link, junction, or other reparse point."
        }
    }
}

function Assert-CoeReadOnlyAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if ($env:OS -ne "Windows_NT") {
        throw "Windows ACL verification is unavailable on this host."
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principalSids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [void]$principalSids.Add($identity.User.Value)
    foreach ($group in $identity.Groups) {
        [void]$principalSids.Add($group.Value)
    }
    $writeMask = (
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    $full = Resolve-CoePath -Path $Path -MustExist
    $targets = @(Get-Item -LiteralPath $full -Force)
    if ($targets[0].PSIsContainer) {
        $targets += @(Get-ChildItem -LiteralPath $full -Force -Recurse)
    }
    foreach ($target in $targets) {
        $acl = Get-Acl -LiteralPath $target.FullName
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
                continue
            }
            try {
                $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                continue
            }
            if ($principalSids.Contains($sid) -and (($rule.FileSystemRights -band $writeMask) -ne 0)) {
                throw "$Label grants write-capable ACL rights to the current runtime identity or one of its groups."
            }
        }
    }
}

function Get-CoeFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CoeApplicationWheelIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = Resolve-CoePath -Path $Path -MustExist
    $item = Get-Item -LiteralPath $full -Force
    if (
        $item -isnot [IO.FileInfo] -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "The COE application wheel must be a regular, non-reparse file."
    }
    $current = $item
    while ($null -ne $current) {
        if (($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The COE application wheel path cannot cross a reparse point."
        }
        $parentPath = Split-Path -Parent $current.FullName
        if ([string]::IsNullOrWhiteSpace($parentPath) -or $parentPath -eq $current.FullName) {
            break
        }
        $current = Get-Item -LiteralPath $parentPath -Force
    }

    $fileName = $item.Name
    $wheelPattern = '^coe_corpus_ontology_enricher-(?<version>[0-9][A-Za-z0-9._+!]*)-py3-none-any\.whl$'
    $wheelMatch = [regex]::Match(
        $fileName,
        $wheelPattern,
        [Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $wheelMatch.Success) {
        throw "The application artifact name is not the approved COE pure-Python wheel pattern."
    }
    $fileVersion = $wheelMatch.Groups["version"].Value
    $expectedMetadataPath = "coe_corpus_ontology_enricher-$fileVersion.dist-info/METADATA"

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $archive = [IO.Compression.ZipFile]::OpenRead($full)
    }
    catch {
        throw "The COE application wheel is not a readable ZIP archive."
    }
    try {
        $metadataEntries = @($archive.Entries | Where-Object { $_.FullName -match '^[^/]+\.dist-info/METADATA$' })
        if (
            $metadataEntries.Count -ne 1 -or
            $metadataEntries[0].FullName -cne $expectedMetadataPath -or
            $metadataEntries[0].Length -gt 1048576
        ) {
            throw "The COE application wheel has an invalid metadata inventory."
        }
        $metadataStream = $null
        $reader = $null
        try {
            $metadataStream = $metadataEntries[0].Open()
            $strictUtf8 = New-Object Text.UTF8Encoding($false, $true)
            $reader = [IO.StreamReader]::new($metadataStream, $strictUtf8, $true)
            $metadata = $reader.ReadToEnd()
        }
        catch {
            throw "The COE application wheel metadata is unreadable."
        }
        finally {
            if ($null -ne $reader) {
                $reader.Dispose()
            }
            elseif ($null -ne $metadataStream) {
                $metadataStream.Dispose()
            }
        }
    }
    finally {
        $archive.Dispose()
    }

    $metadataName = $null
    $metadataVersion = $null
    foreach ($line in @($metadata -split '\r?\n')) {
        if ($line -match '^Name:\s*(\S(?:.*\S)?)\s*$') {
            if ($null -ne $metadataName) {
                throw "The COE application wheel metadata contains a duplicate package name."
            }
            $metadataName = $Matches[1]
        }
        elseif ($line -match '^Version:\s*(\S(?:.*\S)?)\s*$') {
            if ($null -ne $metadataVersion) {
                throw "The COE application wheel metadata contains a duplicate version."
            }
            $metadataVersion = $Matches[1]
        }
    }
    if (
        $metadataName -cne "coe-corpus-ontology-enricher" -or
        $metadataVersion -cne $fileVersion -or
        $metadataVersion -notmatch '^[0-9][A-Za-z0-9._+!]*$'
    ) {
        throw "The COE application wheel name or version does not match its embedded metadata."
    }
    return [PSCustomObject]@{
        application_package = $metadataName
        application_version = $metadataVersion
        filename = $fileName
        sha256 = Get-CoeFileSha256 -Path $full
    }
}

function Get-CoeBoundedTreeInventory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][Int64]$MaxFiles,
        [Parameter(Mandatory = $true)][Int64]$MaxBytes,
        [Parameter(Mandatory = $true)][Int64]$MaxWalkEntries
    )

    if ($MaxFiles -lt 1 -or $MaxBytes -lt 1 -or $MaxWalkEntries -lt $MaxFiles) {
        throw "The tree-digest capacity limits are invalid."
    }
    $root = (Resolve-CoePath -Path $Path -MustExist).TrimEnd('\', '/')
    $rootItem = Get-Item -LiteralPath $root -Force
    if (
        -not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
        throw "$Label must be a regular directory and cannot be a reparse point."
    }
    $rootPrefix = $root + [IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($root)
    $files = New-Object 'System.Collections.Generic.List[IO.FileInfo]'
    [Int64]$walkEntries = 0
    [Int64]$totalBytes = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        try {
            foreach ($entryPath in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
                $walkEntries += 1
                if ($walkEntries -gt $MaxWalkEntries) {
                    throw "$Label exceeds the approved filesystem-entry limit."
                }
                $entry = Get-Item -LiteralPath $entryPath -Force
                if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "$Label contains a symbolic link, junction, or other reparse point."
                }
                if ($entry.PSIsContainer) {
                    $pending.Push($entry.FullName)
                    continue
                }
                if ($entry -isnot [IO.FileInfo]) {
                    throw "$Label contains an unsupported filesystem entry."
                }
                if ($files.Count -ge $MaxFiles) {
                    throw "$Label exceeds the approved file-count limit."
                }
                if ($entry.Length -lt 0 -or $entry.Length -gt ($MaxBytes - $totalBytes)) {
                    throw "$Label exceeds the approved byte-count limit."
                }
                $relative = $entry.FullName.Substring($rootPrefix.Length).Replace('\', '/')
                if ($relative.Length -gt 1024) {
                    throw "$Label contains a path longer than the approved digest boundary."
                }
                $totalBytes += $entry.Length
                $files.Add($entry)
            }
        }
        catch {
            if ($_.Exception.Message -match '^The .+ (?:exceeds|contains) ') {
                throw
            }
            throw "$Label could not be enumerated safely within its capacity limits."
        }
    }

    return [PSCustomObject]@{
        root = $root
        root_prefix = $rootPrefix
        files = $files.ToArray()
        file_count = $files.Count
        byte_count = $totalBytes
        walk_entry_count = $walkEntries
    }
}

function Get-CoeTreeDigest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][Int64]$MaxFiles,
        [Parameter(Mandatory = $true)][Int64]$MaxBytes,
        [Parameter(Mandatory = $true)][Int64]$MaxWalkEntries
    )

    $inventory = Get-CoeBoundedTreeInventory `
        -Path $Path `
        -Label $Label `
        -MaxFiles $MaxFiles `
        -MaxBytes $MaxBytes `
        -MaxWalkEntries $MaxWalkEntries
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($file in @($inventory.files)) {
        $relative = $file.FullName.Substring($inventory.root_prefix.Length).Replace('\', '/')
        $current = Get-Item -LiteralPath $file.FullName -Force
        if (
            $current -isnot [IO.FileInfo] -or
            ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $current.Length -ne $file.Length
        ) {
            throw "$Label changed while its digest was being calculated."
        }
        $digest = Get-CoeFileSha256 -Path $file.FullName
        $entries.Add("$digest  $relative")
    }
    $entryArray = $entries.ToArray()
    [Array]::Sort($entryArray, [StringComparer]::Ordinal)
    $payload = [Text.Encoding]::UTF8.GetBytes(($entryArray -join "`n") + "`n")
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $treeDigest = ([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
    return [PSCustomObject]@{
        sha256 = $treeDigest
        file_count = $inventory.file_count
        byte_count = $inventory.byte_count
        walk_entry_count = $inventory.walk_entry_count
    }
}

function Resolve-CoeBundleMember {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    if (
        [string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.Contains('\') -or
        $RelativePath.Contains(':') -or
        $RelativePath.StartsWith('/')
    ) {
        throw "The bundle checksum index contains an unsafe path."
    }
    $parts = $RelativePath.Split('/')
    if ($parts | Where-Object { $_ -in @('', '.', '..') }) {
        throw "The bundle checksum index contains an unsafe path."
    }
    $candidate = Resolve-CoePath -Path (Join-Path $BundleRoot ($parts -join [IO.Path]::DirectorySeparatorChar))
    if (-not (Test-CoePathWithin -Path $candidate -Root $BundleRoot)) {
        throw "The bundle checksum index escapes the bundle root."
    }
    return $candidate
}

function Write-CoeUtf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

function Write-CoeJson {
    param([Parameter(Mandatory = $true)]$Value)

    [Console]::Out.WriteLine(($Value | ConvertTo-Json -Depth 12 -Compress))
}

function Get-CoeSafeError {
    param(
        [Parameter(Mandatory = $true)][Exception]$Exception,
        [string]$Fallback = "The protected operation failed closed; inspect the cause locally without exporting raw diagnostics."
    )

    $message = [string]$Exception.Message
    if (
        [string]::IsNullOrWhiteSpace($message) -or
        $message.Length -gt 512 -or
        $message -match '[\x00-\x1f]' -or
        $message -match '(?i)(?:[a-z]:[\\/]|\\\\|file:/{2,3}|/(?:users|home|data|control|mnt)/)'
    ) {
        return $Fallback
    }
    return $message
}

function Test-CoeOutboundBlock {
    param([Parameter(Mandatory = $true)][string]$ProgramPath)

    if ($null -eq (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        return $false
    }
    $program = Resolve-CoePath -Path $ProgramPath -MustExist
    try {
        $rules = @(Get-NetFirewallRule -Enabled True -Direction Outbound -Action Block -ErrorAction Stop)
        foreach ($rule in $rules) {
            $filters = @(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            foreach ($filter in $filters) {
                if ([string]::Equals($filter.Program, $program, [StringComparison]::OrdinalIgnoreCase)) {
                    return $true
                }
            }
        }
    }
    catch {
        return $false
    }
    return $false
}
