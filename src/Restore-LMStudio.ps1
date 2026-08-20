#Requires -Version 5.1

<#
.SYNOPSIS
    Restores LM Studio JSON files from a verified secure-setup backup.

.DESCRIPTION
    This script reverses the local JSON hardening performed by Setup-LMStudio.ps1.
    It verifies the selected backup manifest and hashes, refuses to run while LM
    Studio is active, creates a separate safety backup of the current files, and
    rolls back if the restore cannot be completed.

    For a ProjectManaged setup, the safe default keeps this project's Windows
    Firewall rules in place. Only the explicit -RemoveFirewall option removes the
    deterministic rule group through a short elevated child process.
    For an ExternallyManaged setup, organization-owned controls are never changed.
    The file restore itself must run as the normal user.

.PARAMETER LmStudioHome
    LM Studio user-data directory. The default is %USERPROFILE%\.lmstudio.

.PARAMETER BackupPath
    A specific setup backup directory. If omitted, the newest valid original
    setup backup below secure-setup\backups is selected. Launch and restore-safety
    backups are not selected automatically.

.PARAMETER RemoveFirewall
    Also removes this project's Firewall rules. This explicitly restores external
    connectivity for the covered binaries and is not used by 3-Restore.cmd.

.EXAMPLE
    .\Restore-LMStudio.ps1

.EXAMPLE
    .\Restore-LMStudio.ps1 -BackupPath 'C:\path\to\.lmstudio\secure-setup\backups\20260819-120000-000-abcd1234'

.NOTES
    Close LM Studio and llmster before running this script. The script never stops
    processes, downloads software, or changes Firewall rules outside the project
    group named "LM Studio Secure Local-Only".
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$LmStudioHome = (Join-Path $env:USERPROFILE '.lmstudio'),

    [ValidateNotNullOrEmpty()]
    [string]$BackupPath,

    [switch]$RemoveFirewall,

    # Internal parameters used only by the elevated child process.
    [switch]$FirewallRemoveOnly,
    [string]$FirewallRequestPath,
    [string]$FirewallRequestSha256,
    [string]$SharedLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SetupRoot = $null
$script:LogPath = $null
$script:FirewallGroup = 'LM Studio Secure Local-Only'

function Write-RestoreLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    Write-Host $line
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 } catch { }
    }
}

function Initialize-RestoreLogging {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$ExistingLogPath
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }
    if (-not [string]::IsNullOrWhiteSpace($ExistingLogPath)) {
        $script:LogPath = [IO.Path]::GetFullPath($ExistingLogPath)
        return
    }

    $logRoot = Join-Path $Root 'logs'
    if (-not (Test-Path -LiteralPath $logRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    }
    $script:LogPath = Join-Path $logRoot (
        'restore-{0}-{1}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $PID
    )
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "JSON file was not found: $Path"
    }
    try {
        $value = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Invalid JSON file: $Path. $($_.Exception.Message)"
    }
    if ($null -eq $value -or $value -is [System.Array]) {
        throw "The JSON root must be an object: $Path"
    }
    return $value
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-JsonText {
    param([Parameter(Mandatory = $true)][object]$InputObject)
    return (($InputObject | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
}

function Write-ValidatedJsonTempFile {
    param(
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][object]$InputObject
    )

    $directory = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $tempPath = Join-Path $directory (
        '.{0}.tmp.{1}.{2}' -f ([IO.Path]::GetFileName($DestinationPath)), $PID, ([guid]::NewGuid().ToString('N'))
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText($tempPath, (ConvertTo-JsonText $InputObject), $utf8NoBom)
        $null = Read-JsonFile -Path $tempPath
        return $tempPath
    }
    catch {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) { [IO.File]::Delete($tempPath) }
        throw
    }
}

function Commit-TempFile {
    param(
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        $replaceBackup = '{0}.replace-backup.{1}.{2}' -f $DestinationPath, $PID, ([guid]::NewGuid().ToString('N'))
        $committed = $false
        try {
            [IO.File]::Replace($TempPath, $DestinationPath, $replaceBackup, $true)
            $committed = $true
        }
        finally {
            if ($committed -and (Test-Path -LiteralPath $replaceBackup -PathType Leaf)) {
                try { [IO.File]::Delete($replaceBackup) } catch { }
            }
        }
    }
    else {
        [IO.File]::Move($TempPath, $DestinationPath)
    }
}

function Test-PathIsUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $fullPath.StartsWith($fullRoot + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Get-RunningLMStudioProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$HomePath,
        [string[]]$KnownProgramPaths = @()
    )

    $names = @(
        'LM Studio', 'LM Studio Helper', 'llmster', 'lms',
        'llama-server', 'mlx-engine'
    )
    $roots = @(
        [IO.Path]::GetFullPath($HomePath),
        (Join-Path $env:LOCALAPPDATA 'Programs\LM Studio'),
        (Join-Path $env:LOCALAPPDATA 'LM Studio')
    )
    $matches = @()
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processPath = $null
        try { $processPath = $process.Path } catch { }
        $isCandidatePath = $false
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            if (@($KnownProgramPaths | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_) -and
                [string]::Equals(
                    [IO.Path]::GetFullPath([string]$_),
                    [IO.Path]::GetFullPath($processPath),
                    [StringComparison]::OrdinalIgnoreCase
                )
            }).Count -gt 0) {
                $isCandidatePath = $true
            }
            foreach ($root in $roots) {
                if ($isCandidatePath) { break }
                if (Test-Path -LiteralPath $root -PathType Container) {
                    if (Test-PathIsUnderRoot -Path $processPath -Root $root) {
                        $isCandidatePath = $true
                        break
                    }
                }
            }
        }
        if ($names -contains $process.ProcessName -or $isCandidatePath) {
            $matches += [pscustomobject]@{
                Name = $process.ProcessName
                Id   = $process.Id
                Path = $processPath
            }
        }
    }
    return @($matches)
}

function Get-VerifiedOriginalBackup {
    param(
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedSettingsPath,
        [Parameter(Mandatory = $true)][string]$ExpectedMcpPath,
        [string]$RequestedPath
    )

    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
        throw "Backup root was not found: $BackupRoot"
    }

    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates = @([IO.Path]::GetFullPath($RequestedPath))
    }
    else {
        $candidates = @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -ExpandProperty FullName)
    }

    foreach ($candidate in $candidates) {
        if (-not (Test-PathIsUnderRoot -Path $candidate -Root $BackupRoot)) {
            throw "BackupPath must be a child of the secure backup root: $BackupRoot"
        }
        $candidateItem = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
        if (($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
                throw "BackupPath cannot be a symbolic link or junction: $candidate"
            }
            continue
        }
        $manifestPath = Join-Path $candidate 'backup-manifest.json'
        $settingsBackup = Join-Path $candidate 'settings.json'
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $settingsBackup -PathType Leaf)) {
            if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
                throw "The selected directory is not an original setup backup: $candidate"
            }
            continue
        }

        try {
            $manifest = Read-JsonFile -Path $manifestPath
            if ((Get-PropertyValue -InputObject $manifest -Name 'SchemaVersion') -ne 1 -or
                [string]::IsNullOrWhiteSpace([string](Get-PropertyValue -InputObject $manifest -Name 'SettingsPath'))) {
                throw 'Manifest type or version is not supported.'
            }

            $manifestSettingsPath = [IO.Path]::GetFullPath(
                [string](Get-PropertyValue -InputObject $manifest -Name 'SettingsPath')
            )
            $manifestMcpPath = [IO.Path]::GetFullPath(
                [string](Get-PropertyValue -InputObject $manifest -Name 'McpPath')
            )
            if (-not [string]::Equals(
                    $manifestSettingsPath,
                    [IO.Path]::GetFullPath($ExpectedSettingsPath),
                    [StringComparison]::OrdinalIgnoreCase
                ) -or
                -not [string]::Equals(
                    $manifestMcpPath,
                    [IO.Path]::GetFullPath($ExpectedMcpPath),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw 'The backup belongs to a different LM Studio profile.'
            }

            $expectedSettingsHash = [string](Get-PropertyValue -InputObject $manifest -Name 'SettingsSha256')
            foreach ($sourceFile in @($manifestPath, $settingsBackup)) {
                $sourceItem = Get-Item -LiteralPath $sourceFile -Force -ErrorAction Stop
                if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Backup files cannot be symbolic links: $sourceFile"
                }
            }
            $actualSettingsHash = (Get-FileHash -LiteralPath $settingsBackup -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expectedSettingsHash -notmatch '^[0-9a-fA-F]{64}$' -or
                $actualSettingsHash -ne $expectedSettingsHash.ToLowerInvariant()) {
                throw 'settings.json backup hash does not match the manifest.'
            }
            $null = Read-JsonFile -Path $settingsBackup

            $mcpOriginallyExists = [bool](Get-PropertyValue -InputObject $manifest -Name 'McpOriginallyExists')
            $mcpBackup = Join-Path $candidate 'mcp.json'
            if ($mcpOriginallyExists) {
                if (-not (Test-Path -LiteralPath $mcpBackup -PathType Leaf)) {
                    throw 'The manifest requires mcp.json, but the backup file is missing.'
                }
                $mcpItem = Get-Item -LiteralPath $mcpBackup -Force -ErrorAction Stop
                if (($mcpItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "Backup files cannot be symbolic links: $mcpBackup"
                }
                $expectedMcpHash = [string](Get-PropertyValue -InputObject $manifest -Name 'McpSha256')
                $actualMcpHash = (Get-FileHash -LiteralPath $mcpBackup -Algorithm SHA256).Hash.ToLowerInvariant()
                if ($expectedMcpHash -notmatch '^[0-9a-fA-F]{64}$' -or
                    $actualMcpHash -ne $expectedMcpHash.ToLowerInvariant()) {
                    throw 'mcp.json backup hash does not match the manifest.'
                }
                $null = Read-JsonFile -Path $mcpBackup
            }

            return [pscustomobject]@{
                Path                = $candidate
                Manifest            = $manifest
                SettingsBackup      = $settingsBackup
                McpBackup           = $mcpBackup
                McpOriginallyExists = $mcpOriginallyExists
                SettingsSha256      = $actualSettingsHash
                McpSha256           = if ($mcpOriginallyExists) { $actualMcpHash } else { $null }
            }
        }
        catch {
            if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) { throw }
        }
    }

    throw 'No verified original setup backup was found.'
}

function Assert-VerifiedBackupUnchanged {
    param([Parameter(Mandatory = $true)][object]$Source)

    $settingsHash = (Get-FileHash -LiteralPath $Source.SettingsBackup -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($settingsHash -ne $Source.SettingsSha256) {
        throw 'The verified settings backup changed before restore; no live files were changed.'
    }
    if ($Source.McpOriginallyExists) {
        $mcpHash = (Get-FileHash -LiteralPath $Source.McpBackup -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($mcpHash -ne $Source.McpSha256) {
            throw 'The verified MCP backup changed before restore; no live files were changed.'
        }
    }
}

function Get-VerifiedHttpServerConfigBackup {
    param(
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) { return $null }
    $verified = New-Object Collections.Generic.List[object]
    foreach ($candidate in @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop)) {
        try {
            if (-not (Test-PathIsUnderRoot -Path $candidate.FullName -Root $BackupRoot) -or
                ($candidate.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $manifestPath = Join-Path $candidate.FullName 'backup-manifest.json'
            $backupPath = Join-Path $candidate.FullName 'http-server-config.json'
            if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
                -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { continue }

            $manifest = Read-JsonFile -Path $manifestPath
            if ((Get-PropertyValue -InputObject $manifest -Name 'HttpServerConfigOriginallyExists') -ne $true) { continue }
            $recordedPath = [IO.Path]::GetFullPath(
                [string](Get-PropertyValue -InputObject $manifest -Name 'HttpServerConfigPath')
            )
            if (-not [string]::Equals(
                $recordedPath,
                [IO.Path]::GetFullPath($ExpectedPath),
                [StringComparison]::OrdinalIgnoreCase
            )) { continue }

            foreach ($file in @($manifestPath, $backupPath)) {
                $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'HTTP server configuration backup cannot be a symbolic link.'
                }
            }
            $expectedHash = [string](Get-PropertyValue -InputObject $manifest -Name 'HttpServerConfigSha256')
            $actualHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expectedHash -notmatch '^[0-9a-fA-F]{64}$' -or
                $actualHash -ne $expectedHash.ToLowerInvariant()) { continue }
            $null = Read-JsonFile -Path $backupPath
            $createdAt = [DateTime]::Parse(
                [string](Get-PropertyValue -InputObject $manifest -Name 'CreatedAtUtc'),
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            )
            $verified.Add([pscustomobject]@{
                Path       = $candidate.FullName
                BackupPath = $backupPath
                Sha256     = $actualHash
                CreatedAt  = $createdAt.ToUniversalTime()
            })
        }
        catch { continue }
    }
    return @($verified | Sort-Object CreatedAt | Select-Object -First 1)
}

function Assert-VerifiedHttpServerConfigBackupUnchanged {
    param([AllowNull()][object]$Source)

    if ($null -eq $Source) { return }
    $actualHash = (Get-FileHash -LiteralPath $Source.BackupPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $Source.Sha256) {
        throw 'The verified HTTP server configuration backup changed before restore; no live files were changed.'
    }
}

function New-RestoreSafetyBackup {
    param(
        [Parameter(Mandatory = $true)][string]$BackupRoot,
        [Parameter(Mandatory = $true)][string]$SettingsPath,
        [Parameter(Mandatory = $true)][string]$McpPath,
        [Parameter(Mandatory = $true)][string]$HttpServerConfigPath
    )

    $directory = Join-Path $BackupRoot (
        'restore-safety-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    )
    New-Item -ItemType Directory -Path $directory -Force | Out-Null

    $settingsExists = Test-Path -LiteralPath $SettingsPath -PathType Leaf
    $mcpExists = Test-Path -LiteralPath $McpPath -PathType Leaf
    $httpServerConfigExists = Test-Path -LiteralPath $HttpServerConfigPath -PathType Leaf
    if ($settingsExists) { [IO.File]::Copy($SettingsPath, (Join-Path $directory 'settings.json'), $false) }
    if ($mcpExists) { [IO.File]::Copy($McpPath, (Join-Path $directory 'mcp.json'), $false) }
    if ($httpServerConfigExists) { [IO.File]::Copy($HttpServerConfigPath, (Join-Path $directory 'http-server-config.json'), $false) }

    $manifest = [ordered]@{
        SchemaVersion  = 1
        BackupType     = 'restore-safety'
        CreatedAtUtc   = [DateTime]::UtcNow.ToString('o')
        SettingsExists = $settingsExists
        SettingsSha256 = if ($settingsExists) { (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        McpExists      = $mcpExists
        McpSha256      = if ($mcpExists) { (Get-FileHash -LiteralPath $McpPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        HttpServerConfigExists = $httpServerConfigExists
        HttpServerConfigSha256 = if ($httpServerConfigExists) { (Get-FileHash -LiteralPath $HttpServerConfigPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
    }
    $manifestPath = Join-Path $directory 'backup-manifest.json'
    $temp = Write-ValidatedJsonTempFile -DestinationPath $manifestPath -InputObject $manifest
    Commit-TempFile -TempPath $temp -DestinationPath $manifestPath
    return [pscustomobject]@{ Path = $directory; Manifest = $manifest }
}

function Copy-JsonAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $value = Read-JsonFile -Path $SourcePath
    $temp = Write-ValidatedJsonTempFile -DestinationPath $DestinationPath -InputObject $value
    Commit-TempFile -TempPath $temp -DestinationPath $DestinationPath
}

function Restore-FromSafetyBackup {
    param(
        [Parameter(Mandatory = $true)][object]$Safety,
        [Parameter(Mandatory = $true)][string]$SettingsPath,
        [Parameter(Mandatory = $true)][string]$McpPath,
        [Parameter(Mandatory = $true)][string]$HttpServerConfigPath
    )

    if ([bool]$Safety.Manifest.SettingsExists) {
        Copy-JsonAtomically -SourcePath (Join-Path $Safety.Path 'settings.json') -DestinationPath $SettingsPath
    }
    elseif (Test-Path -LiteralPath $SettingsPath -PathType Leaf) {
        [IO.File]::Delete($SettingsPath)
    }

    if ([bool]$Safety.Manifest.McpExists) {
        Copy-JsonAtomically -SourcePath (Join-Path $Safety.Path 'mcp.json') -DestinationPath $McpPath
    }
    elseif (Test-Path -LiteralPath $McpPath -PathType Leaf) {
        [IO.File]::Delete($McpPath)
    }

    if ([bool](Get-PropertyValue -InputObject $Safety.Manifest -Name 'HttpServerConfigExists')) {
        Copy-JsonAtomically -SourcePath (Join-Path $Safety.Path 'http-server-config.json') -DestinationPath $HttpServerConfigPath
    }
    elseif (Test-Path -LiteralPath $HttpServerConfigPath -PathType Leaf) {
        [IO.File]::Delete($HttpServerConfigPath)
    }
}

function Remove-ManagedFirewallRules {
    if (-not (Test-IsAdministrator)) {
        throw 'Administrator rights are required to remove Firewall rules.'
    }
    $rules = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
    }
    $remaining = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    if ($remaining.Count -ne 0) {
        throw "Some managed Firewall rules could not be removed: $($remaining.Count)"
    }
    return $rules.Count
}

function Invoke-ElevatedFirewallRemoval {
    param(
        [Parameter(Mandatory = $true)][string]$SetupRoot,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    $requestPath = Join-Path $SetupRoot ('firewall-remove-request-{0}.json' -f ([guid]::NewGuid().ToString('N')))
    $request = [ordered]@{
        SchemaVersion = 1
        CreatedAtUtc  = [DateTime]::UtcNow.ToString('o')
        RuleGroup     = $script:FirewallGroup
    }
    $temp = Write-ValidatedJsonTempFile -DestinationPath $requestPath -InputObject $request
    Commit-TempFile -TempPath $temp -DestinationPath $requestPath
    $hash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    try {
        if (Test-IsAdministrator) { return (Remove-ManagedFirewallRules) }
        if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
            throw 'The script path could not be resolved for elevation.'
        }
        $powerShellExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
            $powerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
        }
        foreach ($value in @($PSCommandPath, $requestPath, $LogPath)) {
            if ($value.Contains('"')) { throw "A path containing a double quote cannot be elevated: $value" }
        }

        Write-RestoreLog -Message 'Windows will request administrator approval to remove the managed Firewall rules.'
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-FirewallRemoveOnly',
            '-FirewallRequestPath', ('"{0}"' -f $requestPath),
            '-FirewallRequestSha256', $hash,
            '-SharedLogPath', ('"{0}"' -f $LogPath)
        )
        $process = Start-Process -FilePath $powerShellExe -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "The elevated Firewall removal failed with exit code $($process.ExitCode)."
        }
    }
    finally {
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) { [IO.File]::Delete($requestPath) }
    }
}

function Invoke-FirewallRemoveOnlyMode {
    if (-not $FirewallRemoveOnly) { return }
    try {
        if (-not (Test-IsAdministrator)) { throw 'FirewallRemoveOnly mode requires administrator rights.' }
        if ([string]::IsNullOrWhiteSpace($FirewallRequestPath) -or
            $FirewallRequestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'The Firewall removal request is missing or malformed.'
        }
        $requestPath = [IO.Path]::GetFullPath($FirewallRequestPath)
        Initialize-RestoreLogging -Root (Split-Path -Parent $requestPath) -ExistingLogPath $SharedLogPath
        $actualHash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $FirewallRequestSha256.ToLowerInvariant()) {
            throw 'The Firewall removal request hash does not match.'
        }
        $request = Read-JsonFile -Path $requestPath
        if ((Get-PropertyValue -InputObject $request -Name 'SchemaVersion') -ne 1 -or
            (Get-PropertyValue -InputObject $request -Name 'RuleGroup') -ne $script:FirewallGroup) {
            throw 'The Firewall removal request is not recognized.'
        }
        $createdAt = [DateTime]::Parse(
            [string](Get-PropertyValue -InputObject $request -Name 'CreatedAtUtc'),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $ageMinutes = [DateTime]::UtcNow.Subtract($createdAt.ToUniversalTime()).TotalMinutes
        if ($ageMinutes -lt -1 -or $ageMinutes -gt 15) {
            throw 'The Firewall removal request has expired.'
        }
        $count = Remove-ManagedFirewallRules
        Write-RestoreLog -Level OK -Message "Removed managed Firewall rules: $count"
        exit 0
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
            Write-RestoreLog -Level ERROR -Message $_.Exception.Message
        }
        else { Write-Error $_.Exception.Message }
        exit 1
    }
}

function Write-RestoredState {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][string]$OriginalBackupPath,
        [Parameter(Mandatory = $true)][string]$SafetyBackupPath,
        [Parameter(Mandatory = $true)][bool]$FirewallConfigured
    )

    if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
        $state = Read-JsonFile -Path $StatePath
    }
    else {
        $state = [pscustomobject]@{ SchemaVersion = 1 }
    }
    $state | Add-Member -NotePropertyName Complete -NotePropertyValue $false -Force
    $state | Add-Member -NotePropertyName RestoredAtUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $state | Add-Member -NotePropertyName RestoredFromBackup -NotePropertyValue $OriginalBackupPath -Force
    $state | Add-Member -NotePropertyName RestoreSafetyBackup -NotePropertyValue $SafetyBackupPath -Force

    $firewall = Get-PropertyValue -InputObject $state -Name 'Firewall'
    if ($null -eq $firewall) {
        $firewall = [pscustomobject]@{}
        $state | Add-Member -NotePropertyName Firewall -NotePropertyValue $firewall -Force
    }
    $firewall | Add-Member -NotePropertyName Configured -NotePropertyValue $FirewallConfigured -Force
    $firewall | Add-Member -NotePropertyName RuleGroup -NotePropertyValue $script:FirewallGroup -Force
    if (-not $FirewallConfigured) {
        $firewall | Add-Member -NotePropertyName RuleCount -NotePropertyValue 0 -Force
    }

    $temp = Write-ValidatedJsonTempFile -DestinationPath $StatePath -InputObject $state
    Commit-TempFile -TempPath $temp -DestinationPath $StatePath
}

function Remove-ManagedModelLink {
    param(
        [Parameter(Mandatory = $true)][string]$LinkPath,
        [Parameter(Mandatory = $true)][string]$LmStudioHomePath
    )

    $managedRoot = [IO.Path]::GetFullPath(
        (Join-Path $LmStudioHomePath 'models\secure-deployment')
    ).TrimEnd('\') + '\'
    $resolvedLinkPath = [IO.Path]::GetFullPath($LinkPath)
    if (-not $resolvedLinkPath.StartsWith($managedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Recorded managed model link is outside the project-owned model directory.'
    }

    $linkParent = Split-Path -Parent $resolvedLinkPath
    if (-not (Test-Path -LiteralPath $linkParent -PathType Container)) {
        return $false
    }
    $linkName = [IO.Path]::GetFileName($resolvedLinkPath)
    $item = @(Get-ChildItem -LiteralPath $linkParent -Force -ErrorAction Stop | Where-Object {
        [string]::Equals($_.Name, $linkName, [StringComparison]::OrdinalIgnoreCase)
    } | Select-Object -First 1)
    if ($item.Count -eq 0) {
        return $false
    }
    $item = $item[0]
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -or
        [string]$item.LinkType -ne 'SymbolicLink') {
        throw 'Recorded managed model link is no longer a symbolic link; it was not deleted.'
    }

    [IO.File]::Delete($resolvedLinkPath)
    return $true
}

function Invoke-MainRestore {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'This script is for Windows only.'
    }
    if (Test-IsAdministrator) {
        throw 'Run the restore as the normal LM Studio user. Administrator approval is requested only for Firewall removal.'
    }

    $homePath = [IO.Path]::GetFullPath($LmStudioHome)
    if (-not (Test-Path -LiteralPath $homePath -PathType Container)) {
        throw "LM Studio home was not found: $homePath"
    }
    $script:SetupRoot = Join-Path $homePath 'secure-setup'
    Initialize-RestoreLogging -Root $script:SetupRoot
    Write-RestoreLog -Message 'Starting verified LM Studio restore.'

    $statePath = Join-Path $script:SetupRoot 'setup-state.json'
    $priorState = $null
    $knownProgramPaths = @()
    $firewallWasConfigured = $false
    $firewallExternallyManaged = $false
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $priorState = Read-JsonFile -Path $statePath
        $priorFirewall = Get-PropertyValue -InputObject $priorState -Name 'Firewall'
        $knownProgramPaths = @((Get-PropertyValue -InputObject $priorFirewall -Name 'ProgramPaths'))
        $firewallWasConfigured = [bool](Get-PropertyValue -InputObject $priorFirewall -Name 'Configured')
        $priorFirewallMode = [string](Get-PropertyValue -InputObject $priorFirewall -Name 'Mode')
        $firewallExternallyManaged = (
            $priorFirewallMode -eq 'ExternallyManaged' -and
            (Get-PropertyValue -InputObject $priorFirewall -Name 'ExternallyManaged') -eq $true -and
            -not $firewallWasConfigured
        )
    }
    $managedModelLinkPath = [string](Get-PropertyValue -InputObject $priorState -Name 'ManagedModelLinkPath')
    $managedVisionProjectorLinkPath = [string](Get-PropertyValue -InputObject $priorState -Name 'ManagedVisionProjectorLinkPath')

    $running = @(Get-RunningLMStudioProcesses -HomePath $homePath -KnownProgramPaths $knownProgramPaths)
    if ($running.Count -gt 0) {
        throw ('Close LM Studio and llmster before restoring. Running process IDs: {0}' -f (($running.Id | Sort-Object -Unique) -join ', '))
    }

    $backupRoot = Join-Path $script:SetupRoot 'backups'
    $settingsPath = Join-Path $homePath 'settings.json'
    $mcpPath = Join-Path $homePath 'mcp.json'
    $httpServerConfigPath = Join-Path $homePath '.internal\http-server-config.json'
    $source = Get-VerifiedOriginalBackup `
        -BackupRoot $backupRoot `
        -ExpectedSettingsPath $settingsPath `
        -ExpectedMcpPath $mcpPath `
        -RequestedPath $BackupPath
    Write-RestoreLog -Level OK -Message "Verified original backup: $($source.Path)"

    $httpServerConfigSource = Get-VerifiedHttpServerConfigBackup `
        -BackupRoot $backupRoot `
        -ExpectedPath $httpServerConfigPath
    if ($null -ne $httpServerConfigSource) {
        Write-RestoreLog -Level OK -Message "Verified original HTTP server configuration backup: $($httpServerConfigSource.Path)"
    }

    $safety = New-RestoreSafetyBackup `
        -BackupRoot $backupRoot `
        -SettingsPath $settingsPath `
        -McpPath $mcpPath `
        -HttpServerConfigPath $httpServerConfigPath
    Write-RestoreLog -Level OK -Message "Created restore safety backup: $($safety.Path)"

    try {
        Assert-VerifiedBackupUnchanged -Source $source
        Assert-VerifiedHttpServerConfigBackupUnchanged -Source $httpServerConfigSource
        Copy-JsonAtomically -SourcePath $source.SettingsBackup -DestinationPath $settingsPath
        if ($source.McpOriginallyExists) {
            Copy-JsonAtomically -SourcePath $source.McpBackup -DestinationPath $mcpPath
        }
        elseif (Test-Path -LiteralPath $mcpPath -PathType Leaf) {
            [IO.File]::Delete($mcpPath)
        }
        if ($null -ne $httpServerConfigSource) {
            Copy-JsonAtomically -SourcePath $httpServerConfigSource.BackupPath -DestinationPath $httpServerConfigPath
        }
        # The rules have not been removed yet. Recording that fact first keeps the
        # state conservative if elevation is cancelled or removal fails.
        Write-RestoredState -StatePath $statePath -OriginalBackupPath $source.Path -SafetyBackupPath $safety.Path -FirewallConfigured $firewallWasConfigured
    }
    catch {
        Write-RestoreLog -Level ERROR -Message 'Restore failed; reverting files from the restore safety backup.'
        Restore-FromSafetyBackup `
            -Safety $safety `
            -SettingsPath $settingsPath `
            -McpPath $mcpPath `
            -HttpServerConfigPath $httpServerConfigPath
        throw
    }

    if (-not [string]::IsNullOrWhiteSpace($managedVisionProjectorLinkPath)) {
        if ([IO.Path]::GetFileName($managedVisionProjectorLinkPath) -notmatch '^(?i:mmproj(?:[-_.].*)?\.gguf)$') {
            throw 'Recorded vision-projector link does not have an mmproj GGUF filename; it was not deleted.'
        }
        if (Remove-ManagedModelLink -LinkPath $managedVisionProjectorLinkPath -LmStudioHomePath $homePath) {
            Write-RestoreLog -Level OK -Message 'Removed the setup-managed vision-projector link.'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($managedModelLinkPath)) {
        if (Remove-ManagedModelLink -LinkPath $managedModelLinkPath -LmStudioHomePath $homePath) {
            Write-RestoreLog -Level OK -Message 'Removed the setup-managed shared model link.'
        }
    }

    $firewallConfigured = $firewallWasConfigured
    if ($firewallExternallyManaged) {
        Write-RestoreLog -Level WARN -Message 'Organization-managed network controls were not changed by this restore.'
    }
    elseif (-not $RemoveFirewall) {
        Write-RestoreLog -Level WARN -Message 'Safe restore kept the managed Firewall rules. Use -RemoveFirewall only for an intentional full network-policy removal.'
    }
    else {
        try {
            Invoke-ElevatedFirewallRemoval -SetupRoot $script:SetupRoot -LogPath $script:LogPath
        }
        catch {
            Write-RestoreLog -Level ERROR -Message 'JSON files were restored, but managed Firewall rules remain. This is the safer failure state.'
            throw
        }
        $firewallConfigured = $false
        try {
            Write-RestoredState `
                -StatePath $statePath `
                -OriginalBackupPath $source.Path `
                -SafetyBackupPath $safety.Path `
                -FirewallConfigured $false
        }
        catch {
            Write-RestoreLog -Level ERROR -Message 'Managed Firewall rules were removed, but the state file could not be updated. Do not start LM Studio normally; re-run Setup-LMStudio.ps1 before use.'
            throw
        }
        Write-RestoreLog -Level WARN -Message 'Managed Firewall rules were explicitly removed. External connectivity is no longer blocked by this project.'
    }

    Write-RestoreLog -Level OK -Message 'Restore completed. Secure launch remains disabled until Setup-LMStudio.ps1 is run again.'
    Write-RestoreLog -Level WARN -Message 'Pre-setup LM Studio settings may enable network-facing features. Do not start LM Studio normally; run 1-Setup.cmd before use.'
    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' LM Studio restore result'
    Write-Host (' Source backup : {0}' -f $source.Path)
    Write-Host (' Safety backup : {0}' -f $safety.Path)
    $firewallSummary = if ($firewallExternallyManaged) {
        'EXTERNAL POLICY UNCHANGED'
    }
    elseif ($firewallConfigured) {
        'MANAGED RULES KEPT (SAFE DEFAULT)'
    }
    else {
        'MANAGED RULES REMOVED'
    }
    Write-Host (' Firewall      : {0}' -f $firewallSummary)
    Write-Host ' Next action   : RUN 1-Setup.cmd BEFORE LM STUDIO'
    Write-Host (' Log           : {0}' -f $script:LogPath)
    Write-Host '============================================================'
}

Invoke-FirewallRemoveOnlyMode

try {
    Invoke-MainRestore
    exit 0
}
catch {
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Write-RestoreLog -Level ERROR -Message $_.Exception.Message
        Write-RestoreLog -Level ERROR -Message 'Restore did not complete. Review the log and safety backup before retrying.'
    }
    else { Write-Error $_.Exception.Message }
    exit 1
}
