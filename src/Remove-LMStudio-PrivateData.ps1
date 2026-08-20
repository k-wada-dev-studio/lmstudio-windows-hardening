#Requires -Version 5.1

<#
.SYNOPSIS
    Permanently removes selected LM Studio private user data.

.DESCRIPTION
    Deletes only the contents of these fixed directories below the current
    user's .lmstudio profile:

      conversations       Chat history
      user-files          Chat attachments and their metadata
      server-logs         LM Studio server logs
      secure-setup\logs   Logs created by this project

    The directories are validated as ordinary directories, moved to a
    same-volume quarantine, replaced with empty directories, and then removed.
    A move failure is rolled back. Models, runtimes, settings, credentials,
    secure-setup backups, and secure-setup state are not deleted.

    This is normal filesystem deletion, not cryptographic secure erasure.

.PARAMETER ConfirmDeletion
    Required for destructive execution. The non-technical command entry point
    asks the user for confirmation before passing this switch.

.PARAMETER PreviewOnly
    Shows the number and size of files that would be deleted without changing
    anything.

.PARAMETER LmStudioHome
    LM Studio user-data directory. The default is %USERPROFILE%\.lmstudio.

.EXAMPLE
    .\Remove-LMStudio-PrivateData.ps1 -PreviewOnly

.EXAMPLE
    .\Remove-LMStudio-PrivateData.ps1 -ConfirmDeletion
#>

[CmdletBinding()]
param(
    [switch]$ConfirmDeletion,
    [switch]$PreviewOnly,
    [string]$LmStudioHome = (Join-Path $env:USERPROFILE '.lmstudio')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PrivateDataPathIsUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    return $resolvedPath.StartsWith(
        $resolvedRoot + '\',
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Get-PrivateDataDeletionTargets {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $resolvedHome = [IO.Path]::GetFullPath($HomePath).TrimEnd('\')
    return @(
        [pscustomobject]@{
            Key = 'ChatHistory'
            Description = 'Chat history'
            Path = Join-Path $resolvedHome 'conversations'
            QuarantineName = 'conversations'
        },
        [pscustomobject]@{
            Key = 'Attachments'
            Description = 'Chat attachments'
            Path = Join-Path $resolvedHome 'user-files'
            QuarantineName = 'user-files'
        },
        [pscustomobject]@{
            Key = 'ServerLogs'
            Description = 'LM Studio server logs'
            Path = Join-Path $resolvedHome 'server-logs'
            QuarantineName = 'server-logs'
        },
        [pscustomobject]@{
            Key = 'ProjectLogs'
            Description = 'Project setup and launch logs'
            Path = Join-Path $resolvedHome 'secure-setup\logs'
            QuarantineName = 'secure-setup-logs'
        }
    )
}

function Assert-OrdinaryPrivateDataDirectoryTree {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$HomePath
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedHome = [IO.Path]::GetFullPath($HomePath).TrimEnd('\')
    if (-not (Test-PrivateDataPathIsUnderRoot -Path $resolvedPath -Root $resolvedHome)) {
        throw "削除対象がLM Studioプロファイル外です: $resolvedPath"
    }

    $homeItem = Get-Item -LiteralPath $resolvedHome -Force -ErrorAction Stop
    if (($homeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'LM Studioプロファイルがシンボリックリンクまたはジャンクションのため削除を拒否します。'
    }
    $relativePath = $resolvedPath.Substring($resolvedHome.Length).TrimStart('\')
    $currentPath = $resolvedHome
    foreach ($segment in @($relativePath.Split('\'))) {
        if ([string]::IsNullOrWhiteSpace($segment)) { continue }
        $currentPath = Join-Path $currentPath $segment
        if (-not (Test-Path -LiteralPath $currentPath)) { break }
        $ancestorItem = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
        if (($ancestorItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "削除対象またはその親にシンボリックリンクまたはジャンクションがあります: $currentPath"
        }
    }
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Container)) {
        return
    }

    $pending = New-Object Collections.Generic.Stack[string]
    $pending.Push($resolvedPath)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
        if (($directoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "削除対象にシンボリックリンクまたはジャンクションがあります: $directory"
        }
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "削除対象内にシンボリックリンクまたはジャンクションがあります: $($child.FullName)"
            }
            if ($child.PSIsContainer) {
                $pending.Push($child.FullName)
            }
        }
    }
}

function Get-PrivateDataDeletionSummary {
    param(
        [Parameter(Mandatory = $true)][object[]]$Targets,
        [Parameter(Mandatory = $true)][string]$HomePath
    )

    $summaries = New-Object Collections.Generic.List[object]
    foreach ($target in $Targets) {
        Assert-OrdinaryPrivateDataDirectoryTree -Path $target.Path -HomePath $HomePath
        $files = @()
        if (Test-Path -LiteralPath $target.Path -PathType Container) {
            $files = @(Get-ChildItem -LiteralPath $target.Path -File -Force -Recurse -ErrorAction Stop)
        }
        $totalBytes = 0
        if ($files.Count -gt 0) {
            $totalBytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
        }
        $summaries.Add([pscustomobject]@{
            Key = $target.Key
            Description = $target.Description
            FileCount = $files.Count
            TotalBytes = [long]$totalBytes
        })
    }
    return $summaries.ToArray()
}

function Get-RunningLMStudioPrivateDataProcesses {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $resolvedHome = [IO.Path]::GetFullPath($HomePath)
    $results = New-Object Collections.Generic.List[object]
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $candidateName = $process.ProcessName -in @('LM Studio', 'llmster', 'lms', 'llama-server')
        $processPath = $null
        try { $processPath = [string]$process.Path } catch { }
        $candidatePath = -not [string]::IsNullOrWhiteSpace($processPath) -and
            (Test-PrivateDataPathIsUnderRoot -Path $processPath -Root $resolvedHome)
        if ($candidateName -or $candidatePath) {
            $results.Add([pscustomobject]@{
                Name = $process.ProcessName
                Id = $process.Id
                Path = $processPath
            })
        }
    }
    return $results.ToArray()
}

function Remove-LMStudioPrivateData {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $resolvedHome = [IO.Path]::GetFullPath($HomePath).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $resolvedHome -PathType Container)) {
        throw "LM Studioプロファイルがありません: $resolvedHome"
    }
    $homeItem = Get-Item -LiteralPath $resolvedHome -Force -ErrorAction Stop
    if (($homeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'LM Studioプロファイルがシンボリックリンクまたはジャンクションのため削除を拒否します。'
    }

    $targets = @(Get-PrivateDataDeletionTargets -HomePath $resolvedHome)
    $summary = @(Get-PrivateDataDeletionSummary -Targets $targets -HomePath $resolvedHome)
    $quarantineName = '.private-data-delete-' + [guid]::NewGuid().ToString('N')
    $quarantineRoot = Join-Path $resolvedHome $quarantineName
    if (-not (Test-PrivateDataPathIsUnderRoot -Path $quarantineRoot -Root $resolvedHome) -or
        [IO.Path]::GetFileName($quarantineRoot) -notmatch '^\.private-data-delete-[0-9a-f]{32}$') {
        throw '一時削除領域の安全性検証に失敗しました。'
    }

    New-Item -ItemType Directory -Path $quarantineRoot -ErrorAction Stop | Out-Null
    $moved = New-Object Collections.Generic.List[object]
    try {
        foreach ($target in $targets) {
            if (-not (Test-Path -LiteralPath $target.Path -PathType Container)) { continue }
            Assert-OrdinaryPrivateDataDirectoryTree -Path $target.Path -HomePath $resolvedHome
            $destination = Join-Path $quarantineRoot $target.QuarantineName
            [IO.Directory]::Move(
                [IO.Path]::GetFullPath($target.Path),
                [IO.Path]::GetFullPath($destination)
            )
            [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($target.Path)) | Out-Null
            $moved.Add([pscustomobject]@{
                Original = [IO.Path]::GetFullPath($target.Path)
                Quarantined = [IO.Path]::GetFullPath($destination)
            })
        }
    }
    catch {
        $moveError = $_.Exception.Message
        $rollbackErrors = New-Object Collections.Generic.List[string]
        for ($index = $moved.Count - 1; $index -ge 0; $index--) {
            $entry = $moved[$index]
            try {
                if (Test-Path -LiteralPath $entry.Original -PathType Container) {
                    $replacementChildren = @(Get-ChildItem -LiteralPath $entry.Original -Force -ErrorAction Stop)
                    if ($replacementChildren.Count -ne 0) {
                        throw 'LM Studio recreated data during rollback.'
                    }
                    [IO.Directory]::Delete($entry.Original, $false)
                }
                [IO.Directory]::Move($entry.Quarantined, $entry.Original)
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
        }
        if ($rollbackErrors.Count -gt 0) {
            throw "削除準備に失敗し、ロールバックも完了しませんでした: $moveError / $($rollbackErrors -join ' | ')"
        }
        if (Test-Path -LiteralPath $quarantineRoot -PathType Container) {
            $remaining = @(Get-ChildItem -LiteralPath $quarantineRoot -Force -ErrorAction Stop)
            if ($remaining.Count -eq 0) { [IO.Directory]::Delete($quarantineRoot, $false) }
        }
        throw "削除準備に失敗したため、元のデータを維持しました: $moveError"
    }

    try {
        $quarantineItem = Get-Item -LiteralPath $quarantineRoot -Force -ErrorAction Stop
        if (($quarantineItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            -not (Test-PrivateDataPathIsUnderRoot -Path $quarantineRoot -Root $resolvedHome)) {
            throw '一時削除領域の再検証に失敗しました。'
        }
        Remove-Item -LiteralPath $quarantineRoot -Recurse -Force -ErrorAction Stop
    }
    catch {
        throw "通常の保存場所は空にしましたが、一時削除領域を完全に消去できませんでした: $quarantineRoot / $($_.Exception.Message)"
    }

    return [pscustomobject]@{
        Categories = $summary.Count
        FileCount = [int](($summary | Measure-Object -Property FileCount -Sum).Sum)
        TotalBytes = [long](($summary | Measure-Object -Property TotalBytes -Sum).Sum)
        Summary = $summary
    }
}

function Invoke-PrivateDataDeletionMain {
    if (Test-IsAdministrator) {
        throw '通常のLM Studioユーザーとして実行してください。管理者権限は不要です。'
    }
    $homePath = [IO.Path]::GetFullPath($LmStudioHome)
    $running = @(Get-RunningLMStudioPrivateDataProcesses -HomePath $homePath)
    if ($running.Count -gt 0) {
        $processSummary = ($running | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
        throw "LM Studio関連プロセスを完全に終了してください: $processSummary"
    }

    $targets = @(Get-PrivateDataDeletionTargets -HomePath $homePath)
    $summary = @(Get-PrivateDataDeletionSummary -Targets $targets -HomePath $homePath)
    Write-Host '============================================================'
    Write-Host ' LM Studio private-data deletion'
    Write-Host '============================================================'
    foreach ($item in $summary) {
        Write-Host (' {0,-32} {1,5} files / {2,12:N0} bytes' -f
            $item.Description, $item.FileCount, $item.TotalBytes)
    }

    if ($PreviewOnly) {
        Write-Host '------------------------------------------------------------'
        Write-Host ' Preview only. Nothing was deleted.'
        return
    }
    if (-not $ConfirmDeletion) {
        throw '削除には -ConfirmDeletion が必要です。内容確認には -PreviewOnly を使用してください。'
    }

    $result = Remove-LMStudioPrivateData -HomePath $homePath
    Write-Host '------------------------------------------------------------'
    Write-Host (' Deleted: {0} files / {1:N0} bytes' -f $result.FileCount, $result.TotalBytes)
    Write-Host ' Chat history, attachments, and selected logs are now empty.'
    Write-Host ' Models, runtimes, settings, credentials, backups, and state were kept.'
}

try {
    Invoke-PrivateDataDeletionMain
    exit 0
}
catch {
    Write-Host ('[ERROR] {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
