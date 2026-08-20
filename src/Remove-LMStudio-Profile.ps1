#Requires -Version 5.1

<#
.SYNOPSIS
    Permanently removes the current user's complete LM Studio profile.

.DESCRIPTION
    This is a post-uninstall cleanup operation for the fixed directory
    %USERPROFILE%\.lmstudio. It refuses to run while LM Studio or a related
    runtime is active, while a recorded or standard LM Studio executable still
    exists, or when the profile itself is a symbolic link or junction.

    Before deletion, the profile is moved atomically to a uniquely named
    same-volume quarantine beside the original directory. The quarantine is
    then deleted without following symbolic links or junctions. This removes
    links registered for shared-folder models without deleting their targets.

    All profile content is deleted, including chats, attachments, settings,
    credentials, locally stored models and runtimes, caches, project backups,
    logs, and setup state. Project-managed Windows Firewall rules are not
    changed. This is normal filesystem deletion, not cryptographic erasure.

.PARAMETER ConfirmDeletion
    Required for destructive execution.

.PARAMETER PreviewOnly
    Shows the profile inventory and safety-check result without changing data.

.PARAMETER RequireTypedConfirmation
    Prompts for the exact word DELETE. Used by the non-technical command entry
    point after its first Y/N confirmation.

.EXAMPLE
    .\Remove-LMStudio-Profile.ps1 -PreviewOnly

.EXAMPLE
    .\Remove-LMStudio-Profile.ps1 -ConfirmDeletion
#>

[CmdletBinding()]
param(
    [switch]$ConfirmDeletion,
    [switch]$PreviewOnly,
    [switch]$RequireTypedConfirmation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:FirewallGroup = 'LM Studio Secure Local-Only'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Assert-ExactDefaultLMStudioProfile {
    param(
        [Parameter(Mandatory = $true)][string]$HomePath,
        [Parameter(Mandatory = $true)][string]$UserProfilePath
    )

    $resolvedUserProfile = [IO.Path]::GetFullPath($UserProfilePath).TrimEnd('\')
    $expectedHome = [IO.Path]::GetFullPath((Join-Path $resolvedUserProfile '.lmstudio')).TrimEnd('\')
    $resolvedHome = [IO.Path]::GetFullPath($HomePath).TrimEnd('\')
    if (-not [string]::Equals($resolvedHome, $expectedHome, [StringComparison]::OrdinalIgnoreCase)) {
        throw "削除対象が現在のユーザーの固定LM Studioプロファイルではありません: $resolvedHome"
    }
    if ([IO.Path]::GetFileName($resolvedHome) -cne '.lmstudio' -or
        -not [string]::Equals(
            [IO.Path]::GetDirectoryName($resolvedHome),
            $resolvedUserProfile,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'LM Studioプロファイルの親パス検証に失敗しました。'
    }

    $homeItem = Get-Item -LiteralPath $resolvedHome -Force -ErrorAction SilentlyContinue
    if ($null -ne $homeItem) {
        if (-not $homeItem.PSIsContainer) {
            throw "LM Studioプロファイルの場所がフォルダではありません: $resolvedHome"
        }
        if (($homeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'LM Studioプロファイル自体がシンボリックリンクまたはジャンクションのため削除を拒否します。'
        }
    }
    return $resolvedHome
}

function Get-RunningLMStudioProfileProcesses {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $names = @(
        'LM Studio', 'LM Studio Helper', 'llmster', 'lms',
        'llama-server', 'mlx-engine'
    )
    $roots = @(
        [IO.Path]::GetFullPath($HomePath),
        (Join-Path $env:LOCALAPPDATA 'Programs\LM Studio'),
        (Join-Path $env:LOCALAPPDATA 'LM Studio')
    )
    $matches = New-Object Collections.Generic.List[object]
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processPath = $null
        try { $processPath = [string]$process.Path } catch { }
        $candidatePath = $false
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            foreach ($root in $roots) {
                if (Test-PathIsUnderRoot -Path $processPath -Root $root) {
                    $candidatePath = $true
                    break
                }
            }
        }
        if ($names -contains $process.ProcessName -or $candidatePath) {
            $matches.Add([pscustomobject]@{
                Name = $process.ProcessName
                Id = $process.Id
                Path = $processPath
            })
        }
    }
    return $matches.ToArray()
}

function Get-RecordedLMStudioExecutablePath {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $recordPath = Join-Path $HomePath '.internal\app-install-location.json'
    if (-not (Test-Path -LiteralPath $recordPath -PathType Leaf)) { return $null }
    try {
        $record = Get-Content -LiteralPath $recordPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        $pathProperty = $record.PSObject.Properties['path']
        if ($null -eq $pathProperty -or [string]::IsNullOrWhiteSpace([string]$pathProperty.Value)) {
            return $null
        }
        return [IO.Path]::GetFullPath([string]$pathProperty.Value)
    }
    catch {
        throw "記録されたLM Studioインストール先を安全に確認できません: $recordPath"
    }
}

function Get-ExistingLMStudioInstallEvidence {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    $candidates = New-Object Collections.Generic.List[string]
    $recordedPath = Get-RecordedLMStudioExecutablePath -HomePath $HomePath
    if (-not [string]::IsNullOrWhiteSpace($recordedPath)) { $candidates.Add($recordedPath) }
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio\LM Studio.exe'))
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'LM Studio\LM Studio.exe'))
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles 'LM Studio\LM Studio.exe'))
    }
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if (-not [string]::IsNullOrWhiteSpace($programFilesX86)) {
        $candidates.Add((Join-Path $programFilesX86 'LM Studio\LM Studio.exe'))
    }

    return @($candidates | ForEach-Object { [IO.Path]::GetFullPath($_) } |
        Sort-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
}

function Get-LMStudioProfileSummary {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $resolvedRoot = [IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) {
        return [pscustomobject]@{
            FileCount = 0
            DirectoryCount = 0
            ReparsePointCount = 0
            TotalBytes = [long]0
        }
    }
    $rootItem = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "集計対象自体が再解析ポイントです: $resolvedRoot"
    }

    $fileCount = 0
    $directoryCount = 1
    $reparsePointCount = 0
    $totalBytes = [long]0
    $pending = New-Object Collections.Generic.Stack[string]
    $pending.Push($resolvedRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                $reparsePointCount++
                continue
            }
            if ($child.PSIsContainer) {
                $directoryCount++
                $pending.Push($child.FullName)
            }
            else {
                $fileCount++
                $totalBytes += [long]$child.Length
            }
        }
    }
    return [pscustomobject]@{
        FileCount = $fileCount
        DirectoryCount = $directoryCount
        ReparsePointCount = $reparsePointCount
        TotalBytes = $totalBytes
    }
}

function Get-ManagedFirewallRuleCount {
    $command = Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }
    try {
        return @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction Stop).Count
    }
    catch {
        return $null
    }
}

function Remove-DirectoryTreeWithoutFollowingLinks {
    param([Parameter(Mandatory = $true)][string]$RootPath)

    $resolvedRoot = [IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    $rootItem = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "削除用隔離フォルダの検証に失敗しました: $resolvedRoot"
    }

    $pending = New-Object Collections.Generic.Stack[string]
    $directories = New-Object Collections.Generic.List[string]
    $pending.Push($resolvedRoot)
    $directories.Add($resolvedRoot)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if (($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                    [IO.Directory]::Delete($child.FullName, $false)
                }
                else {
                    [IO.File]::Delete($child.FullName)
                }
                continue
            }
            if ($child.PSIsContainer) {
                $pending.Push($child.FullName)
                $directories.Add($child.FullName)
            }
            else {
                if (($child.Attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
                    [IO.File]::SetAttributes($child.FullName, [IO.FileAttributes]::Normal)
                }
                [IO.File]::Delete($child.FullName)
            }
        }
    }

    for ($index = $directories.Count - 1; $index -ge 0; $index--) {
        [IO.Directory]::Delete($directories[$index], $false)
    }
}

function Assert-ProfileQuarantinePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$UserProfilePath
    )

    $resolvedPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $resolvedUserProfile = [IO.Path]::GetFullPath($UserProfilePath).TrimEnd('\')
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($resolvedPath),
            $resolvedUserProfile,
            [StringComparison]::OrdinalIgnoreCase
        ) -or [IO.Path]::GetFileName($resolvedPath) -cne '.lmstudio-delete-quarantine') {
        throw "隔離フォルダのパス検証に失敗しました: $resolvedPath"
    }
    $item = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "隔離対象自体が通常フォルダではありません: $resolvedPath"
    }
    return $resolvedPath
}

function Remove-LMStudioCompleteProfile {
    param(
        [Parameter(Mandatory = $true)][string]$HomePath,
        [Parameter(Mandatory = $true)][string]$UserProfilePath
    )

    $resolvedHome = Assert-ExactDefaultLMStudioProfile -HomePath $HomePath -UserProfilePath $UserProfilePath
    $quarantinePath = Join-Path $UserProfilePath '.lmstudio-delete-quarantine'
    $removedResidualQuarantine = $false
    if (Test-Path -LiteralPath $quarantinePath) {
        $verifiedResidual = Assert-ProfileQuarantinePath -Path $quarantinePath -UserProfilePath $UserProfilePath
        Remove-DirectoryTreeWithoutFollowingLinks -RootPath $verifiedResidual
        $removedResidualQuarantine = $true
    }

    if (-not (Test-Path -LiteralPath $resolvedHome -PathType Container)) {
        return [pscustomobject]@{ RemovedProfile = $false; RemovedResidualQuarantine = $removedResidualQuarantine }
    }

    $resolvedQuarantine = [IO.Path]::GetFullPath($quarantinePath)
    if (-not [string]::Equals(
            [IO.Path]::GetDirectoryName($resolvedQuarantine),
            [IO.Path]::GetFullPath($UserProfilePath).TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase
        ) -or [IO.Path]::GetFileName($resolvedQuarantine) -cne '.lmstudio-delete-quarantine') {
        throw '削除用隔離フォルダの生成に失敗しました。'
    }
    if (Test-Path -LiteralPath $resolvedQuarantine) {
        throw "削除用隔離フォルダがすでに存在します: $resolvedQuarantine"
    }

    [IO.Directory]::Move($resolvedHome, $resolvedQuarantine)
    if (Test-Path -LiteralPath $resolvedHome) {
        throw 'LM Studioプロファイルを隔離できませんでした。削除は開始していません。'
    }
    try {
        $verifiedQuarantine = Assert-ProfileQuarantinePath `
            -Path $resolvedQuarantine `
            -UserProfilePath $UserProfilePath
        Remove-DirectoryTreeWithoutFollowingLinks -RootPath $verifiedQuarantine
    }
    catch {
        throw "プロファイルの通常パスは削除しましたが、隔離領域に残存データがあります: $resolvedQuarantine / $($_.Exception.Message)"
    }
    return [pscustomobject]@{ RemovedProfile = $true; RemovedResidualQuarantine = $removedResidualQuarantine }
}

function Invoke-CompleteProfileDeletionMain {
    if (Test-IsAdministrator) {
        throw '通常のLM Studioユーザーとして実行してください。管理者権限は不要です。'
    }
    if ($PreviewOnly -and $ConfirmDeletion) {
        throw '-PreviewOnly と -ConfirmDeletion は同時に指定できません。'
    }

    $userProfilePath = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
    $homePath = Assert-ExactDefaultLMStudioProfile `
        -HomePath (Join-Path $userProfilePath '.lmstudio') `
        -UserProfilePath $userProfilePath

    $running = @(Get-RunningLMStudioProfileProcesses -HomePath $homePath)
    if ($running.Count -gt 0) {
        $processSummary = ($running | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
        throw "LM Studio関連プロセスを完全に終了してください: $processSummary"
    }
    $installEvidence = @(Get-ExistingLMStudioInstallEvidence -HomePath $homePath)
    if ($installEvidence.Count -gt 0) {
        throw ("LM Studio本体がまだ存在します。先にWindowsからアンインストールしてください:`n  {0}" -f
            ($installEvidence -join "`n  "))
    }

    $profileSummary = Get-LMStudioProfileSummary -RootPath $homePath
    $residualPath = Join-Path $userProfilePath '.lmstudio-delete-quarantine'
    $residualSummary = [pscustomobject]@{
        FileCount = 0
        DirectoryCount = 0
        ReparsePointCount = 0
        TotalBytes = [long]0
    }
    $hasResidualQuarantine = Test-Path -LiteralPath $residualPath
    if ($hasResidualQuarantine) {
        $verifiedResidual = Assert-ProfileQuarantinePath -Path $residualPath -UserProfilePath $userProfilePath
        $residualSummary = Get-LMStudioProfileSummary -RootPath $verifiedResidual
    }
    $firewallCount = Get-ManagedFirewallRuleCount

    Write-Host '============================================================'
    Write-Host ' Complete LM Studio profile deletion'
    Write-Host '============================================================'
    Write-Host (' Profile       : {0}' -f $homePath)
    Write-Host (' Files         : {0:N0}' -f ($profileSummary.FileCount + $residualSummary.FileCount))
    Write-Host (' Directories   : {0:N0}' -f ($profileSummary.DirectoryCount + $residualSummary.DirectoryCount))
    Write-Host (' Links         : {0:N0} (targets will not be followed)' -f ($profileSummary.ReparsePointCount + $residualSummary.ReparsePointCount))
    Write-Host (' Total size    : {0:N0} bytes' -f ($profileSummary.TotalBytes + $residualSummary.TotalBytes))
    Write-Host (' Old quarantine: {0}' -f $(if ($hasResidualQuarantine) { 'FOUND' } else { 'none' }))
    if ($null -eq $firewallCount) {
        Write-Host ' Firewall      : project rules could not be inspected; unchanged'
    }
    elseif ($firewallCount -gt 0) {
        Write-Host (' Firewall      : {0} project-managed rules remain; unchanged' -f $firewallCount) -ForegroundColor Yellow
    }
    else {
        Write-Host ' Firewall      : no project-managed rules found'
    }

    if ($PreviewOnly) {
        Write-Host '------------------------------------------------------------'
        Write-Host ' Preview only. Nothing was deleted.'
        return
    }
    if (-not $ConfirmDeletion) {
        throw '完全削除には -ConfirmDeletion が必要です。内容確認には -PreviewOnly を使用してください。'
    }
    if ($RequireTypedConfirmation) {
        $typedConfirmation = Read-Host 'Type DELETE to confirm'
        if (-not [string]::Equals($typedConfirmation, 'DELETE', [StringComparison]::Ordinal)) {
            throw '確認文字列が一致しません。何も削除していません。'
        }
    }

    $result = Remove-LMStudioCompleteProfile -HomePath $homePath -UserProfilePath $userProfilePath
    Write-Host '------------------------------------------------------------'
    if ($result.RemovedProfile) {
        Write-Host ' Deleted the complete LM Studio user profile.'
    }
    else {
        Write-Host ' The LM Studio user profile was already absent.'
    }
    if ($result.RemovedResidualQuarantine) {
        Write-Host ' Deleted a previous incomplete-cleanup quarantine.'
    }
    Write-Host ' Shared-folder targets referenced by links were not followed.'
    Write-Host ' Project-managed Windows Firewall rules were not changed.'
}

try {
    Invoke-CompleteProfileDeletionMain
    exit 0
}
catch {
    Write-Host ('[ERROR] {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 1
}
