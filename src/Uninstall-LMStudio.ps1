#Requires -Version 5.1

<#
.SYNOPSIS
    Verifies and completely uninstalls the current user's LM Studio deployment.

.DESCRIPTION
    Uses the verified vendor uninstaller, then removes only fixed current-user
    LM Studio data roots and project-owned Firewall groups. Shared-folder model
    targets referenced through links are never followed.

    Destructive execution requires both -ConfirmUninstall and, for the public
    command entry point, the exact typed word UNINSTALL. The operation is
    restartable: fixed quarantine directories from an interrupted deletion are
    recognized and safely completed on the next run.

.PARAMETER PreviewOnly
    Performs validation and displays the exact deletion inventory without
    uninstalling, deleting data, or changing Firewall rules.

.PARAMETER ConfirmUninstall
    Required for destructive execution.

.PARAMETER RequireTypedConfirmation
    Requires the exact word UNINSTALL before destructive execution.

.PARAMETER DeploymentConfigPath
    Private deployment file containing the pinned product version and signer
    certificate thumbprint. Other one-click deployment keys are accepted but
    not used for uninstall.

.PARAMETER FirewallOnly
    Internal elevated-child mode. Do not invoke manually.
#>

[CmdletBinding()]
param(
    [switch]$PreviewOnly,
    [switch]$ConfirmUninstall,
    [switch]$RequireTypedConfirmation,
    [string]$DeploymentConfigPath,

    # Internal elevated-child parameters.
    [switch]$FirewallOnly,
    [string]$FirewallRequestPath,
    [string]$FirewallRequestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:FirewallGroups = @('LM Studio Secure Local-Only', 'LM Studio Secure Bootstrap')
$script:UninstallMutex = $null
$script:UninstallMutexOwned = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Resolve-DeploymentConfigPath {
    param([string]$RequestedPath)
    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\config\deployment.local.psd1'))
    }
    return [IO.Path]::GetFullPath($RequestedPath)
}

function Read-UninstallPolicy {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $resolvedPath = [IO.Path]::GetFullPath($ConfigPath)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw '非公開配布設定がありません。検証なしのアンインストールは行いません。'
    }
    try { $config = Import-PowerShellDataFile -LiteralPath $resolvedPath -ErrorAction Stop }
    catch { throw '非公開配布設定を安全なPowerShellデータファイルとして読み込めません。' }
    if ($config -isnot [Collections.IDictionary]) { throw '非公開配布設定の形式が正しくありません。' }

    $allowedKeys = @(
        'ModelSourcePath', 'VisionProjectorPath', 'ModelUserRepo',
        'ProjectFirewall', 'FirewallMode',
        'InstallerPath', 'InstallerSha256', 'InstallerProductVersion',
        'InstallerSignerThumbprint', 'RuntimeProvisioning', 'RequiredRuntime'
    )
    foreach ($key in @($config.Keys)) {
        if ([string]$key -notin $allowedKeys) { throw "配布設定に未対応の項目があります: $key" }
    }
    foreach ($requiredKey in @('InstallerProductVersion', 'InstallerSignerThumbprint')) {
        if (-not $config.Contains($requiredKey) -or
            [string]::IsNullOrWhiteSpace([string]$config[$requiredKey])) {
            throw "アンインストール検証の必須項目が空です: $requiredKey"
        }
    }
    $version = ([string]$config['InstallerProductVersion']).Trim()
    if ($version -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$') {
        throw 'InstallerProductVersionの形式が正しくありません。'
    }
    $thumbprint = ([string]$config['InstallerSignerThumbprint']).Replace(' ', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') {
        throw 'InstallerSignerThumbprintは40桁の証明書指紋を指定してください。'
    }
    return [pscustomobject]@{
        ConfigPath = $resolvedPath
        ProductVersion = $version
        SignerThumbprint = $thumbprint
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

function Get-InstalledLMStudioExecutable {
    $candidates = New-Object Collections.Generic.List[string]
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio\LM Studio.exe'))
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'LM Studio\LM Studio.exe'))
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $candidates.Add((Join-Path $env:ProgramFiles 'LM Studio\LM Studio.exe'))
    }
    $existing = @($candidates | ForEach-Object { [IO.Path]::GetFullPath($_) } |
        Sort-Object -Unique | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($existing.Count -gt 1) { throw 'LM Studio.exeが複数の標準場所にあるため自動選択を拒否します。' }
    if ($existing.Count -eq 0) { return $null }
    return $existing[0]
}

function Get-CurrentUserLMStudioInstallRoots {
    return @(
        [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio')),
        [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'LM Studio'))
    ) | Sort-Object -Unique
}

function Assert-CurrentUserInstallRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed = @(Get-CurrentUserLMStudioInstallRoots | Where-Object {
        [string]::Equals($_.TrimEnd('\'), $resolved, [StringComparison]::OrdinalIgnoreCase)
    })
    if ($allowed.Count -ne 1) { throw 'LM Studioインストール残存フォルダが固定許可リスト外です。' }
    $item = Get-Item -LiteralPath $resolved -Force -ErrorAction SilentlyContinue
    if ($null -ne $item -and
        (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'LM Studioインストール残存パスが通常フォルダではありません。'
    }
    return $resolved
}

function Remove-EmptyCurrentUserInstallRoot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $resolved = Assert-CurrentUserInstallRoot -Path $Path
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) { return $false }
    $children = @(Get-ChildItem -LiteralPath $resolved -Force -ErrorAction Stop)
    if ($children.Count -ne 0) {
        throw '公式アンインストール後の固定インストールフォルダが空ではありません。自動削除しません。'
    }
    [IO.Directory]::Delete($resolved, $false)
    if (Test-Path -LiteralPath $resolved) { throw '空のLM Studioインストール残存フォルダを削除できませんでした。' }
    return $true
}

function Get-AllLMStudioUninstallRegistrations {
    return @(Get-ItemProperty `
        -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue | Where-Object {
            ([string](Get-PropertyValue -InputObject $_ -Name 'DisplayName')).StartsWith(
                'LM Studio',
                [StringComparison]::OrdinalIgnoreCase
            ) -or [string]::Equals(
                [string](Get-PropertyValue -InputObject $_ -Name 'Publisher'),
                'LM Studio',
                [StringComparison]::OrdinalIgnoreCase
            )
        })
}

function Get-LMStudioUninstallRegistrations {
    param([Parameter(Mandatory = $true)][string]$ExpectedVersion)
    return @(Get-AllLMStudioUninstallRegistrations | Where-Object {
        [string]::Equals(
            [string](Get-PropertyValue -InputObject $_ -Name 'DisplayName'),
            "LM Studio $ExpectedVersion",
            [StringComparison]::Ordinal
        ) -and
        [string]::Equals(
            [string](Get-PropertyValue -InputObject $_ -Name 'DisplayVersion'),
            $ExpectedVersion,
            [StringComparison]::Ordinal
        ) -and
        [string]::Equals(
            [string](Get-PropertyValue -InputObject $_ -Name 'Publisher'),
            'LM Studio',
            [StringComparison]::Ordinal
        )
    })
}

function Get-NormalizedDisplayIconPath {
    param([AllowEmptyString()][string]$Value)
    $path = $Value.Trim()
    if ($path.EndsWith(',0', [StringComparison]::Ordinal)) {
        $path = $path.Substring(0, $path.Length - 2)
    }
    $path = $path.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($path)) { return '' }
    try { return [IO.Path]::GetFullPath($path) } catch { return '' }
}

function Assert-AuthenticodeIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedThumbprint,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    $actualThumbprint = if ($null -eq $signature.SignerCertificate) { '' } else {
        ([string]$signature.SignerCertificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
    }
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $actualThumbprint -ne $ExpectedThumbprint) {
        throw "$Description の電子署名が配布固定値と一致しません。"
    }
}

function Assert-InstalledApplication {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][object]$Policy,
        [Parameter(Mandatory = $true)][object]$Registration
    )
    $resolvedExe = [IO.Path]::GetFullPath($ExePath)
    Assert-AuthenticodeIdentity `
        -Path $resolvedExe `
        -ExpectedThumbprint $Policy.SignerThumbprint `
        -Description 'インストール済みLM Studio.exe'

    $versionInfo = (Get-Item -LiteralPath $resolvedExe -Force).VersionInfo
    $versionMatches = [string]::Equals(
        [string]$versionInfo.ProductVersion,
        $Policy.ProductVersion,
        [StringComparison]::Ordinal
    ) -or [string]::Equals(
        [string]$versionInfo.FileVersion,
        $Policy.ProductVersion,
        [StringComparison]::Ordinal
    )
    if (-not [string]::Equals([string]$versionInfo.ProductName, 'LM Studio', [StringComparison]::OrdinalIgnoreCase) -or
        -not $versionMatches) {
        throw 'インストール済みLM Studio.exeの製品情報が配布固定値と一致しません。'
    }

    $packagePath = Join-Path ([IO.Path]::GetDirectoryName($resolvedExe)) 'resources\app\package.json'
    $packageItem = Get-Item -LiteralPath $packagePath -Force -ErrorAction Stop
    if (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'インストール済みpackage.jsonがリンクで置き換えられています。'
    }
    try { $package = Get-Content -LiteralPath $packagePath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'インストール済みpackage.jsonを検証できません。' }
    if ([string](Get-PropertyValue -InputObject $package -Name 'name') -ne 'lm-studio' -or
        [string](Get-PropertyValue -InputObject $package -Name 'productName') -ne 'LM Studio' -or
        [string](Get-PropertyValue -InputObject $package -Name 'version') -ne $Policy.ProductVersion) {
        throw 'インストール済みpackage.jsonが配布固定値と一致しません。'
    }

    $displayIconPath = Get-NormalizedDisplayIconPath `
        -Value ([string](Get-PropertyValue -InputObject $Registration -Name 'DisplayIcon'))
    if (-not [string]::Equals($displayIconPath, $resolvedExe, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Windowsアンインストール登録の対象実行ファイルが一致しません。'
    }
}

function Get-VerifiedVendorUninstaller {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][object]$Policy,
        [Parameter(Mandatory = $true)][object]$Registration
    )
    $installRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ExePath))
    $uninstallerPath = [IO.Path]::GetFullPath((Join-Path $installRoot 'Uninstall LM Studio.exe'))
    if (-not (Test-Path -LiteralPath $uninstallerPath -PathType Leaf)) {
        throw '検証対象の公式LM Studioアンインストーラーがありません。'
    }
    Assert-AuthenticodeIdentity `
        -Path $uninstallerPath `
        -ExpectedThumbprint $Policy.SignerThumbprint `
        -Description 'LM Studioアンインストーラー'
    $info = (Get-Item -LiteralPath $uninstallerPath -Force).VersionInfo
    $versionMatches = [string]::Equals([string]$info.ProductVersion, $Policy.ProductVersion, [StringComparison]::Ordinal) -or
        [string]::Equals([string]$info.FileVersion, $Policy.ProductVersion, [StringComparison]::Ordinal)
    if (-not [string]::Equals([string]$info.ProductName, 'LM Studio', [StringComparison]::OrdinalIgnoreCase) -or
        -not $versionMatches) {
        throw 'LM Studioアンインストーラーの製品情報が配布固定値と一致しません。'
    }
    $expectedQuietCommand = '"{0}" /currentuser /S' -f $uninstallerPath
    if (-not [string]::Equals(
            ([string](Get-PropertyValue -InputObject $Registration -Name 'QuietUninstallString')).Trim(),
            $expectedQuietCommand,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'Windows登録のサイレントアンインストール指定が期待状態ではありません。'
    }
    return $uninstallerPath
}

function Get-RunningLMStudioProcesses {
    param([AllowEmptyString()][string]$ExePath)
    $names = @('LM Studio', 'LM Studio Helper', 'llmster', 'lms', 'llama-server', 'mlx-engine')
    $roots = @(
        [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.lmstudio')),
        [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio')),
        [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'LM Studio'))
    )
    $matches = New-Object Collections.Generic.List[object]
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processPath = $null
        try { $processPath = [string]$process.Path } catch { }
        $pathMatch = $false
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            foreach ($root in $roots) {
                if (Test-PathIsUnderRoot -Path $processPath -Root $root) { $pathMatch = $true; break }
            }
            if (-not [string]::IsNullOrWhiteSpace($ExePath) -and
                [string]::Equals($processPath, $ExePath, [StringComparison]::OrdinalIgnoreCase)) {
                $pathMatch = $true
            }
        }
        if ($names -contains $process.ProcessName -or $pathMatch) {
            $matches.Add([pscustomobject]@{ Name = $process.ProcessName; Id = $process.Id; Path = $processPath })
        }
    }
    return $matches.ToArray()
}

function Get-CompleteUninstallDataTargets {
    $userProfile = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
    $roamingRoot = [IO.Path]::GetFullPath($env:APPDATA).TrimEnd('\')
    $localRoot = [IO.Path]::GetFullPath($env:LOCALAPPDATA).TrimEnd('\')
    return @(
        [pscustomobject]@{
            Key = 'Profile'
            Path = Join-Path $userProfile '.lmstudio'
            QuarantinePath = Join-Path $userProfile '.lmstudio-delete-quarantine'
            Parent = $userProfile
            Name = '.lmstudio'
            QuarantineName = '.lmstudio-delete-quarantine'
        },
        [pscustomobject]@{
            Key = 'LegacyRoaming'
            Path = Join-Path $roamingRoot 'LM Studio'
            QuarantinePath = Join-Path $roamingRoot 'LM Studio-delete-quarantine'
            Parent = $roamingRoot
            Name = 'LM Studio'
            QuarantineName = 'LM Studio-delete-quarantine'
        },
        [pscustomobject]@{
            Key = 'UpdaterCache'
            Path = Join-Path $localRoot 'lm-studio-updater'
            QuarantinePath = Join-Path $localRoot 'lm-studio-updater-delete-quarantine'
            Parent = $localRoot
            Name = 'lm-studio-updater'
            QuarantineName = 'lm-studio-updater-delete-quarantine'
        }
    )
}

function Assert-FixedDataTarget {
    param([Parameter(Mandatory = $true)][object]$Target)
    $expectedTargets = @(Get-CompleteUninstallDataTargets | Where-Object {
        [string]$_.Key -ceq [string]$Target.Key
    })
    if ($expectedTargets.Count -ne 1) { throw '固定削除対象の識別子を認識できません。' }
    $expectedTarget = $expectedTargets[0]
    foreach ($propertyName in @('Path', 'QuarantinePath', 'Parent', 'Name', 'QuarantineName')) {
        if (-not [string]::Equals(
                [string](Get-PropertyValue -InputObject $Target -Name $propertyName),
                [string](Get-PropertyValue -InputObject $expectedTarget -Name $propertyName),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "固定削除対象が許可リストと一致しません: $($Target.Key)"
        }
    }
    $parent = [IO.Path]::GetFullPath([string]$Target.Parent).TrimEnd('\')
    $path = [IO.Path]::GetFullPath([string]$Target.Path).TrimEnd('\')
    $quarantine = [IO.Path]::GetFullPath([string]$Target.QuarantinePath).TrimEnd('\')
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($path), $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($path) -cne [string]$Target.Name -or
        -not [string]::Equals([IO.Path]::GetDirectoryName($quarantine), $parent, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($quarantine) -cne [string]$Target.QuarantineName) {
        throw "固定削除対象のパス検証に失敗しました: $($Target.Key)"
    }
    foreach ($candidate in @($path, $quarantine)) {
        $item = Get-Item -LiteralPath $candidate -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and
            (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "固定削除対象が通常フォルダではありません: $($Target.Key)"
        }
    }
    return [pscustomobject]@{
        Key = [string]$Target.Key
        Path = $path
        QuarantinePath = $quarantine
        Parent = $parent
    }
}

function Get-DirectoryTreeSummaryWithoutFollowingLinks {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
        return [pscustomobject]@{ FileCount = 0; DirectoryCount = 0; LinkCount = 0; TotalBytes = [long]0 }
    }
    $rootItem = Get-Item -LiteralPath $RootPath -Force -ErrorAction Stop
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw '集計対象のルートが再解析ポイントです。'
    }
    $files = 0
    $directories = 1
    $links = 0
    $bytes = [long]0
    $pending = New-Object Collections.Generic.Stack[string]
    $pending.Push([IO.Path]::GetFullPath($RootPath))
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { $links++; continue }
            if ($child.PSIsContainer) { $directories++; $pending.Push($child.FullName) }
            else { $files++; $bytes += [long]$child.Length }
        }
    }
    return [pscustomobject]@{
        FileCount = $files
        DirectoryCount = $directories
        LinkCount = $links
        TotalBytes = $bytes
    }
}

function Remove-DirectoryTreeWithoutFollowingLinks {
    param([Parameter(Mandatory = $true)][string]$RootPath)
    $root = [IO.Path]::GetFullPath($RootPath).TrimEnd('\')
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw '削除用隔離フォルダが通常フォルダではありません。'
    }
    $pending = New-Object Collections.Generic.Stack[string]
    $directories = New-Object Collections.Generic.List[string]
    $pending.Push($root)
    $directories.Add($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($child in @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                if (($child.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                    [IO.Directory]::Delete($child.FullName, $false)
                } else { [IO.File]::Delete($child.FullName) }
                continue
            }
            if ($child.PSIsContainer) { $pending.Push($child.FullName); $directories.Add($child.FullName) }
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

function Remove-CompleteUninstallData {
    param([Parameter(Mandatory = $true)][object[]]$Targets)
    $verified = @($Targets | ForEach-Object { Assert-FixedDataTarget -Target $_ })
    $newlyStaged = New-Object Collections.Generic.List[object]
    foreach ($target in $verified) {
        $sourceExists = Test-Path -LiteralPath $target.Path -PathType Container
        $quarantineExists = Test-Path -LiteralPath $target.QuarantinePath -PathType Container
        if ($sourceExists -and $quarantineExists) {
            throw "通常領域と削除用隔離領域が同時に存在します: $($target.Key)"
        }
    }
    try {
        foreach ($target in $verified) {
            if (Test-Path -LiteralPath $target.Path -PathType Container) {
                [IO.Directory]::Move($target.Path, $target.QuarantinePath)
                $newlyStaged.Add($target)
            }
        }
    }
    catch {
        for ($index = $newlyStaged.Count - 1; $index -ge 0; $index--) {
            $target = $newlyStaged[$index]
            if (-not (Test-Path -LiteralPath $target.Path) -and
                (Test-Path -LiteralPath $target.QuarantinePath -PathType Container)) {
                try { [IO.Directory]::Move($target.QuarantinePath, $target.Path) } catch { }
            }
        }
        throw 'ユーザーデータを安全に隔離できなかったため、隔離済み領域のロールバックを試行しました。'
    }
    foreach ($target in $verified) {
        if (Test-Path -LiteralPath $target.QuarantinePath -PathType Container) {
            Remove-DirectoryTreeWithoutFollowingLinks -RootPath $target.QuarantinePath
        }
        if ((Test-Path -LiteralPath $target.Path) -or
            (Test-Path -LiteralPath $target.QuarantinePath)) {
            throw "ユーザーデータを完全に削除できませんでした: $($target.Key)"
        }
    }
}

function Get-ManagedFirewallRuleSummary {
    $command = Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $null }
    try {
        $counts = [ordered]@{}
        foreach ($group in $script:FirewallGroups) {
            $counts[$group] = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count
        }
        return [pscustomobject]$counts
    }
    catch { return $null }
}

function Remove-ManagedFirewallRules {
    if (-not (Test-IsAdministrator)) { throw 'Firewall規則の削除には管理者権限が必要です。' }
    $removed = 0
    foreach ($group in $script:FirewallGroups) {
        $rules = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            if ([string]$rule.Group -ne $group) { throw '管理外のFirewall規則は削除しません。' }
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
            $removed++
        }
        if (@(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count -ne 0) {
            throw "プロジェクト所有Firewall規則を完全に削除できませんでした: $group"
        }
    }
    return $removed
}

function Write-FirewallRequest {
    param([Parameter(Mandatory = $true)][string]$Path)
    $request = [ordered]@{
        SchemaVersion = 1
        CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
        Action = 'RemoveProjectFirewall'
        Groups = @($script:FirewallGroups)
    }
    [IO.File]::WriteAllText(
        $Path,
        (($request | ConvertTo-Json -Depth 5) + [Environment]::NewLine),
        (New-Object Text.UTF8Encoding($false))
    )
}

function Invoke-ElevatedFirewallRemoval {
    $requestRoot = Join-Path ([IO.Path]::GetTempPath()) 'WindowsLocalAIHardening'
    if (-not (Test-Path -LiteralPath $requestRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $requestRoot -Force | Out-Null
    }
    $requestPath = Join-Path $requestRoot ('uninstall-firewall-{0}.json' -f [guid]::NewGuid().ToString('N'))
    Write-FirewallRequest -Path $requestPath
    $hash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    try {
        if (Test-IsAdministrator) { return Remove-ManagedFirewallRules }
        foreach ($value in @($PSCommandPath, $requestPath)) {
            if ([string]::IsNullOrWhiteSpace($value) -or $value.Contains('"')) {
                throw '管理者処理へ安全に渡せないパスがあります。'
            }
        }
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-FirewallOnly',
            '-FirewallRequestPath', ('"{0}"' -f $requestPath),
            '-FirewallRequestSha256', $hash
        )
        $process = Start-Process `
            -FilePath (Join-Path $PSHOME 'powershell.exe') `
            -ArgumentList $arguments `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        if ($process.ExitCode -ne 0) { throw "Firewall規則の削除に失敗しました。終了コード: $($process.ExitCode)" }
        return 0
    }
    finally {
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) { [IO.File]::Delete($requestPath) }
    }
}

function Invoke-FirewallOnlyMode {
    if (-not $FirewallOnly) { return }
    try {
        if (-not (Test-IsAdministrator)) { throw '管理者権限がありません。' }
        if ([string]::IsNullOrWhiteSpace($FirewallRequestPath) -or
            $FirewallRequestSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Firewall削除要求が不足または不正です。'
        }
        $path = [IO.Path]::GetFullPath($FirewallRequestPath)
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $FirewallRequestSha256.ToLowerInvariant()) { throw 'Firewall削除要求のハッシュが一致しません。' }
        $request = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Get-PropertyValue -InputObject $request -Name 'SchemaVersion') -ne 1 -or
            (Get-PropertyValue -InputObject $request -Name 'Action') -ne 'RemoveProjectFirewall') {
            throw 'Firewall削除要求の形式を認識できません。'
        }
        $requestedGroups = @((Get-PropertyValue -InputObject $request -Name 'Groups'))
        if (($requestedGroups -join '|') -ne ($script:FirewallGroups -join '|')) {
            throw 'Firewall削除要求の対象グループが一致しません。'
        }
        $createdAt = [DateTime]::Parse(
            [string](Get-PropertyValue -InputObject $request -Name 'CreatedAtUtc'),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $age = [DateTime]::UtcNow.Subtract($createdAt.ToUniversalTime()).TotalMinutes
        if ($age -lt -1 -or $age -gt 15) { throw 'Firewall削除要求の有効期限が切れています。' }
        $count = Remove-ManagedFirewallRules
        Write-Host "プロジェクト所有Firewall規則を削除しました: $count 件"
        exit 0
    }
    catch {
        Write-Host ('[ERROR] {0}' -f $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

function Enter-UninstallMutex {
    $createdNew = $false
    $identityBytes = [Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($env:USERPROFILE).ToUpperInvariant())
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $identity = ([BitConverter]::ToString($sha.ComputeHash($identityBytes))).Replace('-', '').Substring(0, 24) }
    finally { $sha.Dispose() }
    $mutex = New-Object Threading.Mutex($true, ('Local\WindowsLocalAIHardening.Uninstall.' + $identity), ([ref]$createdNew))
    if (-not $createdNew) { $mutex.Dispose(); throw '別の完全アンインストールが実行中です。' }
    $script:UninstallMutex = $mutex
    $script:UninstallMutexOwned = $true
}

function Exit-UninstallMutex {
    if ($script:UninstallMutexOwned -and $null -ne $script:UninstallMutex) {
        try { $script:UninstallMutex.ReleaseMutex() } catch { }
    }
    if ($null -ne $script:UninstallMutex) { $script:UninstallMutex.Dispose() }
    $script:UninstallMutex = $null
    $script:UninstallMutexOwned = $false
}

function Invoke-VendorUninstaller {
    param(
        [Parameter(Mandatory = $true)][string]$UninstallerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [int]$TimeoutSeconds = 900
    )
    Write-Host '検証済みLM Studioアンインストーラーを実行します。'
    $process = Start-Process `
        -FilePath $UninstallerPath `
        -ArgumentList @('/currentuser', '/S') `
        -WindowStyle Hidden `
        -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "LM Studioアンインストーラーが$TimeoutSeconds秒以内に終了しませんでした。強制終了は行っていません。"
    }
    $process.WaitForExit()
    $process.Refresh()
    $exitCode = -1
    try { $exitCode = [int]$process.ExitCode } catch { }
    if ($exitCode -ne 0) { throw "LM Studioアンインストーラーが失敗しました。終了コード: $exitCode" }

    $installRoot = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($UninstallerPath))
    $deadline = [DateTime]::UtcNow.AddSeconds(180)
    do {
        $exePresent = Test-Path -LiteralPath (Join-Path $installRoot 'LM Studio.exe') -PathType Leaf
        $uninstallerPresent = Test-Path -LiteralPath $UninstallerPath -PathType Leaf
        $registrations = @(Get-AllLMStudioUninstallRegistrations)
        if (-not $exePresent -and -not $uninstallerPresent -and $registrations.Count -eq 0) {
            if (Test-Path -LiteralPath $installRoot -PathType Container) {
                $children = @(Get-ChildItem -LiteralPath $installRoot -Force -ErrorAction Stop)
                if ($children.Count -gt 0) {
                    Start-Sleep -Seconds 1
                    continue
                }
                $null = Remove-EmptyCurrentUserInstallRoot -Path $installRoot
            }
            Write-Host 'LM Studio本体とWindowsアンインストール登録の削除を確認しました。'
            return
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw '公式アンインストーラー終了後もLM Studio本体またはWindows登録が残っています。ユーザーデータ削除は開始していません。'
}

function Invoke-CompleteUninstallMain {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'このスクリプトはWindows専用です。' }
    if (Test-IsAdministrator) { throw '通常ユーザーとして実行してください。必要なFirewall処理だけ別プロセスで昇格します。' }
    if ($PreviewOnly -and $ConfirmUninstall) { throw '-PreviewOnlyと-ConfirmUninstallは同時に指定できません。' }
    Enter-UninstallMutex

    $policy = Read-UninstallPolicy -ConfigPath (Resolve-DeploymentConfigPath -RequestedPath $DeploymentConfigPath)
    $exePath = Get-InstalledLMStudioExecutable
    $allRegistrations = @(Get-AllLMStudioUninstallRegistrations)
    $registrations = @(Get-LMStudioUninstallRegistrations -ExpectedVersion $policy.ProductVersion)
    $uninstallerPath = $null
    if (-not [string]::IsNullOrWhiteSpace($exePath)) {
        if ($allRegistrations.Count -ne 1 -or $registrations.Count -ne 1) {
            throw 'LM StudioのWindowsアンインストール登録が一意または配布固定状態ではありません。'
        }
        Assert-InstalledApplication -ExePath $exePath -Policy $policy -Registration $registrations[0]
        $uninstallerPath = Get-VerifiedVendorUninstaller `
            -ExePath $exePath `
            -Policy $policy `
            -Registration $registrations[0]
    }
    elseif ($allRegistrations.Count -ne 0) {
        throw 'LM Studio.exeはありませんがWindowsアンインストール登録が残っています。自動実行を拒否します。'
    }

    $emptyInstallResidues = New-Object Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($exePath)) {
        foreach ($installRoot in @(Get-CurrentUserLMStudioInstallRoots)) {
            $verifiedRoot = Assert-CurrentUserInstallRoot -Path $installRoot
            if (Test-Path -LiteralPath $verifiedRoot -PathType Container) {
                $children = @(Get-ChildItem -LiteralPath $verifiedRoot -Force -ErrorAction Stop)
                if ($children.Count -ne 0) {
                    throw 'LM Studio本体はありませんが、固定インストールフォルダに未確認のファイルが残っています。'
                }
                $emptyInstallResidues.Add($verifiedRoot)
            }
        }
    }

    $running = @(Get-RunningLMStudioProcesses -ExePath ([string]$exePath))
    if ($running.Count -gt 0) {
        $summary = ($running | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
        throw "LM Studio関連プロセスを完全に終了してください: $summary"
    }

    $targets = @(Get-CompleteUninstallDataTargets)
    $total = [pscustomobject]@{ Files = 0; Directories = 0; Links = 0; Bytes = [long]0 }
    foreach ($target in $targets) {
        $verified = Assert-FixedDataTarget -Target $target
        foreach ($path in @($verified.Path, $verified.QuarantinePath)) {
            $summary = Get-DirectoryTreeSummaryWithoutFollowingLinks -RootPath $path
            $total.Files += $summary.FileCount
            $total.Directories += $summary.DirectoryCount
            $total.Links += $summary.LinkCount
            $total.Bytes += $summary.TotalBytes
        }
    }
    $firewallSummary = Get-ManagedFirewallRuleSummary
    $firewallCount = if ($null -eq $firewallSummary) { $null } else {
        [int]$firewallSummary.'LM Studio Secure Local-Only' + [int]$firewallSummary.'LM Studio Secure Bootstrap'
    }

    Write-Host '============================================================'
    Write-Host ' Complete LM Studio uninstall preview'
    Write-Host '============================================================'
    Write-Host (' Application : {0}' -f $(if ($null -eq $exePath) { 'already absent' } else { "VERIFIED / $($policy.ProductVersion)" }))
    Write-Host (' Empty app dir: {0}' -f $emptyInstallResidues.Count)
    Write-Host (' Data roots   : {0} fixed current-user locations' -f $targets.Count)
    Write-Host (' Files        : {0:N0}' -f $total.Files)
    Write-Host (' Directories  : {0:N0}' -f $total.Directories)
    Write-Host (' Links        : {0:N0} (targets will not be followed)' -f $total.Links)
    Write-Host (' Total size   : {0:N0} bytes' -f $total.Bytes)
    Write-Host (' Firewall     : {0}' -f $(if ($null -eq $firewallCount) { 'inspection requires elevation during removal' } else { "$firewallCount project-owned rules" }))
    Write-Host ' Shared model : PRESERVED'

    if ($PreviewOnly) {
        Write-Host '------------------------------------------------------------'
        Write-Host ' Preview only. Nothing was uninstalled, deleted, or changed.'
        return
    }
    if (-not $ConfirmUninstall) { throw '完全アンインストールには-ConfirmUninstallが必要です。' }
    if ($RequireTypedConfirmation) {
        $confirmation = Read-Host 'Type UNINSTALL to confirm'
        if (-not [string]::Equals($confirmation, 'UNINSTALL', [StringComparison]::Ordinal)) {
            throw '確認文字列が一致しません。何もアンインストールまたは削除していません。'
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($uninstallerPath)) {
        Invoke-VendorUninstaller `
            -UninstallerPath $uninstallerPath `
            -ExpectedVersion $policy.ProductVersion
    } else {
        Write-Host 'LM Studio本体はすでにアンインストール済みです。'
        foreach ($installRoot in @($emptyInstallResidues.ToArray())) {
            $null = Remove-EmptyCurrentUserInstallRoot -Path $installRoot
        }
    }

    Remove-CompleteUninstallData -Targets $targets
    Write-Host 'LM Studioの固定ユーザーデータ領域を削除しました。'
    $null = Invoke-ElevatedFirewallRemoval
    $remainingFirewall = Get-ManagedFirewallRuleSummary
    if ($null -ne $remainingFirewall -and
        ([int]$remainingFirewall.'LM Studio Secure Local-Only' -ne 0 -or
            [int]$remainingFirewall.'LM Studio Secure Bootstrap' -ne 0)) {
        throw 'プロジェクト所有Firewall規則が残っています。'
    }

    Write-Host '============================================================'
    Write-Host ' Complete uninstall completed'
    Write-Host ' Application : REMOVED'
    Write-Host ' Local data  : REMOVED'
    Write-Host ' Firewall    : PROJECT RULES REMOVED'
    Write-Host ' Shared model: PRESERVED'
    Write-Host '============================================================'
}

Invoke-FirewallOnlyMode

$exitCode = 0
try { Invoke-CompleteUninstallMain }
catch {
    $exitCode = 1
    Write-Host ('[ERROR] {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host '[ERROR] 完全アンインストールは完了していません。原因解消後に同じファイルを再実行してください。' -ForegroundColor Red
}
finally { Exit-UninstallMutex }
exit $exitCode
