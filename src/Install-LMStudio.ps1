#Requires -Version 5.1

<#
.SYNOPSIS
    Installs, initializes, hardens, and securely launches LM Studio.

.DESCRIPTION
    Orchestrates the complete first-use workflow for an ordinary Windows user:

      1. Validate a deployment-pinned LM Studio installer by SHA-256,
         Authenticode signer thumbprint, product name, and product version.
      2. Silently install the pinned NSIS package when that exact version is
         not already installed.
      3. In ProjectFirewall ON mode, block non-loopback traffic before the
         first GUI initialization.
      4. Start LM Studio only long enough to create its user profile and CLI.
      5. If configured, open a clearly logged provisioning network window and
         use an exact runtime identifier with `lms runtime get ... -y`, then
         select and verify that runtime.
      6. Gracefully close bootstrap processes, run Setup-LMStudio.ps1, replace
         temporary bootstrap rules with the full audited rules, and run
         Start-LMStudio-Secure.ps1.

    The script never downloads the LM Studio installer or a model. The
    deployment owner stages those files. Online runtime provisioning is the
    only project-initiated external download and is explicitly selected in the
    private deployment configuration. Re-running the script revalidates and
    resumes completed phases instead of reinstalling blindly.

.PARAMETER DeploymentConfigPath
    Private deployment data file. Defaults to
    config\deployment.local.psd1 below the package root.

.PARAMETER PreviewOnly
    Performs configuration, installer, signature, version, hash, installed-app,
    and process checks without installing, launching, changing Firewall, or
    downloading a runtime.

.PARAMETER BootstrapFirewallOnly
    Internal elevated-child mode. Do not invoke manually.
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$DeploymentConfigPath,

    [switch]$PreviewOnly,

    # Internal elevated-child parameters.
    [switch]$BootstrapFirewallOnly,
    [string]$FirewallRequestPath,
    [string]$FirewallRequestSha256,
    [string]$SharedLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:BootstrapFirewallGroup = 'LM Studio Secure Bootstrap'
$script:ProductionFirewallGroup = 'LM Studio Secure Local-Only'
$script:NonLoopbackRemoteAddresses = @(
    '0.0.0.0-126.255.255.255',
    '128.0.0.0-255.255.255.255',
    '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
)
$script:LogPath = $null
$script:StartedBootstrapProcess = $null
$script:BootstrapFirewallEnabled = $false
$script:InstallMutex = $null
$script:InstallMutexOwned = $false
$script:ConfigurationForCleanup = $null
$script:ExePathForCleanup = $null
$script:HomePathForCleanup = $null
$script:PreviewCompleted = $false

function Write-InstallLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
    switch ($Level) {
        'OK' { Write-Host $line -ForegroundColor Green }
        'WARN' { Write-Warning $line }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8 }
        catch { Write-Warning ('ログへの追記に失敗しました: {0}' -f $_.Exception.Message) }
    }
}

function Initialize-InstallLogging {
    param([string]$ExistingLogPath)

    if (-not [string]::IsNullOrWhiteSpace($ExistingLogPath)) {
        $script:LogPath = [IO.Path]::GetFullPath($ExistingLogPath)
        return
    }
    $temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) 'WindowsLocalAIHardening'
    if (-not (Test-Path -LiteralPath $temporaryRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    }
    $script:LogPath = Join-Path $temporaryRoot (
        'Install-LMStudio-{0}-{1}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $PID
    )
    [IO.File]::WriteAllText($script:LogPath, '', (New-Object Text.UTF8Encoding($false)))
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
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

function Read-OneClickDeploymentConfig {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    $resolvedPath = [IO.Path]::GetFullPath($ConfigPath)
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw 'ワンクリック配布設定がありません。配布管理者が config\deployment.local.psd1 を準備してください。'
    }
    try { $config = Import-PowerShellDataFile -LiteralPath $resolvedPath -ErrorAction Stop }
    catch { throw 'ワンクリック配布設定を安全なPowerShellデータファイルとして読み込めません。' }
    if ($config -isnot [Collections.IDictionary]) {
        throw 'ワンクリック配布設定の形式が正しくありません。'
    }

    $allowedKeys = @(
        'ModelSourcePath', 'VisionProjectorPath', 'ModelUserRepo',
        'ProjectFirewall', 'FirewallMode',
        'InstallerPath', 'InstallerSha256', 'InstallerProductVersion',
        'InstallerSignerThumbprint', 'RuntimeProvisioning', 'RequiredRuntime'
    )
    foreach ($key in @($config.Keys)) {
        if ([string]$key -notin $allowedKeys) {
            throw "配布設定に未対応の項目があります: $key"
        }
    }

    foreach ($requiredKey in @(
        'ModelSourcePath', 'InstallerPath', 'InstallerSha256', 'InstallerProductVersion',
        'InstallerSignerThumbprint', 'RuntimeProvisioning', 'RequiredRuntime'
    )) {
        if (-not $config.Contains($requiredKey) -or
            [string]::IsNullOrWhiteSpace([string]$config[$requiredKey])) {
            throw "ワンクリック配布設定の必須項目が空です: $requiredKey"
        }
    }

    $installerPath = [IO.Path]::GetFullPath([string]$config['InstallerPath'])
    $installerSha256 = ([string]$config['InstallerSha256']).Trim().ToUpperInvariant()
    if ($installerSha256 -notmatch '^[0-9A-F]{64}$') {
        throw 'InstallerSha256 は64桁のSHA-256を指定してください。'
    }
    $signerThumbprint = ([string]$config['InstallerSignerThumbprint']).Replace(' ', '').ToUpperInvariant()
    if ($signerThumbprint -notmatch '^[0-9A-F]{40}$') {
        throw 'InstallerSignerThumbprint は40桁の証明書指紋を指定してください。'
    }
    $productVersion = ([string]$config['InstallerProductVersion']).Trim()
    if ($productVersion -notmatch '^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$') {
        throw 'InstallerProductVersion の形式が正しくありません。'
    }
    $requiredRuntime = ([string]$config['RequiredRuntime']).Trim()
    if ($requiredRuntime -notmatch '^[A-Za-z0-9._-]+@[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$') {
        throw 'RequiredRuntime は runtime-name@version の完全指定にしてください。'
    }

    $runtimeProvisioning = ([string]$config['RuntimeProvisioning']).Trim()
    if ($runtimeProvisioning -notin @('OnlinePinned', 'Existing')) {
        throw "RuntimeProvisioning は 'OnlinePinned' または 'Existing' を指定してください。"
    }

    if ($config.Contains('ProjectFirewall') -and $config.Contains('FirewallMode')) {
        throw 'ProjectFirewall と旧形式FirewallModeは同時に指定できません。'
    }
    $projectFirewall = if ($config.Contains('ProjectFirewall')) {
        ([string]$config['ProjectFirewall']).Trim().ToUpperInvariant()
    }
    elseif ($config.Contains('FirewallMode')) {
        $legacy = [string]$config['FirewallMode']
        if ($legacy -eq 'ProjectManaged') { 'ON' }
        elseif ($legacy -eq 'ExternallyManaged') { 'OFF' }
        else { throw '旧形式FirewallModeの値を認識できません。' }
    }
    else { 'OFF' }
    if ($projectFirewall -notin @('ON', 'OFF')) {
        throw "ProjectFirewall は 'ON' または 'OFF' を指定してください。"
    }

    return [pscustomobject]@{
        ConfigPath = $resolvedPath
        ModelSourcePath = [IO.Path]::GetFullPath([string]$config['ModelSourcePath'])
        VisionProjectorPath = if ($config.Contains('VisionProjectorPath') -and
            -not [string]::IsNullOrWhiteSpace([string]$config['VisionProjectorPath'])) {
            [IO.Path]::GetFullPath([string]$config['VisionProjectorPath'])
        } else { $null }
        InstallerPath = $installerPath
        InstallerSha256 = $installerSha256
        InstallerProductVersion = $productVersion
        InstallerSignerThumbprint = $signerThumbprint
        RuntimeProvisioning = $runtimeProvisioning
        RequiredRuntime = $requiredRuntime
        ProjectFirewall = $projectFirewall
    }
}

function Assert-OneClickModelPackage {
    param([Parameter(Mandatory = $true)][object]$Configuration)

    $sourcePath = [string]$Configuration.ModelSourcePath
    $explicitProjectorPath = [string]$Configuration.VisionProjectorPath
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw '配布設定の共有モデルを参照できません。共有フォルダへの接続を確認してください。'
    }

    $primaryFiles = @()
    $projectorFiles = @()
    if (Test-Path -LiteralPath $sourcePath -PathType Container) {
        if (-not [string]::IsNullOrWhiteSpace($explicitProjectorPath)) {
            throw 'ModelSourcePathがフォルダの場合、VisionProjectorPathは指定せず同じフォルダへ配置してください。'
        }
        $ggufFiles = @(Get-ChildItem -LiteralPath $sourcePath -Filter '*.gguf' -File -ErrorAction Stop)
        $projectorFiles = @($ggufFiles | Where-Object { $_.Name -match '(?i)^mmproj(?:[-_.].*)?\.gguf$' })
        $primaryFiles = @($ggufFiles | Where-Object { $_.Name -notmatch '(?i)^mmproj(?:[-_.].*)?\.gguf$' })
    }
    elseif (Test-Path -LiteralPath $sourcePath -PathType Leaf) {
        if ([IO.Path]::GetExtension($sourcePath) -ine '.gguf' -or
            [IO.Path]::GetFileName($sourcePath) -match '(?i)^mmproj(?:[-_.].*)?\.gguf$') {
            throw 'ModelSourcePathはモデル本体のGGUFファイルを指定してください。'
        }
        $primaryFiles = @((Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop))
        if (-not [string]::IsNullOrWhiteSpace($explicitProjectorPath)) {
            if (-not (Test-Path -LiteralPath $explicitProjectorPath -PathType Leaf) -or
                [IO.Path]::GetExtension($explicitProjectorPath) -ine '.gguf' -or
                [IO.Path]::GetFileName($explicitProjectorPath) -notmatch '(?i)^mmproj(?:[-_.].*)?\.gguf$') {
                throw 'VisionProjectorPathは参照可能なmmproj GGUFファイルを指定してください。'
            }
            $projectorFiles = @((Get-Item -LiteralPath $explicitProjectorPath -Force -ErrorAction Stop))
        }
    }
    else {
        throw '共有モデルの種類を判定できません。'
    }

    if ($primaryFiles.Count -ne 1) {
        throw "共有フォルダ直下のモデル本体GGUFは1つだけにしてください。検出数: $($primaryFiles.Count)"
    }
    if ($projectorFiles.Count -gt 1) {
        throw "画像プロジェクターGGUFは最大1つにしてください。検出数: $($projectorFiles.Count)"
    }
    foreach ($item in @($primaryFiles + $projectorFiles)) {
        if ($item.Length -le 0) { throw '空のGGUFファイルは使用できません。' }
    }

    return [pscustomobject]@{
        PrimaryCount = $primaryFiles.Count
        ProjectorCount = $projectorFiles.Count
        Description = if ($projectorFiles.Count -eq 1) { '1 LLM + 1 VISION PROJECTOR' } else { '1 LLM' }
    }
}

function Test-InstallerIsNsis {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = [Math]::Min([long]1048576, $stream.Length)
        $buffer = New-Object byte[] $length
        $read = $stream.Read($buffer, 0, [int]$length)
        $header = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        return $header.IndexOf('Nullsoft', [StringComparison]::OrdinalIgnoreCase) -ge 0
    }
    finally { $stream.Dispose() }
}

function Assert-PinnedInstaller {
    param([Parameter(Mandatory = $true)][object]$Configuration)

    $path = [string]$Configuration.InstallerPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        [IO.Path]::GetExtension($path) -ine '.exe') {
        throw '配布設定で固定したLM Studioインストーラーを参照できません。'
    }
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actualHash -ne [string]$Configuration.InstallerSha256) {
        throw 'LM StudioインストーラーのSHA-256が配布設定と一致しません。'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "LM Studioインストーラーの電子署名が有効ではありません: $($signature.Status)"
    }
    $actualThumbprint = ([string]$signature.SignerCertificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
    if ($actualThumbprint -ne [string]$Configuration.InstallerSignerThumbprint) {
        throw 'LM Studioインストーラーの署名証明書が配布設定と一致しません。'
    }
    $versionInfo = (Get-Item -LiteralPath $path -Force).VersionInfo
    if (-not [string]::Equals([string]$versionInfo.ProductName, 'LM Studio', [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals(
            [string]$versionInfo.ProductVersion,
            [string]$Configuration.InstallerProductVersion,
            [StringComparison]::Ordinal
        )) {
        throw 'LM Studioインストーラーの製品名またはバージョンが配布設定と一致しません。'
    }
    if (-not (Test-InstallerIsNsis -Path $path)) {
        throw '検証済みのNSIS形式ではないため、サイレントインストールを拒否します。'
    }
    return [pscustomobject]@{
        ProductVersion = [string]$versionInfo.ProductVersion
        SignerSubject = [string]$signature.SignerCertificate.Subject
    }
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
    if ($existing.Count -gt 1) {
        throw 'LM Studio.exeが複数の標準場所に存在するため、自動選択を拒否します。'
    }
    if ($existing.Count -eq 0) { return $null }
    return $existing[0]
}

function Assert-InstalledVersion {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedSignerThumbprint
    )

    $resolvedExePath = [IO.Path]::GetFullPath($ExePath)
    $info = (Get-Item -LiteralPath $ExePath -Force).VersionInfo
    $hasWindowsVersionMetadata = -not [string]::IsNullOrWhiteSpace([string]$info.ProductName) -or
        -not [string]::IsNullOrWhiteSpace([string]$info.ProductVersion) -or
        -not [string]::IsNullOrWhiteSpace([string]$info.FileVersion)
    $windowsVersionMatches = [string]::Equals(
        [string]$info.ProductVersion,
        $ExpectedVersion,
        [StringComparison]::Ordinal
    ) -or [string]::Equals(
        [string]$info.FileVersion,
        $ExpectedVersion,
        [StringComparison]::Ordinal
    )
    if ($hasWindowsVersionMetadata -and
        (-not [string]::Equals([string]$info.ProductName, 'LM Studio', [StringComparison]::OrdinalIgnoreCase) -or
            -not $windowsVersionMatches)) {
        throw 'インストール済みLM Studioが配布固定バージョンと一致しません。既存版を確認してから再実行してください。'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedExePath
    $actualThumbprint = if ($null -eq $signature.SignerCertificate) { '' } else {
        ([string]$signature.SignerCertificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
    }
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $actualThumbprint -ne $ExpectedSignerThumbprint.ToUpperInvariant()) {
        throw 'インストール済みLM Studio.exeの電子署名が配布固定値と一致しません。'
    }

    $installRoot = [IO.Path]::GetDirectoryName($resolvedExePath)
    $packagePath = Join-Path $installRoot 'resources\app\package.json'
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
        throw 'インストール済みLM Studioのpackage.jsonがありません。'
    }
    $packageItem = Get-Item -LiteralPath $packagePath -Force -ErrorAction Stop
    if (($packageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'インストール済みLM Studioのpackage.jsonがリンクで置き換えられています。'
    }
    try { $package = Get-Content -LiteralPath $packagePath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'インストール済みLM Studioのpackage.jsonを検証できません。' }
    if ([string](Get-PropertyValue -InputObject $package -Name 'name') -ne 'lm-studio' -or
        -not [string]::Equals(
            [string](Get-PropertyValue -InputObject $package -Name 'productName'),
            'LM Studio',
            [StringComparison]::Ordinal
        ) -or
        -not [string]::Equals(
            [string](Get-PropertyValue -InputObject $package -Name 'version'),
            $ExpectedVersion,
            [StringComparison]::Ordinal
        )) {
        throw 'インストール済みLM Studioのパッケージ情報が配布固定バージョンと一致しません。'
    }

    $registrations = @(Get-ItemProperty `
        -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
        -ErrorAction SilentlyContinue | Where-Object {
            $displayIcon = ([string](Get-PropertyValue -InputObject $_ -Name 'DisplayIcon')).Trim()
            if ($displayIcon.EndsWith(',0', [StringComparison]::Ordinal)) {
                $displayIcon = $displayIcon.Substring(0, $displayIcon.Length - 2)
            }
            $displayIcon = $displayIcon.Trim().Trim('"')
            if ([string]::IsNullOrWhiteSpace($displayIcon)) { return $false }
            try {
                return [string]::Equals(
                    [IO.Path]::GetFullPath($displayIcon),
                    $resolvedExePath,
                    [StringComparison]::OrdinalIgnoreCase
                )
            }
            catch { return $false }
        })
    if ($registrations.Count -ne 1 -or
        -not [string]::Equals([string]$registrations[0].DisplayName, "LM Studio $ExpectedVersion", [StringComparison]::Ordinal) -or
        -not [string]::Equals([string]$registrations[0].DisplayVersion, $ExpectedVersion, [StringComparison]::Ordinal) -or
        -not [string]::Equals([string]$registrations[0].Publisher, 'LM Studio', [StringComparison]::Ordinal)) {
        throw 'インストール済みLM StudioのWindows登録情報が配布固定バージョンと一致しません。'
    }

    return [pscustomobject]@{
        ProductVersion = $ExpectedVersion
        VerificationSource = if ($hasWindowsVersionMetadata) {
            'Executable metadata, package metadata, signature, and uninstall registration'
        } else {
            'Package metadata, signature, and uninstall registration'
        }
    }
}

function Invoke-PinnedInstaller {
    param(
        [Parameter(Mandatory = $true)][object]$Configuration,
        [int]$TimeoutSeconds = 900
    )

    Write-InstallLog -Message '検証済みLM Studioインストーラーをサイレント実行します。'
    $process = Start-Process `
        -FilePath ([string]$Configuration.InstallerPath) `
        -ArgumentList @('/S') `
        -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "LM Studioインストーラーが$TimeoutSeconds秒以内に終了しませんでした。強制終了は行っていません。"
    }
    $process.Refresh()
    if ($process.ExitCode -ne 0) {
        throw "LM Studioインストーラーが失敗しました。終了コード: $($process.ExitCode)"
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    do {
        $exePath = Get-InstalledLMStudioExecutable
        if (-not [string]::IsNullOrWhiteSpace($exePath)) {
            $null = Assert-InstalledVersion `
                -ExePath $exePath `
                -ExpectedVersion ([string]$Configuration.InstallerProductVersion) `
                -ExpectedSignerThumbprint ([string]$Configuration.InstallerSignerThumbprint)
            Write-InstallLog -Level OK -Message '配布固定バージョンのLM Studioをインストールしました。'
            return $exePath
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'インストール完了後にLM Studio.exeを標準場所から確認できません。'
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
        [AllowEmptyString()][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath
    )
    $names = @('LM Studio', 'LM Studio Helper', 'llmster', 'lms', 'llama-server', 'mlx-engine')
    $roots = @([IO.Path]::GetFullPath($HomePath))
    if (-not [string]::IsNullOrWhiteSpace($ExePath)) {
        $roots += [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ExePath))
    }
    $results = New-Object Collections.Generic.List[object]
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue)) {
        $processPath = $null
        try { $processPath = [string]$process.Path } catch { }
        $pathMatch = $false
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            foreach ($root in $roots) {
                $underRoot = Test-PathIsUnderRoot -Path $processPath -Root $root
                if ($underRoot -or
                    (-not [string]::IsNullOrWhiteSpace($ExePath) -and
                        [string]::Equals($processPath, $ExePath, [StringComparison]::OrdinalIgnoreCase))) {
                    $pathMatch = $true
                    break
                }
            }
        }
        if ($names -contains $process.ProcessName -or $pathMatch) {
            $results.Add([pscustomobject]@{
                Name = $process.ProcessName
                Id = $process.Id
                Path = $processPath
                Process = $process
            })
        }
    }
    return $results.ToArray()
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [ValidateRange(1, 600)][int]$TimeoutSeconds = 60,
        [string]$OperationName = 'LM Studio CLI処理'
    )

    foreach ($argument in $ArgumentList) {
        if ($argument -notmatch '^[A-Za-z0-9@._+/-]+$') {
            throw "$OperationName に安全に渡せない引数があります。"
        }
    }
    $captureRoot = Join-Path ([IO.Path]::GetTempPath()) 'WindowsLocalAIHardening'
    if (-not (Test-Path -LiteralPath $captureRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null
    }
    $captureId = [guid]::NewGuid().ToString('N')
    $stdoutPath = Join-Path $captureRoot ("native-$captureId.stdout.txt")
    $stderrPath = Join-Path $captureRoot ("native-$captureId.stderr.txt")
    $process = $null
    try {
        $process = Start-Process `
            -FilePath $FilePath `
            -ArgumentList $ArgumentList `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -PassThru
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            throw "$OperationName が$TimeoutSeconds秒以内に終了しませんでした。強制終了は行っていません。"
        }
        $process.WaitForExit()
        $process.Refresh()
        $stdout = if (Test-Path -LiteralPath $stdoutPath -PathType Leaf) {
            [IO.File]::ReadAllText($stdoutPath)
        } else { '' }
        $stderr = if (Test-Path -LiteralPath $stderrPath -PathType Leaf) {
            [IO.File]::ReadAllText($stderrPath)
        } else { '' }
        $text = @($stdout.TrimEnd(), $stderr.TrimEnd()) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $exitCode = -1
        try { $exitCode = [int]$process.ExitCode } catch { }
        return [pscustomobject]@{
            ExitCode = $exitCode
            Text = ($text -join [Environment]::NewLine)
        }
    }
    finally {
        foreach ($capturePath in @($stdoutPath, $stderrPath)) {
            if (Test-Path -LiteralPath $capturePath -PathType Leaf) {
                try { [IO.File]::Delete($capturePath) } catch { }
            }
        }
    }
}

function Invoke-NativeVisibleWithTimeout {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$OperationName
    )
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -NoNewWindow
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw "$OperationName が$TimeoutSeconds秒以内に終了しませんでした。強制終了は行っていません。"
    }
    $process.WaitForExit()
    $process.Refresh()
    $exitCode = -1
    try { $exitCode = [int]$process.ExitCode } catch { }
    if ($exitCode -ne 0) {
        $exitDescription = if ($exitCode -eq -1) { '取得不能' } else { [string]$exitCode }
        throw "$OperationName に失敗しました。終了コード: $exitDescription"
    }
}

function ConvertFrom-NativeJson {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [ValidateSet('Object', 'Array')][string]$ExpectedRoot
    )

    $openCharacter = if ($ExpectedRoot -eq 'Array') { '[' } else { '{' }
    $closeCharacter = if ($ExpectedRoot -eq 'Array') { ']' } else { '}' }
    $end = $Text.LastIndexOf($closeCharacter)
    $searchIndex = 0
    $lastParseError = $null
    while ($searchIndex -lt $Text.Length) {
        $start = $Text.IndexOf($openCharacter, $searchIndex)
        if ($start -lt 0 -or $end -lt $start) { break }
        $json = $Text.Substring($start, ($end - $start + 1))
        try { return ($json | ConvertFrom-Json) }
        catch {
            $lastParseError = $_.Exception.Message
            $searchIndex = $start + 1
        }
    }
    if ([string]::IsNullOrWhiteSpace($lastParseError)) {
        throw 'CLI出力からJSONを抽出できませんでした。'
    }
    throw "CLIのJSON出力を解析できませんでした: $lastParseError"
}

function Wait-ForBootstrapProfile {
    param(
        [Parameter(Mandatory = $true)][string]$HomePath,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$GuiProcess,
        [int]$TimeoutSeconds = 240
    )
    $lmsPath = Join-Path $HomePath 'bin\lms.exe'
    $settingsPath = Join-Path $HomePath 'settings.json'
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $GuiProcess.Refresh()
        if ($GuiProcess.HasExited) {
            throw '初期化完了前にLM Studioが終了しました。'
        }
        if ((Test-Path -LiteralPath $lmsPath -PathType Leaf) -and
            (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
            try {
                $null = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
                return $lmsPath
            }
            catch { }
        }
        Start-Sleep -Seconds 1
    }
    throw "LM Studioの初回プロファイルが$TimeoutSeconds秒以内に準備完了しませんでした。"
}

function Wait-ForBootstrapGuiReady {
    param(
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$GuiProcess,
        [int]$TimeoutSeconds = 120
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $nextProgressLog = [DateTime]::UtcNow
    while ([DateTime]::UtcNow -lt $deadline) {
        $GuiProcess.Refresh()
        if ($GuiProcess.HasExited) {
            throw 'CLI接続準備完了前にLM Studioが終了しました。'
        }
        $statusResult = Invoke-NativeCapture `
            -FilePath $LmsPath `
            -ArgumentList @('daemon', 'status', '--json') `
            -TimeoutSeconds 10 `
            -OperationName 'LM Studio GUI接続状態の確認'
        if ($statusResult.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($statusResult.Text)) {
            try {
                $status = ConvertFrom-NativeJson -Text $statusResult.Text -ExpectedRoot Object
                if ((Get-PropertyValue -InputObject $status -Name 'status') -eq 'running') {
                    if ((Get-PropertyValue -InputObject $status -Name 'isDaemon') -eq $true) {
                        throw 'GUIではなくllmsterへ接続したため、初回処理を続行できません。'
                    }
                    Write-InstallLog -Level OK -Message 'LM Studio GUIとCLIの接続準備完了を確認しました。'
                    return
                }
            }
            catch {
                if ($_.Exception.Message -eq 'GUIではなくllmsterへ接続したため、初回処理を続行できません。') {
                    throw
                }
            }
        }
        if ([DateTime]::UtcNow -ge $nextProgressLog) {
            Write-InstallLog -Message 'LM Studio GUI内部APIの準備完了を待っています。'
            $nextProgressLog = [DateTime]::UtcNow.AddSeconds(10)
        }
        Start-Sleep -Seconds 1
    }
    throw "LM Studio GUIが$TimeoutSeconds秒以内にCLI接続可能になりませんでした。"
}

function Start-BootstrapGui {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath
    )
    $running = @(Get-RunningLMStudioProcesses -ExePath $ExePath -HomePath $HomePath)
    if ($running.Count -gt 0) {
        throw 'ワンクリック処理開始前からLM Studio関連プロセスが動作しています。完全に終了して再実行してください。'
    }
    Write-InstallLog -Message 'LM Studioを初回プロファイル作成のため自動起動します。画面操作は不要です。'
    $script:StartedBootstrapProcess = Start-Process -FilePath $ExePath -PassThru
    return $script:StartedBootstrapProcess
}

function Stop-BootstrapGuiGracefully {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath,
        [int]$TimeoutSeconds = 45
    )
    $lmsPath = Join-Path $HomePath 'bin\lms.exe'
    if (Test-Path -LiteralPath $lmsPath -PathType Leaf) {
        try {
            $null = Invoke-NativeCapture `
                -FilePath $lmsPath `
                -ArgumentList @('unload', '--all') `
                -TimeoutSeconds 15 `
                -OperationName 'モデルのアンロード'
        } catch { }
        try {
            $null = Invoke-NativeCapture `
                -FilePath $lmsPath `
                -ArgumentList @('server', 'stop') `
                -TimeoutSeconds 15 `
                -OperationName 'ローカルAPIサーバーの停止'
        } catch { }
    }

    $processes = @(Get-RunningLMStudioProcesses -ExePath $ExePath -HomePath $HomePath)
    foreach ($entry in @($processes | Sort-Object { if ($_.Name -eq 'LM Studio') { 0 } else { 1 } })) {
        try {
            $entry.Process.Refresh()
            if (-not $entry.Process.HasExited -and $entry.Process.MainWindowHandle -ne [IntPtr]::Zero) {
                $null = $entry.Process.CloseMainWindow()
            }
        }
        catch { }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $remaining = @(Get-RunningLMStudioProcesses -ExePath $ExePath -HomePath $HomePath)
        if ($remaining.Count -eq 0) {
            $script:StartedBootstrapProcess = $null
            Write-InstallLog -Level OK -Message 'LM Studioの初期化プロセスを通常終了しました。'
            return
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    $summary = ($remaining | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
    throw "LM Studioを通常終了できませんでした。強制終了は行っていません: $summary"
}

function Test-RequiredRuntimeInstalled {
    param(
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][string]$RequiredRuntime
    )
    $result = Invoke-NativeCapture `
        -FilePath $LmsPath `
        -ArgumentList @('runtime', 'ls') `
        -TimeoutSeconds 60 `
        -OperationName 'Runtime一覧の確認'
    return $result.ExitCode -eq 0 -and
        (Test-RuntimeListContainsExact -ListText $result.Text -RequiredRuntime $RequiredRuntime)
}

function Get-RuntimeIdentifiersFromListText {
    param([AllowEmptyString()][string]$ListText)

    if ([string]::IsNullOrWhiteSpace($ListText)) { return @() }
    $pattern = '(?m)^[\t ]*([A-Za-z0-9._-]+@[A-Za-z0-9][A-Za-z0-9.+_-]{0,63})(?:[\t ]+|$)'
    return @([regex]::Matches($ListText, $pattern) | ForEach-Object { $_.Groups[1].Value })
}

function Test-RuntimeListContainsExact {
    param(
        [AllowEmptyString()][string]$ListText,
        [Parameter(Mandatory = $true)][string]$RequiredRuntime
    )

    return @(
        Get-RuntimeIdentifiersFromListText -ListText $ListText |
            Where-Object { [string]::Equals($_, $RequiredRuntime, [StringComparison]::OrdinalIgnoreCase) }
    ).Count -eq 1
}

function Get-PinnedRuntimeGetArguments {
    param([Parameter(Mandatory = $true)][string]$RequiredRuntime)
    return @('runtime', 'get', $RequiredRuntime, '-y')
}

function Install-PinnedRuntimeOnline {
    param(
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][string]$RequiredRuntime
    )
    Write-InstallLog -Level WARN -Message '固定Runtimeの取得に必要なプロビジョニング通信窓を開始します。'
    Invoke-NativeVisibleWithTimeout `
        -FilePath $LmsPath `
        -ArgumentList (Get-PinnedRuntimeGetArguments -RequiredRuntime $RequiredRuntime) `
        -TimeoutSeconds 1800 `
        -OperationName '固定Runtimeのダウンロード'
    Invoke-NativeVisibleWithTimeout `
        -FilePath $LmsPath `
        -ArgumentList @('runtime', 'select', $RequiredRuntime) `
        -TimeoutSeconds 180 `
        -OperationName '固定Runtimeの選択'
    if (-not (Test-RequiredRuntimeInstalled -LmsPath $LmsPath -RequiredRuntime $RequiredRuntime)) {
        throw '固定Runtimeの取得後検証に失敗しました。'
    }
    Write-InstallLog -Level OK -Message '固定Runtimeをダウンロード・選択・検証しました。'
}

function Assert-FirewallEnvironment {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    if (@($profiles | Where-Object { $_.Enabled -ne $true }).Count -gt 0) {
        throw 'Windows Firewallが無効なプロファイルがあるため、初回起動を開始できません。'
    }
    if (@($profiles | Where-Object { $_.AllowLocalFirewallRules -eq $false }).Count -gt 0) {
        throw 'ローカルFirewall規則が組織ポリシーで無効です。ProjectFirewall OFFを配布管理者が検討してください。'
    }
}

function Test-StringSetEquals {
    param(
        [AllowNull()][object[]]$Actual,
        [AllowNull()][object[]]$Expected
    )

    $actualValues = @($Actual | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    $expectedValues = @($Expected | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if ($actualValues.Count -ne $expectedValues.Count) { return $false }
    foreach ($value in $expectedValues) {
        if ($actualValues -notcontains $value) { return $false }
    }
    return $true
}

function Test-BootstrapFirewallRules {
    param([Parameter(Mandatory = $true)][string]$ProgramPath)

    Assert-FirewallEnvironment
    $fullProgramPath = [IO.Path]::GetFullPath($ProgramPath)
    $pathHash = (Get-StringSha256 -Value $fullProgramPath).Substring(0, 16)
    $verifiedCount = 0
    foreach ($direction in @('Outbound', 'Inbound')) {
        $name = 'LMStudioBootstrap-{0}-{1}' -f $direction, $pathHash
        $rules = @(Get-NetFirewallRule -Name $name -ErrorAction Stop)
        if ($rules.Count -ne 1) {
            throw "初回起動Firewall規則が一意ではありません: $name / $($rules.Count) 件"
        }
        $rule = $rules[0]
        if ([string]$rule.Enabled -ne 'True' -or
            [string]$rule.Action -ne 'Block' -or
            [string]$rule.Direction -ne $direction -or
            [string]$rule.Group -ne $script:BootstrapFirewallGroup -or
            [string]$rule.Profile -ne 'Any') {
            throw "初回起動Firewall規則の基本条件が一致しません: $name"
        }

        $applicationFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
        if ($applicationFilters.Count -ne 1 -or
            -not [string]::Equals(
                [IO.Path]::GetFullPath([string]$applicationFilters[0].Program),
                $fullProgramPath,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw "初回起動Firewall規則の対象プログラムが一致しません: $name"
        }

        $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
        if ($addressFilters.Count -ne 1 -or
            -not (Test-StringSetEquals -Actual @($addressFilters[0].LocalAddress) -Expected @('Any')) -or
            -not (Test-StringSetEquals -Actual @($addressFilters[0].RemoteAddress) -Expected $script:NonLoopbackRemoteAddresses)) {
            throw "初回起動Firewall規則のアドレス範囲が一致しません: $name"
        }

        $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
        if ($portFilters.Count -ne 1 -or
            [string]$portFilters[0].Protocol -ne 'Any' -or
            -not (Test-StringSetEquals -Actual @($portFilters[0].LocalPort) -Expected @('Any')) -or
            -not (Test-StringSetEquals -Actual @($portFilters[0].RemotePort) -Expected @('Any'))) {
            throw "初回起動Firewall規則のプロトコルまたはポートが一致しません: $name"
        }

        $interfaceFilters = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
        if ($interfaceFilters.Count -ne 1 -or [string]$interfaceFilters[0].InterfaceType -ne 'Any') {
            throw "初回起動Firewall規則のインターフェース範囲が一致しません: $name"
        }
        $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
        if ($serviceFilters.Count -ne 1 -or [string]$serviceFilters[0].Service -ne 'Any') {
            throw "初回起動Firewall規則のサービス範囲が一致しません: $name"
        }
        $verifiedCount++
    }

    $groupRules = @(Get-NetFirewallRule -Group $script:BootstrapFirewallGroup -ErrorAction Stop)
    if ($groupRules.Count -ne $verifiedCount) {
        throw "初回起動Firewallグループに想定外の規則があります: $($groupRules.Count) 件"
    }
    return $verifiedCount
}

function Set-BootstrapFirewallRules {
    param([Parameter(Mandatory = $true)][string]$ProgramPath)

    if (-not (Test-IsAdministrator)) { throw '初回起動Firewall設定には管理者権限が必要です。' }
    if (-not (Test-Path -LiteralPath $ProgramPath -PathType Leaf) -or
        [IO.Path]::GetFileName($ProgramPath) -ine 'LM Studio.exe') {
        throw '初回起動Firewall対象が検証済みのLM Studio.exeではありません。'
    }
    Assert-FirewallEnvironment
    $pathHash = (Get-StringSha256 -Value ([IO.Path]::GetFullPath($ProgramPath))).Substring(0, 16)
    foreach ($direction in @('Outbound', 'Inbound')) {
        $name = 'LMStudioBootstrap-{0}-{1}' -f $direction, $pathHash
        $existing = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
        if (@($existing | Where-Object { [string]$_.Group -ne $script:BootstrapFirewallGroup }).Count -gt 0) {
            throw "管理外の同名Firewall規則があります: $name"
        }
        if ($existing.Count -eq 0) {
            New-NetFirewallRule `
                -Name $name `
                -DisplayName "LM Studio bootstrap $direction" `
                -Description 'Temporary non-loopback block for one-click LM Studio initialization.' `
                -Group $script:BootstrapFirewallGroup `
                -Direction $direction `
                -Action Block `
                -Enabled True `
                -Profile Any `
                -Program $ProgramPath `
                -Protocol Any `
                -LocalPort Any `
                -RemotePort Any `
                -RemoteAddress $script:NonLoopbackRemoteAddresses `
                -ErrorAction Stop | Out-Null
        }
        else {
            Set-NetFirewallRule `
                -Name $name `
                -Enabled True `
                -Profile Any `
                -Direction $direction `
                -Action Block `
                -Program $ProgramPath `
                -Protocol Any `
                -LocalPort Any `
                -RemotePort Any `
                -RemoteAddress $script:NonLoopbackRemoteAddresses `
                -ErrorAction Stop | Out-Null
        }
    }
    $verifiedCount = Test-BootstrapFirewallRules -ProgramPath $ProgramPath
    if ($verifiedCount -ne 2) { throw "初回起動Firewall規則数が2ではありません: $verifiedCount" }
    return $verifiedCount
}

function Remove-BootstrapFirewallRules {
    if (-not (Test-IsAdministrator)) { throw '初回起動Firewall解除には管理者権限が必要です。' }
    $rules = @(Get-NetFirewallRule -Group $script:BootstrapFirewallGroup -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        if ([string]$rule.Group -ne $script:BootstrapFirewallGroup) {
            throw '管理外のFirewall規則は削除しません。'
        }
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
    }
    if (@(Get-NetFirewallRule -Group $script:BootstrapFirewallGroup -ErrorAction SilentlyContinue).Count -ne 0) {
        throw '初回起動Firewall規則を完全に削除できませんでした。'
    }
    return $rules.Count
}

function Write-FirewallRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 10
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, ($json + [Environment]::NewLine), $encoding)
    $null = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
}

function Invoke-ElevatedBootstrapFirewall {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Enable', 'Remove')][string]$Action,
        [Parameter(Mandatory = $true)][string]$ProgramPath
    )
    $requestRoot = Split-Path -Parent $script:LogPath
    $requestPath = Join-Path $requestRoot ('bootstrap-firewall-{0}.json' -f [guid]::NewGuid().ToString('N'))
    $request = [ordered]@{
        SchemaVersion = 1
        CreatedAtUtc = [DateTime]::UtcNow.ToString('o')
        Action = $Action
        ProgramPath = [IO.Path]::GetFullPath($ProgramPath)
        RuleGroup = $script:BootstrapFirewallGroup
    }
    Write-FirewallRequest -Path $requestPath -Value $request
    $hash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    try {
        if (Test-IsAdministrator) {
            if ($Action -eq 'Enable') { return Set-BootstrapFirewallRules -ProgramPath $ProgramPath }
            return Remove-BootstrapFirewallRules
        }
        foreach ($value in @($PSCommandPath, $requestPath, $script:LogPath)) {
            if ([string]::IsNullOrWhiteSpace($value) -or $value.Contains('"')) {
                throw '管理者処理へ安全に渡せないパスがあります。'
            }
        }
        $powershellExe = Join-Path $PSHOME 'powershell.exe'
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-BootstrapFirewallOnly',
            '-FirewallRequestPath', ('"{0}"' -f $requestPath),
            '-FirewallRequestSha256', $hash,
            '-SharedLogPath', ('"{0}"' -f $script:LogPath)
        )
        $process = Start-Process `
            -FilePath $powershellExe `
            -ArgumentList $arguments `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru
        if ($process.ExitCode -ne 0) {
            throw "初回起動Firewallの$Action処理に失敗しました。終了コード: $($process.ExitCode)"
        }
        return 0
    }
    finally {
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) { [IO.File]::Delete($requestPath) }
    }
}

function Invoke-BootstrapFirewallOnlyMode {
    if (-not $BootstrapFirewallOnly) { return }
    try {
        if (-not (Test-IsAdministrator)) { throw '管理者権限がありません。' }
        Initialize-InstallLogging -ExistingLogPath $SharedLogPath
        if ([string]::IsNullOrWhiteSpace($FirewallRequestPath) -or
            $FirewallRequestSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
            throw 'Firewall要求が不足または不正です。'
        }
        $requestPath = [IO.Path]::GetFullPath($FirewallRequestPath)
        $actualHash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $FirewallRequestSha256.ToLowerInvariant()) {
            throw 'Firewall要求のSHA-256が一致しません。'
        }
        $request = Get-Content -LiteralPath $requestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ((Get-PropertyValue -InputObject $request -Name 'SchemaVersion') -ne 1 -or
            (Get-PropertyValue -InputObject $request -Name 'RuleGroup') -ne $script:BootstrapFirewallGroup) {
            throw 'Firewall要求の形式を認識できません。'
        }
        $createdAt = [DateTime]::Parse(
            [string](Get-PropertyValue -InputObject $request -Name 'CreatedAtUtc'),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        $age = [DateTime]::UtcNow.Subtract($createdAt.ToUniversalTime()).TotalMinutes
        if ($age -lt -1 -or $age -gt 15) { throw 'Firewall要求の有効期限が切れています。' }
        $action = [string](Get-PropertyValue -InputObject $request -Name 'Action')
        $programPath = [string](Get-PropertyValue -InputObject $request -Name 'ProgramPath')
        if ($action -eq 'Enable') { $count = Set-BootstrapFirewallRules -ProgramPath $programPath }
        elseif ($action -eq 'Remove') { $count = Remove-BootstrapFirewallRules }
        else { throw 'Firewall要求の操作を認識できません。' }
        Write-InstallLog -Level OK -Message "初回起動Firewall $action を完了しました: $count 件"
        exit 0
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
            Write-InstallLog -Level ERROR -Message $_.Exception.Message
        }
        else { Write-Error $_.Exception.Message }
        exit 1
    }
}

function Enter-InstallMutex {
    $identity = (Get-StringSha256 -Value ([IO.Path]::GetFullPath($env:USERPROFILE))).Substring(0, 24)
    $createdNew = $false
    $mutex = New-Object Threading.Mutex($true, ('Local\WindowsLocalAIHardening.Install.' + $identity), ([ref]$createdNew))
    if (-not $createdNew) {
        $mutex.Dispose()
        throw '別のワンクリックインストールが実行中です。二重起動しないでください。'
    }
    $script:InstallMutex = $mutex
    $script:InstallMutexOwned = $true
}

function Exit-InstallMutex {
    if ($script:InstallMutexOwned -and $null -ne $script:InstallMutex) {
        try { $script:InstallMutex.ReleaseMutex() } catch { }
    }
    if ($null -ne $script:InstallMutex) { $script:InstallMutex.Dispose() }
    $script:InstallMutex = $null
    $script:InstallMutexOwned = $false
}

function Invoke-LocalPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$OperationName
    )
    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "$OperationName のスクリプトがありません。"
    }
    if ($ScriptPath.Contains('"')) {
        throw "$OperationName に安全に渡せないスクリプトパスがあります。"
    }
    $powershellExe = Join-Path $PSHOME 'powershell.exe'
    $argumentList = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $ScriptPath)
    ) + $Arguments
    $process = Start-Process -FilePath $powershellExe -ArgumentList $argumentList -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$OperationName に失敗しました。終了コード: $($process.ExitCode)"
    }
}

function Copy-InstallLogIntoProfile {
    param([Parameter(Mandatory = $true)][string]$HomePath)

    if ([string]::IsNullOrWhiteSpace($script:LogPath) -or
        -not (Test-Path -LiteralPath $script:LogPath -PathType Leaf)) { return $null }
    $logRoot = Join-Path $HomePath 'secure-setup\logs'
    if (-not (Test-Path -LiteralPath $logRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    }
    $destination = Join-Path $logRoot ([IO.Path]::GetFileName($script:LogPath))
    Copy-Item -LiteralPath $script:LogPath -Destination $destination -Force
    return $destination
}

function Invoke-OneClickInstallMain {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'このスクリプトはWindows専用です。'
    }
    if (Test-IsAdministrator) {
        throw '通常ユーザーとして実行してください。必要な管理者処理だけ別プロセスで要求します。'
    }
    Initialize-InstallLogging
    Write-InstallLog -Message 'LM Studioワンクリック導入を開始します。'
    Enter-InstallMutex

    $configPath = Resolve-DeploymentConfigPath -RequestedPath $DeploymentConfigPath
    $configuration = Read-OneClickDeploymentConfig -ConfigPath $configPath
    $script:ConfigurationForCleanup = $configuration
    $modelPackage = Assert-OneClickModelPackage -Configuration $configuration
    Write-InstallLog -Level OK -Message '配布設定から共有フォルダ上の承認モデル構成を確認しました（パスは記録しません）。'
    $null = Assert-PinnedInstaller -Configuration $configuration
    Write-InstallLog -Level OK -Message 'LM Studioインストーラーのハッシュ、署名、形式、バージョンを検証しました。'

    $homePath = [IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.lmstudio'))
    $script:HomePathForCleanup = $homePath
    $exePath = Get-InstalledLMStudioExecutable
    if (-not [string]::IsNullOrWhiteSpace($exePath)) {
        $null = Assert-InstalledVersion `
            -ExePath $exePath `
            -ExpectedVersion ([string]$configuration.InstallerProductVersion) `
            -ExpectedSignerThumbprint ([string]$configuration.InstallerSignerThumbprint)
    }
    $runningBefore = @(Get-RunningLMStudioProcesses -ExePath ([string]$exePath) -HomePath $homePath)

    if ($PreviewOnly) {
        Write-Host '============================================================'
        Write-Host ' LM Studio one-click deployment preview'
        Write-Host '============================================================'
        Write-Host (' Installer       : VERIFIED / {0}' -f $configuration.InstallerProductVersion)
        Write-Host (' Installed app   : {0}' -f $(if ($null -eq $exePath) { 'ABSENT / WILL INSTALL' } else { 'PINNED VERSION PRESENT' }))
        Write-Host (' Running process : {0}' -f $runningBefore.Count)
        Write-Host (' Runtime         : {0} / {1}' -f $configuration.RuntimeProvisioning, $configuration.RequiredRuntime)
        Write-Host (' Project Firewall: {0}' -f $configuration.ProjectFirewall)
        Write-Host (' Model           : {0} / PRIVATE PATH NOT DISPLAYED' -f $modelPackage.Description)
        Write-Host '------------------------------------------------------------'
        Write-Host ' Preview only. Nothing was installed, launched, downloaded, or changed.'
        $script:PreviewCompleted = $true
        return
    }
    if ($runningBefore.Count -gt 0) {
        throw 'LM Studio関連プロセスを完全に終了してから再実行してください。'
    }

    if ([string]::IsNullOrWhiteSpace($exePath)) {
        $exePath = Invoke-PinnedInstaller -Configuration $configuration
    }
    else {
        Write-InstallLog -Level OK -Message '配布固定バージョンのLM Studioはインストール済みです。'
    }
    $script:ExePathForCleanup = $exePath

    if ($configuration.ProjectFirewall -eq 'ON') {
        $null = Invoke-ElevatedBootstrapFirewall -Action Enable -ProgramPath $exePath
        $script:BootstrapFirewallEnabled = $true
        Write-InstallLog -Level OK -Message '初回起動前にLM Studio GUIの非ループバック通信を遮断しました。'
    }
    else {
        Write-InstallLog -Level WARN -Message 'ProjectFirewall OFF: 初回導入中の通信保護も会社・組織側へ委任します。'
    }

    $lmsPath = Join-Path $homePath 'bin\lms.exe'
    $settingsPath = Join-Path $homePath 'settings.json'
    $profileReady = (Test-Path -LiteralPath $lmsPath -PathType Leaf) -and
        (Test-Path -LiteralPath $settingsPath -PathType Leaf)
    $guiProcess = Start-BootstrapGui -ExePath $exePath -HomePath $homePath
    if (-not $profileReady) {
        $lmsPath = Wait-ForBootstrapProfile -HomePath $homePath -GuiProcess $guiProcess
        Write-InstallLog -Level OK -Message 'LM StudioのユーザープロファイルとCLIを自動初期化しました。'
    }
    else {
        Write-InstallLog -Level OK -Message 'LM StudioのユーザープロファイルとCLIは初期化済みです。'
    }
    Wait-ForBootstrapGuiReady -LmsPath $lmsPath -GuiProcess $guiProcess

    $runtimeInstalled = Test-RequiredRuntimeInstalled `
        -LmsPath $lmsPath `
        -RequiredRuntime ([string]$configuration.RequiredRuntime)
    if (-not $runtimeInstalled) {
        if ($configuration.RuntimeProvisioning -eq 'Existing') {
            throw '配布固定Runtimeがありません。RuntimeProvisioning Existingではダウンロードしません。'
        }
        if ($configuration.ProjectFirewall -eq 'ON' -and $script:BootstrapFirewallEnabled) {
            $null = Invoke-ElevatedBootstrapFirewall -Action Remove -ProgramPath $exePath
            $script:BootstrapFirewallEnabled = $false
            Write-InstallLog -Level WARN -Message '固定Runtime取得の間だけ、初回起動Firewall規則を解除しました。'
        }
        Install-PinnedRuntimeOnline `
            -LmsPath $lmsPath `
            -RequiredRuntime ([string]$configuration.RequiredRuntime)
    }
    else {
        Write-InstallLog -Level OK -Message '配布固定Runtimeはインストール済みです。'
    }

    Stop-BootstrapGuiGracefully -ExePath $exePath -HomePath $homePath
    if ($configuration.ProjectFirewall -eq 'ON' -and -not $script:BootstrapFirewallEnabled) {
        $null = Invoke-ElevatedBootstrapFirewall -Action Enable -ProgramPath $exePath
        $script:BootstrapFirewallEnabled = $true
        Write-InstallLog -Level OK -Message '固定Runtime取得後、初回起動Firewall規則を再適用しました。'
    }

    $setupScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Setup-LMStudio.ps1'))
    $startScript = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'Start-LMStudio-Secure.ps1'))
    Invoke-LocalPowerShellScript `
        -ScriptPath $setupScript `
        -Arguments @(
            '-DeploymentConfigPath', ('"{0}"' -f $configuration.ConfigPath),
            '-RequiredRuntime', ([string]$configuration.RequiredRuntime),
            '-LmStudioExePath', ('"{0}"' -f $exePath)
        ) `
        -OperationName '安全な初期セットアップ'

    if ($script:BootstrapFirewallEnabled) {
        $null = Invoke-ElevatedBootstrapFirewall -Action Remove -ProgramPath $exePath
        $script:BootstrapFirewallEnabled = $false
        Write-InstallLog -Level OK -Message '完全なFirewall規則への移行後、初回起動用規則を削除しました。'
    }

    Invoke-LocalPowerShellScript `
        -ScriptPath $startScript `
        -Arguments @('-LmStudioExePath', ('"{0}"' -f $exePath)) `
        -OperationName '初回安全起動'

    Write-InstallLog -Level OK -Message 'LM Studioのインストール、初期化、Setup、承認モデルの安全起動が完了しました。'
    $savedLogPath = Copy-InstallLogIntoProfile -HomePath $homePath
    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' LM Studio one-click deployment completed'
    Write-Host (' Version   : {0}' -f $configuration.InstallerProductVersion)
    Write-Host (' Runtime   : {0}' -f $configuration.RequiredRuntime)
    Write-Host (' Firewall  : {0}' -f $configuration.ProjectFirewall)
    Write-Host ' Model     : APPROVED MODEL LOADED'
    if (-not [string]::IsNullOrWhiteSpace($savedLogPath)) {
        Write-Host (' Log       : {0}' -f $savedLogPath)
    }
    Write-Host '============================================================'
    if (-not [string]::IsNullOrWhiteSpace($savedLogPath) -and
        -not [string]::Equals($savedLogPath, $script:LogPath, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $script:LogPath -PathType Leaf)) {
        [IO.File]::Delete($script:LogPath)
        $script:LogPath = $savedLogPath
    }
}

Invoke-BootstrapFirewallOnlyMode

$exitCode = 0
try {
    Invoke-OneClickInstallMain
}
catch {
    $exitCode = 1
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Write-InstallLog -Level ERROR -Message $_.Exception.Message
        Write-InstallLog -Level ERROR -Message 'ワンクリック導入は完了していません。同じファイルを二重起動せず、原因解消後に再実行してください。'
    }
    else { Write-Error $_.Exception.Message }
    if (-not [string]::IsNullOrWhiteSpace($script:ExePathForCleanup) -and
        -not [string]::IsNullOrWhiteSpace($script:HomePathForCleanup)) {
        try {
            Stop-BootstrapGuiGracefully `
                -ExePath $script:ExePathForCleanup `
                -HomePath $script:HomePathForCleanup `
                -TimeoutSeconds 15
        }
        catch {
            Write-InstallLog -Level ERROR -Message '失敗後にLM Studioを通常終了できませんでした。手動で終了してください。'
        }
    }
    if ($null -ne $script:ConfigurationForCleanup -and
        $script:ConfigurationForCleanup.ProjectFirewall -eq 'ON' -and
        -not $script:BootstrapFirewallEnabled -and
        -not [string]::IsNullOrWhiteSpace($script:ExePathForCleanup) -and
        (Test-Path -LiteralPath $script:ExePathForCleanup -PathType Leaf)) {
        try {
            $null = Invoke-ElevatedBootstrapFirewall `
                -Action Enable `
                -ProgramPath $script:ExePathForCleanup
            $script:BootstrapFirewallEnabled = $true
            Write-InstallLog -Level WARN -Message '失敗後の安全処理として初回起動Firewall規則を再適用しました。'
        }
        catch {
            Write-InstallLog -Level ERROR -Message '失敗後に初回起動Firewall規則を再適用できませんでした。会社・組織側の通信保護を確認してください。'
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($script:HomePathForCleanup) -and
        (Test-Path -LiteralPath $script:HomePathForCleanup -PathType Container)) {
        try { $null = Copy-InstallLogIntoProfile -HomePath $script:HomePathForCleanup } catch { }
    }
}
finally {
    Exit-InstallMutex
    if ($script:PreviewCompleted -and
        -not [string]::IsNullOrWhiteSpace($script:LogPath) -and
        (Test-Path -LiteralPath $script:LogPath -PathType Leaf)) {
        $previewLogRoot = [IO.Path]::GetFullPath(
            (Join-Path ([IO.Path]::GetTempPath()) 'WindowsLocalAIHardening')
        ).TrimEnd('\') + '\'
        $previewLogPath = [IO.Path]::GetFullPath($script:LogPath)
        if ($previewLogPath.StartsWith($previewLogRoot, [StringComparison]::OrdinalIgnoreCase) -and
            [IO.Path]::GetFileName($previewLogPath).StartsWith('Install-LMStudio-', [StringComparison]::Ordinal)) {
            [IO.File]::Delete($previewLogPath)
        }
    }
}
exit $exitCode
