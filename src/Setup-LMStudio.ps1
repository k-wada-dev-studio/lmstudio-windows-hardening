#Requires -Version 5.1

<#
.SYNOPSIS
    LM Studio をローカル利用向けに初期セットアップします。

.DESCRIPTION
    次の処理を慎重な順序で行います。

    1. 配布設定で指定した共有フォルダの1つのGGUFを確認
    2. LM Studio、lms CLI、settings.json の存在と JSON 構文を確認
    3. 配布設定の ProjectFirewall が ON の場合、Windows Firewall で LM Studio 関連実行ファイルの通信を
       ループバック (127.0.0.0/8 と ::1) 以外について送受信とも遮断。
       OFF の場合は本プロジェクトの規則を使用せず、会社・組織側へ委任する
    4. lms import のシンボリックリンク方式で共有モデルを自動登録
    5. LM Studio が停止したことを再確認
    6. settings.json と mcp.json をバックアップ後、対象項目だけを更新
    7. 初回安全起動でモデル・Runtime検証を確定する保留状態を保存

    モデルや Runtime のダウンロード、モデルファイルの移動・コピー、アプリの起動、
    モデルのロードは行いません。
    LM Studio の settings.json は公開された管理 API ではないため、設定変更は
    補助的な防御として限定的に行います。通信境界は ProjectFirewall = 'ON' では Windows Firewall、
    'OFF' では配布責任者が確認する会社・組織側の保護です。

    公式資料（2026-08-19 確認）:
      https://lmstudio.ai/docs/app/offline
      https://lmstudio.ai/docs/cli
      https://lmstudio.ai/docs/cli/local-models/ls
      https://lmstudio.ai/docs/cli/local-models/import
      https://lmstudio.ai/docs/cli/runtime/runtime
      https://lmstudio.ai/docs/cli/local-models/load
      https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule

.PARAMETER AllowedModel
    自動登録後に期待する model_key を追加確認したい場合だけ指定します。通常は不要です。
    省略時は、配布設定の共有モデルを登録した結果から自動取得します。

.PARAMETER RequiredRuntime
    必要な Runtime 名。省略時はモデル形式（例: GGUF）に対応する Runtime が
    1つ以上インストールされていることを初回安全起動で確認します。

.PARAMETER LmStudioExePath
    LM Studio.exe のパス。省略時は標準的なインストール先を探索します。

.PARAMETER LmStudioHome
    LM Studio のユーザーデータディレクトリ。既定値は %USERPROFILE%\.lmstudio です。

.PARAMETER DeploymentConfigPath
    配布管理者が用意する deployment.local.psd1。省略時はリポジトリ内の
    config\deployment.local.psd1 を使用します。利用者が LM Studio の設定を
    操作する必要はありません。ProjectFirewall の ON/OFF もこの非公開設定で指定します。

.PARAMETER SkipFirewall
    Windows Firewall の設定をコマンドから強制的に省略します。状態ファイルの Complete は
    false になります。会社側へ委任する場合はこの指定ではなく、配布設定の
    ProjectFirewall = 'OFF' を使用します。

.PARAMETER SkipLoadEstimate
    初回および通常の安全起動で `lms load --estimate-only` による
    互換性・メモリ見積もりを省略します。

.EXAMPLE
    .\Setup-LMStudio.ps1

    配布設定の共有GGUFを登録し、初回安全起動用の状態を準備します。

.EXAMPLE
    .\Setup-LMStudio.ps1 -AllowedModel 'publisher/model' `
        -RequiredRuntime 'llama.cpp-win-x86_64-nvidia-cuda12-avx2@2.28.2'

.NOTES
    前提:
      - LM Studio を少なくとも一度起動済みであること
      - 配布管理者が deployment.local.psd1 を準備済みであること
      - 共有モデルへアクセスでき、対応 Runtime を事前配置済みであること
      - 実行前に LM Studio と llmster を完全に終了していること

    管理者権限はモデルリンク登録と、本プロジェクトのFirewall規則をON/OFFする短い子プロセスだけに要求します。
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$AllowedModel,

    [ValidateNotNullOrEmpty()]
    [string]$RequiredRuntime,

    [ValidateNotNullOrEmpty()]
    [string]$LmStudioExePath,

    [ValidateNotNullOrEmpty()]
    [string]$LmStudioHome = (Join-Path $env:USERPROFILE '.lmstudio'),

    [ValidateNotNullOrEmpty()]
    [string]$DeploymentConfigPath,

    [switch]$SkipFirewall,
    [switch]$SkipLoadEstimate,

    # 以下は昇格した子プロセスだけが使う内部パラメーターです。
    [switch]$FirewallOnly,
    [string]$FirewallRequestPath,
    [string]$FirewallRequestSha256,
    [string]$SharedLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SetupRoot = $null
$script:LogPath = $null
$script:CreatedManagedModelLink = $null
$script:SetupMutex = $null
$script:SetupMutexOwned = $false
$script:FirewallGroup = 'LM Studio Secure Local-Only'
$script:NonLoopbackRemoteAddresses = @(
    '0.0.0.0-126.255.255.255',
    '128.0.0.0-255.255.255.255',
    '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
)

function Write-SetupLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message

    switch ($Level) {
        'OK'    { Write-Host $line -ForegroundColor Green }
        'WARN'  { Write-Warning $line }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }

    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        try {
            Add-Content -LiteralPath $script:LogPath -Value $line -Encoding UTF8
        }
        catch {
            Write-Warning ('ログへの追記に失敗しました: {0}' -f $_.Exception.Message)
        }
    }
}

function Initialize-Logging {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [string]$ExistingLogPath
    )

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($ExistingLogPath)) {
        $logDirectory = Join-Path $Root 'logs'
        if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
            New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        }

        $script:LogPath = Join-Path $logDirectory (
            'Setup-LMStudio-{0}-{1}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $PID
        )
        [System.IO.File]::WriteAllText(
            $script:LogPath,
            '',
            (New-Object System.Text.UTF8Encoding($false))
        )
    }
    else {
        $script:LogPath = [System.IO.Path]::GetFullPath($ExistingLogPath)
    }
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
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-ModelPathIdentitySha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'モデルのパス識別子が空です。'
    }

    # lms may represent the same model path with either slash style. Keep the
    # value relative when lms returns it relative, and normalize only the parts
    # that are not significant for Windows path identity. The normalized value
    # is used only in memory and is never persisted or logged.
    $normalized = $Path.Trim().Replace('/', '\').TrimEnd('\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw 'モデルのパス識別子を正規化できません。'
    }
    return Get-StringSha256 -Value $normalized
}

function Get-AbsolutePathIdentitySha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw '絶対パス識別子が空です。'
    }
    $normalized = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/').ToUpperInvariant()
    return Get-StringSha256 -Value $normalized
}

function Read-DeploymentModelConfig {
    param([string]$ConfigPath)

    $resolvedConfigPath = if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\config\deployment.local.psd1'))
    }
    else {
        [IO.Path]::GetFullPath($ConfigPath)
    }

    if (-not (Test-Path -LiteralPath $resolvedConfigPath -PathType Leaf)) {
        throw ('配布設定がありません。配布管理者が config\deployment.local.psd1 を準備してください。' +
            '利用者が LM Studio の設定を変更する必要はありません。')
    }

    try {
        $config = Import-PowerShellDataFile -LiteralPath $resolvedConfigPath -ErrorAction Stop
    }
    catch {
        throw '配布設定を安全な PowerShell データファイルとして読み込めません。'
    }

    if ($config -isnot [System.Collections.IDictionary] -or $config.Count -eq 0) {
        throw ('配布設定が空として読み込まれました。deployment.local.psd1 をUTF-8 BOM付きで保存し、' +
            'ModelSourcePath を設定してください。')
    }

    foreach ($key in @($config.Keys)) {
        if ([string]$key -notin @('ModelSourcePath', 'ModelUserRepo', 'ProjectFirewall', 'FirewallMode')) {
            throw "配布設定に未対応の項目があります: $key"
        }
    }

    $sourceSetting = if ($config.Contains('ModelSourcePath')) {
        [string]$config['ModelSourcePath']
    }
    else { '' }
    if ([string]::IsNullOrWhiteSpace($sourceSetting)) {
        throw '配布設定の ModelSourcePath が空です。'
    }

    try {
        $sourcePath = [IO.Path]::GetFullPath($sourceSetting)
        if (Test-Path -LiteralPath $sourcePath -PathType Container) {
            $candidates = @(Get-ChildItem -LiteralPath $sourcePath -Filter '*.gguf' -File -ErrorAction Stop)
            if ($candidates.Count -ne 1) {
                throw "共有フォルダ直下の GGUF は1つだけ必要です。検出数: $($candidates.Count)"
            }
            $sourcePath = $candidates[0].FullName
        }
        elseif (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            throw '共有モデルファイルを参照できません。'
        }
    }
    catch {
        if ($_.Exception.Message -like '共有フォルダ直下*') { throw }
        throw '共有モデルを参照できません。共有先、資格情報、アクセス権を配布管理者が確認してください。'
    }

    if (-not [string]::Equals([IO.Path]::GetExtension($sourcePath), '.gguf', [StringComparison]::OrdinalIgnoreCase)) {
        throw '現在の自動登録で扱える共有モデルは GGUF ファイルだけです。'
    }

    $userRepo = if ($config.Contains('ModelUserRepo')) {
        [string]$config['ModelUserRepo']
    }
    else { '' }
    if ([string]::IsNullOrWhiteSpace($userRepo)) {
        $userRepo = 'secure-deployment/approved-model'
    }
    if ($userRepo -notmatch '^secure-deployment/[A-Za-z0-9._-]+$') {
        throw 'ModelUserRepo はプロジェクト専用領域 secure-deployment/repository の形式で指定してください。'
    }

    if ($config.Contains('ProjectFirewall') -and $config.Contains('FirewallMode')) {
        throw 'ProjectFirewall と旧形式の FirewallMode は同時に指定できません。ProjectFirewall だけを使用してください。'
    }

    $projectFirewall = if ($config.Contains('ProjectFirewall')) {
        [string]$config['ProjectFirewall']
    }
    elseif ($config.Contains('FirewallMode')) {
        $legacyMode = [string]$config['FirewallMode']
        if ([string]::Equals($legacyMode, 'ProjectManaged', [StringComparison]::OrdinalIgnoreCase)) { 'ON' }
        elseif ([string]::Equals($legacyMode, 'ExternallyManaged', [StringComparison]::OrdinalIgnoreCase)) { 'OFF' }
        else { throw '旧形式の FirewallMode は ProjectManaged または ExternallyManaged を指定してください。' }
    }
    else { 'ON' }

    if ([string]::Equals($projectFirewall, 'ON', [StringComparison]::OrdinalIgnoreCase)) {
        $projectFirewall = 'ON'
        $firewallMode = 'ProjectManaged'
    }
    elseif ([string]::Equals($projectFirewall, 'OFF', [StringComparison]::OrdinalIgnoreCase)) {
        $projectFirewall = 'OFF'
        $firewallMode = 'ExternallyManaged'
    }
    else {
        throw "ProjectFirewall は 'ON' または 'OFF' を指定してください。"
    }

    return [pscustomobject]@{
        SourcePath = $sourcePath
        UserRepo = $userRepo
        ProjectFirewall = $projectFirewall
        FirewallMode = $firewallMode
    }
}

function Get-SymbolicLinkTargetPath {
    param([Parameter(Mandatory = $true)][string]$LinkPath)

    $item = Get-Item -LiteralPath $LinkPath -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -or
        [string]$item.LinkType -ne 'SymbolicLink') {
        throw '管理対象モデルの配置先がシンボリックリンクではありません。'
    }
    $targets = @($item.Target)
    if ($targets.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$targets[0])) {
        throw '管理対象モデルのリンク先を一意に確認できません。'
    }
    $target = [string]$targets[0]
    if (-not [IO.Path]::IsPathRooted($target)) {
        $target = Join-Path (Split-Path -Parent $LinkPath) $target
    }
    return [IO.Path]::GetFullPath($target)
}

function Get-DeploymentModelLinkInfo {
    param(
        [Parameter(Mandatory = $true)][string]$LmStudioHomePath,
        [Parameter(Mandatory = $true)][object]$DeploymentConfig
    )

    $sourcePath = [string]$DeploymentConfig.SourcePath
    $userRepo = [string]$DeploymentConfig.UserRepo
    $repoParts = $userRepo.Split('/')
    $repositoryRoot = Join-Path (Join-Path (Join-Path $LmStudioHomePath 'models') $repoParts[0]) $repoParts[1]
    return [pscustomobject]@{
        LinkPath = (Join-Path $repositoryRoot ([IO.Path]::GetFileName($sourcePath)))
        IndexedPath = ($userRepo + '/' + [IO.Path]::GetFileName($sourcePath))
    }
}

function Register-DeploymentModel {
    param(
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][string]$LmStudioHomePath,
        [Parameter(Mandatory = $true)][object]$DeploymentConfig
    )

    $sourcePath = [string]$DeploymentConfig.SourcePath
    $userRepo = [string]$DeploymentConfig.UserRepo
    $linkInfo = Get-DeploymentModelLinkInfo `
        -LmStudioHomePath $LmStudioHomePath `
        -DeploymentConfig $DeploymentConfig
    $linkPath = [string]$linkInfo.LinkPath
    $sourceHash = Get-AbsolutePathIdentitySha256 -Path $sourcePath

    if (Test-Path -LiteralPath $linkPath) {
        $existingTarget = Get-SymbolicLinkTargetPath -LinkPath $linkPath
        if (-not [string]::Equals(
            (Get-AbsolutePathIdentitySha256 -Path $existingTarget),
            $sourceHash,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw '管理対象モデルの既存リンクが、配布設定とは異なる共有モデルを指しています。'
        }
        return [pscustomobject]@{
            LinkPath = $linkPath
            IndexedPath = [string]$linkInfo.IndexedPath
            Created = $false
        }
    }

    $dryRun = Invoke-NativeCapture -FilePath $LmsPath -ArgumentList @(
        'import', $sourcePath, '--symbolic-link', '--user-repo', $userRepo, '-y', '--dry-run'
    )
    if ($dryRun.ExitCode -ne 0) {
        throw '共有モデルの自動登録を事前検査できませんでした。元ファイルは変更していません。'
    }

    $importResult = Invoke-NativeCapture -FilePath $LmsPath -ArgumentList @(
        'import', $sourcePath, '--symbolic-link', '--user-repo', $userRepo, '-y'
    )
    if (Test-Path -LiteralPath $linkPath) {
        $script:CreatedManagedModelLink = $linkPath
    }
    if ($importResult.ExitCode -ne 0) {
        throw ('共有モデルのシンボリックリンク登録に失敗しました。元ファイルは移動・コピーしていません。' +
            '配布管理者はWindowsのシンボリックリンク作成権限を確認してください。')
    }
    if (-not (Test-Path -LiteralPath $linkPath)) {
        throw '共有モデルの登録先を検証できませんでした。'
    }

    $actualTarget = Get-SymbolicLinkTargetPath -LinkPath $linkPath
    if (-not [string]::Equals(
        (Get-AbsolutePathIdentitySha256 -Path $actualTarget),
        $sourceHash,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw '作成されたモデルリンクの参照先が配布設定と一致しません。'
    }

    return [pscustomobject]@{
        LinkPath = $linkPath
        IndexedPath = [string]$linkInfo.IndexedPath
        Created = $true
    }
}

function Remove-CreatedManagedModelLink {
    if ([string]::IsNullOrWhiteSpace($script:CreatedManagedModelLink)) {
        return
    }
    try {
        if (Test-Path -LiteralPath $script:CreatedManagedModelLink) {
            $item = Get-Item -LiteralPath $script:CreatedManagedModelLink -Force -ErrorAction Stop
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
                throw '失敗時に削除予定の対象がリンクではないため、削除しません。'
            }
            [IO.File]::Delete($script:CreatedManagedModelLink)
            Write-SetupLog -Level WARN -Message '今回作成した共有モデルリンクを巻き戻しました。'
        }
    }
    catch {
        Write-SetupLog -Level ERROR -Message "共有モデルリンクの巻き戻しに失敗しました: $($_.Exception.Message)"
    }
    finally {
        $script:CreatedManagedModelLink = $null
    }
}

function Get-PropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function Set-JsonProperty {
    param(
        [Parameter(Mandatory = $true)][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$Value
    )

    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        $InputObject | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
    }
    else {
        $property.Value = $Value
    }
}

function Read-JsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "JSON ファイルが見つかりません: $Path"
    }

    $raw = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "JSON ファイルが空です: $Path"
    }

    try {
        $value = $raw | ConvertFrom-Json
    }
    catch {
        throw "JSON の解析に失敗しました: $Path`n$($_.Exception.Message)"
    }

    if ($null -eq $value -or $value -is [System.Array]) {
        throw "JSON のルートはオブジェクトである必要があります: $Path"
    }

    return $value
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
        [System.IO.File]::WriteAllText($tempPath, (ConvertTo-JsonText $InputObject), $utf8NoBom)
        $null = Read-JsonFile -Path $tempPath
        return $tempPath
    }
    catch {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            [System.IO.File]::Delete($tempPath)
        }
        throw
    }
}

function Commit-TempFile {
    param(
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        $replaceBackupPath = '{0}.replace-backup.{1}.{2}' -f (
            $DestinationPath,
            $PID,
            ([guid]::NewGuid().ToString('N'))
        )
        $replaceSucceeded = $false
        try {
            [System.IO.File]::Replace($TempPath, $DestinationPath, $replaceBackupPath, $true)
            $replaceSucceeded = $true
        }
        finally {
            if ($replaceSucceeded -and (Test-Path -LiteralPath $replaceBackupPath -PathType Leaf)) {
                try {
                    [System.IO.File]::Delete($replaceBackupPath)
                }
                catch {
                    # 置換は完了済みです。残った一時バックアップは次回の手動確認対象とします。
                }
            }
        }
    }
    else {
        [System.IO.File]::Move($TempPath, $DestinationPath)
    }
}

function Get-LMStudioExecutablePath {
    param([string]$RequestedPath)

    $candidates = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates.Add($RequestedPath)
    }

    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio\LM Studio.exe'))
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'LM Studio\LM Studio.exe'))

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return [System.IO.Path]::GetFullPath($candidate)
        }
    }

    throw ("LM Studio.exe が見つかりません。-LmStudioExePath で指定してください。確認先: {0}" -f
        ($candidates -join ', '))
}

function Test-PathIsUnderRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    return $fullPath.StartsWith($fullRoot, [StringComparison]::OrdinalIgnoreCase)
}

function Get-LMStudioProgramPaths {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath
    )

    $installRoot = Split-Path -Parent $ExePath
    $roots = @(
        $installRoot,
        (Join-Path $HomePath 'bin'),
        (Join-Path $HomePath '.internal'),
        (Join-Path $HomePath 'extensions\backends')
    )

    $paths = New-Object System.Collections.Generic.List[string]
    $paths.Add([IO.Path]::GetFullPath($ExePath))

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        Get-ChildItem -LiteralPath $root -File -Filter '*.exe' -Recurse -ErrorAction Stop |
            ForEach-Object {
                $fullPath = [IO.Path]::GetFullPath($_.FullName)
                if (Test-PathIsUnderRoot -Path $fullPath -Root $root) {
                    $paths.Add($fullPath)
                }
            }
    }

    return @($paths | Sort-Object -Unique)
}

function Get-RunningLMStudioProcesses {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath
    )

    $installRoot = Split-Path -Parent $ExePath
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) {
        $isCandidateName = $process.ProcessName -in @('LM Studio', 'llmster', 'lms', 'llama-server')
        $processPath = $null
        try {
            $processPath = $process.Path
        }
        catch {
            # 一部のシステムプロセスでは Path を取得できません。
        }

        $isCandidatePath = $false
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            $isCandidatePath =
                (Test-PathIsUnderRoot -Path $processPath -Root $installRoot) -or
                (Test-PathIsUnderRoot -Path $processPath -Root $HomePath)
        }

        if ($isCandidateName -or $isCandidatePath) {
            $results.Add([pscustomobject]@{
                Name = $process.ProcessName
                Id   = $process.Id
                Path = $processPath
            })
        }
    }

    # Windows PowerShell 5.1 throws "Argument types do not match" when an
    # empty List[object] is wrapped directly in @(...). Materialize a typed
    # array first so the normal "nothing is running" case remains valid.
    return $results.ToArray()
}

function Enter-SetupMutex {
    param([Parameter(Mandatory = $true)][string]$LmStudioHomePath)

    $identity = (Get-StringSha256 -Value ([IO.Path]::GetFullPath($LmStudioHomePath))).Substring(0, 24)
    $mutexName = 'Local\WindowsLocalAIHardening.Setup.' + $identity
    $createdNew = $false
    $mutex = New-Object Threading.Mutex($true, $mutexName, ([ref]$createdNew))
    if (-not $createdNew) {
        $mutex.Dispose()
        throw '別の初期セットアップが実行中です。開いているセットアップが完了するまで待ってください。'
    }
    $script:SetupMutex = $mutex
    $script:SetupMutexOwned = $true
}

function Exit-SetupMutex {
    if ($script:SetupMutexOwned -and $null -ne $script:SetupMutex) {
        try { $script:SetupMutex.ReleaseMutex() } catch { }
    }
    if ($null -ne $script:SetupMutex) {
        $script:SetupMutex.Dispose()
    }
    $script:SetupMutex = $null
    $script:SetupMutexOwned = $false
}

function Assert-NoActiveSetupRequest {
    param([Parameter(Mandatory = $true)][string]$SetupRoot)

    $requests = @(Get-ChildItem -LiteralPath $SetupRoot -Filter 'firewall-request-*.json' -File -ErrorAction SilentlyContinue)
    if ($requests.Count -gt 0) {
        throw ('別の管理者セットアップ処理、または中断された一時要求を検出しました。' +
            '新しく起動せず、既存のセットアップが完了するまで待ってください。')
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

    # Windows PowerShell 5.1 converts a native program's stderr into a
    # terminating RemoteException when the caller uses Stop. Capture stderr
    # without masking it, and decide success only from the native exit code.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines    = $output
        Text     = ($output -join [Environment]::NewLine)
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
        if ($start -lt 0 -or $end -lt $start) {
            break
        }

        $json = $Text.Substring($start, ($end - $start + 1))
        try {
            return ($json | ConvertFrom-Json)
        }
        catch {
            $lastParseError = $_.Exception.Message
            $searchIndex = $start + 1
        }
    }

    if ([string]::IsNullOrWhiteSpace($lastParseError)) {
        throw 'CLI 出力から JSON を抽出できませんでした。'
    }
    throw "CLI の JSON 出力を解析できませんでした: $lastParseError"
}

function Assert-FirewallEnvironment {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
    $disabled = @($profiles | Where-Object { $_.Enabled -ne $true })
    if ($disabled.Count -gt 0) {
        throw ('Windows Firewall が無効なプロファイルがあります: {0}' -f
            (($disabled | ForEach-Object { $_.Name }) -join ', '))
    }

    $mergeDisabled = @($profiles | Where-Object { $_.AllowLocalFirewallRules -eq $false })
    if ($mergeDisabled.Count -gt 0) {
        throw ('ローカル Firewall 規則がポリシーで無効です: {0}。管理者または組織の IT 部門に確認してください。' -f
            (($mergeDisabled | ForEach-Object { $_.Name }) -join ', '))
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

function Test-LMStudioFirewallRules {
    param([Parameter(Mandatory = $true)][string[]]$ProgramPaths)

    Assert-FirewallEnvironment
    $verifiedCount = 0
    foreach ($programPath in ($ProgramPaths | Sort-Object -Unique)) {
        foreach ($direction in @('Outbound', 'Inbound')) {
            $pathHash = (Get-StringSha256 -Value $programPath).Substring(0, 16)
            $ruleName = 'LMStudioSecure-{0}-{1}' -f $direction, $pathHash
            $rules = @(Get-NetFirewallRule -Name $ruleName -ErrorAction Stop)
            if ($rules.Count -ne 1) {
                throw "Firewall 規則が一意ではありません: $ruleName / $($rules.Count) 件"
            }
            $rule = $rules[0]
            if ([string]$rule.Enabled -ne 'True' -or
                [string]$rule.Action -ne 'Block' -or
                [string]$rule.Direction -ne $direction -or
                [string]$rule.Group -ne $script:FirewallGroup -or
                [string]$rule.Profile -ne 'Any') {
                throw "Firewall 規則の基本条件が期待状態ではありません: $ruleName"
            }

            $applicationFilters = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
            if ($applicationFilters.Count -ne 1 -or
                -not [string]::Equals(
                    [IO.Path]::GetFullPath([string]$applicationFilters[0].Program),
                    [IO.Path]::GetFullPath($programPath),
                    [StringComparison]::OrdinalIgnoreCase
                )) {
                throw "Firewall 規則の対象プログラムが一致しません: $ruleName"
            }

            $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            if ($addressFilters.Count -ne 1 -or
                -not (Test-StringSetEquals -Actual @($addressFilters[0].LocalAddress) -Expected @('Any')) -or
                -not (Test-StringSetEquals -Actual @($addressFilters[0].RemoteAddress) -Expected $script:NonLoopbackRemoteAddresses)) {
                throw "Firewall 規則のアドレス範囲が一致しません: $ruleName"
            }

            $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            if ($portFilters.Count -ne 1 -or
                [string]$portFilters[0].Protocol -ne 'Any' -or
                -not (Test-StringSetEquals -Actual @($portFilters[0].LocalPort) -Expected @('Any')) -or
                -not (Test-StringSetEquals -Actual @($portFilters[0].RemotePort) -Expected @('Any'))) {
                throw "Firewall 規則のプロトコルまたはポートが制限されています: $ruleName"
            }

            $interfaceFilters = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
            if ($interfaceFilters.Count -ne 1 -or [string]$interfaceFilters[0].InterfaceType -ne 'Any') {
                throw "Firewall 規則のインターフェース範囲が一致しません: $ruleName"
            }
            $serviceFilters = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
            if ($serviceFilters.Count -ne 1 -or [string]$serviceFilters[0].Service -ne 'Any') {
                throw "Firewall 規則が特定サービスだけに限定されています: $ruleName"
            }
            $verifiedCount++
        }
    }
    return $verifiedCount
}

function Set-LMStudioFirewallRules {
    param([Parameter(Mandatory = $true)][string[]]$ProgramPaths)

    if (-not (Test-IsAdministrator)) {
        throw 'Firewall 規則の設定には管理者権限が必要です。'
    }

    Assert-FirewallEnvironment

    $ruleCount = 0
    foreach ($programPath in ($ProgramPaths | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $programPath -PathType Leaf)) {
            throw "Firewall 対象の実行ファイルが見つかりません: $programPath"
        }
        if ([IO.Path]::GetExtension($programPath) -ine '.exe') {
            throw "Firewall 対象は .exe に限定されます: $programPath"
        }

        $pathHash = (Get-StringSha256 -Value $programPath).Substring(0, 16)
        foreach ($direction in @('Outbound', 'Inbound')) {
            $ruleName = 'LMStudioSecure-{0}-{1}' -f $direction, $pathHash
            $displayName = 'LM Studio secure {0}: {1}' -f $direction, ([IO.Path]::GetFileName($programPath))
            $description = 'Blocks non-loopback LM Studio traffic. Managed by Setup-LMStudio.ps1.'
            $existing = @(Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue)

            # A same-name rule outside our group is left untouched and treated as
            # a collision instead of deleting an unrelated rule.
            $foreignRules = @($existing | Where-Object { [string]$_.Group -ne $script:FirewallGroup })
            if ($foreignRules.Count -gt 0) {
                throw "管理外の同名Firewall規則が存在します。削除せず停止します: $ruleName"
            }

            if ($existing.Count -eq 0) {
                New-NetFirewallRule `
                    -Name $ruleName `
                    -DisplayName $displayName `
                    -Description $description `
                    -Group $script:FirewallGroup `
                    -Direction $direction `
                    -Action Block `
                    -Enabled True `
                    -Profile Any `
                    -Program $programPath `
                    -Protocol Any `
                    -LocalPort Any `
                    -RemotePort Any `
                    -RemoteAddress $script:NonLoopbackRemoteAddresses `
                    -ErrorAction Stop | Out-Null
            }
            else {
                Set-NetFirewallRule `
                    -Name $ruleName `
                    -NewDisplayName $displayName `
                    -Description $description `
                    -Direction $direction `
                    -Action Block `
                    -Enabled True `
                    -Profile Any `
                    -Program $programPath `
                    -Protocol Any `
                    -LocalPort Any `
                    -RemotePort Any `
                    -RemoteAddress $script:NonLoopbackRemoteAddresses `
                    -ErrorAction Stop | Out-Null
            }

            $ruleCount++
        }
    }

    $verifiedCount = Test-LMStudioFirewallRules -ProgramPaths $ProgramPaths
    if ($verifiedCount -ne $ruleCount) {
        throw "Firewall 規則数の検証に失敗しました: 作成 $ruleCount / 検証 $verifiedCount"
    }
    return $verifiedCount
}

function Remove-LMStudioFirewallRules {
    if (-not (Test-IsAdministrator)) {
        throw '本プロジェクトのFirewall規則をOFFにするには管理者権限が必要です。'
    }

    $rules = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        if ([string]$rule.Group -ne $script:FirewallGroup) {
            throw "本プロジェクトの管理外にあるFirewall規則は削除しません: $($rule.Name)"
        }
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
    }

    $remaining = @(Get-NetFirewallRule -Group $script:FirewallGroup -ErrorAction SilentlyContinue)
    if ($remaining.Count -ne 0) {
        throw "本プロジェクトのFirewall規則をすべて削除できませんでした: $($remaining.Count) 件"
    }
    return $rules.Count
}

function Invoke-ElevatedFirewallSetup {
    param(
        [Parameter(Mandatory = $true)][string[]]$ProgramPaths,
        [Parameter(Mandatory = $true)][string]$SetupRoot,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][string]$LmStudioHomePath,
        [Parameter(Mandatory = $true)][object]$DeploymentConfig,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable', 'Skip')]
        [string]$FirewallAction
    )

    $requestPath = Join-Path $SetupRoot ('firewall-request-{0}.json' -f ([guid]::NewGuid().ToString('N')))
    $request = [ordered]@{
        SchemaVersion   = 4
        CreatedAtUtc    = [DateTime]::UtcNow.ToString('o')
        ProgramPaths    = @($ProgramPaths)
        LmsPath         = $LmsPath
        LmStudioHomePath = $LmStudioHomePath
        ModelSourcePath = [string]$DeploymentConfig.SourcePath
        ModelUserRepo   = [string]$DeploymentConfig.UserRepo
        FirewallAction  = $FirewallAction
    }

    $tempPath = Write-ValidatedJsonTempFile -DestinationPath $requestPath -InputObject $request
    Commit-TempFile -TempPath $tempPath -DestinationPath $requestPath
    $requestSha256 = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    try {
        if (Test-IsAdministrator) {
            $null = Register-DeploymentModel `
                -LmsPath $LmsPath `
                -LmStudioHomePath $LmStudioHomePath `
                -DeploymentConfig $DeploymentConfig
            $count = switch ($FirewallAction) {
                'Enable'  { Set-LMStudioFirewallRules -ProgramPaths $ProgramPaths }
                'Disable' { $null = Remove-LMStudioFirewallRules; 0 }
                default   { 0 }
            }
            $script:CreatedManagedModelLink = $null
            return $count
        }

        if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or
            -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
            throw 'スクリプト自身のパスを解決できないため、管理者権限へ昇格できません。'
        }

        $powerShellExe = Join-Path $PSHOME 'powershell.exe'
        if (-not (Test-Path -LiteralPath $powerShellExe -PathType Leaf)) {
            $powerShellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
        }

        foreach ($value in @($PSCommandPath, $requestPath, $LogPath)) {
            if ($value.Contains('"')) {
                throw "ダブルクォートを含むパスは昇格処理で使用できません: $value"
            }
        }

        $elevationReason = switch ($FirewallAction) {
            'Enable'  { '共有モデルのリンク登録と本プロジェクトのFirewall規則ON' }
            'Disable' { '共有モデルのリンク登録と本プロジェクトのFirewall規則OFF' }
            default   { '共有モデルのリンク登録' }
        }
        Write-SetupLog -Message "$elevationReason のため、Windowsの管理者確認を表示します。"
        if ($FirewallAction -eq 'Enable') {
            Write-SetupLog -Message ("Firewall規則は{0}件を作成・検証します。数分かかる場合があります。セットアップを二重起動しないでください。" -f ($ProgramPaths.Count * 2))
        }
        $arguments = @(
            '-NoLogo',
            '-NoProfile',
            '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-FirewallOnly',
            '-FirewallRequestPath', ('"{0}"' -f $requestPath),
            '-FirewallRequestSha256', $requestSha256,
            '-SharedLogPath', ('"{0}"' -f $LogPath)
        )

        $process = Start-Process `
            -FilePath $powerShellExe `
            -ArgumentList $arguments `
            -Verb RunAs `
            -WindowStyle Hidden `
            -Wait `
            -PassThru

        if ($process.ExitCode -ne 0) {
            throw "管理者プロセスでのモデルリンク登録またはFirewall設定に失敗しました。終了コード: $($process.ExitCode)"
        }

        return $(if ($FirewallAction -eq 'Enable') { $ProgramPaths.Count * 2 } else { 0 })
    }
    finally {
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) {
            [System.IO.File]::Delete($requestPath)
        }
    }
}

function Invoke-FirewallOnlyMode {
    if (-not $FirewallOnly) {
        return
    }

    $requestFullPath = $null
    $childExitCode = 0
    try {
        if (-not (Test-IsAdministrator)) {
            throw 'FirewallOnly モードは管理者権限で実行する必要があります。'
        }
        if ([string]::IsNullOrWhiteSpace($FirewallRequestPath)) {
            throw 'FirewallRequestPath が指定されていません。'
        }
        if ($FirewallRequestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'FirewallRequestSha256 が指定されていないか、形式が不正です。'
        }

        $requestFullPath = [IO.Path]::GetFullPath($FirewallRequestPath)
        $requestRoot = Split-Path -Parent $requestFullPath
        Initialize-Logging -Root $requestRoot -ExistingLogPath $SharedLogPath
        Write-SetupLog -Message '管理者プロセスで共有モデル登録の昇格処理を開始します。'

        $actualRequestSha256 = (
            Get-FileHash -LiteralPath $requestFullPath -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if (-not [string]::Equals(
            $actualRequestSha256,
            $FirewallRequestSha256.ToLowerInvariant(),
            [StringComparison]::Ordinal
        )) {
            throw 'Firewall 要求ファイルのハッシュが一致しません。処理を中止します。'
        }

        $request = Read-JsonFile -Path $requestFullPath
        if ((Get-PropertyValue -InputObject $request -Name 'SchemaVersion') -ne 4) {
            throw 'Firewall 要求ファイルのバージョンを認識できません。'
        }

        $createdAt = [DateTime]::Parse(
            [string](Get-PropertyValue -InputObject $request -Name 'CreatedAtUtc'),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        if ([DateTime]::UtcNow.Subtract($createdAt.ToUniversalTime()).TotalMinutes -gt 15) {
            throw 'Firewall 要求ファイルの有効期限（15分）が切れています。'
        }

        $programPaths = @((Get-PropertyValue -InputObject $request -Name 'ProgramPaths'))
        if ($programPaths.Count -eq 0) {
            throw 'Firewall 対象が空です。'
        }

        $lmsPath = [IO.Path]::GetFullPath([string](Get-PropertyValue -InputObject $request -Name 'LmsPath'))
        $homePath = [IO.Path]::GetFullPath([string](Get-PropertyValue -InputObject $request -Name 'LmStudioHomePath'))
        $modelSourcePath = [IO.Path]::GetFullPath([string](Get-PropertyValue -InputObject $request -Name 'ModelSourcePath'))
        $modelUserRepo = [string](Get-PropertyValue -InputObject $request -Name 'ModelUserRepo')
        $firewallAction = [string](Get-PropertyValue -InputObject $request -Name 'FirewallAction')
        if ($firewallAction -notin @('Enable', 'Disable', 'Skip')) {
            throw 'Firewall要求のON/OFF指定を認識できません。'
        }
        if (-not (Test-Path -LiteralPath $lmsPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $homePath -PathType Container) -or
            -not (Test-Path -LiteralPath $modelSourcePath -PathType Leaf) -or
            -not [string]::Equals([IO.Path]::GetExtension($modelSourcePath), '.gguf', [StringComparison]::OrdinalIgnoreCase) -or
            $modelUserRepo -notmatch '^secure-deployment/[A-Za-z0-9._-]+$') {
            throw '共有モデル登録要求の内容を検証できません。'
        }
        $deploymentConfig = [pscustomobject]@{
            SourcePath = $modelSourcePath
            UserRepo = $modelUserRepo
        }

        $null = Register-DeploymentModel `
            -LmsPath $lmsPath `
            -LmStudioHomePath $homePath `
            -DeploymentConfig $deploymentConfig
        Write-SetupLog -Level OK -Message '共有モデルのシンボリックリンク登録を検証しました。'

        $count = switch ($firewallAction) {
            'Enable'  { Set-LMStudioFirewallRules -ProgramPaths $programPaths }
            'Disable' { $null = Remove-LMStudioFirewallRules; 0 }
            default   { 0 }
        }
        $script:CreatedManagedModelLink = $null
        if ($firewallAction -eq 'Enable') {
            Write-SetupLog -Level OK -Message "Firewall 規則を検証しました: $count 件"
        }
        elseif ($firewallAction -eq 'Disable') {
            Write-SetupLog -Level OK -Message '本プロジェクトのFirewall規則をOFFにし、残っていないことを確認しました。'
        }
        else {
            Write-SetupLog -Level WARN -Message 'Firewall処理をコマンド指定で省略しました。'
        }
    }
    catch {
        Remove-CreatedManagedModelLink
        Write-SetupLog -Level ERROR -Message $_.Exception.Message
        $childExitCode = 1
    }
    finally {
        if (-not [string]::IsNullOrWhiteSpace($requestFullPath) -and
            (Test-Path -LiteralPath $requestFullPath -PathType Leaf)) {
            try { [IO.File]::Delete($requestFullPath) } catch { }
        }
    }
    exit $childExitCode
}

function Test-EmptyObject {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) {
        return $false
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        return ($InputObject.Count -eq 0)
    }

    return (@($InputObject.PSObject.Properties).Count -eq 0)
}

function Update-LMStudioJsonSettings {
    param(
        [Parameter(Mandatory = $true)][string]$SettingsPath,
        [Parameter(Mandatory = $true)][string]$McpPath,
        [Parameter(Mandatory = $true)][string]$HttpServerConfigPath,
        [Parameter(Mandatory = $true)][string]$BackupRoot
    )

    $settings = Read-JsonFile -Path $SettingsPath
    $developer = Get-PropertyValue -InputObject $settings -Name 'developer'
    if ($null -eq $developer) {
        $developer = [pscustomobject]@{}
        Set-JsonProperty -InputObject $settings -Name 'developer' -Value $developer
    }

    $desiredTopLevel = [ordered]@{
        developerMode      = $false
        autoLoadBundledLLM = $false
        enableLocalService = $false
        useHFProxy         = $false
        hfSearchToken      = ''
        hfDownloadToken    = ''
    }
    $desiredDeveloper = [ordered]@{
        showExperimentalFeatures = $false
        allowDevelopmentPlugins  = $false
        autoUpdateExtensionPacks = $false
    }

    $settingsChanged = $false
    foreach ($entry in $desiredTopLevel.GetEnumerator()) {
        $current = Get-PropertyValue -InputObject $settings -Name $entry.Key
        if ($current -ne $entry.Value) {
            Set-JsonProperty -InputObject $settings -Name $entry.Key -Value $entry.Value
            $settingsChanged = $true
        }
    }
    foreach ($entry in $desiredDeveloper.GetEnumerator()) {
        $current = Get-PropertyValue -InputObject $developer -Name $entry.Key
        if ($current -ne $entry.Value) {
            Set-JsonProperty -InputObject $developer -Name $entry.Key -Value $entry.Value
            $settingsChanged = $true
        }
    }

    $mcpExisted = Test-Path -LiteralPath $McpPath -PathType Leaf
    if ($mcpExisted) {
        $mcp = Read-JsonFile -Path $McpPath
    }
    else {
        $mcp = [pscustomobject]@{}
    }

    $mcpServers = Get-PropertyValue -InputObject $mcp -Name 'mcpServers'
    $mcpChanged = -not (Test-EmptyObject -InputObject $mcpServers)
    if ($mcpChanged) {
        Set-JsonProperty -InputObject $mcp -Name 'mcpServers' -Value ([pscustomobject]@{})
    }

    $httpServerConfigExisted = Test-Path -LiteralPath $HttpServerConfigPath -PathType Leaf
    $httpServerConfig = if ($httpServerConfigExisted) {
        Read-JsonFile -Path $HttpServerConfigPath
    }
    else { $null }
    $httpServerConfigChanged = $false
    if ($httpServerConfigExisted) {
        $desiredHttpServer = [ordered]@{
            autoStartOnLaunch = $false
            networkInterface  = '127.0.0.1'
        }
        foreach ($entry in $desiredHttpServer.GetEnumerator()) {
            if ((Get-PropertyValue -InputObject $httpServerConfig -Name $entry.Key) -ne $entry.Value) {
                Set-JsonProperty -InputObject $httpServerConfig -Name $entry.Key -Value $entry.Value
                $httpServerConfigChanged = $true
            }
        }
    }

    if (-not $settingsChanged -and -not $mcpChanged -and -not $httpServerConfigChanged) {
        Write-SetupLog -Level OK -Message 'settings.json、mcp.json、公開APIサーバー設定は既に目標状態です。'
        return [pscustomobject]@{
            SettingsChanged         = $false
            McpChanged              = $false
            HttpServerConfigChanged = $false
            BackupPath              = $null
        }
    }

    $backupDirectory = Join-Path $BackupRoot (
        '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    )
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null

    $settingsBackup = Join-Path $backupDirectory 'settings.json'
    [System.IO.File]::Copy($SettingsPath, $settingsBackup, $false)
    $mcpBackup = Join-Path $backupDirectory 'mcp.json'
    if ($mcpExisted) {
        [System.IO.File]::Copy($McpPath, $mcpBackup, $false)
    }
    $httpServerConfigBackup = Join-Path $backupDirectory 'http-server-config.json'
    if ($httpServerConfigExisted) {
        [System.IO.File]::Copy($HttpServerConfigPath, $httpServerConfigBackup, $false)
    }

    $manifest = [ordered]@{
        SchemaVersion       = 1
        CreatedAtUtc        = [DateTime]::UtcNow.ToString('o')
        SettingsPath        = $SettingsPath
        SettingsSha256      = (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash.ToLowerInvariant()
        McpPath             = $McpPath
        McpOriginallyExists = $mcpExisted
        McpSha256           = if ($mcpExisted) {
            (Get-FileHash -LiteralPath $McpPath -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
        HttpServerConfigPath = $HttpServerConfigPath
        HttpServerConfigOriginallyExists = $httpServerConfigExisted
        HttpServerConfigSha256 = if ($httpServerConfigExisted) {
            (Get-FileHash -LiteralPath $HttpServerConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
        } else { $null }
    }
    $manifestTemp = Write-ValidatedJsonTempFile `
        -DestinationPath (Join-Path $backupDirectory 'backup-manifest.json') `
        -InputObject $manifest
    Commit-TempFile -TempPath $manifestTemp -DestinationPath (Join-Path $backupDirectory 'backup-manifest.json')
    Write-SetupLog -Level OK -Message "バックアップを作成しました: $backupDirectory"

    $settingsTemp = $null
    $mcpTemp = $null
    $httpServerConfigTemp = $null
    $settingsCommitted = $false
    $mcpCommitted = $false
    $httpServerConfigCommitted = $false

    try {
        if ($settingsChanged) {
            $settingsTemp = Write-ValidatedJsonTempFile -DestinationPath $SettingsPath -InputObject $settings
        }
        if ($mcpChanged) {
            $mcpTemp = Write-ValidatedJsonTempFile -DestinationPath $McpPath -InputObject $mcp
        }
        if ($httpServerConfigChanged) {
            $httpServerConfigTemp = Write-ValidatedJsonTempFile -DestinationPath $HttpServerConfigPath -InputObject $httpServerConfig
        }

        if ($settingsChanged) {
            Commit-TempFile -TempPath $settingsTemp -DestinationPath $SettingsPath
            $settingsTemp = $null
            $settingsCommitted = $true
        }
        if ($mcpChanged) {
            Commit-TempFile -TempPath $mcpTemp -DestinationPath $McpPath
            $mcpTemp = $null
            $mcpCommitted = $true
        }
        if ($httpServerConfigChanged) {
            Commit-TempFile -TempPath $httpServerConfigTemp -DestinationPath $HttpServerConfigPath
            $httpServerConfigTemp = $null
            $httpServerConfigCommitted = $true
        }

        $verifiedSettings = Read-JsonFile -Path $SettingsPath
        $verifiedDeveloper = Get-PropertyValue -InputObject $verifiedSettings -Name 'developer'
        foreach ($entry in $desiredTopLevel.GetEnumerator()) {
            if ((Get-PropertyValue -InputObject $verifiedSettings -Name $entry.Key) -ne $entry.Value) {
                throw "settings.json の検証に失敗しました: $($entry.Key)"
            }
        }
        foreach ($entry in $desiredDeveloper.GetEnumerator()) {
            if ((Get-PropertyValue -InputObject $verifiedDeveloper -Name $entry.Key) -ne $entry.Value) {
                throw "settings.json の検証に失敗しました: developer.$($entry.Key)"
            }
        }

        $verifiedMcp = Read-JsonFile -Path $McpPath
        if (-not (Test-EmptyObject -InputObject (
            Get-PropertyValue -InputObject $verifiedMcp -Name 'mcpServers'
        ))) {
            throw 'mcp.json の検証に失敗しました: mcpServers が空ではありません。'
        }
        if ($httpServerConfigExisted) {
            $verifiedHttpServerConfig = Read-JsonFile -Path $HttpServerConfigPath
            if ((Get-PropertyValue -InputObject $verifiedHttpServerConfig -Name 'autoStartOnLaunch') -ne $false -or
                (Get-PropertyValue -InputObject $verifiedHttpServerConfig -Name 'networkInterface') -ne '127.0.0.1') {
                throw '公開APIサーバー設定の検証に失敗しました。'
            }
        }
    }
    catch {
        Write-SetupLog -Level ERROR -Message 'JSON 更新に失敗したため、バックアップから復元します。'

        if ($settingsCommitted) {
            [System.IO.File]::Copy($settingsBackup, $SettingsPath, $true)
        }
        if ($mcpCommitted) {
            if ($mcpExisted) {
                [System.IO.File]::Copy($mcpBackup, $McpPath, $true)
            }
            elseif (Test-Path -LiteralPath $McpPath -PathType Leaf) {
                [System.IO.File]::Delete($McpPath)
            }
        }
        if ($httpServerConfigCommitted) {
            [System.IO.File]::Copy($httpServerConfigBackup, $HttpServerConfigPath, $true)
        }
        throw
    }
    finally {
        foreach ($temp in @($settingsTemp, $mcpTemp, $httpServerConfigTemp)) {
            if (-not [string]::IsNullOrWhiteSpace($temp) -and
                (Test-Path -LiteralPath $temp -PathType Leaf)) {
                [System.IO.File]::Delete($temp)
            }
        }
    }

    Write-SetupLog -Level OK -Message 'settings.json、mcp.json、公開APIサーバー設定を安全に更新し、再検証しました。'
    return [pscustomobject]@{
        SettingsChanged         = $settingsChanged
        McpChanged              = $mcpChanged
        HttpServerConfigChanged = $httpServerConfigChanged
        BackupPath              = $backupDirectory
    }
}

function Write-SetupState {
    param(
        [Parameter(Mandatory = $true)][string]$StatePath,
        [Parameter(Mandatory = $true)][object]$State
    )

    $temp = Write-ValidatedJsonTempFile -DestinationPath $StatePath -InputObject $State
    Commit-TempFile -TempPath $temp -DestinationPath $StatePath
    $null = Read-JsonFile -Path $StatePath
}

function Disable-ExistingSetupStateBeforeFirewallOff {
    param([Parameter(Mandatory = $true)][string]$StatePath)

    if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) {
        return
    }

    $state = Read-JsonFile -Path $StatePath
    $state | Add-Member -NotePropertyName Complete -NotePropertyValue $false -Force
    $state | Add-Member `
        -NotePropertyName PendingConfigurationChange `
        -NotePropertyValue 'ProjectFirewall OFF' `
        -Force
    Write-SetupState -StatePath $StatePath -State $state
    Write-SetupLog -Level WARN -Message 'Firewall規則をOFFへ切り替えるため、既存の安全起動状態を一時的に未完了へ変更しました。'
}

function Invoke-MainSetup {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'このスクリプトは Windows 専用です。'
    }
    if (Test-IsAdministrator) {
        throw '通常のLM Studioユーザーとして実行してください。管理者権限はモデルリンク登録と、必要な場合のFirewall処理を行う短い子プロセスだけに要求します。'
    }
    if (-not [string]::IsNullOrWhiteSpace($AllowedModel) -and
        $AllowedModel.IndexOfAny([char[]]@("`r", "`n", "`0")) -ge 0) {
        throw '-AllowedModel に制御文字は使用できません。'
    }

    $homePath = [IO.Path]::GetFullPath($LmStudioHome)
    if (-not (Test-Path -LiteralPath $homePath -PathType Container)) {
        throw "LM Studio のデータディレクトリがありません。まず LM Studio を1回起動してください: $homePath"
    }

    $script:SetupRoot = Join-Path $homePath 'secure-setup'
    Initialize-Logging -Root $script:SetupRoot
    Write-SetupLog -Message 'LM Studio の安全な初期セットアップを開始します。'
    Write-SetupLog -Message "ログ: $script:LogPath"
    Enter-SetupMutex -LmStudioHomePath $homePath
    Assert-NoActiveSetupRequest -SetupRoot $script:SetupRoot

    $deploymentConfig = Read-DeploymentModelConfig -ConfigPath $DeploymentConfigPath
    Write-SetupLog -Level OK -Message '配布設定から共有フォルダ上の1つのGGUFを確認しました（パスは記録しません）。'
    Write-SetupLog -Message ("本プロジェクトのFirewall規則: {0}" -f $deploymentConfig.ProjectFirewall)

    $exePath = Get-LMStudioExecutablePath -RequestedPath $LmStudioExePath
    $lmsPath = Join-Path $homePath 'bin\lms.exe'
    $settingsPath = Join-Path $homePath 'settings.json'
    $mcpPath = Join-Path $homePath 'mcp.json'
    $httpServerConfigPath = Join-Path $homePath '.internal\http-server-config.json'

    if (-not (Test-Path -LiteralPath $lmsPath -PathType Leaf)) {
        throw "lms CLI がありません。LM Studio を少なくとも1回起動してから再実行してください: $lmsPath"
    }
    $null = Read-JsonFile -Path $settingsPath
    if (Test-Path -LiteralPath $mcpPath -PathType Leaf) {
        $null = Read-JsonFile -Path $mcpPath
    }

    $running = @(Get-RunningLMStudioProcesses -ExePath $exePath -HomePath $homePath)
    if ($running.Count -gt 0) {
        $summary = ($running | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
        throw "LM Studio 関連プロセスが動作中です。未保存の内容を確認して完全に終了し、再実行してください: $summary"
    }

    $modelLinkInfo = Get-DeploymentModelLinkInfo `
        -LmStudioHomePath $homePath `
        -DeploymentConfig $deploymentConfig
    $modelLinkExistedBefore = Test-Path -LiteralPath ([string]$modelLinkInfo.LinkPath)

    $programPaths = @(Get-LMStudioProgramPaths -ExePath $exePath -HomePath $homePath)
    if ($programPaths.Count -eq 0) {
        throw 'LM Studio関連の実行ファイルを検出できませんでした。'
    }
    Write-SetupLog -Message "LM Studio関連の実行ファイルを検出しました: $($programPaths.Count) 個"

    $requestedFirewallMode = [string]$deploymentConfig.FirewallMode
    $firewallConfigured = $false
    $firewallExternallyManaged = $false
    $firewallReady = $false
    $effectiveFirewallMode = 'Incomplete'
    $firewallAction = if ($SkipFirewall) {
        'Skip'
    }
    elseif ($requestedFirewallMode -eq 'ProjectManaged') {
        'Enable'
    }
    else {
        'Disable'
    }
    if ($SkipFirewall) {
        Write-SetupLog -Level WARN -Message 'コマンド指定によりFirewall設定を省略します。安全セットアップは未完成になります。'
    }
    elseif ($requestedFirewallMode -eq 'ExternallyManaged') {
        $firewallExternallyManaged = $true
        $firewallReady = $true
        $effectiveFirewallMode = 'ExternallyManaged'
        Write-SetupLog -Level WARN -Message '本プロジェクトのFirewall規則はOFFです。通信保護は会社・組織側へ委任し、本プロジェクトでは実効性を検証しません。'
        Disable-ExistingSetupStateBeforeFirewallOff `
            -StatePath (Join-Path $script:SetupRoot 'setup-state.json')
    }

    $firewallRuleCount = Invoke-ElevatedFirewallSetup `
        -ProgramPaths $programPaths `
        -SetupRoot $script:SetupRoot `
        -LogPath $script:LogPath `
        -LmsPath $lmsPath `
        -LmStudioHomePath $homePath `
        -DeploymentConfig $deploymentConfig `
        -FirewallAction $firewallAction
    if ($firewallAction -eq 'Enable') {
        $firewallConfigured = $true
        $firewallReady = $true
        $effectiveFirewallMode = 'ProjectManaged'
        Write-SetupLog -Level OK -Message (
            "ループバック以外を遮断する Firewall 規則を検証しました: $firewallRuleCount 件"
        )
    }
    if (-not $modelLinkExistedBefore -and
        (Test-Path -LiteralPath ([string]$modelLinkInfo.LinkPath))) {
        $script:CreatedManagedModelLink = [string]$modelLinkInfo.LinkPath
    }
    $modelRegistration = Register-DeploymentModel `
        -LmsPath $lmsPath `
        -LmStudioHomePath $homePath `
        -DeploymentConfig $deploymentConfig
    Write-SetupLog -Level OK -Message '共有モデルをLM Studio標準モデル領域へリンク登録しました。'

    $stillRunning = @(Get-RunningLMStudioProcesses -ExePath $exePath -HomePath $homePath)
    if ($stillRunning.Count -gt 0) {
        throw 'LM Studio 関連プロセスが残っているため、JSON 設定を変更しません。'
    }

    # Model registration must not introduce an executable that was absent from
    # the Firewall snapshot. Runtime/model validation is intentionally deferred
    # to the first secure GUI launch because some LM Studio builds cannot start
    # the headless daemon even though the GUI-backed CLI works correctly.
    $postValidationProgramPaths = @(Get-LMStudioProgramPaths -ExePath $exePath -HomePath $homePath)
    $newProgramPaths = @($postValidationProgramPaths | Where-Object {
        $candidate = $_
        @($programPaths | Where-Object {
            [string]::Equals([string]$_, [string]$candidate, [StringComparison]::OrdinalIgnoreCase)
        }).Count -eq 0
    })
    if ($newProgramPaths.Count -gt 0) {
        throw ("登録中に新しい実行ファイルが作成されたため、今回は完了状態にしません:`n  {0}`n" -f
            ($newProgramPaths -join "`n  ")) + 'すべて停止したままSetup-LMStudio.ps1を再実行してください。'
    }

    $backupRoot = Join-Path $script:SetupRoot 'backups'
    if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    }
    $jsonUpdate = Update-LMStudioJsonSettings `
        -SettingsPath $settingsPath `
        -McpPath $mcpPath `
        -HttpServerConfigPath $httpServerConfigPath `
        -BackupRoot $backupRoot

    $completedAtUtc = [DateTime]::UtcNow.ToString('o')
    $state = [ordered]@{
        SchemaVersion          = 4
        Complete               = $firewallReady
        CompletedAtUtc         = $completedAtUtc
        AllowedModelRequested  = $AllowedModel
        ResolvedModelKey       = ''
        ResolvedModelPathSha256 = ''
        ExpectedModelRepository = [string]$deploymentConfig.UserRepo
        ModelValidationPending = $true
        ProvisioningMode       = 'ManagedSymbolicLink'
        ManagedModelLinkPath   = [string]$modelRegistration.LinkPath
        ModelFormat            = 'gguf'
        RequiredRuntime        = $RequiredRuntime
        OmitLoadEstimate        = [bool]$SkipLoadEstimate
        LoadEstimateChecked    = $false
        Firewall = [ordered]@{
            ProjectFirewall  = [string]$deploymentConfig.ProjectFirewall
            Mode             = $effectiveFirewallMode
            Configured       = $firewallConfigured
            ExternallyManaged = $firewallExternallyManaged
            RuleGroup       = $script:FirewallGroup
            RuleCount       = $firewallRuleCount
            ProgramCount    = $programPaths.Count
            LoopbackIPv4    = '127.0.0.0/8'
            LoopbackIPv6    = '::1'
            ProgramPaths    = @($programPaths)
            LastVerifiedAtUtc = if ($firewallConfigured) { $completedAtUtc } else { '' }
        }
        Settings = [ordered]@{
            SettingsPath    = $settingsPath
            McpPath         = $mcpPath
            HttpServerConfigPath = $httpServerConfigPath
            SettingsChanged = $jsonUpdate.SettingsChanged
            McpChanged      = $jsonUpdate.McpChanged
            HttpServerConfigChanged = $jsonUpdate.HttpServerConfigChanged
            BackupPath     = $jsonUpdate.BackupPath
        }
        RuntimeInventorySha256 = ''
        LogPath                = $script:LogPath
        SecurityNote           = if ($firewallConfigured) {
            'Internal JSON settings are defense-in-depth; project-managed Windows Firewall rules are the enforced network boundary.'
        }
        elseif ($firewallExternallyManaged) {
            'Network enforcement is delegated to the organization and is not verified by this project; internal JSON settings are defense-in-depth only.'
        }
        else {
            'Network enforcement is incomplete; internal JSON settings are defense-in-depth only.'
        }
    }

    $statePath = Join-Path $script:SetupRoot 'setup-state.json'
    Write-SetupState -StatePath $statePath -State $state
    $script:CreatedManagedModelLink = $null
    Write-SetupLog -Level OK -Message "状態ファイルを保存しました: $statePath"

    if ($firewallConfigured) {
        Write-SetupLog -Level OK -Message '初期セットアップが完了しました。LM Studio は起動していません。'
    }
    elseif ($firewallExternallyManaged) {
        Write-SetupLog -Level WARN -Message '初期セットアップは完了しました。本プロジェクトのFirewall規則はOFFです。会社・組織側の通信保護を確認してください。'
    }
    else {
        Write-SetupLog -Level WARN -Message 'JSON 設定は完了しましたが、Firewall が未設定のため安全セットアップは未完成です。'
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' LM Studio secure setup result'
    Write-Host ' Model     : PENDING FIRST SECURE LAUNCH'
    $firewallSummary = if ($firewallConfigured) { 'ON / LOCALHOST ONLY' } elseif ($firewallExternallyManaged) { 'OFF / EXTERNAL PROTECTION NOT VERIFIED HERE' } else { 'SKIPPED / INCOMPLETE' }
    Write-Host (' Firewall  : {0}' -f $firewallSummary)
    Write-Host ' Public API: AUTOSTART OFF / LOOPBACK ONLY'
    Write-Host ' MCP        : EMPTY'
    Write-Host ' Local svc  : DISABLED'
    Write-Host (' State      : {0}' -f $statePath)
    Write-Host (' Log        : {0}' -f $script:LogPath)
    Write-Host '============================================================'
}

Invoke-FirewallOnlyMode

$mainExitCode = 0
try {
    Invoke-MainSetup
}
catch {
    $setupError = $_
    Remove-CreatedManagedModelLink
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Write-SetupLog -Level ERROR -Message $setupError.Exception.Message
        Write-SetupLog -Level ERROR -Message 'セットアップは完了していません。上記の原因を解消して再実行してください。'
    }
    else {
        Write-Error $setupError.Exception.Message
    }
    $mainExitCode = 1
}
finally {
    Exit-SetupMutex
}
exit $mainExitCode
