#Requires -Version 5.1

<#
.SYNOPSIS
    Setup-LMStudio.ps1 で準備した LM Studio を、安全な日常利用モードで起動します。

.DESCRIPTION
    ネットワーク保護の管理方法と設定を起動前に確認し、モデル関連項目は通常ユーザーでGUIを起動した直後、
    モデルをロードする前に確認します。1つでも不一致があればロードを完了しません。

    - setup-state.json が完全なセットアップ結果であること
    - LM Studio を管理者権限で起動しようとしていないこと
    - 現在の実行ファイルがセットアップ時の記録にすべて含まれること
    - ProjectManaged の場合、各実行ファイルの送受信 Firewall 規則が有効で、
      ループバック以外を遮断すること
    - ExternallyManaged の場合、保護の実効性を本プロジェクトで検証済みと表示しないこと
    - settings.json の安全設定と、空の mcpServers が復元できること
    - 指定モデルだけがローカル LLM として存在すること
    - Runtime 構成がセットアップ時から変化していないこと
    - 指定モデルを指定した Context Length / GPU 条件で見積もれること

    検査後、LM Studio GUI を通常ユーザー権限で起動し、ロード済みモデルをすべて解除して
    承認モデルだけをロードします。最後に `lms ps --json` でロード状態を再確認します。

    モデル・Runtime・アプリのダウンロードや更新は行いません。ローカル API Server も
    起動しません。ProjectManaged の Firewall 監査に管理者権限が必要な環境では、監査専用の短い子プロセス
    だけを昇格させ、LM Studio 本体は昇格しません。

    公式資料（2026-08-19 確認）:
      https://lmstudio.ai/docs/app/offline
      https://lmstudio.ai/docs/cli/local-models/load
      https://lmstudio.ai/docs/cli/local-models/ps

.PARAMETER ContextLength
    モデルの Context Length。既定値は 8192 です。

.PARAMETER Identifier
    LM Studio 内で承認モデルに付ける識別名。既定値は approved-model です。

.PARAMETER Gpu
    GPU オフロード指定。off、max、または 0～1 の数値文字列を指定します。
    省略時は LM Studio の自動判断に任せます。

.PARAMETER StartupTimeoutSeconds
    GUI が CLI 接続可能になるまで待つ最大秒数。既定値は 90 秒です。

.PARAMETER LmStudioHome
    LM Studio のユーザーデータディレクトリ。既定値は %USERPROFILE%\.lmstudio です。

.PARAMETER LmStudioExePath
    LM Studio.exe のパス。通常は setup-state.json と標準場所から自動解決します。

.PARAMETER SetupStatePath
    Setup-LMStudio.ps1 が生成した状態ファイル。既定値は
    %USERPROFILE%\.lmstudio\secure-setup\setup-state.json です。

.EXAMPLE
    .\Start-LMStudio-Secure.ps1

.EXAMPLE
    .\Start-LMStudio-Secure.ps1 -ContextLength 8192 -Gpu max

.NOTES
    LM Studio または llmster が既に起動中の場合は処理を中止します。
    LM Studio / Runtime の更新後は Setup-LMStudio.ps1 を再実行してください。
#>

[CmdletBinding()]
param(
    [ValidateRange(256, 1048576)]
    [int]$ContextLength = 8192,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Identifier = 'approved-model',

    [string]$Gpu,

    [ValidateRange(15, 300)]
    [int]$StartupTimeoutSeconds = 90,

    [ValidateNotNullOrEmpty()]
    [string]$LmStudioHome = (Join-Path $env:USERPROFILE '.lmstudio'),

    [string]$LmStudioExePath,
    [string]$SetupStatePath,

    # 以下は Firewall 監査用の昇格子プロセスだけが使用します。
    [switch]$FirewallAuditOnly,
    [string]$FirewallAuditRequestPath,
    [string]$FirewallAuditRequestSha256,
    [string]$SharedLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:LogPath = $null
$script:SetupRoot = $null
$script:LmsPathForCleanup = $null
$script:StartedGuiProcess = $null
$script:GuiStarted = $false
$script:ModelLoadAttempted = $false
$script:LaunchSucceeded = $false
$script:FirewallAuditMaxAgeHours = 24
$script:FirewallGroup = 'LM Studio Secure Local-Only'
$script:NonLoopbackRemoteAddresses = @(
    '0.0.0.0-126.255.255.255',
    '128.0.0.0-255.255.255.255',
    '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
)

function Write-LaunchLog {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')][string]$Level = 'INFO'
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

function Initialize-LaunchLogging {
    param(
        [Parameter(Mandatory = $true)][string]$SetupRoot,
        [string]$ExistingLogPath
    )

    if (-not (Test-Path -LiteralPath $SetupRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $SetupRoot -Force | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($ExistingLogPath)) {
        $script:LogPath = [IO.Path]::GetFullPath($ExistingLogPath)
        return
    }

    $logDirectory = Join-Path $SetupRoot 'logs'
    if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    }

    $script:LogPath = Join-Path $logDirectory (
        'Start-LMStudio-Secure-{0}-{1}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), $PID
    )
    [IO.File]::WriteAllText(
        $script:LogPath,
        '',
        (New-Object Text.UTF8Encoding($false))
    )
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

    $normalized = $Path.Trim().Replace('/', '\').TrimEnd('\').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw 'モデルのパス識別子を正規化できません。'
    }
    return Get-StringSha256 -Value $normalized
}

function Assert-ManagedModelLink {
    param(
        [Parameter(Mandatory = $true)][string]$LinkPath,
        [Parameter(Mandatory = $true)][string]$LmStudioHomePath
    )

    $managedRoot = [IO.Path]::GetFullPath(
        (Join-Path $LmStudioHomePath 'models\secure-deployment')
    ).TrimEnd('\') + '\'
    $resolvedLinkPath = [IO.Path]::GetFullPath($LinkPath)
    if (-not $resolvedLinkPath.StartsWith($managedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw '管理対象モデルリンクがプロジェクト専用モデル領域の外を指しています。'
    }
    if (-not (Test-Path -LiteralPath $resolvedLinkPath)) {
        throw '管理対象の共有モデルリンクまたはリンク先が利用できません。'
    }

    $item = Get-Item -LiteralPath $resolvedLinkPath -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -or
        [string]$item.LinkType -ne 'SymbolicLink') {
        throw '管理対象モデルの配置先がシンボリックリンクではありません。'
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
    $raw = [IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "JSON ファイルが空です: $Path"
    }
    try {
        $value = $raw | ConvertFrom-Json
    }
    catch {
        throw "JSON の解析に失敗しました: $Path`n$($_.Exception.Message)"
    }
    if ($null -eq $value -or $value -is [Array]) {
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
    try {
        [IO.File]::WriteAllText(
            $tempPath,
            (ConvertTo-JsonText -InputObject $InputObject),
            (New-Object Text.UTF8Encoding($false))
        )
        $null = Read-JsonFile -Path $tempPath
        return $tempPath
    }
    catch {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) {
            [IO.File]::Delete($tempPath)
        }
        throw
    }
}

function Commit-TempFile {
    param(
        [Parameter(Mandatory = $true)][string]$TempPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (-not (Test-Path -LiteralPath $DestinationPath -PathType Leaf)) {
        [IO.File]::Move($TempPath, $DestinationPath)
        return
    }

    $replaceBackupPath = '{0}.replace-backup.{1}.{2}' -f (
        $DestinationPath,
        $PID,
        ([guid]::NewGuid().ToString('N'))
    )
    $replaceSucceeded = $false
    try {
        [IO.File]::Replace($TempPath, $DestinationPath, $replaceBackupPath, $true)
        $replaceSucceeded = $true
    }
    finally {
        if ($replaceSucceeded -and (Test-Path -LiteralPath $replaceBackupPath -PathType Leaf)) {
            try { [IO.File]::Delete($replaceBackupPath) } catch { }
        }
    }
}

function Test-EmptyObject {
    param([AllowNull()][object]$InputObject)

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [Collections.IDictionary]) {
        return ($InputObject.Count -eq 0)
    }
    return (@($InputObject.PSObject.Properties).Count -eq 0)
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

function Get-LMStudioExecutablePath {
    param(
        [string]$RequestedPath,
        [Parameter(Mandatory = $true)][object]$SetupState
    )

    $candidates = New-Object Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace($RequestedPath)) {
        $candidates.Add($RequestedPath)
    }

    $firewallState = Get-PropertyValue -InputObject $SetupState -Name 'Firewall'
    foreach ($programPath in @((Get-PropertyValue -InputObject $firewallState -Name 'ProgramPaths'))) {
        if ([IO.Path]::GetFileName([string]$programPath) -ieq 'LM Studio.exe') {
            $candidates.Add([string]$programPath)
        }
    }
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'Programs\LM Studio\LM Studio.exe'))
    $candidates.Add((Join-Path $env:LOCALAPPDATA 'LM Studio\LM Studio.exe'))

    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and
            (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return [IO.Path]::GetFullPath($candidate)
        }
    }
    throw 'LM Studio.exe を解決できません。Setup-LMStudio.ps1 を再実行してください。'
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
    $paths = New-Object Collections.Generic.List[string]
    $paths.Add([IO.Path]::GetFullPath($ExePath))

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
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
    $results = New-Object Collections.Generic.List[object]
    foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) {
        $isCandidateName = $process.ProcessName -in @('LM Studio', 'llmster', 'lms', 'llama-server')
        $processPath = $null
        try { $processPath = $process.Path } catch { }
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
    # Windows PowerShell 5.1 cannot directly array-wrap an empty List[object].
    return $results.ToArray()
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )

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

function ConvertFrom-NetstatListeningEndpoints {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][int[]]$ProcessIds
    )

    $results = New-Object Collections.Generic.List[object]
    foreach ($line in @($Text -split "`r?`n")) {
        $match = [regex]::Match($line, '^\s*TCP\s+(\S+)\s+\S+\s+\S+\s+(\d+)\s*$', 'IgnoreCase')
        if (-not $match.Success) { continue }

        $processId = [int]$match.Groups[2].Value
        if ($processId -notin $ProcessIds) { continue }

        $localEndpoint = $match.Groups[1].Value
        $endpointMatch = [regex]::Match($localEndpoint, '^\[(.+)\]:(\d+)$')
        if (-not $endpointMatch.Success) {
            $endpointMatch = [regex]::Match($localEndpoint, '^(.+):(\d+)$')
        }
        if (-not $endpointMatch.Success) {
            throw "待受けアドレスを解析できません: $localEndpoint"
        }

        $address = $null
        if (-not [Net.IPAddress]::TryParse($endpointMatch.Groups[1].Value, [ref]$address)) {
            throw "待受けIPアドレスを解析できません: $localEndpoint"
        }
        if (-not [Net.IPAddress]::IsLoopback($address)) {
            $results.Add([pscustomobject]@{
                Address   = $address.ToString()
                Port      = [int]$endpointMatch.Groups[2].Value
                ProcessId = $processId
            })
        }
    }
    return $results.ToArray()
}

function Assert-LMStudioListensOnlyOnLoopback {
    param(
        [Parameter(Mandatory = $true)][string]$ExePath,
        [Parameter(Mandatory = $true)][string]$HomePath
    )

    $processes = @(Get-RunningLMStudioProcesses -ExePath $ExePath -HomePath $HomePath)
    if ($processes.Count -eq 0) {
        throw '待受け確認対象のLM Studio関連プロセスがありません。'
    }

    $netstatPath = Join-Path $env:SystemRoot 'System32\netstat.exe'
    if (-not (Test-Path -LiteralPath $netstatPath -PathType Leaf)) {
        throw 'Windowsの待受け確認コマンドが見つかりません。'
    }
    $netstat = Invoke-NativeCapture -FilePath $netstatPath -ArgumentList @('-ano', '-p', 'tcp')
    if ($netstat.ExitCode -ne 0) {
        throw 'LM Studioのネットワーク待受け状態を確認できません。'
    }

    $nonLoopback = @(ConvertFrom-NetstatListeningEndpoints `
        -Text $netstat.Text `
        -ProcessIds @($processes.Id))
    if ($nonLoopback.Count -gt 0) {
        $summary = ($nonLoopback | ForEach-Object {
            '{0}:{1} (PID {2})' -f $_.Address, $_.Port, $_.ProcessId
        }) -join ', '
        throw "LM Studio関連プロセスがlocalhost以外で待受けています: $summary"
    }
    Write-LaunchLog -Level OK -Message 'LM Studio関連プロセスのTCP待受けがlocalhost内に限定されていることを確認しました。'
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
        throw 'CLI 出力から JSON を抽出できませんでした。'
    }
    throw "CLI の JSON 出力を解析できませんでした: $lastParseError"
}

function Test-IsAccessDeniedError {
    param([Parameter(Mandatory = $true)][Management.Automation.ErrorRecord]$ErrorRecord)

    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [UnauthorizedAccessException] -or
            $exception.HResult -eq -2147024891 -or
            $exception.Message -match '(?i)access.*denied|アクセス.*拒否') {
            return $true
        }
        $exception = $exception.InnerException
    }
    return $false
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
        throw ('ローカル Firewall 規則がポリシーで無効です: {0}' -f
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

function Test-FirewallAuditIsRecent {
    param(
        [string]$VerifiedAtUtc,
        [int]$MaxAgeHours = 24
    )

    if ([string]::IsNullOrWhiteSpace($VerifiedAtUtc) -or $MaxAgeHours -lt 1) {
        return $false
    }
    try {
        $verified = [DateTime]::Parse(
            $VerifiedAtUtc,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        ).ToUniversalTime()
    }
    catch {
        return $false
    }
    $ageHours = [DateTime]::UtcNow.Subtract($verified).TotalHours
    return ($ageHours -ge (-5.0 / 60.0) -and $ageHours -le $MaxAgeHours)
}

function Get-FirewallManagementState {
    param([AllowNull()][object]$FirewallState)

    if ($null -eq $FirewallState) {
        throw 'setup-state.json にFirewall管理状態がありません。Setup-LMStudio.ps1を再実行してください。'
    }

    $configured = (Get-PropertyValue -InputObject $FirewallState -Name 'Configured') -eq $true
    $externallyManaged = (Get-PropertyValue -InputObject $FirewallState -Name 'ExternallyManaged') -eq $true
    $mode = [string](Get-PropertyValue -InputObject $FirewallState -Name 'Mode')

    # Schema 4 の初期版には Mode がありません。完成済みの旧状態は
    # ProjectManaged としてのみ引き継ぎ、保護の弱い推測はしません。
    if ([string]::IsNullOrWhiteSpace($mode)) {
        if ($configured -and -not $externallyManaged) {
            $mode = 'ProjectManaged'
        }
        else {
            throw 'Firewall管理方法を判定できません。Setup-LMStudio.ps1を再実行してください。'
        }
    }

    switch ($mode) {
        'ProjectManaged' {
            if (-not $configured -or $externallyManaged) {
                throw 'ProjectManaged のFirewall状態が矛盾しています。Setup-LMStudio.ps1を再実行してください。'
            }
        }
        'ExternallyManaged' {
            if ($configured -or -not $externallyManaged) {
                throw 'ExternallyManaged のFirewall状態が矛盾しています。Setup-LMStudio.ps1を再実行してください。'
            }
        }
        default {
            throw 'setup-state.json のFirewall管理方法を認識できません。Setup-LMStudio.ps1を再実行してください。'
        }
    }

    return [pscustomobject]@{
        Mode              = $mode
        ProjectManaged    = ($mode -eq 'ProjectManaged')
        ExternallyManaged = ($mode -eq 'ExternallyManaged')
    }
}

function Test-LMStudioFirewallRules {
    param([Parameter(Mandatory = $true)][string[]]$ProgramPaths)

    Assert-FirewallEnvironment
    $verifiedCount = 0
    foreach ($programPath in ($ProgramPaths | Sort-Object -Unique)) {
        $pathHash = (Get-StringSha256 -Value $programPath).Substring(0, 16)
        foreach ($direction in @('Outbound', 'Inbound')) {
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

function Invoke-FirewallAuditWithElevation {
    param(
        [Parameter(Mandatory = $true)][string[]]$ProgramPaths,
        [Parameter(Mandatory = $true)][string]$SetupRoot,
        [Parameter(Mandatory = $true)][string]$LogPath
    )

    try {
        return (Test-LMStudioFirewallRules -ProgramPaths $ProgramPaths)
    }
    catch {
        if (-not (Test-IsAccessDeniedError -ErrorRecord $_)) { throw }
        Write-LaunchLog -Message 'Firewall の読み取りに管理者権限が必要なため、監査専用の確認画面を表示します。'
    }

    $requestPath = Join-Path $SetupRoot ('firewall-audit-{0}.json' -f ([guid]::NewGuid().ToString('N')))
    $request = [ordered]@{
        SchemaVersion = 1
        CreatedAtUtc  = [DateTime]::UtcNow.ToString('o')
        ProgramPaths  = @($ProgramPaths)
    }
    $requestTemp = Write-ValidatedJsonTempFile -DestinationPath $requestPath -InputObject $request
    Commit-TempFile -TempPath $requestTemp -DestinationPath $requestPath
    $requestHash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()

    try {
        if ([string]::IsNullOrWhiteSpace($PSCommandPath) -or
            -not (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
            throw 'スクリプト自身のパスを解決できないため、Firewall 監査を昇格できません。'
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

        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass',
            '-File', ('"{0}"' -f $PSCommandPath),
            '-FirewallAuditOnly',
            '-FirewallAuditRequestPath', ('"{0}"' -f $requestPath),
            '-FirewallAuditRequestSha256', $requestHash,
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
            throw "管理者プロセスでの Firewall 監査に失敗しました。終了コード: $($process.ExitCode)"
        }
        return ($ProgramPaths.Count * 2)
    }
    finally {
        if (Test-Path -LiteralPath $requestPath -PathType Leaf) {
            [IO.File]::Delete($requestPath)
        }
    }
}

function Invoke-FirewallAuditOnlyMode {
    if (-not $FirewallAuditOnly) { return }

    try {
        if (-not (Test-IsAdministrator)) {
            throw 'FirewallAuditOnly モードは管理者権限で実行する必要があります。'
        }
        if ([string]::IsNullOrWhiteSpace($FirewallAuditRequestPath) -or
            $FirewallAuditRequestSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Firewall 監査要求の引数が不足しているか、形式が不正です。'
        }

        $requestPath = [IO.Path]::GetFullPath($FirewallAuditRequestPath)
        Initialize-LaunchLogging -SetupRoot (Split-Path -Parent $requestPath) -ExistingLogPath $SharedLogPath
        $actualHash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if (-not [string]::Equals(
            $actualHash,
            $FirewallAuditRequestSha256.ToLowerInvariant(),
            [StringComparison]::Ordinal
        )) {
            throw 'Firewall 監査要求ファイルのハッシュが一致しません。'
        }

        $request = Read-JsonFile -Path $requestPath
        if ((Get-PropertyValue -InputObject $request -Name 'SchemaVersion') -ne 1) {
            throw 'Firewall 監査要求のバージョンを認識できません。'
        }
        $createdAt = [DateTime]::Parse(
            [string](Get-PropertyValue -InputObject $request -Name 'CreatedAtUtc'),
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind
        )
        if ([DateTime]::UtcNow.Subtract($createdAt.ToUniversalTime()).TotalMinutes -gt 15) {
            throw 'Firewall 監査要求の有効期限（15分）が切れています。'
        }
        $programPaths = @((Get-PropertyValue -InputObject $request -Name 'ProgramPaths'))
        if ($programPaths.Count -eq 0) { throw 'Firewall 監査対象が空です。' }

        $count = Test-LMStudioFirewallRules -ProgramPaths $programPaths
        Write-LaunchLog -Level OK -Message "管理者プロセスで Firewall 規則を監査しました: $count 件"
        exit 0
    }
    catch {
        Write-LaunchLog -Level ERROR -Message $_.Exception.Message
        exit 1
    }
}

function Set-HardenedJsonState {
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
        if ((Get-PropertyValue -InputObject $settings -Name $entry.Key) -ne $entry.Value) {
            Set-JsonProperty -InputObject $settings -Name $entry.Key -Value $entry.Value
            $settingsChanged = $true
        }
    }
    foreach ($entry in $desiredDeveloper.GetEnumerator()) {
        if ((Get-PropertyValue -InputObject $developer -Name $entry.Key) -ne $entry.Value) {
            Set-JsonProperty -InputObject $developer -Name $entry.Key -Value $entry.Value
            $settingsChanged = $true
        }
    }

    $mcpExisted = Test-Path -LiteralPath $McpPath -PathType Leaf
    $mcp = if ($mcpExisted) { Read-JsonFile -Path $McpPath } else { [pscustomobject]@{} }
    $mcpChanged = -not (Test-EmptyObject -InputObject (
        Get-PropertyValue -InputObject $mcp -Name 'mcpServers'
    ))
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
        Write-LaunchLog -Level OK -Message 'LM Studio の内部設定、MCP、公開APIサーバー設定は既に安全状態です。'
        return [pscustomobject]@{ Changed = $false; BackupPath = $null }
    }

    $backupDirectory = Join-Path $BackupRoot (
        'launch-{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    )
    New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
    $settingsBackup = Join-Path $backupDirectory 'settings.json'
    [IO.File]::Copy($SettingsPath, $settingsBackup, $false)
    $mcpBackup = Join-Path $backupDirectory 'mcp.json'
    if ($mcpExisted) { [IO.File]::Copy($McpPath, $mcpBackup, $false) }
    $httpServerConfigBackup = Join-Path $backupDirectory 'http-server-config.json'
    if ($httpServerConfigExisted) {
        [IO.File]::Copy($HttpServerConfigPath, $httpServerConfigBackup, $false)
    }

    $manifest = [ordered]@{
        SchemaVersion       = 1
        CreatedAtUtc        = [DateTime]::UtcNow.ToString('o')
        Reason              = 'Secure launcher restored hardened settings before launch.'
        SettingsSha256      = (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256).Hash.ToLowerInvariant()
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
    $manifestPath = Join-Path $backupDirectory 'backup-manifest.json'
    $manifestTemp = Write-ValidatedJsonTempFile -DestinationPath $manifestPath -InputObject $manifest
    Commit-TempFile -TempPath $manifestTemp -DestinationPath $manifestPath

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
            throw 'mcp.json の検証に失敗しました。'
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
        Write-LaunchLog -Level ERROR -Message '設定更新に失敗したため、起動前バックアップから復元します。'
        if ($settingsCommitted) { [IO.File]::Copy($settingsBackup, $SettingsPath, $true) }
        if ($mcpCommitted) {
            if ($mcpExisted) { [IO.File]::Copy($mcpBackup, $McpPath, $true) }
            elseif (Test-Path -LiteralPath $McpPath -PathType Leaf) { [IO.File]::Delete($McpPath) }
        }
        if ($httpServerConfigCommitted) {
            [IO.File]::Copy($httpServerConfigBackup, $HttpServerConfigPath, $true)
        }
        throw
    }
    finally {
        foreach ($temp in @($settingsTemp, $mcpTemp, $httpServerConfigTemp)) {
            if (-not [string]::IsNullOrWhiteSpace($temp) -and
                (Test-Path -LiteralPath $temp -PathType Leaf)) {
                [IO.File]::Delete($temp)
            }
        }
    }

    Write-LaunchLog -Level WARN -Message "設定の変化を検出し、安全状態へ復元しました。バックアップ: $backupDirectory"
    return [pscustomobject]@{ Changed = $true; BackupPath = $backupDirectory }
}

function Find-ApprovedModel {
    param(
        [Parameter(Mandatory = $true)][object[]]$Models,
        [Parameter(Mandatory = $true)][string]$AllowedModelKey,
        [Parameter(Mandatory = $true)][string]$ExpectedModelPathSha256
    )

    $matches = New-Object Collections.Generic.List[object]
    foreach ($model in $Models) {
        $identifiers = @(
            (Get-PropertyValue -InputObject $model -Name 'modelKey'),
            (Get-PropertyValue -InputObject $model -Name 'path'),
            (Get-PropertyValue -InputObject $model -Name 'indexedModelIdentifier'),
            (Get-PropertyValue -InputObject $model -Name 'selectedVariant')
        ) + @((Get-PropertyValue -InputObject $model -Name 'variants'))
        if (@($identifiers | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_) -and
            [string]::Equals([string]$_, $AllowedModelKey, [StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0) {
            $matches.Add($model)
        }
    }
    if ($matches.Count -ne 1) {
        throw "承認モデルの一致数が1ではありません: $AllowedModelKey / $($matches.Count) 件"
    }
    $model = $matches[0]
    if ((Get-PropertyValue -InputObject $model -Name 'type') -ne 'llm') {
        throw "承認対象は LLM ではありません: $AllowedModelKey"
    }
    $actualModelPath = [string](Get-PropertyValue -InputObject $model -Name 'path')
    $actualModelPathHash = Get-ModelPathIdentitySha256 -Path $actualModelPath
    if (-not [string]::Equals(
        $actualModelPathHash,
        $ExpectedModelPathSha256,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw '承認モデルのローカルパスがセットアップ時から変化しています。'
    }
    return $model
}

function Find-ProvisionedModel {
    param(
        [Parameter(Mandatory = $true)][object[]]$Models,
        [Parameter(Mandatory = $true)][string]$ExpectedRepository
    )

    if ($ExpectedRepository -notmatch '^secure-deployment/[A-Za-z0-9._-]+$') {
        throw 'セットアップ状態のモデル配置名が不正です。'
    }
    $prefix = $ExpectedRepository.TrimEnd('/') + '/'
    $matches = @($Models | Where-Object {
        if ((Get-PropertyValue -InputObject $_ -Name 'type') -ne 'llm') { return $false }
        $identities = @(
            [string](Get-PropertyValue -InputObject $_ -Name 'path'),
            [string](Get-PropertyValue -InputObject $_ -Name 'indexedModelIdentifier')
        )
        return @($identities | Where-Object {
            [string]::Equals($_, $ExpectedRepository, [StringComparison]::OrdinalIgnoreCase) -or
            $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
        }).Count -gt 0
    })
    if ($matches.Count -ne 1) {
        throw "セットアップが登録した共有LLMの一致数が1ではありません: $($matches.Count) 件"
    }
    return $matches[0]
}

function Assert-NoAdditionalLlms {
    param(
        [Parameter(Mandatory = $true)][object[]]$Models,
        [Parameter(Mandatory = $true)][string]$AllowedModelKey
    )

    $otherLlms = @($Models | Where-Object {
        (Get-PropertyValue -InputObject $_ -Name 'type') -eq 'llm' -and
        -not [string]::Equals(
            [string](Get-PropertyValue -InputObject $_ -Name 'modelKey'),
            $AllowedModelKey,
            [StringComparison]::OrdinalIgnoreCase
        )
    })
    if ($otherLlms.Count -gt 0) {
        $keys = $otherLlms | ForEach-Object { Get-PropertyValue -InputObject $_ -Name 'modelKey' }
        throw "承認されていないローカル LLM を検出しました: $($keys -join ', ')"
    }
}

function Test-LoadedModelMatches {
    param(
        [Parameter(Mandatory = $true)][object]$LoadedModel,
        [Parameter(Mandatory = $true)][string]$AllowedModelKey,
        [Parameter(Mandatory = $true)][string]$ExpectedModelPathSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedIdentifier
    )

    $keyIdentityValues = @(
        (Get-PropertyValue -InputObject $LoadedModel -Name 'modelKey'),
        (Get-PropertyValue -InputObject $LoadedModel -Name 'indexedModelIdentifier')
    )
    $keyMatches = @($keyIdentityValues | Where-Object {
        -not [string]::IsNullOrWhiteSpace([string]$_) -and
        [string]::Equals([string]$_, $AllowedModelKey, [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0

    $pathMatches = $false
    $loadedPath = [string](Get-PropertyValue -InputObject $LoadedModel -Name 'path')
    if (-not [string]::IsNullOrWhiteSpace($loadedPath)) {
        $loadedPathHash = Get-ModelPathIdentitySha256 -Path $loadedPath
        $pathMatches = [string]::Equals(
            $loadedPathHash,
            $ExpectedModelPathSha256,
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    if (-not ($keyMatches -or $pathMatches)) { return $false }

    $actualIdentifier = [string](Get-PropertyValue -InputObject $LoadedModel -Name 'identifier')
    return [string]::Equals(
        $actualIdentifier,
        $ExpectedIdentifier,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Wait-ForLmStudioGui {
    param(
        [Parameter(Mandatory = $true)][string]$LmsPath,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $nextProgressLog = [DateTime]::UtcNow
    while ([DateTime]::UtcNow -lt $deadline) {
        $statusResult = Invoke-NativeCapture -FilePath $LmsPath -ArgumentList @('daemon', 'status', '--json')
        if ($statusResult.ExitCode -eq 0) {
            try {
                $status = ConvertFrom-NativeJson -Text $statusResult.Text -ExpectedRoot Object
                if ((Get-PropertyValue -InputObject $status -Name 'status') -eq 'running') {
                    if ((Get-PropertyValue -InputObject $status -Name 'isDaemon') -eq $true) {
                        throw 'GUI ではなく llmster が起動しました。'
                    }
                    return $status
                }
            }
            catch {
                if ($_.Exception.Message -eq 'GUI ではなく llmster が起動しました。') { throw }
            }
        }
        if ([DateTime]::UtcNow -ge $nextProgressLog) {
            Write-LaunchLog -Message 'LM Studio GUI の準備完了を待っています。'
            $nextProgressLog = [DateTime]::UtcNow.AddSeconds(10)
        }
        Start-Sleep -Seconds 1
    }
    throw "LM Studio GUI が $TimeoutSeconds 秒以内に準備完了しませんでした。"
}

function Invoke-FailureCleanup {
    if ($script:ModelLoadAttempted -and
        -not [string]::IsNullOrWhiteSpace($script:LmsPathForCleanup) -and
        (Test-Path -LiteralPath $script:LmsPathForCleanup -PathType Leaf)) {
        try {
            $result = Invoke-NativeCapture -FilePath $script:LmsPathForCleanup -ArgumentList @('unload', '--all')
            if ($result.ExitCode -eq 0) {
                Write-LaunchLog -Level WARN -Message '失敗後の安全処理として、ロード済みモデルを解除しました。'
            }
        }
        catch {
            Write-LaunchLog -Level ERROR -Message '失敗後にロード済みモデルを解除できませんでした。'
        }
    }

    if ($script:GuiStarted -and $null -ne $script:StartedGuiProcess) {
        try {
            $script:StartedGuiProcess.Refresh()
            if (-not $script:StartedGuiProcess.HasExited) {
                $closeRequested = $script:StartedGuiProcess.CloseMainWindow()
                if ($closeRequested) {
                    $null = $script:StartedGuiProcess.WaitForExit(10000)
                    Write-LaunchLog -Level WARN -Message '起動失敗後、LM Studio GUI に通常終了を要求しました。'
                }
                else {
                    Write-LaunchLog -Level ERROR -Message 'LM Studio GUI を自動終了できません。手動で終了してください。'
                }
            }
        }
        catch {
            Write-LaunchLog -Level ERROR -Message 'LM Studio GUI の終了確認に失敗しました。手動で終了してください。'
        }
    }
}

function Invoke-MainLaunch {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'このスクリプトは Windows 専用です。'
    }
    if (Test-IsAdministrator) {
        throw 'LM Studio を昇格して起動しないため、このスクリプトは通常ユーザー権限で実行してください。'
    }
    if (-not [string]::IsNullOrWhiteSpace($Gpu) -and
        $Gpu -notmatch '^(?i:off|max|0(?:\.\d+)?|1(?:\.0+)?)$') {
        throw '-Gpu は off、max、または 0～1 の数値で指定してください。'
    }

    $homePath = [IO.Path]::GetFullPath($LmStudioHome)
    $script:SetupRoot = Join-Path $homePath 'secure-setup'
    Initialize-LaunchLogging -SetupRoot $script:SetupRoot
    Write-LaunchLog -Message 'LM Studio の安全な日常起動を開始します。'

    $statePath = if ([string]::IsNullOrWhiteSpace($SetupStatePath)) {
        Join-Path $script:SetupRoot 'setup-state.json'
    } else { [IO.Path]::GetFullPath($SetupStatePath) }
    $state = Read-JsonFile -Path $statePath
    if ((Get-PropertyValue -InputObject $state -Name 'SchemaVersion') -ne 4 -or
        (Get-PropertyValue -InputObject $state -Name 'Complete') -ne $true -or
        (Get-PropertyValue -InputObject $state -Name 'ProvisioningMode') -ne 'ManagedSymbolicLink') {
        throw '完全なセットアップ状態がありません。Setup-LMStudio.ps1 を再実行してください。'
    }

    $modelValidationPending = (Get-PropertyValue -InputObject $state -Name 'ModelValidationPending') -eq $true
    $allowedModelKey = [string](Get-PropertyValue -InputObject $state -Name 'ResolvedModelKey')
    $expectedModelPathHash = [string](Get-PropertyValue -InputObject $state -Name 'ResolvedModelPathSha256')
    $expectedModelRepository = [string](Get-PropertyValue -InputObject $state -Name 'ExpectedModelRepository')
    $managedModelLinkPath = [string](Get-PropertyValue -InputObject $state -Name 'ManagedModelLinkPath')
    if ([string]::IsNullOrWhiteSpace($managedModelLinkPath) -or
        ($modelValidationPending -and
            $expectedModelRepository -notmatch '^secure-deployment/[A-Za-z0-9._-]+$') -or
        (-not $modelValidationPending -and (
            [string]::IsNullOrWhiteSpace($allowedModelKey) -or
            $expectedModelPathHash -notmatch '^[0-9a-fA-F]{64}$'
        ))) {
        throw 'setup-state.json に承認モデルが記録されていません。'
    }
    Assert-ManagedModelLink -LinkPath $managedModelLinkPath -LmStudioHomePath $homePath

    $exePath = Get-LMStudioExecutablePath -RequestedPath $LmStudioExePath -SetupState $state
    $lmsPath = Join-Path $homePath 'bin\lms.exe'
    $script:LmsPathForCleanup = $lmsPath
    $settingsPath = Join-Path $homePath 'settings.json'
    $mcpPath = Join-Path $homePath 'mcp.json'
    $httpServerConfigPath = Join-Path $homePath '.internal\http-server-config.json'
    foreach ($requiredPath in @($exePath, $lmsPath, $settingsPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "必要なファイルがありません: $requiredPath"
        }
    }

    $running = @(Get-RunningLMStudioProcesses -ExePath $exePath -HomePath $homePath)
    if ($running.Count -gt 0) {
        $summary = ($running | ForEach-Object { '{0} (PID {1})' -f $_.Name, $_.Id }) -join ', '
        throw "LM Studio 関連プロセスが既に動作中です。完全に終了して再実行してください: $summary"
    }

    $firewallState = Get-PropertyValue -InputObject $state -Name 'Firewall'
    $firewallManagement = Get-FirewallManagementState -FirewallState $firewallState
    $firewallMode = [string]$firewallManagement.Mode
    $stateProgramPaths = @((Get-PropertyValue -InputObject $firewallState -Name 'ProgramPaths'))
    $recordedFirewallRuleCount = Get-PropertyValue -InputObject $firewallState -Name 'RuleCount'
    $recordedFirewallProgramCount = Get-PropertyValue -InputObject $firewallState -Name 'ProgramCount'
    if ($stateProgramPaths.Count -eq 0 -or
        $recordedFirewallProgramCount -ne $stateProgramPaths.Count) {
        throw 'セットアップ状態のLM Studio関連実行ファイル数が整合していません。Setup-LMStudio.ps1を再実行してください。'
    }
    if ($firewallManagement.ProjectManaged -and
        $recordedFirewallRuleCount -ne ($stateProgramPaths.Count * 2)) {
        throw 'セットアップ状態のFirewall規則数が整合していません。Setup-LMStudio.ps1を再実行してください。'
    }
    if ($firewallManagement.ExternallyManaged -and $recordedFirewallRuleCount -ne 0) {
        throw '外部管理の状態に本プロジェクトのFirewall規則数が記録されています。Setup-LMStudio.ps1を再実行してください。'
    }
    $currentProgramPaths = @(Get-LMStudioProgramPaths -ExePath $exePath -HomePath $homePath)
    $auditProgramPaths = New-Object Collections.Generic.List[string]
    $newPrograms = New-Object Collections.Generic.List[string]
    foreach ($currentPath in $currentProgramPaths) {
        $stateMatch = @($stateProgramPaths | Where-Object {
            [string]::Equals([string]$_, $currentPath, [StringComparison]::OrdinalIgnoreCase)
        })
        if ($stateMatch.Count -eq 0) {
            $newPrograms.Add($currentPath)
        }
        else {
            $auditProgramPaths.Add([IO.Path]::GetFullPath([string]$stateMatch[0]))
        }
    }
    if ($newPrograms.Count -gt 0) {
        throw ("セットアップ時に未記録の新しい実行ファイルを検出しました:`n  {0}`n" -f
            ($newPrograms -join "`n  ")) + 'LM Studio / Runtime 更新後は Setup-LMStudio.ps1 を再実行してください。'
    }
    if ($auditProgramPaths.Count -ne $stateProgramPaths.Count) {
        throw 'LM Studio関連実行ファイルの構成がセットアップ時から減少しています。Setup-LMStudio.ps1を再実行してください。'
    }

    if ($firewallManagement.ProjectManaged) {
        $lastFirewallVerifiedAtUtc = [string](Get-PropertyValue -InputObject $firewallState -Name 'LastVerifiedAtUtc')
        if ([string]::IsNullOrWhiteSpace($lastFirewallVerifiedAtUtc)) {
            $lastFirewallVerifiedAtUtc = [string](Get-PropertyValue -InputObject $state -Name 'CompletedAtUtc')
        }
        if (Test-FirewallAuditIsRecent `
            -VerifiedAtUtc $lastFirewallVerifiedAtUtc `
            -MaxAgeHours $script:FirewallAuditMaxAgeHours) {
            $firewallRuleCount = [int]$recordedFirewallRuleCount
            Write-LaunchLog -Level OK -Message (
                "Firewall は直近24時間以内に完全検証済みです。今回は記録と実行ファイルの整合性を確認しました: $firewallRuleCount 件"
            )
        }
        else {
            $firewallRuleCount = Invoke-FirewallAuditWithElevation `
                -ProgramPaths @($auditProgramPaths) `
                -SetupRoot $script:SetupRoot `
                -LogPath $script:LogPath
            $verifiedAtUtc = [DateTime]::UtcNow.ToString('o')
            $firewallState | Add-Member -NotePropertyName LastVerifiedAtUtc -NotePropertyValue $verifiedAtUtc -Force
            $stateTemp = Write-ValidatedJsonTempFile -DestinationPath $statePath -InputObject $state
            Commit-TempFile -TempPath $stateTemp -DestinationPath $statePath
            Write-LaunchLog -Level OK -Message "Firewall のローカル専用規則を完全監査しました: $firewallRuleCount 件"
        }
    }
    else {
        $firewallRuleCount = 0
        Write-LaunchLog -Level WARN -Message 'ネットワーク保護は会社・組織側へ委任されています。本プロジェクトではFirewall/EDR/ネットワークポリシーの実効性を検証していません。'
    }

    $backupRoot = Join-Path $script:SetupRoot 'backups'
    if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    }
    $null = Set-HardenedJsonState `
        -SettingsPath $settingsPath `
        -McpPath $mcpPath `
        -HttpServerConfigPath $httpServerConfigPath `
        -BackupRoot $backupRoot

    Write-LaunchLog -Message 'LM Studio GUI を通常ユーザー権限で起動します。'
    $script:StartedGuiProcess = Start-Process -FilePath $exePath -PassThru
    $script:GuiStarted = $true
    $null = Wait-ForLmStudioGui -LmsPath $lmsPath -TimeoutSeconds $StartupTimeoutSeconds
    Write-LaunchLog -Level OK -Message 'LM Studio GUI が CLI 接続可能になりました。'
    Assert-LMStudioListensOnlyOnLoopback -ExePath $exePath -HomePath $homePath

    $modelsResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList @('ls', '--json')
    if ($modelsResult.ExitCode -ne 0) {
        throw "モデル一覧を取得できません: $($modelsResult.Text)"
    }
    $models = @(ConvertFrom-NativeJson -Text $modelsResult.Text -ExpectedRoot Array)
    if ($modelValidationPending) {
        $approvedModel = Find-ProvisionedModel `
            -Models $models `
            -ExpectedRepository $expectedModelRepository
        $allowedModelKey = [string](Get-PropertyValue -InputObject $approvedModel -Name 'modelKey')
        $approvedModelPath = [string](Get-PropertyValue -InputObject $approvedModel -Name 'path')
        if ([string]::IsNullOrWhiteSpace($allowedModelKey) -or
            [string]::IsNullOrWhiteSpace($approvedModelPath)) {
            throw '自動登録した共有モデルから modelKey またはパス識別子を取得できません。'
        }
        $requestedModelKey = [string](Get-PropertyValue -InputObject $state -Name 'AllowedModelRequested')
        if (-not [string]::IsNullOrWhiteSpace($requestedModelKey) -and
            -not [string]::Equals($requestedModelKey, $allowedModelKey, [StringComparison]::OrdinalIgnoreCase)) {
            throw '自動登録した共有モデルが、セットアップ時の明示modelKeyと一致しません。'
        }
        $expectedModelPathHash = Get-ModelPathIdentitySha256 -Path $approvedModelPath
    }
    else {
        $approvedModel = Find-ApprovedModel `
            -Models $models `
            -AllowedModelKey $allowedModelKey `
            -ExpectedModelPathSha256 $expectedModelPathHash
    }
    Assert-NoAdditionalLlms -Models $models -AllowedModelKey $allowedModelKey
    Write-LaunchLog -Level OK -Message "承認モデルだけが存在することを確認しました: $allowedModelKey"

    $runtimeResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList @('runtime', 'ls')
    if ($runtimeResult.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($runtimeResult.Text)) {
        throw 'Runtime 一覧を取得できません。'
    }
    $actualRuntimeHash = Get-StringSha256 -Value $runtimeResult.Text
    if ($modelValidationPending) {
        $requiredRuntime = [string](Get-PropertyValue -InputObject $state -Name 'RequiredRuntime')
        $modelFormat = [string](Get-PropertyValue -InputObject $approvedModel -Name 'format')
        if (-not [string]::IsNullOrWhiteSpace($requiredRuntime)) {
            if ($runtimeResult.Text.IndexOf($requiredRuntime, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw 'セットアップで要求された Runtime がインストールされていません。'
            }
        }
        if ([string]::IsNullOrWhiteSpace($modelFormat)) {
            throw '共有モデルの形式を確認できません。'
        }
    }
    else {
        $expectedRuntimeHash = [string](Get-PropertyValue -InputObject $state -Name 'RuntimeInventorySha256')
        if ([string]::IsNullOrWhiteSpace($expectedRuntimeHash) -or
            -not [string]::Equals($actualRuntimeHash, $expectedRuntimeHash, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Runtime 構成が初回安全起動時から変化しています。Setup-LMStudio.ps1 を再実行してください。'
        }
    }

    $skipLoadEstimate = (Get-PropertyValue -InputObject $state -Name 'OmitLoadEstimate') -eq $true
    if (-not $skipLoadEstimate) {
        $estimateArguments = @(
            'load', '--estimate-only', $allowedModelKey,
            '--context-length', [string]$ContextLength,
            '-y'
        )
        if (-not [string]::IsNullOrWhiteSpace($Gpu)) {
            $estimateArguments += @('--gpu', $Gpu)
        }
        $estimateResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList $estimateArguments
        if ($estimateResult.ExitCode -ne 0) {
            throw "モデルのロード見積もりに失敗しました: $($estimateResult.Text)"
        }
        Write-LaunchLog -Level OK -Message '指定したロード条件で、モデルと Runtime の互換性を確認しました。'
    }
    else {
        Write-LaunchLog -Level WARN -Message 'セットアップ指定によりロード見積もりを省略しました。'
    }

    $postGuiProgramPaths = @(Get-LMStudioProgramPaths -ExePath $exePath -HomePath $homePath)
    $unprotectedPrograms = @($postGuiProgramPaths | Where-Object {
        $candidate = $_
        @($stateProgramPaths | Where-Object {
            [string]::Equals([string]$_, [string]$candidate, [StringComparison]::OrdinalIgnoreCase)
        }).Count -eq 0
    })
    if ($unprotectedPrograms.Count -gt 0) {
        throw 'GUI起動後にセットアップ時にはなかった実行ファイルを検出しました。Setup-LMStudio.ps1を再実行してください。'
    }

    $script:ModelLoadAttempted = $true
    $unloadResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList @('unload', '--all')
    if ($unloadResult.ExitCode -ne 0) {
        throw "既存のロード済みモデルを解除できません: $($unloadResult.Text)"
    }

    $loadArguments = @(
        'load', $allowedModelKey,
        '--identifier', $Identifier,
        '--context-length', [string]$ContextLength,
        '-y'
    )
    if (-not [string]::IsNullOrWhiteSpace($Gpu)) {
        $loadArguments += @('--gpu', $Gpu)
    }
    $loadResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList $loadArguments
    if ($loadResult.ExitCode -ne 0) {
        throw "承認モデルをロードできません: $($loadResult.Text)"
    }

    $loadedResult = Invoke-NativeCapture -FilePath $lmsPath -ArgumentList @('ps', '--json')
    if ($loadedResult.ExitCode -ne 0) {
        throw "ロード済みモデルを確認できません: $($loadedResult.Text)"
    }
    $loadedModels = @(ConvertFrom-NativeJson -Text $loadedResult.Text -ExpectedRoot Array)
    if ($loadedModels.Count -ne 1) {
        throw "ロード済みモデル数が1ではありません: $($loadedModels.Count)"
    }
    if (-not (Test-LoadedModelMatches `
        -LoadedModel $loadedModels[0] `
        -AllowedModelKey $allowedModelKey `
        -ExpectedModelPathSha256 $expectedModelPathHash `
        -ExpectedIdentifier $Identifier)) {
        throw 'ロードされたモデルが承認モデルと一致しません。'
    }
    Assert-LMStudioListensOnlyOnLoopback -ExePath $exePath -HomePath $homePath

    if ($modelValidationPending) {
        $state | Add-Member -NotePropertyName ResolvedModelKey -NotePropertyValue $allowedModelKey -Force
        $state | Add-Member -NotePropertyName ResolvedModelPathSha256 -NotePropertyValue $expectedModelPathHash -Force
        $state | Add-Member -NotePropertyName ModelFormat -NotePropertyValue ([string](Get-PropertyValue -InputObject $approvedModel -Name 'format')) -Force
        $state | Add-Member -NotePropertyName RuntimeInventorySha256 -NotePropertyValue $actualRuntimeHash -Force
        $state | Add-Member -NotePropertyName ModelValidationPending -NotePropertyValue $false -Force
        $state | Add-Member -NotePropertyName LoadEstimateChecked -NotePropertyValue (-not $skipLoadEstimate) -Force
        $state | Add-Member -NotePropertyName ValidatedAtUtc -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
        $stateTemp = Write-ValidatedJsonTempFile -DestinationPath $statePath -InputObject $state
        Commit-TempFile -TempPath $stateTemp -DestinationPath $statePath
        Write-LaunchLog -Level OK -Message '初回安全起動のモデル・Runtime検証結果を状態ファイルへ確定しました。'
    }

    $lastLaunch = [ordered]@{
        SchemaVersion     = 4
        SucceededAtUtc    = [DateTime]::UtcNow.ToString('o')
        ModelKey          = $allowedModelKey
        ModelPathSha256   = $expectedModelPathHash
        Identifier        = $Identifier
        ContextLength     = $ContextLength
        Gpu               = $Gpu
        GuiProcessId      = $script:StartedGuiProcess.Id
        FirewallMode      = $firewallMode
        FirewallRuleCount = $firewallRuleCount
        PublicApiAutoStart = $false
        TcpListenersLoopbackOnly = $true
        LogPath           = $script:LogPath
    }
    $lastLaunchPath = Join-Path $script:SetupRoot 'last-launch.json'
    $lastLaunchTemp = Write-ValidatedJsonTempFile -DestinationPath $lastLaunchPath -InputObject $lastLaunch
    Commit-TempFile -TempPath $lastLaunchTemp -DestinationPath $lastLaunchPath

    $script:LaunchSucceeded = $true
    Write-LaunchLog -Level OK -Message "承認モデルだけをロードしました: $allowedModelKey"
    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' LM Studio secure launch'
    Write-Host (' Model    : {0}' -f $allowedModelKey)
    Write-Host (' Identifier: {0}' -f $Identifier)
    Write-Host (' Context  : {0}' -f $ContextLength)
    $networkSummary = if ($firewallManagement.ProjectManaged) {
        'LOCALHOST ONLY (PROJECT VERIFIED)'
    }
    else {
        'EXTERNALLY MANAGED / NOT VERIFIED HERE'
    }
    Write-Host (' Network  : {0}' -f $networkSummary)
    Write-Host ' Public API: AUTOSTART OFF / LOOPBACK ONLY'
    Write-Host ' MCP      : EMPTY'
    Write-Host (' Log      : {0}' -f $script:LogPath)
    Write-Host '============================================================'
}

Invoke-FirewallAuditOnlyMode

try {
    Invoke-MainLaunch
    exit 0
}
catch {
    if (-not $script:LaunchSucceeded) {
        Invoke-FailureCleanup
    }
    if (-not [string]::IsNullOrWhiteSpace($script:LogPath)) {
        Write-LaunchLog -Level ERROR -Message $_.Exception.Message
        Write-LaunchLog -Level ERROR -Message '安全条件を満たさないため、起動処理を完了しませんでした。'
    }
    else {
        Write-Error $_.Exception.Message
    }
    exit 1
}
