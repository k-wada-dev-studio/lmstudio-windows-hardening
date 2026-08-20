#Requires -Version 5.1

[CmdletBinding()]
param([string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Passed = 0

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAILED: $Message" }
    $script:Passed++
    Write-Host "PASS: $Message"
}

function Get-TextFiles {
    param([string[]]$Roots)
    $items = @()
    foreach ($root in $Roots) {
        if (Test-Path -LiteralPath $root -PathType Leaf) {
            $items += Get-Item -LiteralPath $root
        }
        elseif (Test-Path -LiteralPath $root -PathType Container) {
            $items += Get-ChildItem -LiteralPath $root -Recurse -File |
                Where-Object { $_.Extension -in @('.ps1', '.psd1', '.cmd', '.json', '.md', '.yml', '.yaml') }
        }
    }
    return @($items | Sort-Object FullName -Unique)
}

$repo = [IO.Path]::GetFullPath($RepoRoot)
$scripts = @(Get-ChildItem -LiteralPath (Join-Path $repo 'src') -Filter '*.ps1' -File)
Assert-True ($scripts.Count -eq 3) 'Exactly three product scripts are present'

foreach ($scriptFile in $scripts) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $scriptFile.FullName,
        [ref]$tokens,
        [ref]$errors
    )
    Assert-True ($errors.Count -eq 0) "$($scriptFile.Name) parses in Windows PowerShell 5.1"

    $bytes = [IO.File]::ReadAllBytes($scriptFile.FullName)
    $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
    Assert-True $hasBom "$($scriptFile.Name) has a UTF-8 BOM for Windows PowerShell 5.1"

    $text = [IO.File]::ReadAllText($scriptFile.FullName)
    foreach ($forbidden in @(
        '(?i)\bInvoke-WebRequest\b',
        '(?i)\bInvoke-RestMethod\b',
        '(?i)\bStart-BitsTransfer\b',
        '(?i)\bStop-Process\b',
        '(?i)\btaskkill(?:\.exe)?\b',
        '(?i)\blms(?:\.exe)?\s+get\b',
        '(?i)\blms(?:\.exe)?\s+runtime\s+get\b'
    )) {
        Assert-True (-not [regex]::IsMatch($text, $forbidden)) "$($scriptFile.Name) excludes forbidden operation $forbidden"
    }
}

$deploymentExample = Join-Path $repo 'config\deployment.local.psd1.example'
$deploymentExampleBytes = [IO.File]::ReadAllBytes($deploymentExample)
$deploymentExampleHasBom = $deploymentExampleBytes.Length -ge 3 -and
    $deploymentExampleBytes[0] -eq 0xEF -and
    $deploymentExampleBytes[1] -eq 0xBB -and
    $deploymentExampleBytes[2] -eq 0xBF
Assert-True $deploymentExampleHasBom 'Deployment configuration example has a UTF-8 BOM for Windows PowerShell 5.1'
$deploymentExampleText = [IO.File]::ReadAllText($deploymentExample)
Assert-True ($deploymentExampleText.Contains("ProjectFirewall = 'ON'")) 'Deployment example defaults ProjectFirewall to ON'
Assert-True ($deploymentExampleText.Contains('OFF')) 'Deployment example documents the ProjectFirewall OFF choice'

$scanFiles = Get-TextFiles -Roots @(
    (Join-Path $repo 'src'),
    (Join-Path $repo 'config'),
    (Join-Path $repo 'docs'),
    (Join-Path $repo '.github'),
    (Join-Path $repo 'README.md'),
    (Join-Path $repo 'README.ja.md'),
    (Join-Path $repo 'SECURITY.md'),
    (Join-Path $repo '1-Setup.cmd'),
    (Join-Path $repo '2-Start-Secure.cmd'),
    (Join-Path $repo '3-Restore.cmd'),
    (Join-Path $repo 'Check-Package.cmd')
)
foreach ($file in $scanFiles) {
    $text = [IO.File]::ReadAllText($file.FullName)
    Assert-True (-not [regex]::IsMatch($text, '(?i)[A-Z]:\\Users\\(?!%|<)[^\\\s]+')) "$($file.Name) contains no concrete Windows username path"
    Assert-True (-not [regex]::IsMatch($text, '(?i)\b(?:sk|ghp|github_pat)-?[A-Za-z0-9_]{20,}\b')) "$($file.Name) contains no common token shape"
    Assert-True (-not [regex]::IsMatch($text, '(?i)(?:api[_-]?key|token|secret)\s*[:=]\s*["''][^"'']{8,}["'']')) "$($file.Name) contains no obvious assigned secret"
}

$baselinePath = Join-Path $repo 'config\settings.baseline.json'
$baseline = Get-Content -LiteralPath $baselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
$expectedTop = [ordered]@{
    developerMode = $false
    autoLoadBundledLLM = $false
    enableLocalService = $false
    useHFProxy = $false
    hfSearchToken = ''
    hfDownloadToken = ''
}
$expectedDeveloper = [ordered]@{
    showExperimentalFeatures = $false
    allowDevelopmentPlugins = $false
    autoUpdateExtensionPacks = $false
}
foreach ($entry in $expectedTop.GetEnumerator()) {
    Assert-True ($baseline.settings.PSObject.Properties[$entry.Key].Value -eq $entry.Value) "Baseline enforces settings.$($entry.Key)"
}
foreach ($entry in $expectedDeveloper.GetEnumerator()) {
    Assert-True ($baseline.settings.developer.PSObject.Properties[$entry.Key].Value -eq $entry.Value) "Baseline enforces settings.developer.$($entry.Key)"
}
Assert-True (@($baseline.mcp.mcpServers.PSObject.Properties).Count -eq 0) 'Baseline empties MCP servers'
Assert-True ($baseline.httpServerConfig.autoStartOnLaunch -eq $false) 'Baseline disables public API server auto-start'
Assert-True ($baseline.httpServerConfig.networkInterface -eq '127.0.0.1') 'Baseline binds any explicitly started public API server to loopback'

foreach ($name in @('Setup-LMStudio.ps1', 'Start-LMStudio-Secure.ps1')) {
    $text = [IO.File]::ReadAllText((Join-Path $repo "src\$name"))
    foreach ($entry in $expectedTop.GetEnumerator()) {
        Assert-True ($text -match [regex]::Escape($entry.Key)) "$name includes enforced key $($entry.Key)"
    }
    foreach ($entry in $expectedDeveloper.GetEnumerator()) {
        Assert-True ($text -match [regex]::Escape($entry.Key)) "$name includes enforced developer key $($entry.Key)"
    }
}

$setupText = [IO.File]::ReadAllText((Join-Path $repo 'src\Setup-LMStudio.ps1'))
$startText = [IO.File]::ReadAllText((Join-Path $repo 'src\Start-LMStudio-Secure.ps1'))
$restoreText = [IO.File]::ReadAllText((Join-Path $repo 'src\Restore-LMStudio.ps1'))
foreach ($textAndName in @(
    [pscustomobject]@{ Name = 'Setup-LMStudio.ps1'; Text = $setupText },
    [pscustomobject]@{ Name = 'Start-LMStudio-Secure.ps1'; Text = $startText }
)) {
    foreach ($requiredAudit in @(
        'Get-NetFirewallPortFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter',
        "Profile -ne 'Any'",
        "Protocol -ne 'Any'"
    )) {
        Assert-True ($textAndName.Text.Contains($requiredAudit)) "$($textAndName.Name) performs full Firewall audit: $requiredAudit"
    }
}
Assert-True (-not $setupText.Contains('AllowAdditionalModels')) 'Setup exposes no relaxed additional-model option'
Assert-True ($setupText.Contains('if (Test-IsAdministrator)')) 'Setup refuses elevated main execution'
Assert-True (-not [regex]::IsMatch($setupText, '(?m)^\s*ResolvedModelPath\s*=')) 'Setup never persists the plaintext model path'
Assert-True (-not [regex]::IsMatch($startText, '(?m)^\s*ModelPath\s*=')) 'Launcher never persists the plaintext model path'
Assert-True ($setupText.Contains('ResolvedModelPathSha256')) 'Setup persists only a model path identity hash'
Assert-True ($startText.Contains("SchemaVersion') -ne 4")) 'Launcher rejects legacy or unmanaged setup state'
Assert-True ($startText.Contains("ProvisioningMode') -ne 'ManagedSymbolicLink'")) 'Launcher requires setup-managed model registration'
Assert-True ($startText.Contains('Assert-ManagedModelLink')) 'Launcher verifies the setup-managed model remains a symbolic link'
Assert-True ($setupText.Contains("'ProjectManaged'") -and $setupText.Contains("'ExternallyManaged'")) 'Setup implements both Firewall management modes'
Assert-True ($setupText.Contains("[ValidateSet('Enable', 'Disable', 'Skip')]")) 'Setup implements explicit project Firewall ON, OFF, and emergency skip actions'
Assert-True ($setupText.Contains('Remove-LMStudioFirewallRules')) 'Setup can remove only its own managed Firewall rules when switched OFF'
Assert-True ($setupText.Contains('Disable-ExistingSetupStateBeforeFirewallOff')) 'Setup invalidates an old launch state before reducing project Firewall protection'
Assert-True ($startText.Contains('Get-FirewallManagementState')) 'Launcher validates the recorded Firewall management mode'
Assert-True ($startText.Contains('EXTERNALLY MANAGED / NOT VERIFIED HERE')) 'Launcher does not claim external policy was verified'
Assert-True ($startText.Contains('FirewallMode      = $firewallMode')) 'Launcher records the effective Firewall mode for each successful launch'
Assert-True ($setupText.Contains('autoStartOnLaunch') -and $setupText.Contains("networkInterface  = '127.0.0.1'")) 'Setup hardens public API server auto-start and bind address'
Assert-True ($startText.Contains('Assert-LMStudioListensOnlyOnLoopback')) 'Launcher verifies actual LM Studio listeners after startup'
Assert-True ($restoreText.Contains('Get-VerifiedHttpServerConfigBackup')) 'Restore supports verified recovery of the public API server configuration'
Assert-True ($setupText.Contains("'import', `$sourcePath, '--symbolic-link'")) 'Setup registers the shared model without moving or copying it'
Assert-True (-not $setupText.Contains("'daemon', 'up'")) 'Setup does not depend on the headless daemon'
Assert-True (-not $startText.Contains("'daemon', 'up'")) 'Launcher validates through the normal-user GUI instead of the headless daemon'
Assert-True ($restoreText.Contains("'llama-server'")) 'Restore explicitly recognizes llama-server'
Assert-True ($restoreText.Contains('ExpectedSettingsPath')) 'Restore verifies the backup profile target'
Assert-True ($restoreText.Contains('Remove-ManagedModelLink')) 'Restore removes only the recorded setup-managed model link'
Assert-True ($restoreText.Contains('EXTERNAL POLICY UNCHANGED')) 'Restore leaves externally managed network controls unchanged'
Assert-True ($restoreText.Contains('[switch]$RemoveFirewall') -and -not $restoreText.Contains('[switch]$KeepFirewall')) 'Restore requires an explicit switch for managed Firewall removal'
Assert-True ($restoreText.Contains('MANAGED RULES KEPT (SAFE DEFAULT)')) 'Restore reports that its safe default keeps managed Firewall rules'
Assert-True ($restoreText.Contains('Managed Firewall rules were removed, but the state file could not be updated')) 'Restore accurately reports state-write failure after successful Firewall removal'
$restoreEntryText = [IO.File]::ReadAllText((Join-Path $repo '3-Restore.cmd'))
Assert-True (-not $restoreEntryText.Contains('-RemoveFirewall')) 'Non-technical Restore entry point never removes Firewall rules by default'
Assert-True ($restoreEntryText.Contains('Run 1-Setup.cmd next')) 'Non-technical Restore entry point gives the safe next action'

$entryPoints = @(Get-ChildItem -LiteralPath $repo -Filter '*.cmd' -File)
Assert-True ($entryPoints.Count -eq 4) 'Four non-technical command entry points are present'
foreach ($entryPoint in $entryPoints) {
    $entryText = [IO.File]::ReadAllText($entryPoint.FullName)
    $entryBytes = [IO.File]::ReadAllBytes($entryPoint.FullName)
    Assert-True ($entryBytes.Length -gt 0 -and $entryBytes[0] -eq 0x40) "$($entryPoint.Name) starts with @ and has no incompatible BOM"
    Assert-True ($entryText.Contains('powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File')) "$($entryPoint.Name) invokes a fixed local PowerShell file"
    Assert-True (-not $entryText.Contains('http://') -and -not $entryText.Contains('https://')) "$($entryPoint.Name) performs no network retrieval"
}

$gitignore = [IO.File]::ReadAllText((Join-Path $repo '.gitignore'))
foreach ($entry in @('settings.json', 'mcp.json', 'config/deployment.local.psd1', 'secure-setup/', '*.gguf', '*.log')) {
    Assert-True ($gitignore.Contains($entry)) ".gitignore excludes $entry"
}

$workflow = [IO.File]::ReadAllText((Join-Path $repo '.github\workflows\ci.yml'))
Assert-True ($workflow -match '(?ms)^permissions:\s*\r?\n\s+contents:\s*read\s*$') 'CI has read-only repository permissions'
Assert-True ($workflow.Contains('actions/checkout@v7')) 'CI uses the current checkout major version'
Assert-True (-not $workflow.Contains('pull_request_target')) 'CI does not execute pull_request_target code'

Write-Host "Static checks passed: $script:Passed"
