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

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert-True $threw $Message
}

function Get-ScriptFunctionDefinitions {
    param([string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) { throw "Cannot import functions from $Path" }
    $functions = $ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    }, $true)
    $definitions = @()
    foreach ($function in $functions) {
        $definitions += [scriptblock]::Create($function.Extent.Text)
    }
    return $definitions
}

function Write-Utf8Json {
    param([string]$Path, [object]$Value)
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, (($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine), $encoding)
}

$repo = [IO.Path]::GetFullPath($RepoRoot)
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('windows-local-ai-hardening-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    foreach ($definition in @(Get-ScriptFunctionDefinitions -Path (Join-Path $repo 'src\Setup-LMStudio.ps1'))) {
        . $definition
    }
    $script:LogPath = $null

    $modelPathHash = Get-ModelPathIdentitySha256 -Path 'Publisher/Model/model.gguf'
    Assert-True ($modelPathHash -eq (Get-ModelPathIdentitySha256 -Path 'publisher\model\MODEL.GGUF')) 'Model path identity normalizes slash style and case without storing the path'

    $sharedModelRoot = Join-Path $tempRoot 'shared-model'
    New-Item -ItemType Directory -Path $sharedModelRoot -Force | Out-Null
    $sharedModelFile = Join-Path $sharedModelRoot 'approved.gguf'
    [IO.File]::WriteAllText($sharedModelFile, 'fixture')
    $deploymentConfigPath = Join-Path $tempRoot 'deployment.local.psd1'
    $escapedSharedModelRoot = $sharedModelRoot.Replace("'", "''")
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model' }"
    )
    $deploymentConfig = Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath
    Assert-True ($deploymentConfig.SourcePath -eq $sharedModelFile) 'Setup resolves the only GGUF from deployment configuration without LM Studio UI input'
    Assert-True ($deploymentConfig.UserRepo -eq 'secure-deployment/approved-model') 'Setup uses the deployment-owned model repository name'
    Assert-True ($deploymentConfig.ProjectFirewall -eq 'OFF') 'Setup defaults omitted ProjectFirewall to OFF'
    Assert-True ($deploymentConfig.FirewallMode -eq 'ExternallyManaged') 'Setup maps the default ProjectFirewall OFF to delegated enforcement'
    Assert-True (-not $deploymentConfig.VisionProjectorConfigured -and [string]::IsNullOrWhiteSpace($deploymentConfig.VisionProjectorPath)) 'Setup keeps a one-file text model deployment compatible'

    $visionProjectorFile = Join-Path $sharedModelRoot 'mmproj-F16.gguf'
    [IO.File]::WriteAllText($visionProjectorFile, 'projector-fixture')
    $visionDeploymentConfig = Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath
    Assert-True ($visionDeploymentConfig.SourcePath -eq $sharedModelFile -and $visionDeploymentConfig.VisionProjectorPath -eq $visionProjectorFile) 'Setup treats one model GGUF plus one mmproj GGUF as a single VLM package'
    Assert-True $visionDeploymentConfig.VisionProjectorConfigured 'Setup records that a separate vision projector is configured'
    $visionLinkInfo = Get-DeploymentModelLinkInfo -LmStudioHomePath (Join-Path $tempRoot 'link-profile') -DeploymentConfig $visionDeploymentConfig
    Assert-True ([IO.Path]::GetFileName($visionLinkInfo.LinkPath) -eq 'approved.gguf') 'Setup keeps the primary model link distinct from the projector'
    Assert-True ([IO.Path]::GetFileName($visionLinkInfo.VisionProjectorLinkPath) -eq 'mmproj-F16.gguf') 'Setup places the projector beside the primary model link'
    [IO.File]::WriteAllText((Join-Path $sharedModelRoot 'mmproj-BF16.gguf'), 'second-projector-fixture')
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects more than one vision projector for the single approved model'
    [IO.File]::Delete((Join-Path $sharedModelRoot 'mmproj-BF16.gguf'))
    [IO.File]::Delete($visionProjectorFile)

    $explicitProjectorFile = Join-Path $tempRoot 'mmproj-explicit.gguf'
    [IO.File]::WriteAllText($explicitProjectorFile, 'projector-fixture')
    $escapedSharedModelFile = $sharedModelFile.Replace("'", "''")
    $escapedExplicitProjector = $explicitProjectorFile.Replace("'", "''")
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelFile'; VisionProjectorPath = '$escapedExplicitProjector'; ModelUserRepo = 'secure-deployment/approved-model' }"
    )
    $explicitVisionConfig = Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath
    Assert-True ($explicitVisionConfig.VisionProjectorPath -eq $explicitProjectorFile) 'Setup accepts an explicit mmproj path when the primary model is configured as a file'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; VisionProjectorPath = '$escapedExplicitProjector'; ModelUserRepo = 'secure-deployment/approved-model' }"
    )
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects an explicit projector when folder auto-discovery is selected'
    [IO.File]::Delete($explicitProjectorFile)
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model' }"
    )
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model'; ProjectFirewall = 'OFF' }"
    )
    $externalDeploymentConfig = Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath
    Assert-True ($externalDeploymentConfig.ProjectFirewall -eq 'OFF') 'Setup accepts ProjectFirewall OFF'
    Assert-True ($externalDeploymentConfig.FirewallMode -eq 'ExternallyManaged') 'Setup maps ProjectFirewall OFF to delegated network protection'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model'; ProjectFirewall = 'INVALID' }"
    )
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects a ProjectFirewall value other than ON or OFF'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model'; FirewallMode = 'ExternallyManaged' }"
    )
    $legacyDeploymentConfig = Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath
    Assert-True ($legacyDeploymentConfig.ProjectFirewall -eq 'OFF') 'Setup remains compatible with the former ExternallyManaged value'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model'; ProjectFirewall = 'ON'; FirewallMode = 'ProjectManaged' }"
    )
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects simultaneous new and legacy Firewall settings'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'outside-managed-root/approved-model' }"
    )
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects a model repository outside the project-owned directory'
    [IO.File]::WriteAllText(
        $deploymentConfigPath,
        "@{ ModelSourcePath = '$escapedSharedModelRoot'; ModelUserRepo = 'secure-deployment/approved-model' }"
    )
    [IO.File]::WriteAllText((Join-Path $sharedModelRoot 'unexpected.gguf'), 'fixture')
    Assert-Throws { Read-DeploymentModelConfig -ConfigPath $deploymentConfigPath } 'Setup rejects a deployment folder containing multiple GGUF files'
    [IO.File]::Delete((Join-Path $sharedModelRoot 'unexpected.gguf'))

    $profile = Join-Path $tempRoot 'profile'
    $backupRoot = Join-Path $tempRoot 'backups'
    New-Item -ItemType Directory -Path $profile, $backupRoot -Force | Out-Null
    $settingsPath = Join-Path $profile 'settings.json'
    $mcpPath = Join-Path $profile 'mcp.json'
    $httpServerConfigPath = Join-Path $profile '.internal\http-server-config.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $httpServerConfigPath) -Force | Out-Null
    Write-Utf8Json -Path $settingsPath -Value ([ordered]@{
        developerMode = $true
        autoLoadBundledLLM = $true
        enableLocalService = $true
        useHFProxy = $true
        hfSearchToken = 'fixture-value'
        hfDownloadToken = 'fixture-value'
        unrelated = 'preserve-me'
        developer = [ordered]@{
            showExperimentalFeatures = $true
            allowDevelopmentPlugins = $true
            autoUpdateExtensionPacks = $true
            unrelatedDeveloper = 42
        }
    })
    Write-Utf8Json -Path $mcpPath -Value ([ordered]@{
        mcpServers = [ordered]@{ fixture = [ordered]@{ command = 'fixture' } }
        unrelatedMcp = 'preserve-me'
    })
    Write-Utf8Json -Path $httpServerConfigPath -Value ([ordered]@{
        autoStartOnLaunch = $true
        port = 8080
        networkInterface = '0.0.0.0'
        unrelatedServerSetting = 'preserve-me'
    })

    $first = Update-LMStudioJsonSettings -SettingsPath $settingsPath -McpPath $mcpPath -HttpServerConfigPath $httpServerConfigPath -BackupRoot $backupRoot
    Assert-True ($first.SettingsChanged -and $first.McpChanged -and $first.HttpServerConfigChanged) 'Setup hardens drifting settings, MCP, and public API server configuration'
    Assert-True (Test-Path -LiteralPath $first.BackupPath -PathType Container) 'Setup creates an original backup'
    $updatedSettings = Get-Content -LiteralPath $settingsPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $updatedMcp = Get-Content -LiteralPath $mcpPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $updatedHttpServerConfig = Get-Content -LiteralPath $httpServerConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($updatedSettings.developerMode -eq $false -and $updatedSettings.enableLocalService -eq $false) 'Setup enforces top-level policy'
    Assert-True ($updatedSettings.developer.allowDevelopmentPlugins -eq $false) 'Setup disables development plugins'
    Assert-True ($updatedSettings.unrelated -eq 'preserve-me' -and $updatedSettings.developer.unrelatedDeveloper -eq 42) 'Setup preserves unrelated settings'
    Assert-True (@($updatedMcp.mcpServers.PSObject.Properties).Count -eq 0 -and $updatedMcp.unrelatedMcp -eq 'preserve-me') 'Setup empties MCP servers and preserves unrelated MCP data'
    Assert-True (-not $updatedHttpServerConfig.autoStartOnLaunch -and $updatedHttpServerConfig.networkInterface -eq '127.0.0.1') 'Setup disables public API auto-start and binds its saved configuration to loopback'
    Assert-True ($updatedHttpServerConfig.port -eq 8080 -and $updatedHttpServerConfig.unrelatedServerSetting -eq 'preserve-me') 'Setup preserves unrelated public API server settings'
    Assert-True (Test-Path -LiteralPath (Join-Path $first.BackupPath 'http-server-config.json') -PathType Leaf) 'Setup backs up the original public API server configuration'

    $second = Update-LMStudioJsonSettings -SettingsPath $settingsPath -McpPath $mcpPath -HttpServerConfigPath $httpServerConfigPath -BackupRoot $backupRoot
    Assert-True (-not $second.SettingsChanged -and -not $second.McpChanged -and -not $second.HttpServerConfigChanged -and $null -eq $second.BackupPath) 'Setup JSON hardening is idempotent'

    function script:Get-Process { return @() }
    try {
        $emptySetupProcesses = @(Get-RunningLMStudioProcesses -ExePath 'C:\fixture\LM Studio.exe' -HomePath 'C:\fixture\profile')
        Assert-True ($emptySetupProcesses.Count -eq 0) 'Setup accepts an empty process inventory in Windows PowerShell 5.1'
    }
    finally {
        Remove-Item -LiteralPath Function:\Get-Process -Force
    }
    $setupNativeWarning = Invoke-NativeCapture `
        -FilePath $env:ComSpec `
        -ArgumentList @('/d', '/c', 'echo fixture-warning 1>&2')
    Assert-True ($setupNativeWarning.ExitCode -eq 0 -and $setupNativeWarning.Text -match 'fixture-warning') 'Setup treats native stderr as captured output when the native exit code is zero'

    $script:SetupMutex = $null
    $script:SetupMutexOwned = $false
    Enter-SetupMutex -LmStudioHomePath $profile
    try {
        Assert-Throws { Enter-SetupMutex -LmStudioHomePath $profile } 'Setup rejects a concurrent invocation for the same LM Studio profile'
    }
    finally {
        Exit-SetupMutex
    }
    $requestFixtureRoot = Join-Path $tempRoot 'request-fixture'
    New-Item -ItemType Directory -Path $requestFixtureRoot -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $requestFixtureRoot 'firewall-request-fixture.json'), '{}')
    Assert-Throws { Assert-NoActiveSetupRequest -SetupRoot $requestFixtureRoot } 'Setup rejects an existing elevated-operation request'

    foreach ($definition in @(Get-ScriptFunctionDefinitions -Path (Join-Path $repo 'src\Start-LMStudio-Secure.ps1'))) {
        . $definition
    }

    function script:Get-Process { return @() }
    try {
        $emptyLaunchProcesses = @(Get-RunningLMStudioProcesses -ExePath 'C:\fixture\LM Studio.exe' -HomePath 'C:\fixture\profile')
        Assert-True ($emptyLaunchProcesses.Count -eq 0) 'Launcher accepts an empty process inventory in Windows PowerShell 5.1'
    }
    finally {
        Remove-Item -LiteralPath Function:\Get-Process -Force
    }
    $launcherNativeWarning = Invoke-NativeCapture `
        -FilePath $env:ComSpec `
        -ArgumentList @('/d', '/c', 'echo fixture-warning 1>&2')
    Assert-True ($launcherNativeWarning.ExitCode -eq 0 -and $launcherNativeWarning.Text -match 'fixture-warning') 'Launcher treats native stderr as captured output when the native exit code is zero'
    Write-Utf8Json -Path $httpServerConfigPath -Value ([ordered]@{
        autoStartOnLaunch = $true
        port = 8080
        networkInterface = '0.0.0.0'
    })
    $launchHardening = Set-HardenedJsonState `
        -SettingsPath $settingsPath `
        -McpPath $mcpPath `
        -HttpServerConfigPath $httpServerConfigPath `
        -BackupRoot $backupRoot
    $launchHttpServerConfig = Get-Content -LiteralPath $httpServerConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($launchHardening.Changed -and -not $launchHttpServerConfig.autoStartOnLaunch -and $launchHttpServerConfig.networkInterface -eq '127.0.0.1') 'Launcher corrects public API server drift before starting LM Studio'
    Assert-True (Test-Path -LiteralPath (Join-Path $launchHardening.BackupPath 'http-server-config.json') -PathType Leaf) 'Launcher backs up public API server drift before correction'
    $recentFirewallAudit = Test-FirewallAuditIsRecent -VerifiedAtUtc ([DateTime]::UtcNow.AddMinutes(-5).ToString('o'))
    $expiredFirewallAudit = Test-FirewallAuditIsRecent -VerifiedAtUtc ([DateTime]::UtcNow.AddHours(-25).ToString('o'))
    $invalidFirewallAudit = Test-FirewallAuditIsRecent -VerifiedAtUtc 'invalid'
    Assert-True $recentFirewallAudit 'Launcher recognizes a recent complete Firewall verification'
    Assert-True (-not $expiredFirewallAudit) 'Launcher expires a Firewall verification after 24 hours'
    Assert-True (-not $invalidFirewallAudit) 'Launcher rejects an invalid Firewall verification timestamp'

    $netstatFixture = @'
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       100
  TCP    127.0.0.1:41343        0.0.0.0:0              LISTENING       100
  TCP    [::]:9090              [::]:0                 LISTENING       200
  TCP    [::1]:61322            [::]:0                 LISTENING       200
  TCP    192.168.1.10:7777      0.0.0.0:0              LISTENING       999
  TCP    192.168.1.10:50699     203.0.113.10:443        ESTABLISHED     100
'@
    $nonLoopbackListeners = @(ConvertFrom-NetstatListeningEndpoints -Text $netstatFixture -ProcessIds @(100, 200))
    Assert-True ($nonLoopbackListeners.Count -eq 2) 'Launcher detects IPv4 and IPv6 wildcard listeners owned by LM Studio processes'
    Assert-True (@($nonLoopbackListeners | Where-Object { $_.Address -eq '0.0.0.0' -and $_.Port -eq 8080 }).Count -eq 1) 'Launcher reports the public IPv4 API listener'
    Assert-True (@($nonLoopbackListeners | Where-Object { $_.Address -eq '::' -and $_.Port -eq 9090 }).Count -eq 1) 'Launcher reports the public IPv6 API listener'
    $establishedOnly = @(
        ConvertFrom-NetstatListeningEndpoints `
            -Text '  TCP    192.168.1.10:50699     203.0.113.10:443        ESTABLISHED     100' `
            -ProcessIds @(100)
    )
    Assert-True ($establishedOnly.Count -eq 0) 'Launcher does not misclassify an outbound established connection as a listener'

    $legacyFirewallManagement = Get-FirewallManagementState -FirewallState ([pscustomobject]@{
        Configured = $true
        RuleCount = 2
    })
    Assert-True ($legacyFirewallManagement.Mode -eq 'ProjectManaged') 'Launcher safely treats a complete legacy state as ProjectManaged'
    $externalFirewallManagement = Get-FirewallManagementState -FirewallState ([pscustomobject]@{
        Mode = 'ExternallyManaged'
        Configured = $false
        ExternallyManaged = $true
        RuleCount = 0
    })
    Assert-True ($externalFirewallManagement.ExternallyManaged) 'Launcher accepts a consistent ExternallyManaged state'
    Assert-Throws {
        Get-FirewallManagementState -FirewallState ([pscustomobject]@{
            Mode = 'ExternallyManaged'
            Configured = $true
            ExternallyManaged = $true
        })
    } 'Launcher rejects an externally managed state that claims project Firewall configuration'
    Assert-Throws {
        Get-FirewallManagementState -FirewallState ([pscustomobject]@{
            Mode = 'Disabled'
            Configured = $false
            ExternallyManaged = $false
        })
    } 'Launcher rejects an unknown Firewall management mode'

    $script:FirewallGroup = 'LM Studio Secure Local-Only'
    $script:NonLoopbackRemoteAddresses = @(
        '0.0.0.0-126.255.255.255',
        '128.0.0.0-255.255.255.255',
        '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    )
    $script:MockFirewallProgram = 'C:\fixture\LM Studio.exe'
    $script:MockFirewallProfile = 'Any'
    $script:MockFirewallProtocol = 'Any'
    $script:MockFirewallLocalPort = 'Any'
    $script:MockFirewallRemotePort = 'Any'
    function script:Get-NetFirewallProfile {
        return @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true; AllowLocalFirewallRules = $true },
            [pscustomobject]@{ Name = 'Private'; Enabled = $true; AllowLocalFirewallRules = $true },
            [pscustomobject]@{ Name = 'Public'; Enabled = $true; AllowLocalFirewallRules = $true }
        )
    }
    function script:Get-NetFirewallRule {
        param([string]$Name)
        $direction = if ($Name -match 'Outbound') { 'Outbound' } else { 'Inbound' }
        return [pscustomobject]@{
            Name = $Name
            Enabled = 'True'
            Action = 'Block'
            Direction = $direction
            Group = 'LM Studio Secure Local-Only'
            Profile = $script:MockFirewallProfile
        }
    }
    function script:Get-NetFirewallApplicationFilter {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process { return [pscustomobject]@{ Program = $script:MockFirewallProgram } }
    }
    function script:Get-NetFirewallAddressFilter {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process {
            return [pscustomobject]@{
                LocalAddress = @('Any')
                RemoteAddress = @(
                    '0.0.0.0-126.255.255.255',
                    '128.0.0.0-255.255.255.255',
                    '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
                )
            }
        }
    }
    function script:Get-NetFirewallPortFilter {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process {
            return [pscustomobject]@{
                Protocol = $script:MockFirewallProtocol
                LocalPort = @($script:MockFirewallLocalPort)
                RemotePort = @($script:MockFirewallRemotePort)
            }
        }
    }
    function script:Get-NetFirewallInterfaceTypeFilter {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process { return [pscustomobject]@{ InterfaceType = 'Any' } }
    }
    function script:Get-NetFirewallServiceFilter {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)
        process { return [pscustomobject]@{ Service = 'Any' } }
    }

    Assert-True ((Test-LMStudioFirewallRules -ProgramPaths @($script:MockFirewallProgram)) -eq 2) 'Firewall audit accepts only the complete all-traffic rule shape'
    $script:MockFirewallProtocol = 'TCP'
    Assert-Throws { Test-LMStudioFirewallRules -ProgramPaths @($script:MockFirewallProgram) } 'Firewall audit rejects a TCP-only rule'
    $script:MockFirewallProtocol = 'Any'
    $script:MockFirewallProfile = 'Private'
    Assert-Throws { Test-LMStudioFirewallRules -ProgramPaths @($script:MockFirewallProgram) } 'Firewall audit rejects a rule limited to one profile'
    $script:MockFirewallProfile = 'Any'
    $script:MockFirewallRemotePort = '443'
    Assert-Throws { Test-LMStudioFirewallRules -ProgramPaths @($script:MockFirewallProgram) } 'Firewall audit rejects a port-limited rule'
    $script:MockFirewallRemotePort = 'Any'

    $transitionStatePath = Join-Path $tempRoot 'transition-state.json'
    Write-Utf8Json -Path $transitionStatePath -Value ([ordered]@{
        SchemaVersion = 5
        Complete = $true
        Settings = [ordered]@{ BackupPath = 'C:\fixture\backup' }
    })
    Disable-ExistingSetupStateBeforeFirewallOff -StatePath $transitionStatePath
    $transitionState = Get-Content -LiteralPath $transitionStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True (-not $transitionState.Complete) 'Setup invalidates the previous secure-launch state before switching project Firewall OFF'
    Assert-True ($transitionState.Settings.BackupPath -eq 'C:\fixture\backup') 'Setup preserves recovery metadata while invalidating the old launch state'

    $script:MockManagedFirewallRules = @(
        [pscustomobject]@{ Name = 'LMStudioSecure-fixture-Outbound'; Group = $script:FirewallGroup },
        [pscustomobject]@{ Name = 'LMStudioSecure-fixture-Inbound'; Group = $script:FirewallGroup }
    )
    $script:RemovedManagedFirewallNames = @()
    function script:Test-IsAdministrator { return $true }
    function script:Get-NetFirewallRule {
        param([string]$Name, [string]$Group)
        if (-not [string]::IsNullOrWhiteSpace($Group)) {
            return @($script:MockManagedFirewallRules)
        }
        return @($script:MockManagedFirewallRules | Where-Object { $_.Name -eq $Name })
    }
    function script:Remove-NetFirewallRule {
        param([string]$Name)
        $script:RemovedManagedFirewallNames += $Name
        $script:MockManagedFirewallRules = @($script:MockManagedFirewallRules | Where-Object { $_.Name -ne $Name })
    }
    $removedRuleCount = Remove-LMStudioFirewallRules
    Assert-True ($removedRuleCount -eq 2) 'Project Firewall OFF removes every rule in the project-owned group'
    Assert-True ($script:RemovedManagedFirewallNames.Count -eq 2 -and $script:MockManagedFirewallRules.Count -eq 0) 'Project Firewall OFF verifies that no project-owned rule remains'

    $validLoaded = [pscustomobject]@{
        modelKey = 'publisher/model'
        path = 'C:\fixture\model.gguf'
        identifier = 'approved-slot'
    }
    $validLoadedPathHash = Get-ModelPathIdentitySha256 -Path 'C:\fixture\model.gguf'
    $otherLoadedPathHash = Get-ModelPathIdentitySha256 -Path 'C:\fixture\other.gguf'
    Assert-True (Test-LoadedModelMatches -LoadedModel $validLoaded -AllowedModelKey 'publisher/model' -ExpectedModelPathSha256 $validLoadedPathHash -ExpectedIdentifier 'approved-slot') 'Launcher accepts matching model identity and identifier'
    Assert-True (-not (Test-LoadedModelMatches -LoadedModel $validLoaded -AllowedModelKey 'publisher/other' -ExpectedModelPathSha256 $otherLoadedPathHash -ExpectedIdentifier 'approved-slot')) 'Launcher rejects a different model identity'
    Assert-True (-not (Test-LoadedModelMatches -LoadedModel $validLoaded -AllowedModelKey 'publisher/model' -ExpectedModelPathSha256 $validLoadedPathHash -ExpectedIdentifier 'spoofed-slot')) 'Launcher rejects a mismatched loaded identifier'

    $approvedInventory = @([pscustomobject]@{
        type = 'llm'
        modelKey = 'publisher/model'
        path = '\\shared-host\models\publisher\model.gguf'
    })
    $approvedPathHash = Get-ModelPathIdentitySha256 -Path '\\shared-host\models\publisher\model.gguf'
    Assert-True ((Find-ApprovedModel -Models $approvedInventory -AllowedModelKey 'publisher/model' -ExpectedModelPathSha256 $approvedPathHash).modelKey -eq 'publisher/model') 'Launcher accepts the approved shared-folder model using only its path hash'
    Assert-Throws { Find-ApprovedModel -Models $approvedInventory -AllowedModelKey 'publisher/model' -ExpectedModelPathSha256 $otherLoadedPathHash } 'Launcher rejects shared-folder model path drift'
    $firstLaunchInventory = @([pscustomobject]@{
        type = 'llm'
        modelKey = 'secure-deployment/approved-model'
        path = 'secure-deployment/approved-model'
        indexedModelIdentifier = 'secure-deployment/approved-model'
    })
    Assert-True ((Find-ProvisionedModel -Models $firstLaunchInventory -ExpectedRepository 'secure-deployment/approved-model').modelKey -eq 'secure-deployment/approved-model') 'First secure GUI launch resolves the setup-managed repository without a pre-known modelKey'
    Assert-Throws { Find-ProvisionedModel -Models @($firstLaunchInventory + $firstLaunchInventory) -ExpectedRepository 'secure-deployment/approved-model' } 'First secure GUI launch rejects an ambiguous managed repository'
    Assert-True (Get-ModelVisionEnabled -Model ([pscustomobject]@{ vision = $true }) -SourceDescription 'fixture') 'Launcher recognizes a vision-capable model'
    Assert-True (-not (Get-ModelVisionEnabled -Model ([pscustomobject]@{ vision = $false }) -SourceDescription 'fixture')) 'Launcher recognizes a text-only model'
    Assert-Throws { Get-ModelVisionEnabled -Model ([pscustomobject]@{}) -SourceDescription 'fixture' } 'Launcher fails closed when LM Studio does not report vision capability'
    Assert-Throws {
        Assert-ManagedModelLink `
            -LinkPath (Join-Path $tempRoot 'outside.gguf') `
            -LmStudioHomePath (Join-Path $tempRoot 'profile') `
            -ExpectedTargetPathSha256 ('0' * 64)
    } 'Launcher rejects a managed-link path outside its dedicated model directory'

    foreach ($definition in @(Get-ScriptFunctionDefinitions -Path (Join-Path $repo 'src\Restore-LMStudio.ps1'))) {
        . $definition
    }
    $originalHttpServerConfigSource = Get-VerifiedHttpServerConfigBackup `
        -BackupRoot $backupRoot `
        -ExpectedPath $httpServerConfigPath
    Assert-True ($null -ne $originalHttpServerConfigSource) 'Restore finds the earliest verified public API server backup across setup and launch backups'
    $originalHttpServerConfig = Get-Content -LiteralPath $originalHttpServerConfigSource.BackupPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($originalHttpServerConfig.autoStartOnLaunch -and $originalHttpServerConfig.networkInterface -eq '0.0.0.0') 'Restore retains the original public API server configuration for explicit recovery'
    Assert-Throws { Remove-ManagedModelLink -LinkPath (Join-Path $tempRoot 'outside.gguf') -LmStudioHomePath (Join-Path $tempRoot 'profile') } 'Restore refuses to delete a model path outside its dedicated directory'
    $missingManagedLink = Join-Path $tempRoot 'profile\models\secure-deployment\owner\repo\missing.gguf'
    Assert-True (-not (Remove-ManagedModelLink -LinkPath $missingManagedLink -LmStudioHomePath (Join-Path $tempRoot 'profile'))) 'Restore treats an already absent managed link as idempotent'
    $danglingManagedLink = Join-Path $tempRoot 'profile\models\secure-deployment\owner\repo\dangling.gguf'
    New-Item -ItemType Directory -Path (Split-Path -Parent $danglingManagedLink) -Force | Out-Null
    function script:Test-Path {
        param([string]$LiteralPath, [string]$PathType)
        return (-not [string]::Equals($LiteralPath, $danglingManagedLink, [StringComparison]::OrdinalIgnoreCase))
    }
    function script:Get-ChildItem {
        param([string]$LiteralPath, [switch]$Force, [object]$ErrorAction)
        return @([pscustomobject]@{
            Name = 'dangling.gguf'
            Attributes = [IO.FileAttributes]::ReparsePoint
            LinkType = 'SymbolicLink'
        })
    }
    try {
        Assert-True (Remove-ManagedModelLink -LinkPath $danglingManagedLink -LmStudioHomePath (Join-Path $tempRoot 'profile')) 'Restore removes a dangling managed model link without resolving its unavailable target'
    }
    finally {
        Remove-Item -LiteralPath Function:\Test-Path -Force
        Remove-Item -LiteralPath Function:\Get-ChildItem -Force
    }
    $restoreRoot = Join-Path $tempRoot 'restore-backups'
    New-Item -ItemType Directory -Path $restoreRoot -Force | Out-Null
    $expectedRestoreSettings = Join-Path $tempRoot 'restore-profile\settings.json'
    $expectedRestoreMcp = Join-Path $tempRoot 'restore-profile\mcp.json'

    $launchBackup = Join-Path $restoreRoot 'launch-newer'
    New-Item -ItemType Directory -Path $launchBackup -Force | Out-Null
    Write-Utf8Json -Path (Join-Path $launchBackup 'settings.json') -Value ([ordered]@{ fixture = 'launch' })
    Write-Utf8Json -Path (Join-Path $launchBackup 'backup-manifest.json') -Value ([ordered]@{ SchemaVersion = 1; Reason = 'launch backup' })

    $originalBackup = Join-Path $restoreRoot 'original-older'
    New-Item -ItemType Directory -Path $originalBackup -Force | Out-Null
    $originalSettings = Join-Path $originalBackup 'settings.json'
    $originalMcp = Join-Path $originalBackup 'mcp.json'
    Write-Utf8Json -Path $originalSettings -Value ([ordered]@{ fixture = 'original' })
    Write-Utf8Json -Path $originalMcp -Value ([ordered]@{ mcpServers = [ordered]@{ original = [ordered]@{} } })
    Write-Utf8Json -Path (Join-Path $originalBackup 'backup-manifest.json') -Value ([ordered]@{
        SchemaVersion = 1
        SettingsPath = $expectedRestoreSettings
        SettingsSha256 = (Get-FileHash -LiteralPath $originalSettings -Algorithm SHA256).Hash.ToLowerInvariant()
        McpPath = $expectedRestoreMcp
        McpOriginallyExists = $true
        McpSha256 = (Get-FileHash -LiteralPath $originalMcp -Algorithm SHA256).Hash.ToLowerInvariant()
    })
    (Get-Item -LiteralPath $launchBackup).LastWriteTimeUtc = [DateTime]::UtcNow
    (Get-Item -LiteralPath $originalBackup).LastWriteTimeUtc = [DateTime]::UtcNow.AddMinutes(-5)

    $selected = Get-VerifiedOriginalBackup `
        -BackupRoot $restoreRoot `
        -ExpectedSettingsPath $expectedRestoreSettings `
        -ExpectedMcpPath $expectedRestoreMcp
    Assert-True ($selected.Path -eq $originalBackup) 'Restore skips newer launch backups and selects an original setup backup'

    Assert-Throws {
        Get-VerifiedOriginalBackup `
            -BackupRoot $restoreRoot `
            -ExpectedSettingsPath (Join-Path $tempRoot 'different-profile\settings.json') `
            -ExpectedMcpPath (Join-Path $tempRoot 'different-profile\mcp.json') `
            -RequestedPath $originalBackup
    } 'Restore rejects a valid backup from a different LM Studio profile'

    [IO.File]::AppendAllText($originalSettings, 'tampered')
    Assert-Throws {
        Get-VerifiedOriginalBackup `
            -BackupRoot $restoreRoot `
            -ExpectedSettingsPath $expectedRestoreSettings `
            -ExpectedMcpPath $expectedRestoreMcp `
            -RequestedPath $originalBackup
    } 'Restore rejects a backup whose hash no longer matches'

    $outside = Join-Path $tempRoot 'outside-backup'
    New-Item -ItemType Directory -Path $outside -Force | Out-Null
    Assert-Throws {
        Get-VerifiedOriginalBackup `
            -BackupRoot $restoreRoot `
            -ExpectedSettingsPath $expectedRestoreSettings `
            -ExpectedMcpPath $expectedRestoreMcp `
            -RequestedPath $outside
    } 'Restore rejects a requested path outside its managed backup root'

    $runtimeHome = Join-Path $tempRoot 'runtime-profile'
    New-Item -ItemType Directory -Path $runtimeHome -Force | Out-Null
    function script:Get-Process {
        return @([pscustomobject]@{
            ProcessName = 'custom-runtime-name'
            Id = 4242
            Path = (Join-Path $runtimeHome 'extensions\backends\runtime.exe')
        })
    }
    $runtimeProcesses = @(Get-RunningLMStudioProcesses -HomePath $runtimeHome)
    Assert-True ($runtimeProcesses.Count -eq 1 -and $runtimeProcesses[0].Id -eq 4242) 'Restore detects a runtime by path even when its process name is unknown'
}
finally {
    $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolvedTemp = [IO.Path]::GetFullPath($tempRoot)
    if ($resolvedTemp.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFileName($resolvedTemp).StartsWith('windows-local-ai-hardening-test-')) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Behavior checks passed: $script:Passed"
