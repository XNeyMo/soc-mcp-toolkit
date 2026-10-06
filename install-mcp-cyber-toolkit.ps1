<#
.SYNOPSIS
    Installs and configures the SOC MCP Toolkit on this machine.

.DESCRIPTION
    The SOC MCP Toolkit is a set of MCP servers for security operations, built
    around Microsoft 365 (Defender, Entra ID, Exchange Online, Intune, Purview),
    Palo Alto Cortex XDR, an Ellucian Banner (ETHOS) identity source, an
    authorized pentesting lab, and a shared team audit vault.

    This script configures, on the local machine:
      - User environment variables (identity-provider + GitHub credentials)
      - A clone of the repository (if it does not exist)
      - Python dependencies per MCP server
      - .claude.json entries (mcpServers)
      - A "MCT-Sync" Scheduled Task for automatic updates

    MCP_ANALYST_NAME is derived from the Windows user. On corporate machines the
    username is the local part of the UPN, e.g. "analyst1" -> "analyst1@example.com".

    Repository: https://github.com/your-org/soc-mcp-toolkit

    NOTE: every value suggested below is a placeholder. Replace it with your own.

.PARAMETER UpnDomain
    Domain used to derive MCP_ANALYST_NAME from the Windows user.

.PARAMETER SkipEnvVars
    Do not prompt for or configure environment variables.

.PARAMETER SkipDependencies
    Do not run pip install.

.PARAMETER SkipClaudeConfig
    Do not modify .claude.json.

.PARAMETER SkipScheduledTask
    Do not register the MCT-Sync Scheduled Task.

.PARAMETER ClaudeConfigPath
    Path to the .claude.json to modify.

.PARAMETER Force
    Skip the interactive confirmations.

.PARAMETER WhatIfOnly
    Only show what it would do, without executing anything.
#>

[CmdletBinding()]
param(
    [string]$UpnDomain = "example.com",
    [switch]$SkipEnvVars,
    [switch]$SkipDependencies,
    [switch]$SkipClaudeConfig,
    [switch]$SkipScheduledTask,
    [string]$ClaudeConfigPath = "$env:USERPROFILE\.claude.json",
    [switch]$Force,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = "Stop"

$RepoRoot = $PSScriptRoot
$TaskName = "MCT-Sync"

$Domains = @(
    [ordered]@{ Name = "mcp-defender"; Prefix = "DEFENDER"; Folder = "mcp-defender"; Label = "Microsoft 365 Defender (XDR)" }
    [ordered]@{ Name = "mcp-identity"; Prefix = "IDENTITY"; Folder = "mcp-identity"; Label = "Entra ID (Identity)" }
    [ordered]@{ Name = "mcp-exchange"; Prefix = "EXCHANGE"; Folder = "mcp-exchange"; Label = "Exchange Online (Mail)" }
    [ordered]@{ Name = "mcp-intune";   Prefix = "INTUNE";   Folder = "mcp-intune";   Label = "Intune (Devices)" }
    [ordered]@{ Name = "mcp-audit";    Prefix = "AUDIT";    Folder = "mcp-audit";    Label = "Audit / Compliance (Purview, read-only)" }
)

# mcp-cortex does not fit the AZURE_TENANT_ID + <PREFIX>_CLIENT_ID/SECRET pattern above
# (Cortex XDR is Palo Alto Networks, not Entra: a single Advanced API Key shared by the
# team, with 4 of its own variables instead of 2) - it is handled separately in each step.
$CortexFolder = "mcp-cortex"

# mcp-banner also does not fit the AZURE_TENANT_ID + <PREFIX>_CLIENT_ID/SECRET pattern:
# it talks to a Banner ETHOS API gateway (sis-gateway.example.com), an academic/SIS system
# outside Entra ID, with OAuth2 client_credentials against its own token endpoint
# (BANNER_TOKEN_URL) instead of login.microsoftonline.com - handled separately, like Cortex.
$BannerFolder = "mcp-banner"

# mcp-vault (remote team audit vault) also does not fit the AZURE_TENANT_ID +
# <PREFIX>_CLIENT_ID/SECRET pattern: it uses no Entra credentials - the identity used for
# auditing is decided by the VM based on which SSH key connected (a forced command in
# authorized_keys), not a local environment variable. This script only generates THIS
# analyst's key pair if it does not yet exist; adding the public key to the VM's
# authorized_keys is still a manual step (it requires admin access to the VM).
$VaultFolder = "mcp-vault"

# mcp-pentesting (dedicated Kali host) also does not fit the AZURE_TENANT_ID +
# <PREFIX>_CLIENT_ID/SECRET pattern: it does not talk to Entra/Graph at all, it only runs
# commands over SSH against a Kali host (PENTEST_SSH_HOST/USER/KEY). Unlike mcp-vault, the
# key is NOT generated here - it usually already exists (shared team access to a pentesting
# lab), so this script only asks for its path.
$PentestFolder = "mcp-pentesting"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Resolve-PythonExe {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    throw "'python' not found in PATH. Install Python before continuing."
}

function ConvertFrom-SecureStringPlain {
    param([System.Security.SecureString]$Secure)
    if (-not $Secure -or $Secure.Length -eq 0) { return "" }
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
    }
}

function Set-UserEnvVar {
    param([string]$Name, [string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return }
    [Environment]::SetEnvironmentVariable($Name, $Value, "User")
    Set-Item -Path "Env:$Name" -Value $Value
}

function Get-AnalystUpn {
    param([string]$Domain)
    $windowsUser = $env:USERNAME
    $derived = "$windowsUser@$Domain"
    if ($env:USERDNSDOMAIN -and ($env:USERDNSDOMAIN.ToLower() -ne $Domain.ToLower())) {
        Write-Warning "The detected network domain (USERDNSDOMAIN=$env:USERDNSDOMAIN) differs from '$Domain'. '$Domain' will be used anyway to derive the UPN."
    }
    return $derived
}

function Read-SecretEnvVar {
    param([string]$VarName, [string]$Prompt)
    $current = [Environment]::GetEnvironmentVariable($VarName, "User")
    $hint = $Prompt
    if ($current) {
        $tail = $current.Substring([Math]::Max(0, $current.Length - 4))
        $hint = "$Prompt (current ends in ...$tail, Enter to keep)"
    }
    $secure = Read-Host $hint -AsSecureString
    $plain = ConvertFrom-SecureStringPlain -Secure $secure
    if ([string]::IsNullOrWhiteSpace($plain)) {
        return $current
    }
    return $plain
}

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

$PythonExe = Resolve-PythonExe
$DetectedUpn = Get-AnalystUpn -Domain $UpnDomain

Write-Host "=== SOC MCP Toolkit - installation ===" -ForegroundColor Cyan
Write-Host "Python detected : $PythonExe"
Write-Host "Windows user    : $env:USERNAME"
Write-Host "Derived UPN     : $DetectedUpn"
Write-Host ""

# ---------------------------------------------------------------------------
# Step 1 - Environment variables
# ---------------------------------------------------------------------------

$envPlan = [ordered]@{}

if (-not $SkipEnvVars) {
    Write-Host "--- Environment variables ---" -ForegroundColor Yellow

    $currentTenant = [Environment]::GetEnvironmentVariable("AZURE_TENANT_ID", "User")
    $tenantPrompt = if ($currentTenant) { "AZURE_TENANT_ID (current: $currentTenant, Enter to keep)" } else { "AZURE_TENANT_ID" }
    $tenant = Read-Host $tenantPrompt
    if ([string]::IsNullOrWhiteSpace($tenant)) { $tenant = $currentTenant }
    if ($tenant) { $envPlan["AZURE_TENANT_ID"] = $tenant }

    $currentAnalyst = [Environment]::GetEnvironmentVariable("MCP_ANALYST_NAME", "User")
    if ($currentAnalyst -and ($currentAnalyst -ne $DetectedUpn)) {
        Write-Warning "Current MCP_ANALYST_NAME ('$currentAnalyst') differs from the detected UPN ('$DetectedUpn'). It will be updated to '$DetectedUpn'."
    }
    $envPlan["MCP_ANALYST_NAME"] = $DetectedUpn

    Write-Host ""
    Write-Host "GitHub - automatic sync:" -ForegroundColor Green

    $ghToken = Read-SecretEnvVar -VarName "GITHUB_MCT_TOKEN" -Prompt "GITHUB_MCT_TOKEN (Fine-grained PAT, contents:read on the repo)"
    if ($ghToken) { $envPlan["GITHUB_MCT_TOKEN"] = $ghToken }

    $currentRepo = [Environment]::GetEnvironmentVariable("GITHUB_MCT_REPO", "User")
    $repoDefault = if ($currentRepo) { $currentRepo } else { "your-org/soc-mcp-toolkit" }
    $repoPrompt = if ($currentRepo) { "GITHUB_MCT_REPO (current: $currentRepo, Enter to keep)" } else { "GITHUB_MCT_REPO (Enter to use '$repoDefault')" }
    $ghRepo = Read-Host $repoPrompt
    if ([string]::IsNullOrWhiteSpace($ghRepo)) { $ghRepo = $repoDefault }
    $envPlan["GITHUB_MCT_REPO"] = $ghRepo

    $currentBranch = [Environment]::GetEnvironmentVariable("GITHUB_MCT_BRANCH", "User")
    $branchDefault = if ($currentBranch) { $currentBranch } else { "main" }
    $ghBranch = Read-Host "GITHUB_MCT_BRANCH (Enter to use '$branchDefault')"
    if ([string]::IsNullOrWhiteSpace($ghBranch)) { $ghBranch = $branchDefault }
    $envPlan["GITHUB_MCT_BRANCH"] = $ghBranch

    $currentPath = [Environment]::GetEnvironmentVariable("MCT_REPO_PATH", "User")
    $pathDefault = if ($currentPath) { $currentPath } else { "$env:USERPROFILE\soc-mcp-toolkit" }
    $mctPath = Read-Host "MCT_REPO_PATH (Enter to use '$pathDefault')"
    if ([string]::IsNullOrWhiteSpace($mctPath)) { $mctPath = $pathDefault }
    $envPlan["MCT_REPO_PATH"] = $mctPath

    Write-Host ""
    foreach ($d in $Domains) {
        Write-Host "$($d.Label) [$($d.Prefix)]" -ForegroundColor Green
        $hasApp = Read-Host "  Do you already have a CLIENT_ID/SECRET for this domain? (y/N)"
        if ($hasApp -notmatch '^[yY]') {
            Write-Host "  Skipped - configure it later by re-running the script." -ForegroundColor DarkGray
            continue
        }
        $clientIdVar = "$($d.Prefix)_CLIENT_ID"
        $clientSecretVar = "$($d.Prefix)_CLIENT_SECRET"

        $currentId = [Environment]::GetEnvironmentVariable($clientIdVar, "User")
        $idPrompt = if ($currentId) { "  $clientIdVar (current: $currentId, Enter to keep)" } else { "  $clientIdVar" }
        $clientId = Read-Host $idPrompt
        if ([string]::IsNullOrWhiteSpace($clientId)) { $clientId = $currentId }

        $clientSecret = Read-SecretEnvVar -VarName $clientSecretVar -Prompt "  $clientSecretVar"

        if ($clientId) { $envPlan[$clientIdVar] = $clientId }
        if ($clientSecret) { $envPlan[$clientSecretVar] = $clientSecret }
    }

    Write-Host ""
    Write-Host "Cortex XDR (Palo Alto Networks) [CORTEX]" -ForegroundColor Green
    $hasCortexKey = Read-Host "  Do you already have the Cortex XDR Advanced API Key? (y/N)"
    if ($hasCortexKey -match '^[yY]') {
        $currentFqdn = [Environment]::GetEnvironmentVariable("CORTEX_FQDN", "User")
        $fqdnPrompt = if ($currentFqdn) { "  CORTEX_FQDN (current: $currentFqdn, Enter to keep)" } else { "  CORTEX_FQDN (e.g. 'mytenant' - visible in Configurations > API Keys)" }
        $cortexFqdn = Read-Host $fqdnPrompt
        if ([string]::IsNullOrWhiteSpace($cortexFqdn)) { $cortexFqdn = $currentFqdn }

        $currentRegion = [Environment]::GetEnvironmentVariable("CORTEX_REGION", "User")
        $regionPrompt = if ($currentRegion) { "  CORTEX_REGION (current: $currentRegion, Enter to keep)" } else { "  CORTEX_REGION (e.g. 'us')" }
        $cortexRegion = Read-Host $regionPrompt
        if ([string]::IsNullOrWhiteSpace($cortexRegion)) { $cortexRegion = $currentRegion }

        $currentKeyId = [Environment]::GetEnvironmentVariable("CORTEX_API_KEY_ID", "User")
        $keyIdPrompt = if ($currentKeyId) { "  CORTEX_API_KEY_ID (current: $currentKeyId, Enter to keep)" } else { "  CORTEX_API_KEY_ID" }
        $cortexKeyId = Read-Host $keyIdPrompt
        if ([string]::IsNullOrWhiteSpace($cortexKeyId)) { $cortexKeyId = $currentKeyId }

        $cortexApiKey = Read-SecretEnvVar -VarName "CORTEX_API_KEY" -Prompt "  CORTEX_API_KEY"

        if ($cortexFqdn) { $envPlan["CORTEX_FQDN"] = $cortexFqdn }
        if ($cortexRegion) { $envPlan["CORTEX_REGION"] = $cortexRegion }
        if ($cortexKeyId) { $envPlan["CORTEX_API_KEY_ID"] = $cortexKeyId }
        if ($cortexApiKey) { $envPlan["CORTEX_API_KEY"] = $cortexApiKey }
    } else {
        Write-Host "  Skipped - configure it later by re-running the script." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "Banner (academic / SIS system, Ellucian) [BANNER]" -ForegroundColor Green
    $hasBannerCreds = Read-Host "  Do you already have Banner CLIENT_ID/SECRET/TOKEN_URL? (y/N)"
    if ($hasBannerCreds -match '^[yY]') {
        $currentBannerId = [Environment]::GetEnvironmentVariable("BANNER_CLIENT_ID", "User")
        $bannerIdPrompt = if ($currentBannerId) { "  BANNER_CLIENT_ID (current: $currentBannerId, Enter to keep)" } else { "  BANNER_CLIENT_ID" }
        $bannerClientId = Read-Host $bannerIdPrompt
        if ([string]::IsNullOrWhiteSpace($bannerClientId)) { $bannerClientId = $currentBannerId }

        $currentBannerTokenUrl = [Environment]::GetEnvironmentVariable("BANNER_TOKEN_URL", "User")
        $bannerTokenUrlPrompt = if ($currentBannerTokenUrl) { "  BANNER_TOKEN_URL (current: $currentBannerTokenUrl, Enter to keep)" } else { "  BANNER_TOKEN_URL (OAuth2 token endpoint, e.g. https://.../oauth/token)" }
        $bannerTokenUrl = Read-Host $bannerTokenUrlPrompt
        if ([string]::IsNullOrWhiteSpace($bannerTokenUrl)) { $bannerTokenUrl = $currentBannerTokenUrl }

        $bannerClientSecret = Read-SecretEnvVar -VarName "BANNER_CLIENT_SECRET" -Prompt "  BANNER_CLIENT_SECRET"

        if ($bannerClientId) { $envPlan["BANNER_CLIENT_ID"] = $bannerClientId }
        if ($bannerTokenUrl) { $envPlan["BANNER_TOKEN_URL"] = $bannerTokenUrl }
        if ($bannerClientSecret) { $envPlan["BANNER_CLIENT_SECRET"] = $bannerClientSecret }
    } else {
        Write-Host "  Skipped - configure it later by re-running the script." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "SOC Vault (remote team audit vault) [VAULT]" -ForegroundColor Green

    $currentVaultHost = [Environment]::GetEnvironmentVariable("VAULT_HOST", "User")
    $vaultHostDefault = if ($currentVaultHost) { $currentVaultHost } else { "10.0.0.10" }
    $vaultHostPrompt = if ($currentVaultHost) { "  VAULT_HOST (current: $currentVaultHost, Enter to keep)" } else { "  VAULT_HOST (Enter to use '$vaultHostDefault')" }
    $vaultHost = Read-Host $vaultHostPrompt
    if ([string]::IsNullOrWhiteSpace($vaultHost)) { $vaultHost = $vaultHostDefault }
    $envPlan["VAULT_HOST"] = $vaultHost

    $currentVaultUser = [Environment]::GetEnvironmentVariable("VAULT_USER", "User")
    $vaultUserDefault = if ($currentVaultUser) { $currentVaultUser } else { "claudian" }
    $vaultUserPrompt = if ($currentVaultUser) { "  VAULT_USER (current: $currentVaultUser, Enter to keep)" } else { "  VAULT_USER (Enter to use '$vaultUserDefault')" }
    $vaultUser = Read-Host $vaultUserPrompt
    if ([string]::IsNullOrWhiteSpace($vaultUser)) { $vaultUser = $vaultUserDefault }
    $envPlan["VAULT_USER"] = $vaultUser

    $currentVaultKey = [Environment]::GetEnvironmentVariable("VAULT_SSH_KEY", "User")
    $vaultKeyDefault = if ($currentVaultKey) { $currentVaultKey } else { "$env:USERPROFILE\.ssh\claudian" }
    $vaultKeyPrompt = if ($currentVaultKey) { "  VAULT_SSH_KEY (current: $currentVaultKey, Enter to keep)" } else { "  VAULT_SSH_KEY (Enter to use '$vaultKeyDefault')" }
    $vaultKey = Read-Host $vaultKeyPrompt
    if ([string]::IsNullOrWhiteSpace($vaultKey)) { $vaultKey = $vaultKeyDefault }
    $envPlan["VAULT_SSH_KEY"] = $vaultKey

    Write-Host ""
    Write-Host "Pentesting (dedicated Kali host) [PENTEST]" -ForegroundColor Green

    $currentPentestHost = [Environment]::GetEnvironmentVariable("PENTEST_SSH_HOST", "User")
    $pentestHostPrompt = if ($currentPentestHost) { "  PENTEST_SSH_HOST (current: $currentPentestHost, Enter to keep)" } else { "  PENTEST_SSH_HOST (IP/hostname of the Kali host)" }
    $pentestHost = Read-Host $pentestHostPrompt
    if ([string]::IsNullOrWhiteSpace($pentestHost)) { $pentestHost = $currentPentestHost }
    if ($pentestHost) { $envPlan["PENTEST_SSH_HOST"] = $pentestHost }

    $currentPentestUser = [Environment]::GetEnvironmentVariable("PENTEST_SSH_USER", "User")
    $pentestUserDefault = if ($currentPentestUser) { $currentPentestUser } else { "kali" }
    $pentestUserPrompt = if ($currentPentestUser) { "  PENTEST_SSH_USER (current: $currentPentestUser, Enter to keep)" } else { "  PENTEST_SSH_USER (Enter to use '$pentestUserDefault')" }
    $pentestUser = Read-Host $pentestUserPrompt
    if ([string]::IsNullOrWhiteSpace($pentestUser)) { $pentestUser = $pentestUserDefault }
    $envPlan["PENTEST_SSH_USER"] = $pentestUser

    $currentPentestKey = [Environment]::GetEnvironmentVariable("PENTEST_SSH_KEY", "User")
    $pentestKeyDefault = if ($currentPentestKey) { $currentPentestKey } else { "$env:USERPROFILE\.ssh\linux" }
    $pentestKeyPrompt = if ($currentPentestKey) { "  PENTEST_SSH_KEY (current: $currentPentestKey, Enter to keep)" } else { "  PENTEST_SSH_KEY (path to the private key already authorized on that host; Enter to use '$pentestKeyDefault')" }
    $pentestKey = Read-Host $pentestKeyPrompt
    if ([string]::IsNullOrWhiteSpace($pentestKey)) { $pentestKey = $pentestKeyDefault }
    $envPlan["PENTEST_SSH_KEY"] = $pentestKey

    Write-Host ""
    Write-Host "The following USER environment variables will be configured:" -ForegroundColor Yellow
    foreach ($k in $envPlan.Keys) {
        if ($k -like "*TOKEN*" -or $k -like "*SECRET*") {
            Write-Host "  $k = ********"
        } else {
            Write-Host "  $k = $($envPlan[$k])"
        }
    }

    if (-not $WhatIfOnly) {
        if ($Force -or (Read-Host "Apply? (y/N)") -match '^[yY]') {
            foreach ($k in $envPlan.Keys) { Set-UserEnvVar -Name $k -Value $envPlan[$k] }
            Write-Host "Variables applied." -ForegroundColor Green
        } else {
            Write-Host "Skipped applying environment variables." -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 2 - SOC Vault SSH key
# ---------------------------------------------------------------------------

$VaultSshKey = [Environment]::GetEnvironmentVariable("VAULT_SSH_KEY", "User")
if ([string]::IsNullOrWhiteSpace($VaultSshKey)) {
    $VaultSshKey = "$env:USERPROFILE\.ssh\claudian"
}
$VaultSshPub = "$VaultSshKey.pub"

Write-Host "--- SOC Vault: SSH key ---" -ForegroundColor Yellow

if (Test-Path $VaultSshKey) {
    Write-Host "A key already exists at '$VaultSshKey' - not generating a new one." -ForegroundColor DarkGray
} else {
    $sshKeygenCmd = Get-Command ssh-keygen -ErrorAction SilentlyContinue
    if (-not $sshKeygenCmd) {
        Write-Warning "'ssh-keygen' not found in PATH (install the optional Windows 'OpenSSH Client'). Skipping key generation."
    } else {
        Write-Host "An ed25519 key pair (no passphrase, for non-interactive use) will be generated at:"
        Write-Host "  $VaultSshKey"
        if (-not $WhatIfOnly) {
            if ($Force -or (Read-Host "Generate the key now? (y/N)") -match '^[yY]') {
                $sshDir = Split-Path $VaultSshKey -Parent
                if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Force -Path $sshDir | Out-Null }
                & ssh-keygen -t ed25519 -f $VaultSshKey -N '""' -C "$DetectedUpn@claudian" -q
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "ssh-keygen failed (exit code $LASTEXITCODE)."
                } else {
                    Write-Host "Key generated." -ForegroundColor Green
                }
            } else {
                Write-Host "Skipped key generation." -ForegroundColor DarkGray
            }
        }
    }
}

if (Test-Path $VaultSshPub) {
    $pubKeyContent = (Get-Content $VaultSshPub -Raw).Trim()
    Write-Host ""
    Write-Host "This analyst's public key - send it to the admin of the SOC vault VM" -ForegroundColor Cyan
    Write-Host "so they add this line to /home/claudian/.ssh/authorized_keys:"
    Write-Host ""
    Write-Host "command=""/data/claudian/bin/vault-agent.py --analyst=$DetectedUpn"",no-port-forwarding,no-X11-forwarding,no-pty,no-agent-forwarding $pubKeyContent" -ForegroundColor White
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 3 - Clone the repository if it does not exist
# ---------------------------------------------------------------------------

$RepoLocalPath = [Environment]::GetEnvironmentVariable("MCT_REPO_PATH", "User")
if ([string]::IsNullOrWhiteSpace($RepoLocalPath)) {
    $RepoLocalPath = "$env:USERPROFILE\soc-mcp-toolkit"
}

if (-not (Test-Path (Join-Path $RepoLocalPath ".git"))) {
    Write-Host "--- Clone repository ---" -ForegroundColor Yellow

    $cloneToken  = [Environment]::GetEnvironmentVariable("GITHUB_MCT_TOKEN", "User")
    $cloneRepo   = [Environment]::GetEnvironmentVariable("GITHUB_MCT_REPO", "User")
    $cloneBranch = [Environment]::GetEnvironmentVariable("GITHUB_MCT_BRANCH", "User")
    if ([string]::IsNullOrWhiteSpace($cloneBranch)) { $cloneBranch = "main" }

    if ($cloneToken -and $cloneRepo) {
        Write-Host "Cloning '$cloneRepo' (branch $cloneBranch) into '$RepoLocalPath'."
        if (-not $WhatIfOnly) {
            git clone --branch $cloneBranch --quiet "https://$cloneToken@github.com/$cloneRepo.git" $RepoLocalPath
            git -C $RepoLocalPath remote set-url origin "https://github.com/$cloneRepo.git"
            Write-Host "Repository cloned." -ForegroundColor Green
        }
    } else {
        Write-Warning "GITHUB_MCT_TOKEN or GITHUB_MCT_REPO missing - could not clone the repository. Set them and re-run this script."
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 4 - Python dependencies
# ---------------------------------------------------------------------------

if (-not $SkipDependencies) {
    Write-Host "--- Python dependencies ---" -ForegroundColor Yellow
    $allFolders = @($Domains | ForEach-Object { $_.Folder }) + @($CortexFolder, $VaultFolder, $BannerFolder, $PentestFolder)
    foreach ($folder in $allFolders) {
        $reqPath = Join-Path $RepoLocalPath "$folder\requirements.txt"
        if (-not (Test-Path $reqPath)) {
            Write-Host "  (skipped) $folder`: no requirements.txt" -ForegroundColor DarkGray
            continue
        }
        Write-Host "  $folder`: pip install -r requirements.txt"
        if (-not $WhatIfOnly) {
            & $PythonExe -m pip install -r $reqPath --quiet
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "pip install failed for $folder (exit code $LASTEXITCODE)"
            }
        }
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 5 - .claude.json
# ---------------------------------------------------------------------------

if (-not $SkipClaudeConfig) {
    Write-Host "--- .claude.json ---" -ForegroundColor Yellow

    if (-not (Test-Path $ClaudeConfigPath)) {
        Write-Warning "$ClaudeConfigPath not found - skipping this step."
    } else {
        # -AsHashtable avoids "duplicated keys" in ConvertFrom-Json: without it, PSObject treats
        # properties as case-insensitive and .claude.json may contain keys that differ only in
        # case (e.g. two "projects" paths with different drive-letter casing).
        $existingConfig = Get-Content $ClaudeConfigPath -Raw | ConvertFrom-Json -AsHashtable

        $newServers = [ordered]@{}
        foreach ($d in $Domains) {
            $serverScript = (Join-Path $RepoLocalPath "$($d.Folder)\server.py") -replace '\\', '/'
            $clientIdVar = "$($d.Prefix)_CLIENT_ID"
            $clientSecretVar = "$($d.Prefix)_CLIENT_SECRET"

            $envBlock = [ordered]@{}
            $envBlock["AZURE_TENANT_ID"] = '${AZURE_TENANT_ID}'
            $envBlock[$clientIdVar] = '${' + $clientIdVar + '}'
            $envBlock[$clientSecretVar] = '${' + $clientSecretVar + '}'
            $envBlock["MCP_ANALYST_NAME"] = $DetectedUpn
            # require_vault (shared/mcp_common.py) is ENABLED by default and blocks all tools of this
            # server unless it can verify the audit vault first - it needs the same SSH
            # credentials as mcp-vault, without relying on the process inheriting the user's
            # environment.
            $envBlock["VAULT_HOST"] = '${VAULT_HOST}'
            $envBlock["VAULT_USER"] = '${VAULT_USER}'
            $envBlock["VAULT_SSH_KEY"] = '${VAULT_SSH_KEY}'

            $newServers[$d.Name] = [ordered]@{
                command = "python"
                args    = @($serverScript)
                env     = $envBlock
            }
        }

        $cortexScript = (Join-Path $RepoLocalPath "$CortexFolder\server.py") -replace '\\', '/'
        $newServers["mcp-cortex"] = [ordered]@{
            command = "python"
            args    = @($cortexScript)
            env     = [ordered]@{
                CORTEX_FQDN       = '${CORTEX_FQDN}'
                CORTEX_REGION     = '${CORTEX_REGION}'
                CORTEX_API_KEY_ID = '${CORTEX_API_KEY_ID}'
                CORTEX_API_KEY    = '${CORTEX_API_KEY}'
                MCP_ANALYST_NAME  = $DetectedUpn
                VAULT_HOST        = '${VAULT_HOST}'
                VAULT_USER        = '${VAULT_USER}'
                VAULT_SSH_KEY     = '${VAULT_SSH_KEY}'
            }
        }

        $bannerScript = (Join-Path $RepoLocalPath "$BannerFolder\server.py") -replace '\\', '/'
        $newServers["mcp-banner"] = [ordered]@{
            command = "python"
            args    = @($bannerScript)
            env     = [ordered]@{
                BANNER_CLIENT_ID     = '${BANNER_CLIENT_ID}'
                BANNER_CLIENT_SECRET = '${BANNER_CLIENT_SECRET}'
                BANNER_TOKEN_URL     = '${BANNER_TOKEN_URL}'
                MCP_ANALYST_NAME     = $DetectedUpn
                VAULT_HOST           = '${VAULT_HOST}'
                VAULT_USER           = '${VAULT_USER}'
                VAULT_SSH_KEY        = '${VAULT_SSH_KEY}'
            }
        }

        $vaultScript = (Join-Path $RepoLocalPath "$VaultFolder\server.py") -replace '\\', '/'
        $newServers["mcp-vault"] = [ordered]@{
            command = "python"
            args    = @($vaultScript)
            env     = [ordered]@{
                # No MCP_ANALYST_NAME on purpose: the identity used for auditing is decided by
                # the VM based on which SSH key connected (forced command), not a client env var.
                VAULT_HOST    = '${VAULT_HOST}'
                VAULT_USER    = '${VAULT_USER}'
                VAULT_SSH_KEY = '${VAULT_SSH_KEY}'
            }
        }

        $pentestScript = (Join-Path $RepoLocalPath "$PentestFolder\server.py") -replace '\\', '/'
        $newServers["mcp-pentesting"] = [ordered]@{
            command = "python"
            args    = @($pentestScript)
            env     = [ordered]@{
                PENTEST_SSH_HOST = '${PENTEST_SSH_HOST}'
                PENTEST_SSH_USER = '${PENTEST_SSH_USER}'
                PENTEST_SSH_KEY  = '${PENTEST_SSH_KEY}'
                MCP_ANALYST_NAME = $DetectedUpn
                VAULT_HOST       = '${VAULT_HOST}'
                VAULT_USER       = '${VAULT_USER}'
                VAULT_SSH_KEY    = '${VAULT_SSH_KEY}'
            }
        }

        Write-Host "The following entries will be added to mcpServers (existing ones with the same name are NOT touched):"
        $newServers.Keys | ForEach-Object { Write-Host "  - $_" }

        if ($existingConfig.mcpServers) {
            $alreadyThere = $newServers.Keys | Where-Object { $existingConfig.mcpServers.Keys -contains $_ }
            if ($alreadyThere) {
                Write-Warning "These entries already exist in $ClaudeConfigPath : $($alreadyThere -join ', '). merge_claude_config.py NEVER overwrites existing entries - if they come from an older version (without VAULT_HOST/VAULT_USER/VAULT_SSH_KEY, needed for require_vault), delete them by hand before applying so they register with the new env."
            }
        }

        if (-not $WhatIfOnly) {
            if ($Force -or (Read-Host "Apply changes to $ClaudeConfigPath ? (y/N)") -match '^[yY]') {
                $tmpJson = Join-Path $env:TEMP "mcp-new-servers-$(Get-Random).json"
                $jsonText = $newServers | ConvertTo-Json -Depth 6
                [System.IO.File]::WriteAllText($tmpJson, $jsonText, (New-Object System.Text.UTF8Encoding($false)))

                $mergeScript = Join-Path $RepoRoot "merge_claude_config.py"
                $result = & $PythonExe $mergeScript $ClaudeConfigPath $tmpJson
                Remove-Item $tmpJson -ErrorAction SilentlyContinue

                foreach ($line in $result) {
                    if ($line -match '^BACKUP=(.+)$') { Write-Host "Backup created at: $($Matches[1])" -ForegroundColor Green }
                    elseif ($line -match '^ADDED=(.*)$') { Write-Host "Added: $($Matches[1])" -ForegroundColor Green }
                    elseif ($line -match '^SKIPPED=(.*)$' -and $Matches[1]) { Write-Host "Already existed (untouched): $($Matches[1])" -ForegroundColor DarkGray }
                }
            } else {
                Write-Host "Skipped modifying .claude.json." -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Step 6 - Scheduled Task MCT-Sync
# ---------------------------------------------------------------------------

if (-not $SkipScheduledTask) {
    Write-Host "--- Scheduled Task: MCT-Sync ---" -ForegroundColor Yellow

    $syncScript = Join-Path $RepoLocalPath "sync-mct.ps1"

    Write-Host "Script      : $syncScript"
    Write-Host "Triggers    : every 30 minutes + at logon ($env:USERNAME)"
    Write-Host "User        : $env:USERNAME"

    if (-not (Test-Path $syncScript)) {
        Write-Warning "$syncScript not found - skipping this step."
    } elseif (-not $WhatIfOnly) {
        if ($Force -or (Read-Host "Register the MCT-Sync Scheduled Task? (y/N)") -match '^[yY]') {
            $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$syncScript`""

            # [TimeSpan]::MaxValue serializes to a duration XML (P99999999DT23H59M59S) outside
            # the range Task Scheduler accepts. 10 years is the standard idiom for "repeat
            # indefinitely" with New-ScheduledTaskTrigger.
            $trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 3650)
            $trigger2 = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME

            $settings = New-ScheduledTaskSettingsSet `
                -StartWhenAvailable `
                -RunOnlyIfNetworkAvailable `
                -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
                -MultipleInstances IgnoreNew `
                -Hidden

            $registered = $null
            try {
                $registered = Register-ScheduledTask `
                    -TaskName $TaskName `
                    -Action $action `
                    -Trigger @($trigger1, $trigger2) `
                    -Settings $settings `
                    -Description "Syncs the SOC MCP Toolkit from GitHub. Installed by install-mcp-cyber-toolkit.ps1." `
                    -RunLevel Limited `
                    -Force -ErrorAction Stop
            } catch {
                Write-Warning "Could not register the Scheduled Task: $_"
            }

            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($registered -and $existingTask) {
                Write-Host "Scheduled Task '$TaskName' registered." -ForegroundColor Green

                Start-ScheduledTask -TaskName $TaskName
                Start-Sleep -Seconds 8
                $info = Get-ScheduledTaskInfo -TaskName $TaskName
                if ($info.LastTaskResult -eq 0) {
                    Write-Host "First run OK." -ForegroundColor Green
                } else {
                    Write-Warning "The first run did not return code 0 (LastTaskResult=$($info.LastTaskResult)). Check $RepoLocalPath\.mct_logs\sync.log"
                }
            } else {
                Write-Warning "The Scheduled Task '$TaskName' was not registered. Check the previous error before continuing."
            }
        } else {
            Write-Host "Skipped registering the Scheduled Task." -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------

Write-Host "=== SOC MCP Toolkit ready ===" -ForegroundColor Cyan
Write-Host "Analyst        : $DetectedUpn"
Write-Host "Local repo     : $RepoLocalPath"
Write-Host "Sync           : every 30 min + at logon (Task: $TaskName)"
Write-Host "Sync logs      : $RepoLocalPath\.mct_logs\sync.log"
Write-Host "Audit logs     : $env:USERPROFILE\.mct_logs\audit\"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Close and reopen Claude Code."
Write-Host "  2. Check the task in Task Scheduler -> '$TaskName'."
Write-Host "  3. Review $RepoLocalPath\.mct_logs\sync.log in 30 min."
Write-Host ""
Write-Host "If your real UPN differs from the detected one, fix it manually:"
Write-Host "  [Environment]::SetEnvironmentVariable('MCP_ANALYST_NAME', 'youruser@$UpnDomain', 'User')"
