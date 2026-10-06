<#
.SYNOPSIS
    Syncs the SOC MCP Toolkit from GitHub.

.DESCRIPTION
    Intended to run as a "MCT-Sync" Scheduled Task every 15 minutes and at logon.
    Performs a read-only git pull using a GitHub fine-grained PAT. If there were
    changes, it shows a Windows notification so the analyst restarts Claude Code.

    Environment variables (User scope):
      GITHUB_MCT_TOKEN   Fine-grained PAT (contents:read)
      GITHUB_MCT_REPO    owner/repo, e.g. your-org/soc-mcp-toolkit
      GITHUB_MCT_BRANCH  branch to sync, default "main"
      MCT_REPO_PATH      local path of the cloned repo
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$GhToken  = $env:GITHUB_MCT_TOKEN
$GhRepo   = $env:GITHUB_MCT_REPO
$GhBranch = if ($env:GITHUB_MCT_BRANCH) { $env:GITHUB_MCT_BRANCH } else { "main" }
$RepoPath = if ($env:MCT_REPO_PATH) { $env:MCT_REPO_PATH } else { "$env:USERPROFILE\soc-mcp-toolkit" }

$LogDir   = Join-Path $RepoPath ".mct_logs"
$LogFile  = Join-Path $LogDir "sync.log"
$LockFile = Join-Path $env:TEMP "mct-sync.lock"

function Write-Log {
    param(
        [ValidateSet("INFO", "WARN", "ERROR")][string]$Level,
        [string]$Message
    )
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    }
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) {
        $rotated = Join-Path $LogDir "sync-$(Get-Date -Format 'yyyyMMdd').log"
        Move-Item -Path $LogFile -Destination $rotated -Force
    }
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Find-GitExe {
    $cmd = Get-Command git -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $candidates = @(
        "C:\Program Files\Git\cmd\git.exe",
        "C:\Program Files (x86)\Git\cmd\git.exe",
        "$env:LOCALAPPDATA\Programs\Git\cmd\git.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    return $null
}

function Show-ToastNotification {
    param([string]$Title, [string]$Message)
    try {
        if (Get-Module -ListAvailable -Name BurntToast) {
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text $Title, $Message
            return
        }
    } catch {
        Write-Log WARN "BurntToast failed, trying the native API: $_"
    }
    try {
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
            [Windows.UI.Notifications.ToastTemplateType]::ToastGeneric
        )
        $xml = $template.GetXml()
        $toastXml = New-Object Windows.Data.Xml.Dom.XmlDocument
        $toastXml.LoadXml($xml)

        $textNodes = $toastXml.GetElementsByTagName("text")
        $textNodes.Item(0).AppendChild($toastXml.CreateTextNode($Title)) | Out-Null
        if ($textNodes.Count -gt 1) {
            $textNodes.Item(1).AppendChild($toastXml.CreateTextNode($Message)) | Out-Null
        }

        $toast = [Windows.UI.Notifications.ToastNotification]::new($toastXml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("soc-mcp-toolkit").Show($toast)
    } catch {
        Write-Log WARN "Could not show the Windows notification: $_"
    }
}

# --- Pre-flight checks ---

if ([string]::IsNullOrWhiteSpace($GhToken)) {
    Write-Log ERROR "GITHUB_MCT_TOKEN is not set."
    exit 1
}
if ([string]::IsNullOrWhiteSpace($GhRepo)) {
    Write-Log ERROR "GITHUB_MCT_REPO is not set."
    exit 1
}
$GitExe = Find-GitExe
if (-not $GitExe) {
    Write-Log ERROR "git.exe not found in PATH or in the known locations."
    exit 1
}
if (-not (Test-Path $RepoPath)) {
    Write-Log ERROR "MCT_REPO_PATH ('$RepoPath') does not exist."
    exit 1
}

# --- Lock ---

if (Test-Path $LockFile) {
    $age = (Get-Date) - (Get-Item $LockFile).LastWriteTime
    if ($age.TotalMinutes -lt 10) {
        exit 0
    }
    Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
}

try {
    New-Item -ItemType File -Force -Path $LockFile | Out-Null

    Set-Location $RepoPath

    $before = (& $GitExe rev-parse HEAD).Trim()

    $remoteUrlWithToken = "https://$GhToken@github.com/$GhRepo.git"
    & $GitExe remote set-url origin $remoteUrlWithToken 2>$null

    $pullOut  = & $GitExe pull --quiet --ff-only origin $GhBranch 2>&1
    $pullExit = $LASTEXITCODE

    # Restore the clean URL immediately, whether or not the pull failed.
    & $GitExe remote set-url origin "https://github.com/$GhRepo.git" 2>$null

    if ($pullExit -ne 0) {
        $safe = ($pullOut -join " ") -replace [regex]::Escape($GhToken), "***"
        Write-Log ERROR "git pull failed (exit $pullExit): $safe"
        exit 1
    }

    $after = (& $GitExe rev-parse HEAD).Trim()

    if ($before -eq $after) {
        Write-Log INFO "No changes (HEAD: $($before.Substring(0,8)))"
        exit 0
    }

    $changedFiles = & $GitExe diff --name-only $before $after
    $count = ($changedFiles | Measure-Object -Line).Lines
    $sb = $before.Substring(0, 8)
    $sa = $after.Substring(0, 8)

    Write-Log INFO "Updated $sb -> $sa ($count file(s))"
    foreach ($f in $changedFiles) {
        Write-Log INFO "  ~ $f"
    }

    Show-ToastNotification -Title "soc-mcp-toolkit updated" -Message "$count new file(s). Restart Claude Code."
}
finally {
    Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
}
