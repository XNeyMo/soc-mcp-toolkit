<#
.SYNOPSIS
    Revokes the sessions (refresh tokens) of a bulk list of Microsoft Entra ID accounts
    from a CSV file with a "mail" column.

.DESCRIPTION
    Reads a CSV of accounts and calls POST /users/{id}/revokeSignInSessions on Microsoft Graph
    directly (REST, without the Microsoft.Graph.Users SDK) using the SAME app registration and
    application credentials as mcp-identity (AZURE_TENANT_ID, IDENTITY_CLIENT_ID,
    IDENTITY_CLIENT_SECRET).
    By default it runs in PREVIEW mode (executes nothing) - -Execute must be passed explicitly
    to really revoke sessions, and a typed confirmation is also required before proceeding.

    Requires the application permission "User.RevokeSessions.All" (or "User.ReadWrite.All") in
    Entra ID, granted to the sec-identity-mcp app used by mcp-identity.

.PARAMETER CsvPath
    Path to the input CSV file. It must have a column named "mail" (or the one given in -MailColumn).

.PARAMETER MailColumn
    Name of the CSV column that contains the email/UPN. Defaults to "mail".

.PARAMETER Execute
    If not specified, the script only shows the preview (dry run) and revokes nothing.
    If specified, performs the real revocation after asking for typed confirmation.

.PARAMETER ThrottleMs
    Milliseconds to wait between Graph calls to avoid throttling (429). Defaults to 150.

.PARAMETER MaxRetries
    Maximum number of retries on a 429 (Too Many Requests) per account. Defaults to 5.

.PARAMETER OutputDir
    Folder where the results CSV is saved. Defaults to the script's own folder.

.EXAMPLE
    # 1) Preview - revokes nothing, only validates the CSV and shows how many accounts would be affected
    .\Revoke-BulkUserSessions.ps1 -CsvPath .\accounts.csv

.EXAMPLE
    # 2) Real execution after reviewing the preview
    .\Revoke-BulkUserSessions.ps1 -CsvPath .\accounts.csv -Execute
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [string]$MailColumn = "mail",

    [switch]$Execute,

    [ValidateRange(0, 60000)]
    [int]$ThrottleMs = 150,

    [ValidateRange(1, 10)]
    [int]$MaxRetries = 5,

    [string]$OutputDir = $PSScriptRoot,

    [string]$TenantId     = $env:AZURE_TENANT_ID,
    [string]$ClientId     = $env:IDENTITY_CLIENT_ID,
    [string]$ClientSecret = $env:IDENTITY_CLIENT_SECRET
)

$ErrorActionPreference = "Stop"

if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
    throw "AZURE_TENANT_ID, IDENTITY_CLIENT_ID or IDENTITY_CLIENT_SECRET is missing from the environment (the same variables used by mcp-identity)."
}

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host "==== $Text ====" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 1. Read and validate the CSV
# ---------------------------------------------------------------------------

Write-Section "Reading CSV: $CsvPath"

$rows = Import-Csv -Path $CsvPath

if (-not ($rows | Get-Member -Name $MailColumn -MemberType NoteProperty)) {
    Write-Host "The CSV has no column '$MailColumn'. Columns found: $((($rows | Get-Member -MemberType NoteProperty).Name) -join ', ')" -ForegroundColor Red
    exit 1
}

$rawEmails = $rows | ForEach-Object { $_.$MailColumn } | Where-Object { $_ -and $_.Trim() -ne "" }

$emails = $rawEmails |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' } |
    Sort-Object -Unique

$invalidCount = $rawEmails.Count - ($rawEmails | Where-Object { $_.Trim() -match '^[^@\s]+@[^@\s]+\.[^@\s]+$' }).Count
$duplicateCount = $rawEmails.Count - $invalidCount - $emails.Count

Write-Host "Rows read from CSV:        $($rows.Count)"
Write-Host "Unique valid emails:       $($emails.Count)"
Write-Host "Duplicates removed:        $duplicateCount"
Write-Host "Invalid/empty rows:        $invalidCount"

if ($emails.Count -eq 0) {
    Write-Host "No valid emails to process. Aborting." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 3. Preview (dry run) - always shown
# ---------------------------------------------------------------------------

Write-Section "PREVIEW"

Write-Host "Sessions (refresh tokens) will be revoked for $($emails.Count) account(s)."
Write-Host "Each user will have to sign in again on all their devices and applications."
Write-Host ""
Write-Host "Sample (first 10):"
$emails | Select-Object -First 10 | ForEach-Object { Write-Host "  - $_" }
if ($emails.Count -gt 10) { Write-Host "  ... and $($emails.Count - 10) more." }

if (-not $Execute) {
    Write-Host ""
    Write-Host "PREVIEW mode (dry run) - no revocation was executed." -ForegroundColor Yellow
    Write-Host "Run again with -Execute to really revoke sessions, after confirming the preview." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# 4. Explicit confirmation before executing
# ---------------------------------------------------------------------------

Write-Section "CONFIRMATION REQUIRED"

Write-Host "You are about to IRREVERSIBLY revoke sessions for $($emails.Count) accounts (each user will have to re-authenticate)." -ForegroundColor Yellow
$confirmText = Read-Host "Type CONFIRM to proceed"
if ($confirmText -ne "CONFIRM") {
    Write-Host "Confirmation not received. Aborting without making changes." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 5. Get an application token (client credentials, same app as mcp-identity)
# ---------------------------------------------------------------------------

Write-Section "Authenticating against Microsoft Graph (app-only)"

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token" }
Write-Host "Token acquired (tenant: $TenantId)." -ForegroundColor Green

# ---------------------------------------------------------------------------
# 6. Execute revocation with retries on throttling (429)
# ---------------------------------------------------------------------------

Write-Section "Executing session revocation"

$results = New-Object System.Collections.Generic.List[object]
$total = $emails.Count
$i = 0

foreach ($mail in $emails) {
    $i++
    Write-Progress -Activity "Revoking sessions" -Status "$i / $total : $mail" -PercentComplete (($i / $total) * 100)

    $attempt = 0
    $done = $false
    $status = "Failed"
    $errorMsg = ""

    while (-not $done -and $attempt -le $MaxRetries) {
        $attempt++
        try {
            Invoke-RestMethod -Method Post `
                -Uri "https://graph.microsoft.com/v1.0/users/$mail/revokeSignInSessions" `
                -Headers $headers -ErrorAction Stop | Out-Null
            $status = "Revoked"
            $errorMsg = ""
            $done = $true
        }
        catch {
            $err = $_
            $isThrottled = $err.Exception.Response -and ($err.Exception.Response.StatusCode.value__ -eq 429)
            if ($isThrottled -and $attempt -le $MaxRetries) {
                $retryAfter = 5
                try {
                    $header = $err.Exception.Response.Headers["Retry-After"]
                    if ($header) { $retryAfter = [int]$header }
                } catch {}
                Write-Host "  Throttled on $mail, waiting $retryAfter s (attempt $attempt/$MaxRetries)..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds $retryAfter
                continue
            } else {
                $status = "Failed"
                $errorMsg = $err.Exception.Message
                $done = $true
            }
        }
    }

    $results.Add([pscustomobject]@{
        Mail   = $mail
        Status = $status
        Error  = $errorMsg
    })

    if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }
}

Write-Progress -Activity "Revoking sessions" -Completed

# ---------------------------------------------------------------------------
# 7. Summary and report
# ---------------------------------------------------------------------------

Write-Section "SUMMARY"

$successCount = ($results | Where-Object { $_.Status -eq "Revoked" }).Count
$failCount = ($results | Where-Object { $_.Status -eq "Failed" }).Count

Write-Host "Total processed: $total"
Write-Host "Revoked OK:      $successCount" -ForegroundColor Green
Write-Host "Failed:          $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$reportPath = Join-Path $OutputDir "Revoke-Results-$timestamp.csv"
$results | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Detailed report saved to: $reportPath"

if ($failCount -gt 0) {
    Write-Host ""
    Write-Host "Failed accounts:" -ForegroundColor Red
    $results | Where-Object { $_.Status -eq "Failed" } | ForEach-Object { Write-Host "  - $($_.Mail): $($_.Error)" }
}
