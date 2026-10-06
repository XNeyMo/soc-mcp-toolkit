#requires -Version 7.0
<#
.SYNOPSIS
    PARALLEL version of the purge (hard-delete / permanentDelete) of internal emails
    listed in the CSV produced by get-emails-2.ps1, via Microsoft Graph.

    SOC tooling. Requires PowerShell 7+ (ForEach-Object -Parallel).

.IMPORTANT
    - IRREVERSIBLE action. Requires formal authorization and prior evidence.
    - Internal mailboxes only (own domain); external ones are skipped.
    - Graph applies throttling (429): ThrottleLimit is kept moderate and requests are
      retried with backoff. Raising it too far DEGRADES performance.
    - Simulation mode by default (-WhatIf $true).

    Application permission: Mail.ReadWrite (admin consent).
    Credentials: uses the SAME app registration and environment variables as mcp-exchange
    (AZURE_TENANT_ID, EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET). No secret is ever
    embedded in this script.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CsvPath,
    [string]$InternalDomain = "example.com",
    [int]   $ThrottleLimit  = 10,        # concurrent threads (raise with care)
    [int]   $MaxRetries     = 5,         # retries on 429/5xx
    [string]$TenantId     = $env:AZURE_TENANT_ID,
    [string]$ClientId     = $env:EXCHANGE_CLIENT_ID,
    [string]$ClientSecret = $env:EXCHANGE_CLIENT_SECRET,
    [bool]  $WhatIf         = $true,
    [string]$LogCsv         = ".\purge_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'
if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
    throw "Missing AZURE_TENANT_ID, EXCHANGE_CLIENT_ID or EXCHANGE_CLIENT_SECRET in the environment (the same variables used by mcp-exchange)."
}
if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
$InternalDomain = $InternalDomain.ToLower()

function Get-Domain { param([string]$Addr)
    if ([string]::IsNullOrWhiteSpace($Addr) -or $Addr -notmatch '@') { return "" }
    return ($Addr.Split('@')[-1]).Trim().ToLower()
}

# ---------- Token (acquired once; shared with the threads) ----------
$tokenBody = @{
    grant_type    = "client_credentials"; client_id = $ClientId
    client_secret = $ClientSecret; scope = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $tokenBody).access_token
Write-Host "[+] Token acquired." -ForegroundColor Green
Write-Host "[*] Internal domain: $InternalDomain | ThrottleLimit: $ThrottleLimit"
if ($WhatIf) { Write-Host "[*] SIMULATION MODE (-WhatIf `$true): nothing will be deleted." -ForegroundColor Yellow }

# ---------- Build the job list (1 per internal mailbox + message) ----------
$rows = Import-Csv -Path $CsvPath
$jobs = New-Object System.Collections.Generic.List[object]
$omitExt = 0
foreach ($r in $rows) {
    if ([string]::IsNullOrWhiteSpace($r.InternetMessageId)) { continue }
    foreach ($pair in @(
        @{ Mailbox = $r.RecipientEmailAddress; Role = "Recipient" },
        @{ Mailbox = $r.SenderFromAddress;     Role = "Sender" }
    )) {
        $mbx = $pair.Mailbox
        if ([string]::IsNullOrWhiteSpace($mbx)) { continue }
        if ((Get-Domain $mbx) -ne $InternalDomain) { $omitExt++; continue }
        $jobs.Add([pscustomobject]@{
            Mailbox = $mbx.Trim(); Role = $pair.Role; InternetMessageId = $r.InternetMessageId
        })
    }
}
$total = $jobs.Count
Write-Host ("[*] Internal jobs to process: {0} (external skipped: {1})" -f $total, $omitExt) -ForegroundColor Cyan

# Progress counter shared between threads.
$counter = [hashtable]::Synchronized(@{ Done = 0 })

# ---------- Parallel execution ----------
$results = $jobs | ForEach-Object -ThrottleLimit $ThrottleLimit -Parallel {
    $job        = $_
    $token      = $using:token
    $whatIf     = $using:WhatIf
    $maxRetries = $using:MaxRetries
    $counter    = $using:counter
    $headers    = @{ Authorization = "Bearer $token" }

    $res = [pscustomobject]@{
        Mailbox = $job.Mailbox; Role = $job.Role; InternetMessageId = $job.InternetMessageId
        Found = $false; Action = ""; Detail = ""
    }

    # Helper: call Graph with retry on 429/5xx (backoff honoring Retry-After).
    function Invoke-GraphWithRetry {
        param([string]$Method, [string]$Uri, $Headers, $MaxRetries)
        for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
            try {
                return Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers `
                    -ContentType "application/json" -ErrorAction Stop
            } catch {
                $code = $_.Exception.Response.StatusCode.value__
                if (($code -eq 429 -or $code -ge 500) -and $attempt -lt $MaxRetries) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    $wait = if ($retryAfter) { [int]$retryAfter } else { [math]::Pow(2, $attempt) }
                    Start-Sleep -Seconds $wait
                    continue
                }
                throw
            }
        }
    }

    try {
        $imidEsc = $job.InternetMessageId.Replace("'", "''")
        $filter  = [System.Web.HttpUtility]::UrlEncode("internetMessageId eq '$imidEsc'")
        $findUri = "https://graph.microsoft.com/v1.0/users/$($job.Mailbox)/messages?`$filter=$filter&`$select=id"
        $resp    = Invoke-GraphWithRetry -Method Get -Uri $findUri -Headers $headers -MaxRetries $maxRetries
        $found   = $resp.Content | ConvertFrom-Json

        if (-not $found.value -or $found.value.Count -eq 0) {
            $res.Detail = "Not found in this mailbox."
        } else {
            $res.Found = $true
            foreach ($msg in $found.value) {
                if ($whatIf) {
                    $res.Action = "SIMULATED (not deleted)"; $res.Detail = "ItemId=$($msg.id)"
                } else {
                    $delUri = "https://graph.microsoft.com/v1.0/users/$($job.Mailbox)/messages/$($msg.id)/permanentDelete"
                    Invoke-GraphWithRetry -Method Post -Uri $delUri -Headers $headers -MaxRetries $maxRetries | Out-Null
                    $res.Action = "DELETED (permanentDelete)"; $res.Detail = "ItemId=$($msg.id)"
                }
            }
        }
    } catch {
        $res.Action = "ERROR"; $res.Detail = $_.Exception.Message
    }

    # Progress (synchronized access).
    [System.Threading.Monitor]::Enter($counter.SyncRoot)
    try { $counter.Done++ } finally { [System.Threading.Monitor]::Exit($counter.SyncRoot) }
    if ($counter.Done % 100 -eq 0) {
        Write-Host ("  ... processed $($counter.Done)") -ForegroundColor DarkGray
    }

    $res
}

# ---------- Summary + log ----------
$enc = ($results | Where-Object Found).Count
$brr = ($results | Where-Object { $_.Action -like "DELETED*" }).Count
$err = ($results | Where-Object { $_.Action -eq "ERROR" }).Count
Write-Host ("[+] Found: {0} | Deleted: {1} | Errors: {2} | External skipped: {3}" -f `
    $enc, $brr, $err, $omitExt) -ForegroundColor Cyan

$results | Export-Csv -Path $LogCsv -NoTypeInformation -Encoding UTF8
Write-Host "[+] Audit log: $LogCsv" -ForegroundColor Green
if ($WhatIf) { Write-Host "[*] To perform the real deletion: re-run with -WhatIf `$false" -ForegroundColor Yellow }
