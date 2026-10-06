<#
.SYNOPSIS
    Queries Advanced Hunting (Defender XDR / Graph Security) for an EXACT subject,
    classifies sender/recipient as internal/external and exports the result to CSV.

    SOC tooling. Incident response / threat hunting.

.NOTES
    - Save this .ps1 as 'UTF-8 with BOM' (or use pwsh 7) for subjects with accented characters.
    - Application permission: ThreatHunting.Read.All (admin consent).
    - Credentials: uses the SAME app registration and environment variables as mcp-exchange
      (AZURE_TENANT_ID, EXCHANGE_CLIENT_ID, EXCHANGE_CLIENT_SECRET). No secret is ever
      embedded in this script.
#>

[CmdletBinding()]
param(
    [string]$Subject        = "FINAL WARNING",         # EXACT match (==)
    [string]$InternalDomain = "example.com",           # the tenant's own domain
    [string]$TenantId     = $env:AZURE_TENANT_ID,
    [string]$ClientId     = $env:EXCHANGE_CLIENT_ID,
    [string]$ClientSecret = $env:EXCHANGE_CLIENT_SECRET,
    [string]$OutputCsv      = ".\emails_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'

if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
    throw "Missing AZURE_TENANT_ID, EXCHANGE_CLIENT_ID or EXCHANGE_CLIENT_SECRET in the environment (the same variables used by mcp-exchange)."
}

# ---------- Encoding diagnostics ----------
$bytesHex = ([System.Text.Encoding]::UTF8.GetBytes($Subject) | ForEach-Object { $_.ToString("X2") }) -join ' '
Write-Host "[*] Subject searched : '$Subject'"
Write-Host "[*] UTF-8 bytes      : $bytesHex" -ForegroundColor DarkGray
Write-Host "[*] Internal domain  : $InternalDomain"

# ---------- Classification helpers ----------
function Get-Domain { param([string]$Addr)
    if ([string]::IsNullOrWhiteSpace($Addr) -or $Addr -notmatch '@') { return "" }
    return ($Addr.Split('@')[-1]).Trim().ToLower()
}
function Get-Origin { param([string]$Addr, [string]$Internal)
    $d = Get-Domain $Addr
    if ($d -eq $Internal.ToLower()) { return "Internal" } else { return "External" }
}

# ---------- KQL query (EXACT match) ----------
$kql = @"
EmailEvents
| where Subject == "$Subject"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by Timestamp desc
"@

# ---------- Token ----------
$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $tokenBody).access_token
Write-Host "[+] Token acquired." -ForegroundColor Green

# ---------- Query ----------
$headers   = @{ Authorization = "Bearer $token" }
$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes((@{ Query = $kql } | ConvertTo-Json))
try {
    $resp = Invoke-RestMethod -Method Post `
        -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
        -Headers $headers -ContentType "application/json; charset=utf-8" -Body $bodyBytes
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    switch ($code) {
        401 { throw "401: token/audience problem (check the scope)." }
        403 { throw "403: ThreatHunting.Read.All is missing admin consent." }
        default { throw $_ }
    }
}

$rows = $resp.results
Write-Host "[+] Results: $($rows.Count)" -ForegroundColor Cyan

if ($rows.Count -eq 0) {
    Write-Host "[-] No results. If you expected rows, check the UTF-8 bytes / BOM." -ForegroundColor Yellow
    return
}

# ---------- Enrich with classification ----------
$enriched = foreach ($r in $rows) {
    [pscustomobject]@{
        Timestamp             = $r.Timestamp
        NetworkMessageId      = $r.NetworkMessageId
        InternetMessageId     = $r.InternetMessageId
        SenderFromAddress     = $r.SenderFromAddress
        SenderOrigin          = Get-Origin  $r.SenderFromAddress     $InternalDomain
        RecipientEmailAddress = $r.RecipientEmailAddress
        RecipientDomain       = Get-Domain  $r.RecipientEmailAddress
        RecipientOrigin       = Get-Origin  $r.RecipientEmailAddress $InternalDomain
        Subject               = $r.Subject
        DeliveryAction        = $r.DeliveryAction
        DeliveryLocation      = $r.DeliveryLocation
    }
}

# ---------- Summary ----------
$uniqueSenders = $enriched | Select-Object -ExpandProperty SenderFromAddress -Unique
Write-Host ("[*] UNIQUE senders: {0}" -f $uniqueSenders.Count) -ForegroundColor Cyan
Write-Host "[*] Senders and volume:"
$enriched | Group-Object SenderFromAddress | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("      {0}: {1}" -f $_.Name, $_.Count) }

Write-Host "[*] Senders by origin:"
$enriched | Group-Object SenderOrigin | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("      {0}: {1}" -f $_.Name, $_.Count) }

Write-Host "[*] Recipients by origin:"
$enriched | Group-Object RecipientOrigin | Sort-Object Count -Descending |
    ForEach-Object { Write-Host ("      {0}: {1}" -f $_.Name, $_.Count) }

$internalRcpt = ($enriched | Where-Object RecipientOrigin -eq 'Internal' |
    Select-Object -ExpandProperty RecipientEmailAddress -Unique).Count
$externalRcpt = ($enriched | Where-Object RecipientOrigin -eq 'External' |
    Select-Object -ExpandProperty RecipientEmailAddress -Unique).Count
Write-Host ("[*] DISTINCT INTERNAL mailboxes (purgeable): {0}" -f $internalRcpt) -ForegroundColor Green
Write-Host ("[*] DISTINCT EXTERNAL recipients (NOT purgeable): {0}" -f $externalRcpt) -ForegroundColor Yellow

# ---------- Export ----------
$enriched | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "[+] $($enriched.Count) rows exported to: $OutputCsv" -ForegroundColor Green
