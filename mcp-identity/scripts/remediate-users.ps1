<#
.SYNOPSIS
    Remediates the internal SENDER accounts (own domain) identified in the CSV
    produced by an email-subject search export, after a phishing / compromised
    account incident.

    Steps per user:
      1. Reset the password to a temporary value (force change at next sign-in).
      2. Revoke all sessions / tokens (revokeSignInSessions).
      3. Force MFA re-registration (delete methods / require re-registration).
      4. Enforce MFA via Conditional Access (add to the "SG-MFA-Enforced" group).

    IT Security / SOC.

.NOTES
    GOVERNANCE
    - High-impact actions on user accounts. Requires formal authorization
      (security leadership) and notice to support/users.
    - Step 4 does NOT use perUserMfaState (deprecated BETA API) - the only supported
      mechanism is Conditional Access via the "SG-MFA-Enforced" group
      (same mechanism as the enforce_mfa tool of mcp-identity).
    - Simulation mode by default (-WhatIf $true).

    Application permissions (admin consent):
      User.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, GroupMember.ReadWrite.All

    Credentials: uses the SAME app registration and environment variables as mcp-identity
    (AZURE_TENANT_ID, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET) instead of a separate
    hardcoded secret. No secret is embedded in this script.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$CsvPath,
    [string]$InternalDomain = "example.com",
    [Parameter(Mandatory)] [string]$NewPassword,  # temporary password to set (supply your own; never hardcode one)
    [string[]]$ExcludeUsers = @(),               # e.g. "jdoe@example.com"
    [string]$TenantId     = $env:AZURE_TENANT_ID,
    [string]$ClientId     = $env:IDENTITY_CLIENT_ID,
    [string]$ClientSecret = $env:IDENTITY_CLIENT_SECRET,
    # Conditional Access group that enforces MFA (same id as MFA_ENFORCEMENT_GROUP_ID in mcp-identity/server.py)
    [string]$MfaGroupId     = "00000000-0000-0000-0000-000000000000",
    [bool]  $WhatIf         = $true,
    [string]$LogCsv         = ".\remediation_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = 'Stop'
if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
    throw "AZURE_TENANT_ID, IDENTITY_CLIENT_ID or IDENTITY_CLIENT_SECRET is missing from the environment (the same variables used by mcp-identity)."
}
if (-not (Test-Path $CsvPath)) { throw "CSV does not exist: $CsvPath" }
$InternalDomain = $InternalDomain.ToLower()
$excl = $ExcludeUsers | ForEach-Object { $_.Trim().ToLower() }

function Get-Domain { param([string]$Addr)
    if ([string]::IsNullOrWhiteSpace($Addr) -or $Addr -notmatch '@') { return "" }
    return ($Addr.Split('@')[-1]).Trim().ToLower()
}

# ---------- Remediation exemptions ----------
# Returns $true if the user must NOT be remediated (exempted).
# Exemption logic is left for you to define. By default, only the list below is exempted.
function Test-Exempt {
    param([string]$Upn)

    # TODO: define the exemption rules here (service accounts,
    # functional mailboxes, distribution lists, VIPs, etc.)

    $exempt = @(
        "postmaster@example.com"
    )

    return ($exempt -contains $Upn.Trim().ToLower())
}

# ---------- Token ----------
$tokenBody = @{
    grant_type    = "client_credentials"; client_id = $ClientId
    client_secret = $ClientSecret; scope = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }
Write-Host "[+] Token acquired." -ForegroundColor Green
if ($WhatIf) { Write-Host "[*] SIMULATION MODE (-WhatIf `$true): no changes are applied." -ForegroundColor Yellow }

# ---------- Unique internal senders (excluding the ones indicated) ----------
$rows = Import-Csv -Path $CsvPath
$targets = $rows | Where-Object { $_.SenderFromAddress } |
    ForEach-Object { $_.SenderFromAddress.Trim().ToLower() } |
    Where-Object { (Get-Domain $_) -eq $InternalDomain -and $excl -notcontains $_ } |
    Sort-Object -Unique |
    Where-Object { -not (Test-Exempt $_) }

Write-Host ("[*] Internal senders to remediate: {0}" -f $targets.Count) -ForegroundColor Cyan
$targets | ForEach-Object { Write-Host "      $_" }
if ($excl) { Write-Host ("[*] Excluded: {0}" -f ($excl -join ', ')) -ForegroundColor Yellow }

$log = New-Object System.Collections.Generic.List[object]
$total = $targets.Count; $i = 0

foreach ($upn in $targets) {
    $i++
    Write-Progress -Activity "Account remediation" -Status "[$i/$total] $upn" `
        -PercentComplete ([int](($i/[math]::Max($total,1))*100))

    $rec = [ordered]@{ User=$upn; Step1_Password=""; Step2_Sessions=""; Step3_MFAReReg=""; Step4_MFAEnable="" }

    # --- Step 1: password reset (force change at next sign-in) ---
    try {
        if ($WhatIf) { $rec.Step1_Password = "SIMULATED" }
        else {
            $body = @{ passwordProfile = @{
                forceChangePasswordNextSignIn = $true; password = $NewPassword } } | ConvertTo-Json
            Invoke-RestMethod -Method Patch -Uri "https://graph.microsoft.com/v1.0/users/$upn" `
                -Headers $headers -Body $body | Out-Null
            $rec.Step1_Password = "OK"
        }
    } catch { $rec.Step1_Password = "ERROR: $($_.Exception.Message)" }

    # --- Step 2: revoke sessions ---
    try {
        if ($WhatIf) { $rec.Step2_Sessions = "SIMULATED" }
        else {
            Invoke-RestMethod -Method Post `
                -Uri "https://graph.microsoft.com/v1.0/users/$upn/revokeSignInSessions" `
                -Headers $headers | Out-Null
            $rec.Step2_Sessions = "OK"
        }
    } catch { $rec.Step2_Sessions = "ERROR: $($_.Exception.Message)" }

    # --- Step 3: force MFA re-registration (delete registered methods) ---
    try {
        if ($WhatIf) { $rec.Step3_MFAReReg = "SIMULATED" }
        else {
            # Enumerates methods and deletes the non-default ones (phone, authenticator, etc.)
            $methods = Invoke-RestMethod -Method Get `
                -Uri "https://graph.microsoft.com/v1.0/users/$upn/authentication/methods" -Headers $headers
            $deleted = 0
            foreach ($m in $methods.value) {
                $type = $m.'@odata.type'
                # The password method cannot be deleted; non-removable ones are skipped.
                if ($type -match 'phoneAuthenticationMethod') {
                    Invoke-RestMethod -Method Delete -Headers $headers `
                        -Uri "https://graph.microsoft.com/v1.0/users/$upn/authentication/phoneMethods/$($m.id)" | Out-Null
                    $deleted++
                } elseif ($type -match 'microsoftAuthenticatorAuthenticationMethod') {
                    Invoke-RestMethod -Method Delete -Headers $headers `
                        -Uri "https://graph.microsoft.com/v1.0/users/$upn/authentication/microsoftAuthenticatorMethods/$($m.id)" | Out-Null
                    $deleted++
                } elseif ($type -match 'softwareOathAuthenticationMethod') {
                    Invoke-RestMethod -Method Delete -Headers $headers `
                        -Uri "https://graph.microsoft.com/v1.0/users/$upn/authentication/softwareOathMethods/$($m.id)" | Out-Null
                    $deleted++
                }
            }
            $rec.Step3_MFAReReg = "OK (methods deleted: $deleted)"
        }
    } catch { $rec.Step3_MFAReReg = "ERROR: $($_.Exception.Message)" }

    # --- Step 4: enforce MFA via Conditional Access (add to the SG-MFA-Enforced group) ---
    try {
        if ($WhatIf) { $rec.Step4_MFAEnable = "SIMULATED" }
        else {
            $userObj = Invoke-RestMethod -Method Get `
                -Uri "https://graph.microsoft.com/v1.0/users/$upn`?`$select=id" -Headers $headers
            $checkBody = @{ groupIds = @($MfaGroupId) } | ConvertTo-Json
            $check = Invoke-RestMethod -Method Post `
                -Uri "https://graph.microsoft.com/v1.0/users/$($userObj.id)/checkMemberGroups" `
                -Headers $headers -Body $checkBody
            if ($check.value -contains $MfaGroupId) {
                $rec.Step4_MFAEnable = "OK (already a member of SG-MFA-Enforced)"
            } else {
                $refBody = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/users/$($userObj.id)" } | ConvertTo-Json
                Invoke-RestMethod -Method Post `
                    -Uri "https://graph.microsoft.com/v1.0/groups/$MfaGroupId/members/`$ref" `
                    -Headers $headers -Body $refBody | Out-Null
                $rec.Step4_MFAEnable = "OK (added to SG-MFA-Enforced)"
            }
        }
    } catch { $rec.Step4_MFAEnable = "ERROR: $($_.Exception.Message)" }

    $log.Add([pscustomobject]$rec)
}
Write-Progress -Activity "Account remediation" -Completed

# ---------- Summary + log ----------
$log | Format-Table -AutoSize
$log | Export-Csv -Path $LogCsv -NoTypeInformation -Encoding UTF8
Write-Host "[+] Remediation log: $LogCsv" -ForegroundColor Green
if ($WhatIf) { Write-Host "[*] To apply for real: re-run with -WhatIf `$false" -ForegroundColor Yellow }
