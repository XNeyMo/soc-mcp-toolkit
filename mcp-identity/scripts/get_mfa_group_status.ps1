# ============================================================
# Script: MFA status per user (Entra group or CSV list)
#
# Two ways to scope who to investigate:
#   1) Members of an Entra group (default: the MFA enforcement group,
#      "SG-MFA-Enforced" - the same Conditional Access group used by
#      enforce_mfa in mcp-identity/server.py).
#   2) A CSV with an email column (-CsvPath), when only specific
#      people are of interest.
#
# For each user it reports the ACTUAL value of each method (not just
# whether it exists) - empty if the method is not registered:
#   - Email (Email OTP)              -> the email address (e.g. analyst@example.com)
#   - Phone (SMS/call)               -> the number (e.g. +1 5550100123)
#   - Microsoft Authenticator (push) -> the device name (e.g. "Pixel 8")
# If a user has more than one method of the same type (e.g. Authenticator
# on two phones), all of them are listed separated by "; " in the same cell.
#
# CSV output: User,DisplayName,Email,Phone,Authenticator,Status
#
# Usage:
#   .\get_mfa_group_status.ps1                                    -> default group (SG-MFA-Enforced)
#   .\get_mfa_group_status.ps1 -GroupId <other-group-id>          -> another Entra group
#   .\get_mfa_group_status.ps1 -CsvPath .\list.csv                -> emails from the "email" column of the CSV
#   .\get_mfa_group_status.ps1 -CsvPath .\list.csv -CsvEmailColumn "Mail"
#
# Required application permissions (app sec-identity-mcp - see the
# "REQUIRED PERMISSIONS" block at the end of mcp-identity/server.py):
#   - GroupMember.ReadWrite.All (or Group.ReadWrite.All) -> group members (group mode)
#   - UserAuthenticationMethod.ReadWrite.All             -> MFA methods per user (both modes)
#   - User.ReadWrite.All                                 -> resolve email -> profile (CSV mode)
#
# Credentials: same app registration and environment variables as mcp-identity
# (AZURE_TENANT_ID, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET).
# ============================================================

param(
    [string]$CsvPath,                  # if given, ignores the group and uses this list of emails
    [string]$CsvEmailColumn = "email", # name of the email column in the CSV
    [string]$GroupId = "00000000-0000-0000-0000-000000000000",  # SG-MFA-Enforced group object ID (set to your group; see MFA_ENFORCEMENT_GROUP_ID in mcp-identity/server.py)
    [string]$OutputCsv = ".\MFA_Status.csv",
    [int]$RETRY_WAIT_SEC = 60,   # wait time on HTTP 429
    [int]$ThrottleLimit = 20     # concurrent calls when reading MFA methods - lower it if Graph keeps returning 429
)

$TenantId     = $env:AZURE_TENANT_ID
$ClientId     = $env:IDENTITY_CLIENT_ID
$ClientSecret = $env:IDENTITY_CLIENT_SECRET

if (-not ($TenantId -and $ClientId -and $ClientSecret)) {
    throw "AZURE_TENANT_ID, IDENTITY_CLIENT_ID or IDENTITY_CLIENT_SECRET is missing from the environment (the same variables used by mcp-identity)."
}

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

# ============================================================
# STEP 1: Resolve the list of users to investigate
# ============================================================
if ($CsvPath) {
    if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
    Write-Host "`nMode: email list from CSV ($CsvPath, column '$CsvEmailColumn')" -ForegroundColor Cyan

    $csvRows = @(Import-Csv -Path $CsvPath)
    if ($csvRows.Count -eq 0) { throw "The CSV '$CsvPath' is empty." }
    if (-not ($csvRows[0] | Get-Member -Name $CsvEmailColumn -MemberType NoteProperty)) {
        $cols = ($csvRows[0] | Get-Member -MemberType NoteProperty).Name -join ", "
        throw "The CSV has no column '$CsvEmailColumn'. Columns found: $cols"
    }

    $emails = @(
        $csvRows |
        ForEach-Object { $_.$CsvEmailColumn } |
        Where-Object { $_ -and $_.Trim() -ne "" } |
        ForEach-Object { $_.Trim() } |
        Select-Object -Unique
    )
    if ($emails.Count -eq 0) { throw "The CSV column '$CsvEmailColumn' has no values." }
    Write-Host "Unique emails read from the CSV: $($emails.Count)" -ForegroundColor Cyan

    # DisplayName is deliberately left as $null: Step 2 resolves it together with
    # the user's real id (one extra call only for this mode, since group mode
    # already gets id/displayName for free from /transitiveMembers).
    $users = @($emails | ForEach-Object { [PSCustomObject]@{ id = $_; userPrincipalName = $_; displayName = $null } })
}
else {
    Write-Host "`nMode: members of group $GroupId" -ForegroundColor Cyan

    $members = New-Object System.Collections.Generic.List[object]
    $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id,userPrincipalName,displayName"
    $pageNum = 0
    while ($membersUri) {
        $pageNum++
        Write-Host "  Page $pageNum... ($($members.Count) members so far)" -ForegroundColor Gray
        $page = Invoke-RestMethod -Method Get -Uri $membersUri -Headers $headers
        $members.AddRange(@($page.value))
        $membersUri = $page.'@odata.nextLink'
    }
    Write-Host "  Member download complete: $($members.Count) objects in $pageNum page(s)." -ForegroundColor Gray

    $users = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' -or $_.userPrincipalName })
}

Write-Host "Total users to investigate: $($users.Count)" -ForegroundColor Cyan
if ($users.Count -eq 0) {
    Write-Warning "No users to investigate (empty group or empty CSV). Check the data source."
    return
}

# ============================================================
# STEP 2: For each user, read their registered authentication
#         methods (a single endpoint covers all types)
#         - in parallel ($ThrottleLimit at a time): with lists of
#         thousands of users, one by one would take hours.
# ============================================================
Write-Host "`nStep 2: Querying MFA methods per user (up to $ThrottleLimit in parallel)..." -ForegroundColor Cyan

$resultsBag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$progress   = [hashtable]::Synchronized(@{ done = 0 })
$totalUsers = $users.Count

$users | ForEach-Object -Parallel {
    $user     = $_
    $headers  = $using:headers
    $retrySec = $using:RETRY_WAIT_SEC
    $bag      = $using:resultsBag

    try {
        # Normalizes the @odata.type returned by Graph to a short type,
        # stripping the "AuthenticationMethod"/"AuthMethod" suffix (varies
        # by tenant/API version) - same criterion as
        # _mfa_canonical_type() in mcp-identity/server.py. Defined
        # inline because each -Parallel iteration runs in its own
        # runspace and cannot see functions declared outside the block.
        function Get-MfaCanonicalTypeLocal {
            param([string]$OdataType)
            $short = ($OdataType -replace '^#', '') -split '\.' | Select-Object -Last 1
            foreach ($suffix in @("AuthenticationMethod", "AuthMethod")) {
                if ($short.EndsWith($suffix)) { return $short.Substring(0, $short.Length - $suffix.Length) }
            }
            return $short
        }

        $userId      = $user.id
        $displayName = $user.displayName
        $methods     = @()
        $status      = "OK"

        # CSV mode: we do not have id/displayName yet, only the email.
        # Resolving against Graph validates that the account exists before
        # asking for its MFA methods.
        if (-not $displayName) {
            try {
                $encodedId = [uri]::EscapeDataString($user.id)
                $prof = Invoke-RestMethod -Method Get `
                    -Uri "https://graph.microsoft.com/v1.0/users/$encodedId`?`$select=id,userPrincipalName,displayName" `
                    -Headers $headers
                $userId      = $prof.id
                $displayName = $prof.displayName
            }
            catch {
                $httpStatus = $_.Exception.Response.StatusCode.value__
                $bag.Add([PSCustomObject]@{
                    User = $user.userPrincipalName; DisplayName = ""
                    Email = ""; Phone = ""; Authenticator = ""
                    Status = "ERROR HTTP $httpStatus - user not found in Entra"
                })
                return
            }
        }

        $uri        = "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods"
        $attempt    = 0
        $maxRetries = 3
        while ($true) {
            try {
                $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers
                if ($response.value) { $methods = @($response.value) }
                break
            }
            catch {
                $httpStatus = $_.Exception.Response.StatusCode.value__
                if ($httpStatus -eq 429 -and $attempt -lt $maxRetries) {
                    $attempt++
                    Start-Sleep -Seconds $retrySec
                    continue
                }
                $status = "ERROR HTTP $httpStatus"
                break
            }
        }

        # Actual value of each method (not just whether it exists):
        #   - email   -> emailAddress          (e.g. analyst@example.com)
        #   - phone   -> phoneNumber           (e.g. +1 5550100123)
        #   - microsoftAuthenticator -> displayName (device name, e.g. "Pixel 8")
        # A user can have MORE THAN ONE method of the same type (e.g. Authenticator
        # registered on two phones) - all are listed separated by "; ".
        $emailValues = @($methods | Where-Object { (Get-MfaCanonicalTypeLocal $_.'@odata.type') -eq "email" } | ForEach-Object { $_.emailAddress } | Where-Object { $_ })
        $phoneValues = @($methods | Where-Object { (Get-MfaCanonicalTypeLocal $_.'@odata.type') -eq "phone" } | ForEach-Object { $_.phoneNumber } | Where-Object { $_ })
        $authValues  = @($methods | Where-Object { (Get-MfaCanonicalTypeLocal $_.'@odata.type') -eq "microsoftAuthenticator" } | ForEach-Object { $_.displayName } | Where-Object { $_ })

        $bag.Add([PSCustomObject]@{
            User          = $user.userPrincipalName
            DisplayName   = $displayName
            Email         = ($emailValues -join "; ")
            Phone         = ($phoneValues -join "; ")
            Authenticator = ($authValues -join "; ")
            Status        = $status
        })
    }
    finally {
        $prog  = $using:progress
        $total = $using:totalUsers
        [System.Threading.Monitor]::Enter($prog)
        try { $prog.done++; $n = $prog.done }
        finally { [System.Threading.Monitor]::Exit($prog) }

        if ($n % 50 -eq 0 -or $n -eq $total) {
            $pct = [math]::Round(($n / $total) * 100, 1)
            Write-Host "  [$pct%] ($n/$total) processed" -ForegroundColor Gray
        }
    }
} -ThrottleLimit $ThrottleLimit

$results = @($resultsBag) | Sort-Object User
$failed  = @($results | Where-Object { $_.Status -ne "OK" })
if ($failed.Count -gt 0) {
    Write-Warning "$($failed.Count) user(s) could not be read (Status column != OK) - their Email/Phone/Authenticator values are NOT reliable, do not count them as 'no MFA'."
}

# ============================================================
# STEP 3: Export results
# ============================================================
$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "Users processed:    $($results.Count)" -ForegroundColor Cyan
Write-Host "With Email:         $(@($results | Where-Object { $_.Email }).Count)" -ForegroundColor Cyan
Write-Host "With Phone:         $(@($results | Where-Object { $_.Phone }).Count)" -ForegroundColor Cyan
Write-Host "With Authenticator: $(@($results | Where-Object { $_.Authenticator }).Count)" -ForegroundColor Cyan
Write-Host "With read error:    $($failed.Count)" -ForegroundColor $(if ($failed.Count -gt 0) { "Red" } else { "Cyan" })
Write-Host "`nResults exported to: $OutputCsv" -ForegroundColor Green

Write-Host "`n-- Sample (first 15 records) --" -ForegroundColor Yellow
$results | Select-Object -First 15 | Format-Table -AutoSize
