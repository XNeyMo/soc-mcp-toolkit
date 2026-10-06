# ============================================================
# Script: Sign-in errors/interruptions per user (group or CSV)
#
# Same source logic as get_mfa_group_status.ps1 /
# get_signin_activity_status.ps1: scopes who to investigate via an
# Entra group or a CSV with an email column.
#
# For each user it reports how many NON-successful sign-ins they had in the
# last $DaysBack days (status.errorCode != 0 - this includes both
# "Failure" and "Interrupted" in the portal, e.g. the case "User needs
# to perform multi-factor authentication": errorCode is non-zero
# even though the portal labels it "Interrupted" rather than "Failure").
# It reports the latest error: date, code, detail, app and IP.
#
# DESIGN NOTE - why queries are batched: querying /auditLogs/signIns ONCE
# PER USER (even in parallel) does not scale against this endpoint - with
# thousands of users it quickly triggers a storm of HTTP 429 responses (all
# threads retry at about the same time, so the storm repeats every round),
# and it is slow anyway because of the query's own latency. Scanning the
# FULL tenant log once (paginated, without filtering by user) does not scale
# either: a tenant can easily have tens of thousands of "non-successful"
# events in 30 days (every MFA "Interrupted" counts, not just real failures),
# and walking that many pages takes longer than the pagination skip token
# lives, ending in HTTP 410 "Skip token has expired. Restart pagination from
# the first page."
#
# The current approach groups the target emails into BATCHES (OR filter)
# of $BatchSize at a time:
#   GET /auditLogs/signIns?$filter=(userPrincipalName eq 'a' or ...
#       eq 'b') and createdDateTime ge {since} and status/errorCode ne 0
# With 2000 targets and batches of 20 that is ~100 calls - far below the
# volume that triggers 429, and each batch returns only the events of those
# ~20 users (it should rarely need more than one page), so the expired
# skip-token problem does not apply either. Requires the header
# ConsistencyLevel: eventual (+ $count=true) because the "ne" operator on
# a nested property counts as an "advanced query" in Graph.
#
# NOTE: the OR filter combined with "ne" may be rejected by some tenants /
# Graph versions - if Graph returns 400, the script reports it clearly (with
# the batch and the emails involved) instead of failing silently; adjust the
# filter if that happens.
#
# CSV output: User,DisplayName,TotalErrors,LastErrorDate,
#             LastErrorCode,LastErrorDetail,LastErrorApp,
#             LastErrorIP,Status
#
# Usage:
#   .\get_signin_errors_status.ps1                                 -> default group (SG-MFA-Enforced)
#   .\get_signin_errors_status.ps1 -GroupId <other-group-id>       -> another Entra group
#   .\get_signin_errors_status.ps1 -CsvPath .\list.csv             -> emails from the "email" column of the CSV
#   .\get_signin_errors_status.ps1 -CsvPath .\list.csv -CsvEmailColumn "Mail"
#   .\get_signin_errors_status.ps1 -DaysBack 7                     -> "last week" instead of "last month"
#
# Required application permissions (app sec-identity-mcp - see the
# "REQUIRED PERMISSIONS" block at the end of mcp-identity/server.py):
#   - GroupMember.ReadWrite.All (or Group.ReadWrite.All) -> group members (group mode)
#   - AuditLog.Read.All                                  -> read /auditLogs/signIns
#
# Tenant retention limit: /auditLogs/signIns only keeps
# ~30 days of history - with a -DaysBack greater than that, the oldest
# days simply will not have data (this is not a script bug).
#
# Credentials: same app registration and environment variables as mcp-identity
# (AZURE_TENANT_ID, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET).
# ============================================================

param(
    [string]$CsvPath,                  # if given, ignores the group and uses this list of emails
    [string]$CsvEmailColumn = "email", # name of the email column in the CSV
    [string]$GroupId = "00000000-0000-0000-0000-000000000000",  # SG-MFA-Enforced group object ID (set to your group; see MFA_ENFORCEMENT_GROUP_ID in mcp-identity/server.py)
    [string]$OutputCsv = ".\SignIn_Errors.csv",
    [int]$DaysBack = 30,          # window in days (real cap: ~30, tenant retention)
    [int]$BatchSize = 20,         # emails per OR query - lower it if Graph returns 400/414 (URL/filter too long)
    [int]$RETRY_WAIT_SEC = 20,    # default wait on 429 if Graph does not send Retry-After
    [int]$MaxRetries = 5
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
# ConsistencyLevel: eventual - required by Graph for "advanced" filters
# (e.g. "ne" on a nested property such as status/errorCode).
$scanHeaders = @{ Authorization = "Bearer $token"; ConsistencyLevel = "eventual" }
Write-Host "Token acquired (tenant: $TenantId)." -ForegroundColor Green

function Invoke-GraphWithRetry {
    param([string]$Uri, [hashtable]$Headers)
    $attempt = 0
    while ($true) {
        try {
            # Explicit TimeoutSec: without it, if Graph hangs mid-response
            # the script waits indefinitely without any notice.
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -TimeoutSec 90
        }
        catch {
            if ($_.Exception -is [System.Threading.Tasks.TaskCanceledException] -or $_.Exception.InnerException -is [System.TimeoutException]) {
                throw "90s timeout waiting for a Graph response for: $Uri"
            }
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $attempt++
                $waitSeconds = $RETRY_WAIT_SEC
                $retryAfterHeader = $_.Exception.Response.Headers.RetryAfter
                if ($retryAfterHeader) {
                    if ($retryAfterHeader.Delta) { $waitSeconds = [math]::Ceiling($retryAfterHeader.Delta.Value.TotalSeconds) }
                    elseif ($retryAfterHeader.Date) { $waitSeconds = [math]::Ceiling(($retryAfterHeader.Date.Value - [DateTimeOffset]::UtcNow).TotalSeconds) }
                }
                if ($waitSeconds -le 0) { $waitSeconds = 5 }
                Write-Warning "  429 - retry $attempt/$MaxRetries in $waitSeconds s"
                Start-Sleep -Seconds $waitSeconds
                continue
            }
            throw
        }
    }
}

# ============================================================
# STEP 1: Resolve the list of target users
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

    $targets = @($emails | ForEach-Object { [PSCustomObject]@{ userPrincipalName = $_ } })
}
else {
    Write-Host "`nMode: members of group $GroupId" -ForegroundColor Cyan

    $members = New-Object System.Collections.Generic.List[object]
    $membersUri = "https://graph.microsoft.com/v1.0/groups/$GroupId/transitiveMembers?`$select=id,userPrincipalName"
    $pageNum = 0
    while ($membersUri) {
        $pageNum++
        Write-Host "  Page $pageNum... ($($members.Count) members so far)" -ForegroundColor Gray
        $page = Invoke-GraphWithRetry -Uri $membersUri -Headers $headers
        $members.AddRange(@($page.value))
        $membersUri = $page.'@odata.nextLink'
    }
    Write-Host "  Member download complete: $($members.Count) objects in $pageNum page(s)." -ForegroundColor Gray

    $targets = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.user' -or $_.userPrincipalName })
}

Write-Host "Total users to investigate: $($targets.Count)" -ForegroundColor Cyan
if ($targets.Count -eq 0) {
    Write-Warning "No users to investigate (empty group or empty CSV). Check the data source."
    return
}

$targetSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($t in $targets) { if ($t.userPrincipalName) { [void]$targetSet.Add($t.userPrincipalName) } }

# ============================================================
# STEP 2: Query NON-successful sign-ins in BATCHES of emails
#         (OR filter), not one by one and not a scan of the
#         WHOLE tenant (see the design note at the top of this file).
#
# Target emails are grouped into batches (OR) of $BatchSize at a time,
# e.g. "(userPrincipalName eq 'a' or ... eq 'b') and createdDateTime ge X
# and status/errorCode ne 0". With 2000 targets and batches of 20, that is
# ~100 calls - far below the volume that triggers 429, and each batch
# returns only the events of those 20 users.
# ============================================================
$sinceStr = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
$select   = "createdDateTime,userPrincipalName,userDisplayName,appDisplayName,ipAddress,location,status,clientAppUsed"

function Get-SignInErrorBatchUri {
    param([string[]]$Upns, [string]$SinceStr, [string]$Select)
    $orClauses = $Upns | ForEach-Object { "userPrincipalName eq '$_'" }
    $filter = "($($orClauses -join ' or ')) and createdDateTime ge $SinceStr and status/errorCode ne 0"
    return "https://graph.microsoft.com/beta/auditLogs/signIns" +
           "?`$filter=$([uri]::EscapeDataString($filter))" +
           "&`$top=999&`$count=true" +
           "&`$select=$([uri]::EscapeDataString($Select))"
}

$emailsList = @($targets | ForEach-Object { $_.userPrincipalName })
$batches = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt $emailsList.Count; $i += $BatchSize) {
    $end = [Math]::Min($i + $BatchSize - 1, $emailsList.Count - 1)
    $batches.Add(@($emailsList[$i..$end]))
}

Write-Host "`nStep 2: Querying sign-in errors in $($batches.Count) batch(es) of up to $BatchSize emails each..." -ForegroundColor Cyan

$errorsByUpn   = @{}
$failedUpns    = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$failedBatches = 0
$totalEvents   = 0
$batchNum      = 0
$stopwatch     = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($batch in $batches) {
    $batchNum++
    $initialUri = Get-SignInErrorBatchUri -Upns $batch -SinceStr $sinceStr -Select $select
    $uri = $initialUri
    $batchResults = New-Object System.Collections.Generic.List[object]
    $restartCount = 0
    $batchFailed  = $false

    Write-Host "  Batch $batchNum/$($batches.Count): sending query ($($batch.Count) emails)..." -ForegroundColor Gray
    $batchSw = [System.Diagnostics.Stopwatch]::StartNew()

    # A batch that fails permanently must NOT bring down the whole script -
    # with 100+ batches, a single failure would lose the results of all the
    # previous ones if the error propagated out of the foreach. The batch is
    # marked as failed and the rest continue; its users are flagged instead of
    # being (incorrectly) reported as "no errors".
    try {
        while ($uri) {
            try {
                $page = Invoke-GraphWithRetry -Uri $uri -Headers $scanHeaders
            }
            catch {
                $status = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { $null }
                if ($status -eq 410 -and $restartCount -lt 3) {
                    $restartCount++
                    Write-Warning "  Batch ${batchNum}: skip token expired, retry $restartCount/3 from the start of the batch."
                    $uri = $initialUri
                    $batchResults.Clear()
                    continue
                }
                $detail = if ($status) { "HTTP $status" } else { $_.Exception.Message }
                throw "The /auditLogs/signIns scan failed ($detail) in batch $batchNum (emails: $($batch -join ', ')). If this is HTTP 400, this tenant/Graph version may not accept the 'status/errorCode ne 0' filter combined with OR this way - adjust the filter. Detail: $_"
            }
            $batchResults.AddRange(@($page.value))
            $uri = $page.'@odata.nextLink'
        }
    }
    catch {
        $batchFailed = $true
        $failedBatches++
        foreach ($u in $batch) { [void]$failedUpns.Add($u) }
        Write-Warning "  Batch ${batchNum}: PERMANENT FAILURE, skipped and continuing with the rest. $($_.Exception.Message)"
    }

    if ($batchFailed) {
        Write-Host "  Batch $batchNum/$($batches.Count): skipped due to error ($($batch.Count) users are flagged)" -ForegroundColor Red
    }
    else {
        Write-Host "  Batch $batchNum/$($batches.Count): $($batchResults.Count) event(s) in $([math]::Round($batchSw.Elapsed.TotalSeconds,1)) s" -ForegroundColor Gray
        $totalEvents += $batchResults.Count
        foreach ($e in $batchResults) {
            if (-not $e.userPrincipalName) { continue }
            $key = $e.userPrincipalName.ToLowerInvariant()
            if (-not $errorsByUpn.ContainsKey($key)) { $errorsByUpn[$key] = New-Object System.Collections.Generic.List[object] }
            $errorsByUpn[$key].Add($e)
        }
    }

    if ($batchNum % 5 -eq 0 -or $batchNum -eq $batches.Count) {
        $pct = [math]::Round(($batchNum / $batches.Count) * 100, 1)
        $rate = $batchNum / $stopwatch.Elapsed.TotalSeconds
        $etaMin = if ($rate -gt 0) { [math]::Round((($batches.Count - $batchNum) / $rate) / 60, 1) } else { "?" }
        Write-Host "  [$pct%] Batch $batchNum/$($batches.Count) - $totalEvents events accumulated - target users with errors: $($errorsByUpn.Count)/$($targetSet.Count) - ETA ~$etaMin min" -ForegroundColor Gray
    }
}

Write-Host "Scan complete: $totalEvents error events among the targets, $($errorsByUpn.Count) of $($targetSet.Count) had at least one." -ForegroundColor Cyan
if ($failedBatches -gt 0) {
    Write-Warning "$failedBatches batch(es) of $($batches.Count) failed completely - $($failedUpns.Count) user(s) are flagged as 'ERROR - could not query' in the Status column."
}

# ============================================================
# STEP 3: Build the result per target
# ============================================================
$results = foreach ($t in $targets) {
    $key = $t.userPrincipalName.ToLowerInvariant()
    $userErrors = $errorsByUpn[$key]

    if (-not $userErrors -or $userErrors.Count -eq 0) {
        $emptyStatus = if ($failedUpns.Contains($t.userPrincipalName)) { "ERROR - could not query (this user's batch failed, see console warnings)" } else { "OK" }
        [PSCustomObject]@{
            User            = $t.userPrincipalName
            DisplayName     = ""
            TotalErrors     = 0
            LastErrorDate   = ""
            LastErrorCode   = ""
            LastErrorDetail = ""
            LastErrorApp    = ""
            LastErrorIP     = ""
            Status          = $emptyStatus
        }
        continue
    }

    $sorted = @($userErrors | Sort-Object createdDateTime -Descending)
    $latest = $sorted[0]

    [PSCustomObject]@{
        User            = $t.userPrincipalName
        DisplayName     = $latest.userDisplayName
        TotalErrors     = $sorted.Count
        LastErrorDate   = $latest.createdDateTime
        LastErrorCode   = $latest.status.errorCode
        LastErrorDetail = if ($latest.status.additionalDetails) { $latest.status.additionalDetails } else { $latest.status.failureReason }
        LastErrorApp    = $latest.appDisplayName
        LastErrorIP     = $latest.ipAddress
        Status          = "OK"
    }
}

$results      = @($results) | Sort-Object User
$withErrors   = @($results | Where-Object { $_.TotalErrors -gt 0 })
$notQueried   = @($results | Where-Object { $_.Status -like "ERROR - could not query*" })

# ============================================================
# STEP 4: Export results
# ============================================================
$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "Users processed: $($results.Count)" -ForegroundColor Cyan
Write-Host "With at least one non-successful sign-in in the last $DaysBack days: $($withErrors.Count)" -ForegroundColor Cyan
Write-Host "Could not be queried (batch failed):                                 $($notQueried.Count)" -ForegroundColor $(if ($notQueried.Count -gt 0) { "Red" } else { "Cyan" })
Write-Host "`nResults exported to: $OutputCsv" -ForegroundColor Green

Write-Host "`n-- Users with errors (top 15 by count) --" -ForegroundColor Yellow
$withErrors | Sort-Object TotalErrors -Descending | Select-Object -First 15 | Format-Table -AutoSize

if ($notQueried.Count -gt 0) {
    Write-Host "`n-- Users NOT queried (their batch failed, do not confuse with 'no errors') --" -ForegroundColor Red
    $notQueried | Select-Object User | Format-Table -AutoSize
}
