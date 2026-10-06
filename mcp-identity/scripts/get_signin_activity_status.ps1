# ============================================================
# Script: Latest sign-in attempts per user (group or CSV)
#
# Same source logic as get_mfa_group_status.ps1 /
# get_signin_errors_status.ps1: scopes who to investigate via an
# Entra group or a CSV with an email column.
#
# DESIGN NOTE - why it does not use signInActivity: the user's
# signInActivity property (a bulk scan of /users) is fast but has NO
# status detail - it only gives two dates (last interactive/non-interactive
# sign-in), and does not say whether it succeeded, what the error code
# was, or allow viewing several attempts. To know "what was the last log,
# its status, and whether it is really failing (not a one-off false
# positive)" the real event detail is needed, which only
# /auditLogs/signIns provides.
#
# For each target user:
#   1. Fetches up to the last 5 INTERACTIVE sign-in attempts
#      (isInteractive eq true - a real login, not background token
#      renewals) within the last $DaysBack days.
#   2. Reports the latest one: date (Excel-friendly format), status,
#      and whether the sign-in succeeded.
#   3. Evaluates the PATTERN of the last 5 (not just the latest) to
#      distinguish a sustained error from a one-off false positive:
#        - "OK"                    -> the most recent attempt succeeded
#        - "SUSTAINED ERROR"       -> all 5 (or however many exist) failed
#        - "POSSIBLE FALSE POSITIVE" -> the most recent failed but there
#                                     was a success among the last 5
#        - "NO ATTEMPTS"           -> no interactive sign-ins in the window
#
# Like get_signin_errors_status.ps1, it queries in BATCHES of emails
# (OR filter) instead of one by one or scanning the whole tenant - see
# the design note in that script (individual calls cause a 429 storm;
# scanning the whole tenant without filtering by user hits HTTP 410
# "skip token expired"). Here the "isInteractive eq true" filter already
# cuts the volume considerably on its own (it drops background token
# renewals), so the risk of those two problems is lower, but the same
# batch + Retry-After retry pattern is kept for consistency and in case
# the volume turns out to be larger than expected.
#
# NOTE: the OR filter combined with "isInteractive eq true" may be
# rejected by some tenants / Graph versions. If Graph returns 400, the
# error indicates the batch and the emails involved so the filter can
# be adjusted.
#
# CSV output: User,DisplayName,LastLogDate,LastLogStatus,
#             SignInSucceeded,AttemptsReviewed,WithError,
#             Assessment,LastErrorDate,LastErrorCode,
#             LastErrorDetail,LastErrorApp,LastErrorIP
#
# All dates are in UTC, format "yyyy-MM-dd HH:mm:ss" (no T/Z)
# so Excel recognizes them as a filterable date/time without adjustments.
#
# Usage:
#   .\get_signin_activity_status.ps1                                 -> default group (SG-MFA-Enforced)
#   .\get_signin_activity_status.ps1 -GroupId <other-group-id>       -> another Entra group
#   .\get_signin_activity_status.ps1 -CsvPath .\list.csv             -> emails from the "email" column of the CSV
#   .\get_signin_activity_status.ps1 -CsvPath .\list.csv -CsvEmailColumn "Mail"
#   .\get_signin_activity_status.ps1 -DaysBack 7                     -> "last week" instead of "last month"
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
    [string]$OutputCsv = ".\SignIn_Activity.csv",
    [int]$DaysBack = 30,          # window in days (real cap: ~30, tenant retention)
    [int]$AttemptsToEvaluate = 5, # how many of the latest attempts to review for the assessment
    [int]$BatchSize = 20,         # emails per OR query - lower it if Graph returns 400/414
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
$headers     = @{ Authorization = "Bearer $token" }
$scanHeaders = @{ Authorization = "Bearer $token"; ConsistencyLevel = "eventual" }
Write-Host "Token acquired (tenant: $TenantId)." -ForegroundColor Green

function Format-ExcelDate {
    param($Value)
    if (-not $Value) { return "" }
    try {
        $d = [datetime]::Parse($Value, [System.Globalization.CultureInfo]::InvariantCulture).ToUniversalTime()
        if ($d.Year -le 1) { return "" }
        return $d.ToString("yyyy-MM-dd HH:mm:ss")
    }
    catch { return $Value }
}

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

# ============================================================
# STEP 2: Query interactive sign-ins in BATCHES of emails
#         (OR filter) - not one by one and not a scan of the WHOLE
#         tenant. See the design note at the top of this file.
# ============================================================
$sinceStr = (Get-Date).ToUniversalTime().AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
$select   = "createdDateTime,userPrincipalName,userDisplayName,appDisplayName,ipAddress,location,status,clientAppUsed,isInteractive"

function Get-SignInBatchUri {
    param([string[]]$Upns, [string]$SinceStr, [string]$Select)
    $orClauses = $Upns | ForEach-Object { "userPrincipalName eq '$_'" }
    $filter = "($($orClauses -join ' or ')) and createdDateTime ge $SinceStr and isInteractive eq true"
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

Write-Host "`nStep 2: Querying interactive sign-ins in $($batches.Count) batch(es) of up to $BatchSize emails each..." -ForegroundColor Cyan

$signinsByUpn = @{}
$failedUpns   = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$failedBatches = 0
$totalEvents  = 0
$batchNum     = 0
$stopwatch    = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($batch in $batches) {
    $batchNum++
    $initialUri = Get-SignInBatchUri -Upns $batch -SinceStr $sinceStr -Select $select
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
    # being (incorrectly) reported as "no attempts".
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
                throw "The /auditLogs/signIns scan failed ($detail) in batch $batchNum (emails: $($batch -join ', ')). If this is HTTP 400, this tenant/Graph version may not accept the 'isInteractive eq true' filter combined with OR this way - adjust the filter. Detail: $_"
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
            if (-not $signinsByUpn.ContainsKey($key)) { $signinsByUpn[$key] = New-Object System.Collections.Generic.List[object] }
            $signinsByUpn[$key].Add($e)
        }
    }

    if ($batchNum % 5 -eq 0 -or $batchNum -eq $batches.Count) {
        $pct = [math]::Round(($batchNum / $batches.Count) * 100, 1)
        $rate = $batchNum / $stopwatch.Elapsed.TotalSeconds
        $etaMin = if ($rate -gt 0) { [math]::Round((($batches.Count - $batchNum) / $rate) / 60, 1) } else { "?" }
        Write-Host "  [$pct%] Batch $batchNum/$($batches.Count) - $totalEvents events accumulated - users with at least one attempt: $($signinsByUpn.Count)/$($targets.Count) - ETA ~$etaMin min" -ForegroundColor Gray
    }
}

Write-Host "Scan complete: $totalEvents interactive events among the targets, $($signinsByUpn.Count) of $($targets.Count) had at least one attempt." -ForegroundColor Cyan
if ($failedBatches -gt 0) {
    Write-Warning "$failedBatches batch(es) of $($batches.Count) failed completely - $($failedUpns.Count) user(s) are flagged as 'ERROR - could not query' instead of being reported as having no attempts."
}

# ============================================================
# STEP 3: Build the result per target - last $AttemptsToEvaluate
#         attempts, status of the latest one, and pattern assessment.
# ============================================================
$results = foreach ($t in $targets) {
    $key    = $t.userPrincipalName.ToLowerInvariant()
    $events = $signinsByUpn[$key]

    if (-not $events -or $events.Count -eq 0) {
        $emptyAssessment = if ($failedUpns.Contains($t.userPrincipalName)) {
            "ERROR - could not query (this user's batch failed, see console warnings)"
        } else {
            "NO ATTEMPTS - no interactive sign-ins in the last $DaysBack days"
        }
        [PSCustomObject]@{
            User             = $t.userPrincipalName
            DisplayName      = ""
            LastLogDate      = ""
            LastLogStatus    = ""
            SignInSucceeded  = ""
            AttemptsReviewed = 0
            WithError        = 0
            Assessment       = $emptyAssessment
            LastErrorDate    = ""
            LastErrorCode    = ""
            LastErrorDetail  = ""
            LastErrorApp     = ""
            LastErrorIP      = ""
        }
        continue
    }

    $sorted   = @($events | Sort-Object createdDateTime -Descending)
    $attempts = @($sorted | Select-Object -First $AttemptsToEvaluate)
    $latest   = $attempts[0]
    $withError = @($attempts | Where-Object { $_.status.errorCode -ne 0 })
    $latestErrorEvent = if ($withError.Count -gt 0) { $withError[0] } else { $null }

    $latestSucceeded = ($latest.status.errorCode -eq 0)
    $assessment =
        if ($latestSucceeded) { "OK - the most recent attempt succeeded" }
        elseif ($withError.Count -eq $attempts.Count) { "SUSTAINED ERROR - the last $($attempts.Count) attempts failed" }
        else { "POSSIBLE FALSE POSITIVE - the most recent failed but there was a success among the last $($attempts.Count)" }

    [PSCustomObject]@{
        User             = $t.userPrincipalName
        DisplayName      = $latest.userDisplayName
        LastLogDate      = Format-ExcelDate $latest.createdDateTime
        LastLogStatus    = if ($latestSucceeded) { "Success" } else { "Error $($latest.status.errorCode)$(if ($latest.status.additionalDetails) { ': ' + $latest.status.additionalDetails } elseif ($latest.status.failureReason) { ': ' + $latest.status.failureReason })" }
        SignInSucceeded  = if ($latestSucceeded) { "YES" } else { "NO" }
        AttemptsReviewed = $attempts.Count
        WithError        = $withError.Count
        Assessment       = $assessment
        LastErrorDate    = if ($latestErrorEvent) { Format-ExcelDate $latestErrorEvent.createdDateTime } else { "" }
        LastErrorCode    = if ($latestErrorEvent) { $latestErrorEvent.status.errorCode } else { "" }
        LastErrorDetail  = if ($latestErrorEvent) { if ($latestErrorEvent.status.additionalDetails) { $latestErrorEvent.status.additionalDetails } else { $latestErrorEvent.status.failureReason } } else { "" }
        LastErrorApp     = if ($latestErrorEvent) { $latestErrorEvent.appDisplayName } else { "" }
        LastErrorIP      = if ($latestErrorEvent) { $latestErrorEvent.ipAddress } else { "" }
    }
}

$results        = @($results) | Sort-Object User
$noAttempts     = @($results | Where-Object { $_.Assessment -like "NO ATTEMPTS*" })
$sustainedError = @($results | Where-Object { $_.Assessment -like "SUSTAINED ERROR*" })
$falsePositive  = @($results | Where-Object { $_.Assessment -like "POSSIBLE FALSE POSITIVE*" })
$notQueried     = @($results | Where-Object { $_.Assessment -like "ERROR - could not query*" })

# ============================================================
# STEP 4: Export results
# ============================================================
$results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "Users processed: $($results.Count)" -ForegroundColor Cyan
Write-Host "Sustained error (all latest attempts failed):               $($sustainedError.Count)" -ForegroundColor Red
Write-Host "Possible false positive (one-off failure, recent success):  $($falsePositive.Count)" -ForegroundColor Yellow
Write-Host "No interactive attempts in the window:                      $($noAttempts.Count)" -ForegroundColor Cyan
Write-Host "Could not be queried (batch failed):                        $($notQueried.Count)" -ForegroundColor $(if ($notQueried.Count -gt 0) { "Red" } else { "Cyan" })
Write-Host "`nResults exported to: $OutputCsv" -ForegroundColor Green

Write-Host "`n-- Users with sustained error (top 15) --" -ForegroundColor Yellow
$sustainedError | Select-Object -First 15 | Format-Table User, LastLogDate, WithError, AttemptsReviewed -AutoSize

if ($notQueried.Count -gt 0) {
    Write-Host "`n-- Users NOT queried (their batch failed, do not confuse with 'no attempts') --" -ForegroundColor Red
    $notQueried | Select-Object User, DisplayName | Format-Table -AutoSize
}
