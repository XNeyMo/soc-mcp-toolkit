# ============================================================
# Script: Users whose MFA phone number has an anomalous local length (default: 11 digits)
#
# Detects accounts where the local part of the MFA phone number
# has 11 digits instead of the expected 10.
# Problematic example: +1 5550100123 (11 local digits)
# Correct example:     +1 555010012   (10 local digits)
#
# Required application permissions (same app as mcp-identity, sec-identity-mcp):
#   - UserAuthenticationMethod.Read.All  -> read methods per user
#   - AuditLog.Read.All                  -> method registration report
#   - User.Read.All                      -> basic user data
#
# Credentials: uses the SAME app registration and environment variables as mcp-identity
# (AZURE_TENANT_ID, IDENTITY_CLIENT_ID, IDENTITY_CLIENT_SECRET) - direct REST calls
# instead of the interactive Microsoft.Graph SDK.
# ============================================================

#region -- Configurable parameters ---------------------------
$ANOMALY_DIGITS    = 11                                      # local length to detect
$outputPhones      = ".\Users_Phone_${ANOMALY_DIGITS}digits_MFA.csv"
$DELAY_MS          = 50                                      # pause between calls (ms), increase if throttled
$RETRY_WAIT_SEC    = 60                                      # wait time on HTTP 429

$TenantId     = $env:AZURE_TENANT_ID
$ClientId     = $env:IDENTITY_CLIENT_ID
$ClientSecret = $env:IDENTITY_CLIENT_SECRET
#endregion

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
# HELPER FUNCTION: Invoke Graph with retries on throttling
# ============================================================
function Invoke-GraphWithRetry {
    param(
        [string]$Uri,
        [int]$MaxRetries = 3
    )
    $attempt = 0
    while ($attempt -le $MaxRetries) {
        try {
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 429 -and $attempt -lt $MaxRetries) {
                $attempt++
                Write-Warning "  HTTP 429 - Rate limit. Retry $attempt/$MaxRetries in $RETRY_WAIT_SEC sec..."
                Start-Sleep -Seconds $RETRY_WAIT_SEC
            }
            elseif ($status -eq 403) {
                Write-Warning "  HTTP 403 - No permission to read methods from $Uri (may be a service account or protected admin)."
                return $null
            }
            else {
                Write-Warning "  HTTP error $status on $Uri : $_"
                return $null
            }
        }
    }
    return $null
}

# ============================================================
# STEP 1: Bulk report -> pre-filter users with a phone
# ============================================================
Write-Host "`nStep 1: Downloading the tenant authentication methods report..." -ForegroundColor Cyan

$registrationDetails = New-Object System.Collections.Generic.List[object]
$reportUri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
while ($reportUri) {
    $page = Invoke-RestMethod -Method Get -Uri $reportUri -Headers $headers
    $registrationDetails.AddRange(@($page.value))
    $reportUri = $page.'@odata.nextLink'
}
Write-Host "Total users in the report: $($registrationDetails.Count)" -ForegroundColor Cyan

# mobilePhone          -> primary MFA / SMS phone
# alternateMobilePhone -> alternate phone
# officePhone          -> office phone
$phoneMethods = @("mobilePhone", "alternateMobilePhone", "officePhone")

$usersWithPhone = @(
    $registrationDetails | Where-Object {
        $registeredMethods = @($_.methodsRegistered)
        ($registeredMethods | Where-Object { $phoneMethods -contains $_ }).Count -gt 0
    }
)

Write-Host "Users with at least one registered phone method: $($usersWithPhone.Count)" -ForegroundColor Yellow

if ($usersWithPhone.Count -eq 0) {
    Write-Warning "No users with a phone as an MFA method were found. Check the permissions."
    return
}

# ============================================================
# STEP 2: For each user, fetch the actual number and evaluate
#         the length of the local part (after the +CC)
# ============================================================
Write-Host "`nStep 2: Reading phone numbers and checking local length..." -ForegroundColor Cyan
Write-Host "         (Looking for local numbers with exactly $ANOMALY_DIGITS digits)`n" -ForegroundColor Cyan

$results      = [System.Collections.Generic.List[Object]]::new()
$formatErrors = [System.Collections.Generic.List[string]]::new()
$counter      = 0
$total        = $usersWithPhone.Count

foreach ($user in $usersWithPhone) {
    $counter++

    # Progress every 50 users
    if ($counter % 50 -eq 0 -or $counter -eq 1 -or $counter -eq $total) {
        $pct = [math]::Round(($counter / $total) * 100, 1)
        Write-Host "  [$pct%] Processing $counter of $total - $($user.userPrincipalName)" -ForegroundColor Gray
    }

    # Pause to avoid saturating the API
    if ($DELAY_MS -gt 0) { Start-Sleep -Milliseconds $DELAY_MS }

    $uri      = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/phoneMethods"
    $response = Invoke-GraphWithRetry -Uri $uri

    if (-not $response -or -not $response.value) { continue }

    foreach ($phoneMethod in $response.value) {
        $rawPhone = $phoneMethod.phoneNumber
        if (-not $rawPhone) { continue }

        # -- Parse the number ---------------------------------
        # The API returns the format: "+1 555010012"
        #   Group 1: country code (digits after the +)
        #   Group 2: local number (may contain spaces or dashes)
        if ($rawPhone -match '^\+(\d+)\s+(.+)$') {
            $countryCode  = "+$($Matches[1])"
            $localRaw     = $Matches[2]
            $localDigits  = $localRaw -replace '[^\d]', ''   # digits only
            $length       = $localDigits.Length

            if ($length -eq $ANOMALY_DIGITS) {
                $results.Add([PSCustomObject]@{
                    UserPrincipalName   = $user.userPrincipalName
                    DisplayName         = $user.userDisplayName
                    PhoneType           = $phoneMethod.phoneType   # mobile | alternateMobile | office
                    FullNumber          = $rawPhone
                    CountryCode         = $countryCode
                    LocalNumber         = $localDigits
                    LocalLength         = $length
                    # Include SMS Sign-In state if applicable (mobile only)
                    SmsSignInState      = if ($phoneMethod.smsSignInState) { $phoneMethod.smsSignInState } else { "N/A" }
                    # Hypothesis: the extra digit may be part of the country code
                    PossibleCorrectedNumber = "$countryCode $($localDigits.Substring(1))"   # drops the first digit
                })
            }
        }
        else {
            # Number with an unexpected format -> record for review
            $formatErrors.Add("Unexpected format | $($user.userPrincipalName) | $rawPhone")
        }
    }
}

# ============================================================
# STEP 3: Export results and show summary
# ============================================================
Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
Write-Host "Users with a phone in the tenant:                          $($usersWithPhone.Count)" -ForegroundColor Cyan
Write-Host "Users with a $ANOMALY_DIGITS-digit local number (anomaly):          $($results.Count)" -ForegroundColor Red
if ($formatErrors.Count -gt 0) {
    Write-Host "Numbers with an unexpected format (review):                $($formatErrors.Count)" -ForegroundColor Yellow
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $outputPhones -NoTypeInformation -Encoding UTF8
    Write-Host "`nResults exported to: $outputPhones" -ForegroundColor Green

    Write-Host "`n-- Sample (first 15 records) --" -ForegroundColor Yellow
    $results |
        Select-Object -First 15 |
        Format-Table DisplayName, FullNumber, LocalNumber, PossibleCorrectedNumber -AutoSize
}
else {
    Write-Host "`nNo $ANOMALY_DIGITS-digit local numbers were found in the tenant." -ForegroundColor Green
}

# Log unexpected formats if any
if ($formatErrors.Count -gt 0) {
    $errorsFile = ".\MFA_Phone_UnexpectedFormats.txt"
    $formatErrors | Out-File -FilePath $errorsFile -Encoding UTF8
    Write-Host "Unexpected formats saved to: $errorsFile" -ForegroundColor Yellow
}
