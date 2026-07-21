# Project Description 
Built a multi-module PowerShell security auditing toolkit that connects to Microsoft Entra ID via Microsoft Graph API and automatically scans for security vulnerabilities, misconfigurations, and compliance risks across the tenant. Each module produces color-coded console output and exports a detailed CSV report.

# Day 1 — App Secret & Certificate Expiry Scanner
What it does:
- Connects to Microsoft Entra ID via Microsoft Graph API, scans all App Registrations across the tenant, identifies client secrets and certificates expiring within 90 days or already expired, and exports a prioritized report.
**Steps completed today:**

**Step 1 — Environment Setup**
- Verified Microsoft.Graph PowerShell module version 2.37.0
- Confirmed PowerShell 7.5.4
- Verified Global Admin access to Entra tenant

**Step 2 — Microsoft Graph Connection**
- Connected to Graph using delegated authentication
- Requested Application.Read.All scope
- Verified connection using Get-MgContext

```powershell
Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome
Write-Host "Connected to Graph" -ForegroundColor Green
```
**Step 3 — Data Collection**
- Used Get-MgApplication -All to pull all 28 App Registrations from the tenant
- Retrieved PasswordCredentials (secrets) and KeyCredentials (certificates) properties
```powershell
$apps = Get-MgApplication -All -Property "Id,DisplayName,AppId,PasswordCredentials,KeyCredentials"
Write-Host "Total apps found: $($apps.Count)" -ForegroundColor Green
```
**Step 4 — Urgency Classification**
- Built Get-UrgencyLevel function classifying credentials into:
- EXPIRED (already past due)
-CRITICAL (0-30 days)
- WARNING (31-60 days)
- NOTICE (61-90 days)
- OK (over 90 days)

**Step 5 — Color Coded Output**
- Built Get-UrgencyColor function returning console colors per urgency level
- Added null safety checks for credentials with missing data
```powershell
function Get-UrgencyLevel {
    param($Days)
    if ($Days -lt 0)      { return "EXPIRED" }
    elseif ($Days -le 30) { return "CRITICAL" }
    elseif ($Days -le 60) { return "WARNING" }
    elseif ($Days -le 90) { return "NOTICE" }
    else                  { return "OK" }
}

function Get-UrgencyColor {
    param($Urgency)
    if ($Urgency -eq "EXPIRED")      { return "Red" }
    elseif ($Urgency -eq "CRITICAL") { return "Red" }
    elseif ($Urgency -eq "WARNING")  { return "Yellow" }
    elseif ($Urgency -eq "NOTICE")   { return "Cyan" }
    else                             { return "Green" }
}
```
**Step 6 — Create empty results list and capture today's date**
```powershell
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$today   = Get-Date
```
**Step 7 — Main Scanning Loop**
- Built nested foreach loop scanning every secret and certificate on every app
- Implemented skip logic for OK credentials
- Printed flagged credentials to console with color coding
```powershell
foreach ($app in $apps) {

    foreach ($secret in $app.PasswordCredentials) {

        if (-not $secret.EndDateTime) { continue }

        $expiry   = $secret.EndDateTime
        $daysLeft = [int]($expiry - $today).TotalDays
        $urgency  = Get-UrgencyLevel -Days $daysLeft
        $color    = Get-UrgencyColor -Urgency $urgency

        if ($urgency -eq "OK") { continue }

        Write-Host "App: $($app.DisplayName) | Secret: $($secret.DisplayName) | Days: $daysLeft | Status: $urgency" -ForegroundColor $color

        $results.Add([PSCustomObject]@{
            AppName        = $app.DisplayName
            CredentialType = "Secret"
            CredentialName = if ($secret.DisplayName) { $secret.DisplayName } else { "(unnamed)" }
            ExpiryDate     = $expiry.ToString("yyyy-MM-dd")
            DaysRemaining  = $daysLeft
            Urgency        = $urgency
        })
    }

    foreach ($cert in $app.KeyCredentials) {

        if (-not $cert.EndDateTime) { continue }

        $expiry   = $cert.EndDateTime
        $daysLeft = [int]($expiry - $today).TotalDays
        $urgency  = Get-UrgencyLevel -Days $daysLeft
        $color    = Get-UrgencyColor -Urgency $urgency

        if ($urgency -eq "OK") { continue }

        Write-Host "App: $($app.DisplayName) | Cert: $($cert.DisplayName) | Days: $daysLeft | Status: $urgency" -ForegroundColor $color

        $results.Add([PSCustomObject]@{
            AppName        = $app.DisplayName
            CredentialType = "Certificate"
            CredentialName = if ($cert.DisplayName) { $cert.DisplayName } else { "(unnamed)" }
            ExpiryDate     = $expiry.ToString("yyyy-MM-dd")
            DaysRemaining  = $daysLeft
            Urgency        = $urgency
        })
    }
}
```
**Step 8 — Print scan complete summary**
```powershell
Write-Host "`nScan complete — $($results.Count) credential(s) flagged" -ForegroundColor Green
```
