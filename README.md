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
**Results of this part of the script**
<img width="932" height="193" alt="Screenshot 2026-07-20 at 22 42 29" src="https://github.com/user-attachments/assets/468e8ecb-1278-450e-8e02-6ec40d623708" />

**Step 9 — Exported flagged credentials to CSV**
- Checked if any credentials were flagged before creating a file.
- Sorted results by days remaining so most urgent items appear at the top of the report.
- Exported to CSV on the Desktop.
- The report includes AppName, CredentialType, CredentialName, ExpiryDate, DaysRemaining, and Urgency columns.
```powershell
if ($results.Count -gt 0) {
    $results | Sort-Object DaysRemaining | Export-Csv -Path "$HOME/Desktop/AppSecretExpiry.csv" -NoTypeInformation
}
```
**Step 10 — Calculated urgency counts for summary**
- Created new variables to filter the results list by each urgency level and counted how many items matched.
- Used to build the summary report showing breakdown of issues found.
```powershell
$expired  = ($results | Where-Object Urgency -eq "EXPIRED").Count
$critical = ($results | Where-Object Urgency -eq "CRITICAL").Count
$warning  = ($results | Where-Object Urgency -eq "WARNING").Count
$notice   = ($results | Where-Object Urgency -eq "NOTICE").Count
```
**Step 10 — Printed formatted summary**
- Printed a clean formatted summary box showing total apps scanned, total credentials flagged, and breakdown by urgency level.
- Each count printed in its matching color — **red** for **expired** and **critical**, **yellow** for **warning**, **cyan** for **notice**.
```powershell
Write-Host "`n========================================" -ForegroundColor Green
Write-Host " SCAN SUMMARY" -ForegroundColor Green
Write-Host " Total apps scanned: $($apps.Count)" -ForegroundColor White
Write-Host " Credentials flagged: $($result.Count)" -ForegroundColor White
Write-Host " Expired: $expired" -ForegroundColor Red
Write-Host "Critical (<=30d): $critical" -ForegroundColor Red
Write-Host "Warning (<=60d): $warning" -ForegroundColor Yellow
Write-Host "Notice (<=90d): $notice" -ForegroundColor Cyan
Write-Host "=========================================`n" -ForegroundColor Green
```
**Results shown in PowerShell**
<img width="915" height="154" alt="Screenshot 2026-07-21 at 20 00 38" src="https://github.com/user-attachments/assets/557fccc9-76b2-4dd9-b044-799aefa94e7a" />

**Results shown AppSecretExpiry CSV file**
<img width="920" height="154" alt="Screenshot 2026-07-21 at 20 01 35" src="https://github.com/user-attachments/assets/29cbdb01-a307-4ccc-a071-b4b9949bdc7a" />
