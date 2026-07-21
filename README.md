# 📋 Project Description 
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

**Step 5 — Urgency Classification**
- Built Get-UrgencyLevel function classifying credentials into:
EXPIRED (already past due)
CRITICAL (0-30 days)
WARNING (31-60 days)
NOTICE (61-90 days)
OK (over 90 days)

**Step 6 — Color Coded Output**
- Built Get-UrgencyColor function returning console colors per urgency level
- Added null safety checks for credentials with missing data
