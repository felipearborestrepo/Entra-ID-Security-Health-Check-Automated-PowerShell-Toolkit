# 📋 Project Description (for your portfolio)
Built a multi-module PowerShell security auditing toolkit that connects to Microsoft Entra ID via Microsoft Graph API and automatically scans for security vulnerabilities, misconfigurations, and compliance risks across the tenant. Each module produces color-coded console output and exports a detailed CSV report.

# ✅ Day 1 — App Secret & Certificate Expiry Scanner
What it does:
- Connects to Microsoft Entra ID via Microsoft Graph API, scans all App Registrations across the tenant, identifies client secrets and certificates expiring within 90 days or already expired, and exports a prioritized report.
**Steps completed today:**

**Step 1 — Environment Setup**
- Verified Microsoft.Graph PowerShell module version 2.37.0
- Confirmed PowerShell 7.5.4
- Verified Global Admin access to Entra tenant
