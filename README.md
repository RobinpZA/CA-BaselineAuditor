# CA-BaselineAuditor

Audits your Microsoft Entra Conditional Access policies against the **Kenneth van Surksum October 2025 baseline** (50 policies) and **Microsoft built-in CA templates**, then generates a self-contained HTML gap-analysis report.

## Features

- **Baseline Comparison** — Weighted scoring engine matches tenant policies against 50 baseline policies across 4 categories (Prerequisite, User, Device, Location)
- **License-Aware Filtering** — Automatically detects P1/P2/Intune/MDCA licensing and marks inapplicable policies as N/A
- **Device Platform Analysis** — Enumerates Entra devices (+ Intune if scope consented) to validate platform-specific policies
- **Security Posture Checks** — 9 automated checks (break-glass, admin coverage, guest policies, named locations, auth methods, exclusions, report-only age, conflicts, security defaults)
- **Actionable Recommendations** — Prioritised by severity with effort estimates (Quick Win / Moderate / Complex)
- **Self-Contained HTML Report** — Dark theme, interactive tables with filtering/search, compliance score ring, 6 report sections

## Requirements

- **PowerShell 7.2+**
- **Microsoft.Graph.Authentication** module
- Microsoft Entra tenant with Conditional Access policies

### Required Graph Permissions

| Permission | Type | Purpose |
|---|---|---|
| `Policy.Read.All` | Delegated or Application | Read CA policies and templates |
| `Directory.Read.All` | Delegated or Application | Directory roles, named locations, org settings |
| `Organization.Read.All` | Delegated or Application | Licensing (subscribedSkus) |
| `Device.Read.All` | Delegated or Application | Entra device inventory |
| `DeviceManagementManagedDevices.Read.All` | Delegated or Application | Intune managed devices *(optional — falls back to Entra `isManaged` if not granted)* |

## Installation

```powershell
# Clone the repository
git clone https://github.com/<your-org>/CA-BaselineAuditor.git

# Import the module
Import-Module .\CA-BaselineAuditor\CA-BaselineAuditor.psd1

# Install dependency if missing
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## Quick Start

### Interactive Authentication

```powershell
Import-Module .\CA-BaselineAuditor.psd1

# Connect interactively (browser sign-in)
Connect-CABaselineAuditor

# Run the full audit and open the report
Invoke-CABaselineAudit -OpenReport
```

### App Registration Authentication

```powershell
# Connect with app registration (certificate or client secret)
Connect-CABaselineAuditor -TenantId 'xxxxxxxx-...' -ClientId 'xxxxxxxx-...' -CertificateThumbprint 'ABC123...'

# Run audit with options
Invoke-CABaselineAudit -OutputPath '.\MyAudit.html' -SkipDeviceInventory -OpenReport
```

## Usage

### Full Audit (Recommended)

```powershell
# Single command — collects everything and generates the report
$audit = Invoke-CABaselineAudit -OpenReport
```

### Step-by-Step

```powershell
# 1. Connect
Connect-CABaselineAuditor

# 2. Collect data
$policies  = Get-CACurrentPolicies
$licensing = Get-CATenantLicensing
$devices   = Get-CATenantDevices
$context   = Get-CATenantContext
$templates = Get-CAMicrosoftTemplates

# 3. Load baseline and compare
$baselineJson = Get-Content (Join-Path (Get-Module CA-BaselineAuditor).ModuleBase 'Baselines' 'vansurksum-202510.json') -Raw | ConvertFrom-Json
$comparison = Compare-CABaseline -CurrentPolicies $policies -BaselinePolicies $baselineJson.policies -Licensing $licensing -DeviceInfo $devices

# 4. Get recommendations
$recommendations = Get-CARecommendations -ComparisonResult $comparison

# 5. Generate report
Export-CABaselineReport -AuditData ([PSCustomObject]@{
    Comparison = $comparison; Recommendations = $recommendations
    CurrentPolicies = $policies; Licensing = $licensing
    DeviceInfo = $devices; TenantContext = $context
    MicrosoftTemplates = $templates; PostureChecks = @{}
}) -OutputPath '.\report.html' -OpenReport
```

### Parameters for Invoke-CABaselineAudit

| Parameter | Description |
|---|---|
| `-OutputPath` | Custom file path for the HTML report |
| `-BaselinePath` | Path to a custom baseline JSON (default: bundled vansurksum-202510) |
| `-IncludeDisabledPolicies` | Include disabled policies in analysis |
| `-SkipDeviceInventory` | Skip device collection for faster runs |
| `-SkipMicrosoftTemplates` | Skip Microsoft template comparison |
| `-OpenReport` | Auto-open the report in the default browser |

## Report Sections

1. **Executive Summary** — Compliance score ring, matched/partial/missing/N/A counts
2. **Security Posture Findings** — 9 security checks with pass/warning/fail status
3. **Licensing & Feature Detection** — License availability with upgrade recommendations
4. **Current Policy Inventory** — Searchable/filterable table of all tenant policies
5. **Baseline Gap Analysis** — Per-policy comparison grouped by category with status badges
6. **Recommendations** — Prioritised action items with severity and effort estimates

## Baseline Reference

The bundled baseline (`Baselines/vansurksum-202510.json`) contains 50 policies:

| Category | Count | Prefix | Examples |
|---|---|---|---|
| Prerequisite | 4 | CAP | Break-glass exclusions, named locations, terms of use |
| User | 20 | CAU | MFA, password change, app protection, token protection, AI agent workload identities |
| Device | 19 | CAD | Compliance, FIDO2, managed devices, Windows/macOS/Linux/iOS/Android |
| Location | 6 | CAL | Trusted locations, country blocks, registration restrictions |

## Building & Testing

```powershell
# Run the build pipeline (analyse + test)
.\build.ps1 -Task CI

# Run tests only
.\build.ps1 -Task Test

# Run PSScriptAnalyzer only
.\build.ps1 -Task Analyze
```

## License

MIT

## Credits

- Baseline: [Kenneth van Surksum](https://yourecloudninja.com/) — CA Baseline October 2025
- Microsoft Graph API — Conditional Access templates
