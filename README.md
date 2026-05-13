# CA-BaselineAuditor

Audits your Microsoft Entra Conditional Access policies against **four industry baselines** and generates a self-contained HTML gap-analysis report with an interactive policy flow visualizer.

A **browser-based portal** is included — launch it with a single command, sign in to Microsoft 365, configure your audit options, and view results without touching the command line again.

## Features

- **Web Portal** — Local browser UI (`http://127.0.0.1:8080`) for sign-in, audit configuration, results summary, and report download
- **Multi-Baseline Support** — Audit against VanSurksum, CISA SCuBA, Maester, CIS M365, or all four simultaneously with per-baseline scoring
- **Weighted Scoring Engine** — Matches tenant policies against baseline policies across categories with partial-match detection
- **License-Aware Filtering** — Automatically detects P1/P2/Intune/MDCA licensing and marks inapplicable policies as N/A
- **Device Platform Analysis** — Enumerates Entra devices (+ Intune if scope consented) to validate platform-specific policies
- **Security Posture Checks** — 9 automated tenant-level checks (break-glass, admin coverage, guest policies, named locations, auth methods, exclusions, report-only age, conflicts, security defaults)
- **Policy Flow Visualizer** — Interactive per-policy flow diagrams showing targets, conditions, grant controls, and outcomes with color-coded node types
- **Actionable Recommendations** — Prioritised by severity with effort estimates (Quick Win / Moderate / Complex)
- **Self-Contained HTML Report** — Dark theme, interactive tables with filtering/search, compliance score ring, 7 report sections

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

### Web Portal (Recommended)

The portal starts a local HTTP server on `127.0.0.1`, opens your browser automatically, and blocks the PowerShell session until you click **✕ Close**.

```powershell
Import-Module .\CA-BaselineAuditor.psd1

Start-CABaselineAuditorPortal
```

From the portal you can:

1. **Connect** — sign in via interactive Microsoft Graph browser authentication
2. **Configure** — choose a baseline (VanSurksum / CISA / Maester / CIS / All) and toggle options
3. **Run Audit** — results appear with a compliance score ring, matched/partial/missing counts, and a tenant security posture bar
4. **View Full Report** — opens the full HTML report in a new browser tab
5. **Download Report** — saves the report file locally via the browser's Save dialog
6. **Sign Out** — disconnects the Microsoft Graph session and returns to the connect screen

```powershell
# Use a custom port if 8080 is already in use
Start-CABaselineAuditorPortal -Port 9090
```

### Command Line

```powershell
Import-Module .\CA-BaselineAuditor.psd1

# Connect interactively (browser sign-in)
Connect-CABaselineAuditor

# Run the full audit and open the report
Invoke-CABaselineAudit -OpenReport
```

### App Registration Authentication

```powershell
# Connect with app registration (certificate thumbprint)
Connect-CABaselineAuditor -TenantId 'xxxxxxxx-...' -ClientId 'xxxxxxxx-...' -CertificateThumbprint 'ABC123...'

# Or store credentials in Config/auth.json (see Config/auth.example.json)
Connect-CABaselineAuditor

# Run audit with options
Invoke-CABaselineAudit -OutputPath '.\MyAudit.html' -SkipDeviceInventory -OpenReport
```

## Usage

### Full Audit (Recommended)

```powershell
# Default baseline (VanSurksum)
$audit = Invoke-CABaselineAudit -OpenReport

# Audit against CISA SCuBA
$audit = Invoke-CABaselineAudit -Baseline CISA -OpenReport

# Cross-framework audit against all four baselines
$audit = Invoke-CABaselineAudit -Baseline All -OpenReport
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

### Parameters for Start-CABaselineAuditorPortal

| Parameter | Description |
|---|---|
| `-Port` | Starting port for the local server (default `8080`). Automatically tries the next available port up to `Port+9`. |

### Parameters for Invoke-CABaselineAudit

| Parameter | Description |
|---|---|
| `-OutputPath` | Custom file path for the HTML report |
| `-Baseline` | Baseline to audit against: `VanSurksum` (default), `CISA`, `Maester`, `CIS`, `All` |
| `-BaselinePath` | Path to a custom baseline JSON file (overrides `-Baseline`) |
| `-IncludeDisabledPolicies` | Include disabled policies in analysis |
| `-SkipDeviceInventory` | Skip device collection for faster runs |
| `-SkipMicrosoftTemplates` | Skip Microsoft template comparison |
| `-OpenReport` | Auto-open the report in the default browser |

## Report Sections

1. **Executive Summary** — Compliance score ring, matched/partial/missing/N/A counts, per-baseline score cards (when using `All`)
2. **Security Posture Findings** — 9 tenant-level security checks with pass/warning/fail status (baseline-independent)
3. **Licensing & Feature Detection** — License availability with upgrade recommendations
4. **Current Policy Inventory** — Searchable/filterable table of all tenant policies
5. **Baseline Gap Analysis** — Per-policy comparison grouped by category with status badges and baseline source filter
6. **Recommendations** — Prioritised action items with severity and effort estimates
7. **Policy Flow Visualizer** — Interactive card grid with per-policy flow diagrams; click **Flow** on any card to open a modal showing the full policy logic tree (targets, conditions, grant/session controls, and outcomes)

## Policy Flow Visualizer

Each policy card in section 7 has a **Flow** button that opens a modal with a top-down flow diagram. Nodes are color-coded by role:

| Color | Node type |
|---|---|
| Blue/Indigo | Policy (name + enabled state) |
| Cyan | Targets (What) — apps, auth contexts |
| Rose/Pink | Applies To (Who) — users, groups, roles |
| Purple | Decision — evaluate conditions / grant controls |
| Amber | Condition — client apps, device filter, sign-in risk, etc. |
| Green | Outcome — Access Granted / Session Controls Applied |
| Red | Outcome — Access Denied / Blocked |

User and group GUIDs are resolved to display names automatically.

## Baseline Reference

| Baseline | Key | Policies | Framework |
|---|---|---|---|
| Kenneth van Surksum Oct 2025 | `VanSurksum` | 50 | CAP/CAU/CAD/CAL categories |
| CISA SCuBA MS.AAD | `CISA` | ~20 | MS.AAD.x controls |
| Maester MT.1xxx | `Maester` | ~30 | MT.1xxx test suite |
| CIS M365 Foundations v6.0.1 | `CIS` | ~15 | CIS benchmark controls |

### VanSurksum baseline categories

| Category | Count | Prefix | Examples |
|---|---|---|---|
| Prerequisite | 4 | CAP | Break-glass exclusions, named locations, terms of use |
| User | 20 | CAU | MFA, password change, app protection, token protection, AI agent workload identities |
| Device | 19 | CAD | Compliance, FIDO2, managed devices, Windows/macOS/Linux/iOS/Android |
| Location | 6 | CAL | Trusted locations, country blocks, registration restrictions |

## Module Structure

```
CA-BaselineAuditor/
├── Public/
│   ├── Start-CABaselineAuditorPortal.ps1   # Web portal entry point
│   ├── Invoke-CABaselineAudit.ps1          # Main audit orchestrator
│   ├── Connect-CABaselineAuditor.ps1       # Graph authentication
│   ├── Export-CABaselineReport.ps1         # HTML report generator
│   └── ...                                 # Other public functions
├── Private/
│   ├── Server/
│   │   ├── Start-AuditorServer.ps1         # TCP listener loop
│   │   ├── Invoke-AuditorRouter.ps1        # HTTP request router & API handlers
│   │   └── Write-AuditorResponse.ps1       # HTTP response helpers
│   └── ...                                 # Audit logic functions
├── Assets/
│   └── portal/
│       ├── index.html                      # SPA shell
│       ├── style.css                       # Dark theme (Poppins, blue accent)
│       └── app.js                          # SPA logic
├── Baselines/                              # Baseline JSON files
├── Reports/                                # Generated HTML reports
└── Config/
    └── auth.example.json                   # App registration auth template
```

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
- [CISA SCuBA](https://www.cisa.gov/resources-tools/services/secure-cloud-business-applications) — MS.AAD Baseline
- [Maester](https://maester.dev/) — MT.1xxx Conditional Access Test Suite
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/microsoft_365) — M365 Foundations Benchmark
- Microsoft Graph API — Conditional Access templates

