function Invoke-CABaselineAudit {
    <#
    .SYNOPSIS
        Runs a complete Conditional Access baseline audit and generates an HTML report.
    .DESCRIPTION
        Orchestrates the full audit workflow: collects tenant data, compares against
        one or more industry baselines, performs security posture checks, generates
        recommendations and produces a self-contained HTML report.

        Available baselines:
          VanSurksum  — Kenneth van Surksum October 2025 (50 policies, default)
          CISA        — CISA SCuBA Microsoft 365 Entra ID Baseline (MS.AAD controls)
          Maester      — Maester MT.1xxx Conditional Access Test Suite
          CIS          — CIS Microsoft 365 Foundations Benchmark v6.0.1
          All          — Merge all four baselines for a comprehensive cross-framework audit
    .PARAMETER OutputPath
        Path for the generated HTML report. Defaults to .\Reports\CA-Baseline-Audit_<timestamp>.html
    .PARAMETER Baseline
        Which baseline(s) to audit against. Accepts: VanSurksum, CISA, Maester, CIS, All.
        Defaults to VanSurksum for backward compatibility.
    .PARAMETER BaselinePath
        Path to a custom baseline JSON file. Overrides the -Baseline parameter when provided.
    .PARAMETER IncludeDisabledPolicies
        Include disabled policies in the analysis.
    .PARAMETER SkipDeviceInventory
        Skip device data collection (faster, but no platform analysis in report).
    .PARAMETER SkipMicrosoftTemplates
        Skip fetching Microsoft CA templates.
    .PARAMETER OpenReport
        Automatically open the report in the default browser.
    .EXAMPLE
        Invoke-CABaselineAudit -OpenReport
    .EXAMPLE
        Invoke-CABaselineAudit -Baseline CISA -OpenReport
    .EXAMPLE
        Invoke-CABaselineAudit -Baseline All -OpenReport
    .EXAMPLE
        Invoke-CABaselineAudit -OutputPath 'C:\Reports\audit.html' -SkipDeviceInventory
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\Reports\CA-Baseline-Audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html",

        [ValidateSet('VanSurksum', 'CISA', 'Maester', 'CIS', 'All')]
        [string]$Baseline = 'VanSurksum',

        [string]$BaselinePath,

        [switch]$IncludeDisabledPolicies,

        [switch]$SkipDeviceInventory,

        [switch]$SkipMicrosoftTemplates,

        [switch]$OpenReport
    )

    $ErrorActionPreference = 'Stop'
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # ── Verify connection ──
    $connStatus = Get-CABaselineAuditorConnectionStatus
    if (-not $connStatus.Connected) {
        throw 'Not connected to Microsoft Graph. Run Connect-CABaselineAuditor first.'
    }

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host '║         CA-BaselineAuditor — Starting Audit                  ║' -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $totalSteps = 8
    $step = 0

    # ── Step 1: Tenant Context ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Collecting tenant context...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Collecting tenant context..." -ForegroundColor Yellow
    $tenantContext = Get-CATenantContext

    # ── Step 2: Licensing ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Detecting licensing...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Detecting tenant licensing..." -ForegroundColor Yellow
    $licensing = Get-CATenantLicensing

    # ── Step 3: Current Policies ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Retrieving CA policies...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Retrieving current CA policies..." -ForegroundColor Yellow
    $currentPolicies = Get-CACurrentPolicies -IncludeDisabled:$IncludeDisabledPolicies
    Write-Host "  Found $($currentPolicies.Count) policies" -ForegroundColor DarkGray

    # ── Step 4: Devices ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Collecting device data...' -PercentComplete (($step / $totalSteps) * 100)
    if ($SkipDeviceInventory) {
        Write-Host "[Step $step/$totalSteps] Skipping device inventory (flag set)" -ForegroundColor DarkGray
        $deviceInfo = [PSCustomObject]@{
            EntraDeviceCount  = 0; IntuneDeviceCount = 0; CompliantCount = 0
            NonCompliantCount = 0; CorporateOwned = 0; PersonalBYOD = 0
            PlatformCounts    = [PSCustomObject]@{}
        }
    }
    else {
        Write-Host "[Step $step/$totalSteps] Collecting device information..." -ForegroundColor Yellow
        $deviceInfo = Get-CATenantDevices -HasIntune $licensing.HasIntune
        Write-Host "  Found $($deviceInfo.EntraDeviceCount) Entra devices, $($deviceInfo.IntuneDeviceCount) Intune managed" -ForegroundColor DarkGray
    }

    # ── Step 5: Microsoft Templates ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Fetching MS templates...' -PercentComplete (($step / $totalSteps) * 100)
    if ($SkipMicrosoftTemplates) {
        Write-Host "[Step $step/$totalSteps] Skipping Microsoft templates (flag set)" -ForegroundColor DarkGray
        $msTemplates = @()
    }
    else {
        Write-Host "[Step $step/$totalSteps] Fetching Microsoft CA templates..." -ForegroundColor Yellow
        $msTemplates = Get-CAMicrosoftTemplates
        Write-Host "  Found $($msTemplates.Count) templates" -ForegroundColor DarkGray
    }

    # ── Step 6: Baseline Comparison ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Comparing against baseline...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Comparing against baseline..." -ForegroundColor Yellow

    # ── Resolve which baseline file(s) to load ──
    $baselineMap = @{
        'VanSurksum' = 'vansurksum-202510.json'
        'CISA'       = 'cisa-scuba-aad.json'
        'Maester'    = 'maester-mt.json'
        'CIS'        = 'cis-m365-foundations.json'
    }

    $activeBaselineName = 'VanSurksum'
    $baselinePolicies   = [System.Collections.Generic.List[object]]::new()

    if ($BaselinePath) {
        # Custom file overrides everything
        $customData = Get-Content $BaselinePath -Raw | ConvertFrom-Json
        foreach ($p in $customData.policies) {
            if (-not $p.PSObject.Properties['BaselineSource']) {
                $p | Add-Member -NotePropertyName 'BaselineSource' -NotePropertyValue ($customData.source ?? 'Custom') -Force
            }
            $baselinePolicies.Add($p)
        }
        $activeBaselineName = $customData.source ?? 'Custom'
        Write-Host "  Loaded $($baselinePolicies.Count) baseline policies from $BaselinePath" -ForegroundColor DarkGray
    } elseif ($Baseline -eq 'All') {
        $activeBaselineName = 'All Baselines'
        foreach ($key in $baselineMap.Keys) {
            $file = Join-Path $script:ModuleRoot 'Baselines' $baselineMap[$key]
            if (Test-Path $file) {
                $data = Get-Content $file -Raw | ConvertFrom-Json
                foreach ($p in $data.policies) {
                    $p | Add-Member -NotePropertyName 'BaselineSource' -NotePropertyValue $key -Force
                    $baselinePolicies.Add($p)
                }
                Write-Host "  Loaded $($data.policies.Count) policies from $($baselineMap[$key]) [$key]" -ForegroundColor DarkGray
            }
        }
        Write-Host "  Total: $($baselinePolicies.Count) policies across all baselines" -ForegroundColor DarkGray
    } else {
        $activeBaselineName = $Baseline
        $file = Join-Path $script:ModuleRoot 'Baselines' $baselineMap[$Baseline]
        $data = Get-Content $file -Raw | ConvertFrom-Json
        foreach ($p in $data.policies) {
            $p | Add-Member -NotePropertyName 'BaselineSource' -NotePropertyValue $Baseline -Force
            $baselinePolicies.Add($p)
        }
        Write-Host "  Loaded $($baselinePolicies.Count) baseline policies from $($baselineMap[$Baseline]) [$Baseline]" -ForegroundColor DarkGray
    }

    $comparison = Compare-CABaseline -CurrentPolicies $currentPolicies -BaselinePolicies $baselinePolicies -Licensing $licensing -DeviceInfo $deviceInfo

    Write-Host "  Matched: $($comparison.Summary.Matched), Partial: $($comparison.Summary.Partial), Missing: $($comparison.Summary.Missing), N/A: $($comparison.Summary.NotApplicable)" -ForegroundColor DarkGray

    # ── Step 7: Security Posture Checks ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Running security posture checks...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Running security posture checks..." -ForegroundColor Yellow

    $postureChecks = [ordered]@{}
    $postureChecks['SecurityDefaults']    = Test-CASecurityDefaults    -TenantContext $tenantContext
    $postureChecks['BreakGlass']          = Test-CABreakGlassAccounts  -CurrentPolicies $currentPolicies -TenantContext $tenantContext
    $postureChecks['AdminCoverage']       = Test-CAAdminCoverage       -CurrentPolicies $currentPolicies -TenantContext $tenantContext
    $postureChecks['GuestPolicies']       = Test-CAGuestPolicies       -CurrentPolicies $currentPolicies -TenantContext $tenantContext
    $postureChecks['NamedLocations']      = Test-CANamedLocations      -TenantContext $tenantContext
    $postureChecks['AuthMethodReadiness'] = Test-CAAuthMethodReadiness -TenantContext $tenantContext
    $postureChecks['PolicyExclusions']    = Test-CAPolicyExclusions    -CurrentPolicies $currentPolicies
    $postureChecks['ReportOnlyAge']       = Test-CAReportOnlyAge       -CurrentPolicies $currentPolicies
    $postureChecks['PolicyConflicts']     = Test-CAPolicyConflicts     -CurrentPolicies $currentPolicies

    $passCount = @($postureChecks.Values | Where-Object { $_.Status -eq 'Pass' }).Count
    Write-Host "  $passCount/$($postureChecks.Count) checks passed" -ForegroundColor DarkGray

    # ── Step 8: Generate Report ──
    $step++
    Write-Progress -Activity 'CA Baseline Audit' -Status 'Generating HTML report...' -PercentComplete (($step / $totalSteps) * 100)
    Write-Host "[Step $step/$totalSteps] Generating HTML report..." -ForegroundColor Yellow

    $recommendations = Get-CARecommendations -ComparisonResult $comparison -Licensing $licensing

    $auditData = [PSCustomObject]@{
        Comparison         = $comparison
        Recommendations    = $recommendations
        CurrentPolicies    = $currentPolicies
        Licensing          = $licensing
        DeviceInfo         = $deviceInfo
        TenantContext      = $tenantContext
        MicrosoftTemplates = $msTemplates
        PostureChecks      = $postureChecks
        ActiveBaseline     = $activeBaselineName
    }

    $reportPath = Export-CABaselineReport -AuditData $auditData -OutputPath $OutputPath -OpenReport:$OpenReport

    $stopwatch.Stop()
    Write-Progress -Activity 'CA Baseline Audit' -Completed

    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host '║                    Audit Complete!                           ║' -ForegroundColor Green
    Write-Host "╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Green
    Write-Host "║  Tenant:   $($tenantContext.TenantName.PadRight(48))  ║" -ForegroundColor Green
    Write-Host "║  Policies: $($currentPolicies.Count.ToString().PadRight(48))  ║" -ForegroundColor Green
    Write-Host "║  Score:    $("$($comparison.Summary.Matched)/$($comparison.Summary.TotalBaseline) matched".PadRight(48))  ║" -ForegroundColor Green
    Write-Host "║  Duration: $("$([math]::Round($stopwatch.Elapsed.TotalSeconds, 1))s".PadRight(48))  ║" -ForegroundColor Green
    Write-Host "║  Report:   $($reportPath.ToString().Substring(0, [math]::Min($reportPath.Length, 48)).PadRight(48))  ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""

    # Return the audit data for programmatic use
    $auditData
}
