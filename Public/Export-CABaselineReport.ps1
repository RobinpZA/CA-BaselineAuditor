function Export-CABaselineReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report from the CA baseline audit results.
    .DESCRIPTION
        Creates a single-file HTML report with dark theme, interactive tables,
        and 7 sections covering the complete CA baseline audit including executive
        summary, gap analysis, security posture, and recommendations.
    .PARAMETER AuditData
        The complete audit data object from Invoke-CABaselineAudit.
    .PARAMETER OutputPath
        File path for the generated report.
    .PARAMETER OpenReport
        Automatically open the report in the default browser.
    .EXAMPLE
        Export-CABaselineReport -AuditData $data -OutputPath '.\CA-Baseline-Report.html' -OpenReport
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditData,

        [string]$OutputPath = ".\Reports\CA-Baseline-Audit_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html",

        [switch]$OpenReport
    )

    Write-Host '[CA-BaselineAuditor] Generating HTML report...' -ForegroundColor Cyan

    $comparison     = $AuditData.Comparison
    $recommendations = $AuditData.Recommendations
    $policies       = $AuditData.CurrentPolicies
    $licensing      = $AuditData.Licensing
    $devices        = $AuditData.DeviceInfo
    $tenantCtx      = $AuditData.TenantContext
    $postureChecks  = $AuditData.PostureChecks
    $summary        = $comparison.Summary
    $tenantName     = $tenantCtx.TenantName ?? 'Unknown Tenant'
    $reportDate     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # ── Compute compliance score ──
    $applicableMusts = @($comparison.BaselineResults | Where-Object { $_.Priority -eq 'Must Have' -and $_.Status -ne 'NotApplicable' })
    $matchedMusts    = @($applicableMusts | Where-Object { $_.Status -eq 'Matched' })
    $complianceScore = if ($applicableMusts.Count -gt 0) { [math]::Round(($matchedMusts.Count / $applicableMusts.Count) * 100) } else { 0 }

    # ── Severity counts for posture ──
    $postureFindings = @($postureChecks.Values | Where-Object { $_.Status -ne 'Pass' })
    $criticalFindings = @($postureFindings | Where-Object { $_.Severity -eq 'Critical' }).Count

    # ═══════════════════════════════════════════════════════════════════
    # CSS
    # ═══════════════════════════════════════════════════════════════════
    $css = @'
:root {
    --bg-primary: #0f172a;
    --bg-secondary: #1e293b;
    --bg-card: #1e293b;
    --bg-hover: #334155;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --border: #334155;
    --accent-blue: #3b82f6;
    --accent-green: #22c55e;
    --accent-yellow: #eab308;
    --accent-red: #ef4444;
    --accent-orange: #f97316;
    --accent-purple: #a855f7;
    --accent-cyan: #06b6d4;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 0; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px 24px; }
.header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%); padding: 32px 24px; border-bottom: 2px solid var(--accent-blue); margin-bottom: 24px; }
.header h1 { font-size: 1.8rem; font-weight: 700; color: #fff; }
.header .meta { color: var(--text-secondary); font-size: 0.85rem; margin-top: 6px; }
nav { background: var(--bg-secondary); padding: 10px 24px; border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; display: flex; flex-wrap: wrap; gap: 4px; }
nav a { color: var(--text-secondary); text-decoration: none; padding: 6px 14px; border-radius: 6px; font-size: 0.82rem; white-space: nowrap; transition: all 0.2s; }
nav a:hover, nav a.active { background: var(--bg-hover); color: var(--text-primary); }
section { margin-bottom: 32px; scroll-margin-top: 56px; }
h2 { font-size: 1.25rem; font-weight: 600; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
h3 { font-size: 1rem; font-weight: 600; margin: 16px 0 10px; }
.card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; text-align: center; }
.card .value { font-size: 2rem; font-weight: 700; line-height: 1.2; }
.card .label { font-size: 0.78rem; color: var(--text-secondary); margin-top: 4px; }
.score-ring { width: 120px; height: 120px; margin: 0 auto 12px; position: relative; }
.score-ring svg { transform: rotate(-90deg); }
.score-ring .score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.6rem; font-weight: 700; }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-bottom: 16px; }
thead th { background: var(--bg-hover); color: var(--text-primary); padding: 10px 12px; text-align: left; font-weight: 600; cursor: pointer; white-space: nowrap; user-select: none; }
thead th.sort-asc::after  { content: ' \25B2'; font-size: 0.65rem; color: var(--accent-cyan); }
thead th.sort-desc::after { content: ' \25BC'; font-size: 0.65rem; color: var(--accent-cyan); }
tbody td { padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tbody tr:hover { background: var(--bg-hover); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 600; }
.badge-green { background: rgba(34,197,94,0.15); color: var(--accent-green); }
.badge-yellow { background: rgba(234,179,8,0.15); color: var(--accent-yellow); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--accent-red); }
.badge-blue { background: rgba(59,130,246,0.15); color: var(--accent-blue); }
.badge-purple { background: rgba(168,85,247,0.15); color: var(--accent-purple); }
.badge-gray { background: rgba(100,116,139,0.15); color: var(--text-muted); }
.badge-orange { background: rgba(249,115,22,0.15); color: var(--accent-orange); }
.badge-cyan { background: rgba(6,182,212,0.15); color: var(--accent-cyan); }
.status-matched { color: var(--accent-green); }
.status-partial { color: var(--accent-yellow); }
.status-missing { color: var(--accent-red); }
.status-na { color: var(--text-muted); }
.posture-pass { color: var(--accent-green); }
.posture-warning { color: var(--accent-yellow); }
.posture-fail { color: var(--accent-red); }
.diff-list { margin: 4px 0; padding-left: 16px; font-size: 0.75rem; color: var(--text-secondary); }
.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
.compare-btn { background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; cursor: pointer; margin-left: 6px; transition: all 0.15s; white-space: nowrap; }
.compare-btn:hover { background: var(--bg-hover); color: var(--text-primary); border-color: var(--accent-cyan); }
.diff-panel-wrap { background: var(--bg-secondary); border-top: 2px solid var(--accent-cyan); padding: 0; }
.diff-inner-table { width: 100%; margin: 0; font-size: 0.78rem; border: none; }
.diff-inner-table th { background: var(--bg-primary); padding: 6px 10px; font-size: 0.72rem; font-weight: 600; }
.diff-inner-table td { padding: 5px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; }
.diff-inner-table tr:last-child td { border-bottom: none; }
.diff-dim { color: var(--text-muted); width: 150px; white-space: nowrap; }
.diff-match { color: var(--accent-green); }
.diff-mismatch { color: var(--accent-red); }
.filter-bar input, .filter-bar select { background: var(--bg-primary); border: 1px solid var(--border); color: var(--text-primary); padding: 6px 12px; border-radius: 6px; font-size: 0.82rem; }
.filter-bar input { min-width: 200px; }
.progress-bar { height: 8px; background: var(--bg-hover); border-radius: 4px; overflow: hidden; margin: 4px 0; }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.lic-table td:first-child { font-weight: 600; width: 250px; }
.lic-icon { font-size: 1.1rem; }
.footer { text-align: center; padding: 24px; color: var(--text-muted); font-size: 0.75rem; border-top: 1px solid var(--border); margin-top: 32px; }
@media print { body { background: #fff; color: #000; } .card { border: 1px solid #ccc; } nav { display: none; } thead th { background: #eee; } }
@media (max-width: 768px) { .card-grid { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); } }
'@

    # ═══════════════════════════════════════════════════════════════════
    # HTML SECTIONS
    # ═══════════════════════════════════════════════════════════════════

    # ── Score colour ──
    $scoreColour = if ($complianceScore -ge 80) { 'var(--accent-green)' }
                   elseif ($complianceScore -ge 50) { 'var(--accent-yellow)' }
                   else { 'var(--accent-red)' }
    $dashArray   = [math]::Round(($complianceScore / 100) * 314, 1)

    # ── Section 1: Executive Summary ──
    $sec1 = @"
<section id="summary">
<h2>Executive Summary</h2>
<div class="card-grid">
    <div class="card">
        <div class="score-ring">
            <svg viewBox="0 0 120 120" width="120" height="120">
                <circle cx="60" cy="60" r="50" fill="none" stroke="var(--bg-hover)" stroke-width="10"/>
                <circle cx="60" cy="60" r="50" fill="none" stroke="$scoreColour" stroke-width="10" stroke-dasharray="$dashArray 314" stroke-linecap="round"/>
            </svg>
            <div class="score-text" style="color:$scoreColour">$complianceScore%</div>
        </div>
        <div class="label">Must Have Compliance</div>
    </div>
    <div class="card"><div class="value status-matched">$($summary.Matched)</div><div class="label">Matched</div></div>
    <div class="card"><div class="value status-partial">$($summary.Partial)</div><div class="label">Partial</div></div>
    <div class="card"><div class="value status-missing">$($summary.Missing)</div><div class="label">Missing</div></div>
    <div class="card"><div class="value status-na">$($summary.NotApplicable)</div><div class="label">Not Applicable</div></div>
    <div class="card"><div class="value" style="color:var(--accent-cyan)">$($summary.TotalTenant)</div><div class="label">Tenant Policies</div></div>
    <div class="card"><div class="value" style="color:var(--accent-purple)">$($summary.Custom)</div><div class="label">Custom Policies</div></div>
    $(if ($criticalFindings -gt 0) { "<div class='card'><div class='value' style='color:var(--accent-red)'>$criticalFindings</div><div class='label'>Critical Findings</div></div>" })
</div>
</section>
"@

    # ── Section 2: Licensing ──
    $licRows = @(
        @('Entra ID P1 (Basic CA, MFA, Location)', $licensing.HasEntraP1),
        @('Entra ID P2 (Risk-based CA)', $licensing.HasEntraP2),
        @('Microsoft Intune (Device Compliance)', $licensing.HasIntune),
        @('Defender for Cloud Apps (MDCA)', $licensing.HasMDCA),
        @('Workload Identity Premium', $licensing.HasWorkloadIdentity),
        @('Windows 365 Cloud PC', $licensing.HasCloudPC),
        @('Defender for Endpoint', $licensing.HasDefenderForEndpoint)
    )
    $licTableRows = ($licRows | ForEach-Object {
        $icon  = if ($_[1]) { '<span class="lic-icon">&#x2705;</span>' } else { '<span class="lic-icon">&#x274C;</span>' }
        $badge = if ($_[1]) { '<span class="badge badge-green">Available</span>' } else { '<span class="badge badge-red">Not Licensed</span>' }
        "<tr><td class='lic-table'>$($_[0])</td><td>$icon $badge</td></tr>"
    }) -join "`n"

    $licUpgradeRows = ''
    if ($recommendations.LicenseUpgrades.Count -gt 0) {
        $licUpgradeRows = '<h3>License Upgrade Recommendations</h3><table><thead><tr><th>License</th><th>Unlocks</th><th>Policies</th><th>Impact</th></tr></thead><tbody>'
        foreach ($lu in $recommendations.LicenseUpgrades) {
            $licUpgradeRows += "<tr><td><strong>$($lu.License)</strong></td><td>$($lu.PolicyCount) policies</td><td>$($lu.Policies)</td><td>$($lu.Impact)</td></tr>"
        }
        $licUpgradeRows += '</tbody></table>'
    }

    $sec2 = @"
<section id="licensing">
<h2>Licensing &amp; Feature Detection</h2>
<table class="lic-table"><tbody>
$licTableRows
</tbody></table>
$licUpgradeRows
</section>
"@

    # ── Section 3: Current Policy Inventory ──
    $policyRows = [System.Text.StringBuilder]::new()
    foreach ($p in ($policies | Sort-Object { $_.displayName })) {
        $stateBadge = switch ($p.state) {
            'enabled'                          { '<span class="badge badge-green">Enabled</span>' }
            'enabledForReportingButNotEnforced' { '<span class="badge badge-yellow">Report-Only</span>' }
            'disabled'                         { '<span class="badge badge-red">Disabled</span>' }
            default                            { "<span class='badge badge-gray'>$($p.state)</span>" }
        }
        $grant   = Format-GrantControls -Policy $p
        $session = Format-SessionControls -Policy $p
        $apps    = Format-TargetApps -Policy $p
        $users   = Format-TargetUsers -Policy $p
        [void]$policyRows.Append("<tr><td>$([System.Web.HttpUtility]::HtmlEncode($p.displayName))</td><td>$stateBadge</td><td>$users</td><td>$apps</td><td>$grant</td><td>$session</td></tr>")
    }

    $sec3 = @"
<section id="inventory">
<h2>Current Policy Inventory ($($policies.Count) policies)</h2>
<div class="filter-bar"><input type="text" id="policyFilter" placeholder="Filter policies..." onkeyup="filterTable('policyTable','policyFilter')"><select onchange="filterTableByCol('policyTable',1,this.value)"><option value="">All States</option><option value="Enabled">Enabled</option><option value="Report-Only">Report-Only</option><option value="Disabled">Disabled</option></select></div>
<div style="overflow-x:auto"><table id="policyTable"><thead><tr><th onclick="sortTable('policyTable',0)">Policy Name</th><th onclick="sortTable('policyTable',1)">State</th><th onclick="sortTable('policyTable',2)">Users</th><th onclick="sortTable('policyTable',3)">Applications</th><th onclick="sortTable('policyTable',4)">Grant Controls</th><th onclick="sortTable('policyTable',5)">Session Controls</th></tr></thead><tbody>
$($policyRows.ToString())
</tbody></table></div>
</section>
"@

    # ── Section 4: Baseline Gap Analysis ──

    # ── Helper: build the policy diff panel HTML ──
    function Format-DiffRow {
        param([string]$dim, [string]$bVal, [string]$tVal, [bool]$match)
        $icon    = if ($match) { '<span class="diff-match">&#x2713;</span>' } else { '<span class="diff-mismatch">&#x2717;</span>' }
        $valCls  = if ($match) { 'diff-match' } else { 'diff-mismatch' }
        $enc     = [System.Web.HttpUtility]
        "<tr><td class='diff-dim'>$dim</td><td>$($enc::HtmlEncode($bVal))</td><td class='$valCls'>$icon $($enc::HtmlEncode($tVal))</td></tr>"
    }

    function Format-PolicyDiffPanel {
        param([object]$r)
        $mp = $r.BaselineMatchPatterns
        $p  = $r.MatchedPolicyObject
        if (-not $mp -or -not $p) { return '' }

        $rowsHtml = [System.Text.StringBuilder]::new()

        # State
        $stateRaw = $p.state ?? 'unknown'
        $stateLabel = switch ($stateRaw) {
            'enabled'                           { 'Enabled' }
            'enabledForReportingButNotEnforced' { 'Report-only (not enforced)' }
            'disabled'                          { 'Disabled' }
            default                             { $stateRaw }
        }
        [void]$rowsHtml.Append((Format-DiffRow 'State' 'Enabled' $stateLabel ($stateRaw -eq 'enabled')))

        # Users
        if ($mp.users) {
            $bParts = @()
            if (($mp.users.includeUsers ?? @()) -contains 'All') { $bParts += 'All users' }
            elseif (($mp.users.includeUsers ?? @()).Count -gt 0)  { $bParts += ($mp.users.includeUsers -join ', ') }
            if ($mp.users.includeGuestsOrExternalUsers) { $bParts += 'Guests / External' }
            if (($mp.users.includeRoles ?? @()).Count -gt 0) { $bParts += 'Admin roles' }
            $tu = $p.conditions.users
            $tParts = @()
            if (($tu.includeUsers ?? @()) -contains 'All') { $tParts += 'All users' }
            elseif (($tu.includeUsers ?? @()).Count -gt 0)  { $tParts += ($tu.includeUsers -join ', ') }
            if ($tu.includeGuestsOrExternalUsers) { $tParts += 'Guests / External' }
            if (($tu.includeRoles  ?? @()).Count -gt 0) { $tParts += "$($tu.includeRoles.Count) admin role(s)" }
            if (($tu.includeGroups ?? @()).Count -gt 0) { $tParts += "$($tu.includeGroups.Count) group(s)" }
            $uBStr = if ($bParts) { $bParts -join ' + ' } else { 'Any' }
            $uTStr = if ($tParts) { $tParts -join ' + ' } else { 'None specified' }
            $uMatch = -not ($r.Differences | Where-Object { $_ -match 'targeting|guest|admin role' })
            [void]$rowsHtml.Append((Format-DiffRow 'Users' $uBStr $uTStr $uMatch))
        }

        # Applications
        if ($mp.applications.includeApplications) {
            if ($mp.applications.includeApplications -is [bool]) {
                # Boolean placeholder — baseline defers app selection to the implementer
                $tApps = (($p.conditions.applications.includeApplications ?? @()) -join ', ')
                $aTStr = if ($tApps) { $tApps } else { 'None configured' }
                [void]$rowsHtml.Append((Format-DiffRow 'Applications' 'Customer-defined (baseline placeholder)' $aTStr $true))
            } else {
                $tApps = (($p.conditions.applications.includeApplications ?? @()) -join ', ')
                $aBStr = $mp.applications.includeApplications -join ', '
                $aTStr = if ($tApps) { $tApps } else { 'None' }
                $aMatch = -not ($r.Differences | Where-Object { $_ -match 'Target applications differ' })
                [void]$rowsHtml.Append((Format-DiffRow 'Applications' $aBStr $aTStr $aMatch))
            }
        }
        if ($mp.applications.includeUserActions) {
            $tActions = (($p.conditions.applications.includeUserActions ?? @()) -join ', ')
            $acBStr = $mp.applications.includeUserActions -join ', '
            $acTStr = if ($tActions) { $tActions } else { 'None' }
            $acMatch = -not ($r.Differences | Where-Object { $_ -match 'User actions differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'User Actions' $acBStr $acTStr $acMatch))
        }

        # Client App Types
        if ($mp.clientAppTypes) {
            $tClients = (($p.conditions.clientAppTypes ?? @()) -join ', ')
            $cBStr = $mp.clientAppTypes -join ', '
            $cTStr = if ($tClients) { $tClients } else { 'Not set' }
            $cMatch = -not ($r.Differences | Where-Object { $_ -match 'Client app types differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'Client App Types' $cBStr $cTStr $cMatch))
        }

        # Grant Controls
        if ($mp.grantControls.builtInControls) {
            $tGrant = (($p.grantControls.builtInControls ?? @()) -join ', ')
            $gBStr = $mp.grantControls.builtInControls -join ', '
            $gTStr = if ($tGrant) { $tGrant } else { 'None' }
            $gMatch = -not ($r.Differences | Where-Object { $_ -match 'Grant controls differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'Grant Controls' $gBStr $gTStr $gMatch))
        }
        if ($mp.grantControls.authenticationStrength) {
            $baselineLevel  = if ($mp.grantControls.authenticationStrength -is [bool]) { 'mfa' } else { $mp.grantControls.authenticationStrength.requirementsSatisfied ?? 'mfa' }
            $tenantStrength = $p.grantControls.authenticationStrength
            $tenantHasMfa   = ($p.grantControls.builtInControls ?? @()) -contains 'mfa'
            $strengthRank   = @{ 'mfa' = 1; 'phishingResistant' = 2 }
            $requiredRank   = $strengthRank[$baselineLevel] ?? 1
            $hasStr = if ($tenantStrength) {
                ($strengthRank[$tenantStrength.requirementsSatisfied] ?? 0) -ge $requiredRank
            } elseif ($tenantHasMfa -and $requiredRank -le 1) {
                $true
            } else { $false }
            $tenantLevel = if ($tenantStrength) { $tenantStrength.requirementsSatisfied ?? 'Configured' }
                           elseif ($tenantHasMfa) { 'mfa (via grant control)' }
                           else { 'Not configured' }
            [void]$rowsHtml.Append((Format-DiffRow 'Auth Strength' $baselineLevel $tenantLevel $hasStr))
        }

        # Session Controls
        if ($mp.sessionControls) {
            $bSess = @(); $tSess = @(); $sessOk = $true
            if ($mp.sessionControls.signInFrequency) {
                $bSess += 'Sign-in Frequency'
                $sif = $p.sessionControls.signInFrequency
                if ($sif.isEnabled) { $tSess += "Sign-in Frequency ($($sif.value) $($sif.type))" } else { $sessOk = $false }
            }
            if ($mp.sessionControls.persistentBrowser) {
                $bSess += "Persistent Browser (mode: $($mp.sessionControls.persistentBrowser.mode))"
                $pb = $p.sessionControls.persistentBrowser
                if ($pb.isEnabled) { $tSess += "Persistent Browser (mode: $($pb.mode))" } else { $sessOk = $false }
            }
            if ($mp.sessionControls.applicationEnforcedRestrictions) {
                $bSess += 'App Enforced Restrictions'
                if ($p.sessionControls.applicationEnforcedRestrictions.isEnabled) { $tSess += 'App Enforced Restrictions' } else { $sessOk = $false }
            }
            if ($mp.sessionControls.cloudAppSecurity) {
                $mpCasType = $mp.sessionControls.cloudAppSecurity.cloudAppSecurityType
                $bSess += if ($mpCasType) { "MCAS / Defender for Cloud Apps ($mpCasType)" } else { 'MCAS / Defender for Cloud Apps' }
                $cas = $p.sessionControls.cloudAppSecurity
                if ($cas.isEnabled) {
                    $tSess += "MCAS ($($cas.cloudAppSecurityType ?? 'type not set'))"
                    # If baseline specifies a type, check it matches
                    if ($mpCasType -and $cas.cloudAppSecurityType -ne $mpCasType) { $sessOk = $false }
                } else { $sessOk = $false }
            }
            if ($mp.sessionControls.secureSignInSession) {
                $bSess += 'Token Protection'
                if ($null -ne $p.sessionControls.secureSignInSession) { $tSess += 'Token Protection' } else { $sessOk = $false }
            }
            $sessBStr = if ($bSess) { $bSess -join ' + ' } else { 'Required' }
            $sessTStr = if ($tSess) { $tSess -join ' + ' } else { 'None configured' }
            [void]$rowsHtml.Append((Format-DiffRow 'Session Controls' $sessBStr $sessTStr $sessOk))
        }

        # Platforms
        if ($mp.platforms.includePlatforms) {
            $tPlat = (($p.conditions.platforms.includePlatforms ?? @()) -join ', ')
            $platBStr = $mp.platforms.includePlatforms -join ', '
            $platTStr = if ($tPlat) { $tPlat } else { 'None' }
            $platMatch = -not ($r.Differences | Where-Object { $_ -match 'Platform filter differs' })
            [void]$rowsHtml.Append((Format-DiffRow 'Include Platforms' $platBStr $platTStr $platMatch))
        }
        if ($mp.platforms.excludePlatforms) {
            $tExPlat = (($p.conditions.platforms.excludePlatforms ?? @()) -join ', ')
            $exBStr = $mp.platforms.excludePlatforms -join ', '
            $exTStr = if ($tExPlat) { $tExPlat } else { 'None' }
            $exMatch = -not ($r.Differences | Where-Object { $_ -match 'Platform exclude filter differs' })
            [void]$rowsHtml.Append((Format-DiffRow 'Exclude Platforms' $exBStr $exTStr $exMatch))
        }

        # Device State / Device Filter
        $tDevFilter = $p.conditions.devices.deviceFilter
        $hasCompliantFilter = $null -ne $tDevFilter -and (
            ($tDevFilter.rule -match 'isCompliant.*True') -or
            ($tDevFilter.rule -match 'trustType.*ServerAD')
        )
        if ($mp.deviceState) {
            if ($mp.deviceState.requireCompliant -eq $true) {
                $bDevStr = 'Compliant or Hybrid Azure AD joined devices'
                $tDevStr = if ($hasCompliantFilter) { $tDevFilter.rule } else { 'No device filter (targets all devices)' }
                $devMatch = $hasCompliantFilter
            } else {
                $bDevStr = 'All devices (no compliance filter)'
                $tDevStr = if ($hasCompliantFilter) { "Restricted: $($tDevFilter.rule)" } else { 'All devices' }
                $devMatch = -not $hasCompliantFilter
            }
            [void]$rowsHtml.Append((Format-DiffRow 'Device State' $bDevStr $tDevStr $devMatch))
        } elseif ($tDevFilter -and $tDevFilter.mode) {
            # No baseline expectation but tenant has a filter — show informationally
            $filterMode = if ($tDevFilter.mode -eq 'include') { 'Include matching' } else { 'Exclude matching' }
            $filterRule = if ($tDevFilter.rule) { $tDevFilter.rule } else { '(no rule)' }
            [void]$rowsHtml.Append((Format-DiffRow 'Device Filter (tenant)' 'Not specified in baseline' "$($filterMode): $($filterRule)" $false))
        }

        # Locations
        if ($mp.conditions.locations) {
            $locPat = $mp.conditions.locations; $bLoc = @(); $tLoc = @()
            if ($locPat.includeLocations -eq $true)       { $bLoc += 'Include: named locations' }
            elseif ($locPat.includeLocations -is [array])  { $bLoc += "Include: $($locPat.includeLocations -join ', ')" }
            if ($locPat.excludeLocations -eq $true)        { $bLoc += 'Exclude: any trusted location' }
            elseif ($locPat.excludeLocations -is [array])  { $bLoc += "Exclude: $($locPat.excludeLocations -join ', ')" }
            $tlocs = $p.conditions.locations
            if ($tlocs -and ($tlocs.includeLocations ?? @()).Count -gt 0) { $tLoc += "Include: $($tlocs.includeLocations -join ', ')" }
            if ($tlocs -and ($tlocs.excludeLocations ?? @()).Count -gt 0) { $tLoc += "Exclude: $($tlocs.excludeLocations -join ', ')" }
            $locBStr = if ($bLoc) { $bLoc -join '; ' } else { 'Any' }
            $locTStr = if ($tLoc) { $tLoc -join '; ' } else { 'No location condition' }
            $locMatch = -not ($r.Differences | Where-Object { $_ -match 'location' })
            [void]$rowsHtml.Append((Format-DiffRow 'Locations' $locBStr $locTStr $locMatch))
        }

        # Authentication Flows
        if ($mp.conditions.authenticationFlows) {
            $tFlows = (($p.conditions.authenticationFlows.transferMethods ?? @()) -join ', ')
            $flowBStr = $mp.conditions.authenticationFlows -join ', '
            $flowTStr = if ($tFlows) { $tFlows } else { 'No auth flow condition' }
            $flowMatch = -not ($r.Differences | Where-Object { $_ -match 'auth.?flow' })
            [void]$rowsHtml.Append((Format-DiffRow 'Auth Flows' $flowBStr $flowTStr $flowMatch))
        }

        # Risk Levels
        if ($mp.conditions.signInRiskLevels) {
            $tRisk = (($p.conditions.signInRiskLevels ?? @()) -join ', ')
            $rTStr = if ($tRisk) { $tRisk } else { 'Not configured' }
            $rMatch = -not ($r.Differences | Where-Object { $_ -match 'Sign-in risk levels differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'Sign-in Risk' ($mp.conditions.signInRiskLevels -join ', ') $rTStr $rMatch))
        }
        if ($mp.conditions.userRiskLevels) {
            $tRisk = (($p.conditions.userRiskLevels ?? @()) -join ', ')
            $rTStr = if ($tRisk) { $tRisk } else { 'Not configured' }
            $rMatch = -not ($r.Differences | Where-Object { $_ -match 'User risk levels differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'User Risk' ($mp.conditions.userRiskLevels -join ', ') $rTStr $rMatch))
        }
        if ($mp.conditions.insiderRiskLevels) {
            $tRisk = (($p.conditions.insiderRiskLevels ?? @()) -join ', ')
            $rTStr = if ($tRisk) { $tRisk } else { 'Not configured' }
            $rMatch = -not ($r.Differences | Where-Object { $_ -match 'Insider risk levels differ' })
            [void]$rowsHtml.Append((Format-DiffRow 'Insider Risk' ($mp.conditions.insiderRiskLevels -join ', ') $rTStr $rMatch))
        }

        $enc = [System.Web.HttpUtility]
        $bLabel = $enc::HtmlEncode($r.BaselineName)
        $pLabel = $enc::HtmlEncode($p.displayName)
        return @"
<div class="diff-panel-wrap">
  <div style="padding:8px 12px;font-size:0.75rem;color:var(--text-muted);border-bottom:1px solid var(--border)">
    <span style="color:var(--accent-cyan)">&#x1F4CB; Baseline:</span> $bLabel
    &ensp;&mdash;&ensp;
    <span style="color:var(--accent-purple)">&#x1F4DD; Tenant Policy:</span> $pLabel
  </div>
  <table class="diff-inner-table">
    <thead><tr>
      <th class="diff-dim">Property</th>
      <th style="color:var(--accent-cyan)">Baseline expects</th>
      <th style="color:var(--accent-purple)">Tenant policy has</th>
    </tr></thead>
    <tbody>$($rowsHtml.ToString())</tbody>
  </table>
</div>
"@
    }

    $gapRows = [System.Text.StringBuilder]::new()
    $categories = @('Prerequisite', 'User', 'Device', 'Location')
    foreach ($cat in $categories) {
        $catResults = @($comparison.BaselineResults | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }

        [void]$gapRows.Append("<tr class='cat-header'><td colspan='7' style='background:var(--bg-primary);padding:12px;font-weight:700;font-size:0.9rem;'>$cat Policies ($($catResults.Count))</td></tr>")

        foreach ($r in $catResults) {
            $statusBadge = switch ($r.Status) {
                'Matched'       { '<span class="badge badge-green">&#x2705; Matched</span>' }
                'Partial'       { '<span class="badge badge-yellow">&#x26A0;&#xFE0F; Partial</span>' }
                'Missing'       { '<span class="badge badge-red">&#x274C; Missing</span>' }
                'NotApplicable' { '<span class="badge badge-gray">&#x2298; N/A</span>' }
            }
            $priorityBadge = switch ($r.Priority) {
                'Must Have'   { '<span class="badge badge-red">Must Have</span>' }
                'Should Have' { '<span class="badge badge-orange">Should Have</span>' }
                'Could Have'  { '<span class="badge badge-blue">Could Have</span>' }
            }
            $diffHtml = ''
            if ($r.Differences -and $r.Differences.Count -gt 0) {
                $diffHtml = '<ul class="diff-list">' + (($r.Differences | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join '') + '</ul>'
            }
            $matchedName = if ($r.MatchedPolicy) { [System.Web.HttpUtility]::HtmlEncode($r.MatchedPolicy) } else { '—' }
            $recText = if ($r.Recommendation) { [System.Web.HttpUtility]::HtmlEncode($r.Recommendation) } else { '' }

            $compareBtn = ''
            $panelRow   = ''
            if ($r.Status -in 'Partial', 'Missing' -and $r.MatchedPolicyObject) {
                $bid = [System.Web.HttpUtility]::HtmlEncode($r.BaselineId)
                $compareBtn = " <button class='compare-btn' onclick='toggleDiff(`"$bid`")'>&harr; Diff</button>"
                $panelHtml  = Format-PolicyDiffPanel -r $r
                $panelRow   = "<tr class='diff-panel-row' id='diff-row-$bid' style='display:none'><td colspan='6' style='padding:0'>$panelHtml</td></tr>"
            }

            [void]$gapRows.Append("<tr data-status='$($r.Status)' data-priority='$($r.Priority)' data-category='$cat'><td><strong>$($r.BaselineId)</strong></td><td>$([System.Web.HttpUtility]::HtmlEncode($r.BaselineName))</td><td>$priorityBadge</td><td>$statusBadge</td><td>$matchedName$compareBtn$diffHtml</td><td>$recText</td></tr>")
            if ($panelRow) { [void]$gapRows.Append($panelRow) }
        }
    }

    $sec4 = @"
<section id="gap-analysis">
<h2>Baseline Gap Analysis</h2>
<div class="filter-bar">
<input type="text" id="gapFilter" placeholder="Search baseline..." onkeyup="filterTable('gapTable','gapFilter')">
<select onchange="filterGapTable('status',this.value)"><option value="">All Statuses</option><option value="Matched">Matched</option><option value="Partial">Partial</option><option value="Missing">Missing</option><option value="NotApplicable">N/A</option></select>
<select onchange="filterGapTable('priority',this.value)"><option value="">All Priorities</option><option value="Must Have">Must Have</option><option value="Should Have">Should Have</option><option value="Could Have">Could Have</option></select>
</div>
<div style="overflow-x:auto"><table id="gapTable"><thead><tr><th onclick="sortTable('gapTable',0)">ID</th><th onclick="sortTable('gapTable',1)">Baseline Policy</th><th onclick="sortTable('gapTable',2)">Priority</th><th onclick="sortTable('gapTable',3)">Status</th><th onclick="sortTable('gapTable',4)">Matched / Differences</th><th onclick="sortTable('gapTable',5)">Recommendation</th></tr></thead><tbody>
$($gapRows.ToString())
</tbody></table></div>
</section>
"@

    # ── Section 5: Device Platform Analysis ──
    $platformRows = ''
    if ($devices.PlatformCounts) {
        $pc  = $devices.PlatformCounts
        $iep = $devices.IntuneEnrolledPerPlatform   # Entra devices cross-referenced to Intune
        $showIntune = $devices.HasIntuneData -eq $true
        $platformRows = ($pc.PSObject.Properties | ForEach-Object {
            $platform      = $_.Name
            $entraCount    = $_.Value
            $intuneCount   = if ($showIntune -and $iep -and $null -ne $iep.$platform) { $iep.$platform } else { $null }
            $pct           = if ($devices.EntraDeviceCount -gt 0) { [math]::Round(($entraCount / $devices.EntraDeviceCount) * 100, 1) } else { 0 }

            $intuneCell = if ($showIntune) {
                if ($null -ne $intuneCount -and $intuneCount -eq $entraCount) {
                    "<td style='color:var(--accent-green)'>$intuneCount / $entraCount</td>"
                } elseif ($null -ne $intuneCount -and $intuneCount -gt 0) {
                    "<td style='color:var(--accent-orange)'>$intuneCount / $entraCount</td>"
                } else {
                    "<td style='color:var(--accent-red)'>0 / $entraCount</td>"
                }
            } else {
                "<td style='color:var(--text-muted)'>—</td>"
            }

            "<tr><td><strong>$platform</strong></td><td>$entraCount</td>$intuneCell<td><div class='progress-bar'><div class='progress-fill' style='width:${pct}%;background:var(--accent-blue)'></div></div> $pct%</td></tr>"
        }) -join "`n"
    }

    $platformTableHeader = if ($devices.HasIntuneData) {
        "<thead><tr><th>Platform</th><th>Entra</th><th>Intune Enrolled</th><th>Distribution</th></tr></thead>"
    } else {
        "<thead><tr><th>Platform</th><th>Entra</th><th>Intune Enrolled</th><th>Distribution</th></tr></thead>"
    }

    $sec5 = @"
<section id="devices">
<h2>Device Platform Analysis</h2>
<div class="card-grid">
    <div class="card"><div class="value" style="color:var(--accent-blue)">$($devices.EntraDeviceCount)</div><div class="label">Entra Devices</div></div>
    <div class="card"><div class="value" style="color:var(--accent-cyan)">$($devices.IntuneDeviceCount)</div><div class="label">$(if ($licensing.HasIntune) { 'Intune Managed' } else { 'MDM Managed (Entra)' })</div></div>
    <div class="card"><div class="value" style="color:var(--accent-green)">$($devices.CompliantCount)</div><div class="label">Compliant</div></div>
    <div class="card"><div class="value" style="color:var(--accent-red)">$($devices.NonCompliantCount)</div><div class="label">Non-Compliant</div></div>
    <div class="card"><div class="value" style="color:var(--accent-purple)">$($devices.CorporateOwned)</div><div class="label">Corporate-Owned</div></div>
    <div class="card"><div class="value" style="color:var(--accent-orange)">$($devices.PersonalBYOD)</div><div class="label">BYOD</div></div>
</div>
<h3>Platform Breakdown</h3>
<table>$platformTableHeader<tbody>
$platformRows
</tbody></table>
</section>
"@

    # ── Section 6: Security Posture ──
    $postureRows = [System.Text.StringBuilder]::new()
    $checkOrder = @('SecurityDefaults', 'BreakGlass', 'AdminCoverage', 'GuestPolicies', 'NamedLocations', 'AuthMethodReadiness', 'PolicyExclusions', 'ReportOnlyAge', 'PolicyConflicts')
    $checkLabels = @{
        SecurityDefaults    = 'Security Defaults'
        BreakGlass          = 'Break-Glass Accounts'
        AdminCoverage       = 'Admin Role Coverage'
        GuestPolicies       = 'Guest Policy Coverage'
        NamedLocations      = 'Named Locations'
        AuthMethodReadiness = 'Auth Method Readiness'
        PolicyExclusions    = 'Policy Exclusions'
        ReportOnlyAge       = 'Report-Only Policy Age'
        PolicyConflicts     = 'Policy Conflicts'
    }

    foreach ($key in $checkOrder) {
        if (-not $postureChecks.Contains($key)) { continue }
        $check = $postureChecks[$key]
        $statusIcon = switch ($check.Status) {
            'Pass'    { '<span class="posture-pass">&#x2705;</span>' }
            'Warning' { '<span class="posture-warning">&#x26A0;&#xFE0F;</span>' }
            'Fail'    { '<span class="posture-fail">&#x274C;</span>' }
        }
        $sevBadge = switch ($check.Severity) {
            'Critical' { '<span class="badge badge-red">Critical</span>' }
            'High'     { '<span class="badge badge-orange">High</span>' }
            'Medium'   { '<span class="badge badge-yellow">Medium</span>' }
            'Low'      { '<span class="badge badge-blue">Low</span>' }
            'Info'     { '<span class="badge badge-gray">Info</span>' }
        }
        [void]$postureRows.Append("<tr><td>$statusIcon</td><td><strong>$($checkLabels[$key])</strong></td><td>$sevBadge</td><td>$([System.Web.HttpUtility]::HtmlEncode($check.Finding))</td></tr>")
    }

    $sec6 = @"
<section id="posture">
<h2>Security Posture Findings</h2>
<table><thead><tr><th style="width:40px"></th><th>Check</th><th>Severity</th><th>Finding</th></tr></thead><tbody>
$($postureRows.ToString())
</tbody></table>
</section>
"@

    # ── Section 7: Recommendations ──
    $recRows = [System.Text.StringBuilder]::new()
    if ($recommendations.Recommendations.Count -gt 0) {
        foreach ($rec in $recommendations.Recommendations) {
            if ($rec.Status -eq 'NotApplicable') { continue }
            $sevBadge = switch ($rec.Severity) {
                'Critical' { '<span class="badge badge-red">Critical</span>' }
                'High'     { '<span class="badge badge-orange">High</span>' }
                'Medium'   { '<span class="badge badge-yellow">Medium</span>' }
                'Low'      { '<span class="badge badge-blue">Low</span>' }
            }
            $effortBadge = switch ($rec.Effort) {
                'Quick Win' { '<span class="badge badge-green">Quick Win</span>' }
                'Moderate'  { '<span class="badge badge-yellow">Moderate</span>' }
                'Complex'   { '<span class="badge badge-purple">Complex</span>' }
                default     { '<span class="badge badge-gray">N/A</span>' }
            }
            [void]$recRows.Append("<tr><td><strong>$($rec.BaselineId)</strong></td><td>$([System.Web.HttpUtility]::HtmlEncode($rec.BaselineName))</td><td>$sevBadge</td><td>$effortBadge</td><td>$([System.Web.HttpUtility]::HtmlEncode($rec.Recommendation))</td></tr>")
        }
    }

    $recTableHeader = '<thead><tr>' +
        '<th onclick="sortTable(''recTable'',0)">ID</th>' +
        '<th onclick="sortTable(''recTable'',1)">Policy</th>' +
        '<th onclick="sortTable(''recTable'',2)">Severity</th>' +
        '<th onclick="sortTable(''recTable'',3)">Effort</th>' +
        '<th onclick="sortTable(''recTable'',4)">Recommendation</th>' +
        '</tr></thead>'

    $sec7 = @"
<section id="recommendations">
<h2>Recommendations ($($recommendations.TotalCount))</h2>
$(if ($recommendations.TotalCount -eq 0) { '<p style="color:var(--accent-green);font-weight:600;">No recommendations — all applicable baseline policies are matched!</p>' }
  else { "<div style='overflow-x:auto'><table id='recTable'>$recTableHeader<tbody>$($recRows.ToString())</tbody></table></div>" })
</section>
"@

    # ═══════════════════════════════════════════════════════════════════
    # JavaScript
    # ═══════════════════════════════════════════════════════════════════
    $js = @'
function filterTable(tableId, inputId) {
    var filter = document.getElementById(inputId).value.toLowerCase();
    var sorted = document.getElementById(tableId).dataset.sorted === '1';
    var rows = document.getElementById(tableId).querySelectorAll('tbody tr');
    rows.forEach(function(r) {
        if (r.classList.contains('cat-header')) { r.style.display = sorted ? 'none' : ''; return; }
        if (r.classList.contains('diff-panel-row')) { r.style.display = 'none'; return; }
        r.style.display = r.textContent.toLowerCase().includes(filter) ? '' : 'none';
    });
}
function filterTableByCol(tableId, colIdx, value) {
    var sorted = document.getElementById(tableId).dataset.sorted === '1';
    var rows = document.getElementById(tableId).querySelectorAll('tbody tr');
    rows.forEach(function(r) {
        if (r.classList.contains('cat-header')) { r.style.display = sorted ? 'none' : ''; return; }
        if (!value) { r.style.display = ''; return; }
        var cell = r.cells[colIdx];
        r.style.display = cell && cell.textContent.includes(value) ? '' : 'none';
    });
}
function filterGapTable(attr, value) {
    var sorted = document.getElementById('gapTable').dataset.sorted === '1';
    var rows = document.getElementById('gapTable').querySelectorAll('tbody tr');
    rows.forEach(function(r) {
        if (r.classList.contains('cat-header')) { r.style.display = sorted ? 'none' : ''; return; }
        if (r.classList.contains('diff-panel-row')) { r.style.display = 'none'; return; }
        if (!value) { r.style.display = ''; return; }
        r.style.display = r.dataset[attr] === value ? '' : 'none';
    });
}
function toggleDiff(baselineId) {
    var panelRow = document.getElementById('diff-row-' + baselineId);
    if (!panelRow) return;
    panelRow.style.display = panelRow.style.display === 'none' ? '' : 'none';
}

// Column sort
var _sortState = {};
function sortTable(tableId, colIdx) {
    var table = document.getElementById(tableId);
    if (!table) return;
    var key = tableId + ':' + colIdx;
    var asc = _sortState[key] !== true;
    _sortState[key] = asc;
    table.dataset.sorted = '1';
    // Update header indicators
    table.querySelectorAll('thead th').forEach(function(th, i) {
        th.classList.remove('sort-asc', 'sort-desc');
        if (i === colIdx) th.classList.add(asc ? 'sort-asc' : 'sort-desc');
    });
    var tbody = table.querySelector('tbody');
    // Build units: each data row paired with any immediately-following diff-panel-row
    // Use tbody.children (direct children only) — querySelectorAll('tr') would also match
    // nested <tr> elements inside the diff-panel inner tables.
    var units = [];
    var allRows = Array.from(tbody.children);
    for (var i = 0; i < allRows.length; i++) {
        var r = allRows[i];
        if (r.classList.contains('cat-header') || r.classList.contains('diff-panel-row')) continue;
        var unit = { row: r, panel: null };
        var next = allRows[i + 1];
        if (next && next.classList.contains('diff-panel-row')) {
            unit.panel = next;
        }
        units.push(unit);
    }
    var severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4 };
    var statusOrder   = { 'missing': 0, 'partial': 1, 'matched': 2, 'notapplicable': 3 };
    var priorityOrder = { 'must have': 0, 'should have': 1, 'could have': 2 };
    units.sort(function(a, b) {
        var av = (a.row.cells[colIdx] ? a.row.cells[colIdx].textContent.trim().toLowerCase() : '');
        var bv = (b.row.cells[colIdx] ? b.row.cells[colIdx].textContent.trim().toLowerCase() : '');
        var ai, bi;
        if (severityOrder[av] !== undefined || severityOrder[bv] !== undefined) {
            ai = severityOrder[av] !== undefined ? severityOrder[av] : 99;
            bi = severityOrder[bv] !== undefined ? severityOrder[bv] : 99;
            return asc ? ai - bi : bi - ai;
        }
        if (statusOrder[av] !== undefined || statusOrder[bv] !== undefined) {
            ai = statusOrder[av] !== undefined ? statusOrder[av] : 99;
            bi = statusOrder[bv] !== undefined ? statusOrder[bv] : 99;
            return asc ? ai - bi : bi - ai;
        }
        if (priorityOrder[av] !== undefined || priorityOrder[bv] !== undefined) {
            ai = priorityOrder[av] !== undefined ? priorityOrder[av] : 99;
            bi = priorityOrder[bv] !== undefined ? priorityOrder[bv] : 99;
            return asc ? ai - bi : bi - ai;
        }
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    // Hide cat-header rows when sorted (they're meaningless across a sorted view)
    Array.from(tbody.children).forEach(function(h) {
        if (h.classList.contains('cat-header')) h.style.display = 'none';
    });
    units.forEach(function(u) {
        tbody.appendChild(u.row);
        if (u.panel) { tbody.appendChild(u.panel); }
    });
}

document.querySelectorAll('nav a').forEach(function(link) {
    link.addEventListener('click', function() {
        document.querySelectorAll('nav a').forEach(function(a) { a.classList.remove('active'); });
        this.classList.add('active');
    });
});
// Apply scroll offset from actual nav height
(function() {
    var nav = document.querySelector('nav');
    if (!nav) return;
    function applyNavHeight() {
        var h = Math.ceil(nav.getBoundingClientRect().height);
        document.querySelectorAll('section').forEach(function(s) { s.style.scrollMarginTop = (h + 4) + 'px'; });
        document.documentElement.style.scrollPaddingTop = (h + 4) + 'px';
    }
    applyNavHeight();
    window.addEventListener('resize', applyNavHeight);
})();
'@

    # ═══════════════════════════════════════════════════════════════════
    # Assemble final HTML
    # ═══════════════════════════════════════════════════════════════════
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CA Baseline Audit — $([System.Web.HttpUtility]::HtmlEncode($tenantName))</title>
<style>$css</style>
</head>
<body>
<div class="header">
    <h1>&#x1F6E1;&#xFE0F; Conditional Access Baseline Audit</h1>
    <div class="meta">$([System.Web.HttpUtility]::HtmlEncode($tenantName)) ($($tenantCtx.TenantDomain)) &mdash; Generated $reportDate</div>
</div>
<nav>
    <a href="#summary" class="active">Summary</a>
    <a href="#posture">Security Posture</a>
    <a href="#licensing">Licensing</a>
    <a href="#inventory">Policy Inventory</a>
    <a href="#gap-analysis">Gap Analysis</a>
    <a href="#recommendations">Recommendations</a>
</nav>
<div class="container">
$sec1
$sec6
$sec2
$sec3
$sec4
$sec7
</div>
<div class="footer">
    CA-BaselineAuditor v1.0.0 &mdash; Baseline: Kenneth van Surksum October 2025 &mdash; Generated with PowerShell $($PSVersionTable.PSVersion)
</div>
<script>$js</script>
</body>
</html>
"@

    # ── Write output ──
    $outputDir = Split-Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Host "[CA-BaselineAuditor] Report saved to: $OutputPath" -ForegroundColor Green

    if ($OpenReport) {
        Start-Process $OutputPath
    }

    $OutputPath
}
