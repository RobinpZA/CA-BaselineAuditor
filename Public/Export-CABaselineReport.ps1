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
    $activeBaseline = $AuditData.ActiveBaseline ?? 'VanSurksum'

    # ── Collect distinct baseline sources for filter options ──
    $baselineSources = @($comparison.BaselineResults | Select-Object -ExpandProperty BaselineSource -Unique | Where-Object { $_ })
    $multiBaseline   = $baselineSources.Count -gt 1

    # ── Compute compliance score ──
    $applicableMusts = @($comparison.BaselineResults | Where-Object { $_.Priority -eq 'Must Have' -and $_.Status -ne 'NotApplicable' })
    $matchedMusts    = @($applicableMusts | Where-Object { $_.Status -eq 'Matched' })
    $complianceScore = if ($applicableMusts.Count -gt 0) { [math]::Round(($matchedMusts.Count / $applicableMusts.Count) * 100) } else { 0 }

    # ── Per-baseline scores (used when multiple baselines are active) ──
    $perBaselineScores = [System.Collections.Generic.List[object]]::new()
    foreach ($src in $baselineSources) {
        $srcMusts   = @($comparison.BaselineResults | Where-Object { $_.BaselineSource -eq $src -and $_.Priority -eq 'Must Have' -and $_.Status -ne 'NotApplicable' })
        $srcMatched = @($srcMusts | Where-Object { $_.Status -eq 'Matched' })
        $srcPartial = @($comparison.BaselineResults | Where-Object { $_.BaselineSource -eq $src -and $_.Status -eq 'Partial' }).Count
        $srcMissing = @($comparison.BaselineResults | Where-Object { $_.BaselineSource -eq $src -and $_.Status -eq 'Missing' }).Count
        $srcScore   = if ($srcMusts.Count -gt 0) { [math]::Round(($srcMatched.Count / $srcMusts.Count) * 100) } else { 0 }
        $perBaselineScores.Add([PSCustomObject]@{
            Source  = $src
            Score   = $srcScore
            Matched = $srcMatched.Count
            Partial = $srcPartial
            Missing = $srcMissing
            Total   = $srcMusts.Count
        })
    }

    # ── Severity counts for posture ──
    $postureFindings = @($postureChecks.Values | Where-Object { $_.Status -ne 'Pass' })
    $criticalFindings = @($postureFindings | Where-Object { $_.Severity -eq 'Critical' }).Count

    # ═══════════════════════════════════════════════════════════════════
    # CSS
    # ═══════════════════════════════════════════════════════════════════
    $css = @'
:root {
    --bg-primary: #0a0c0f;
    --bg-secondary: #0f1219;
    --bg-card: #141820;
    --bg-hover: #1a1f2e;
    --text-primary: #e8edf5;
    --text-secondary: #8896b0;
    --text-muted: #4d5d78;
    --border: #1e2638;
    --border-subtle: #141c2a;
    --accent-blue: #3b82f6;
    --accent-green: #10b981;
    --accent-yellow: #f59e0b;
    --accent-red: #ef4444;
    --accent-orange: #f97316;
    --accent-purple: #a855f7;
    --accent-cyan: #06b6d4;
    --font-display: 'Poppins', system-ui, sans-serif;
    --font-body: 'Poppins', system-ui, sans-serif;
    --font-mono: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    --shadow-card: 0 4px 20px rgba(0,0,0,0.5), 0 1px 3px rgba(0,0,0,0.3);
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: var(--font-body); background: var(--bg-primary); color: var(--text-primary); line-height: 1.6; padding: 0; }
.container { max-width: 1400px; margin: 0 auto; padding: 20px 24px; }
.header { background: linear-gradient(135deg, #0b2045 0%, #06101f 55%, #040a14 100%); padding: 40px 24px 36px; border-bottom: 1px solid rgba(59,130,246,0.22); margin-bottom: 24px; position: relative; overflow: hidden; }
.header::before { content: ''; position: absolute; inset: 0; background-image: linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px); background-size: 44px 44px; pointer-events: none; }
.header::after { content: ''; position: absolute; bottom: -1px; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent 0%, rgba(59,130,246,0.7) 35%, rgba(6,182,212,0.5) 65%, transparent 100%); }
.header h1 { font-family: var(--font-display); font-size: 1.7rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; position: relative; }
.header .meta { color: var(--text-secondary); font-size: 0.78rem; margin-top: 8px; font-family: var(--font-mono); position: relative; letter-spacing: 0.015em; }
nav { background: var(--bg-secondary); padding: 0 24px; border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 100; display: flex; flex-wrap: wrap; gap: 0; }
nav a { color: var(--text-secondary); text-decoration: none; padding: 11px 16px; font-size: 0.79rem; font-weight: 500; white-space: nowrap; transition: color 0.2s, border-color 0.2s, background 0.2s; border-bottom: 2px solid transparent; margin-bottom: -1px; }
nav a:hover { color: var(--text-primary); background: rgba(255,255,255,0.03); }
nav a.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); background: none; }
section { margin-bottom: 32px; scroll-margin-top: 56px; }
h2 { font-family: var(--font-display); font-size: 1.1rem; font-weight: 700; margin-bottom: 20px; padding: 10px 0 10px 16px; border-left: 3px solid var(--accent-blue); letter-spacing: -0.01em; }
h3 { font-size: 1rem; font-weight: 600; margin: 16px 0 10px; }
.card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }
.card { background: linear-gradient(160deg, var(--bg-card) 0%, rgba(7,14,27,0.8) 100%); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; box-shadow: var(--shadow-card); transition: transform 0.2s ease, box-shadow 0.2s ease, border-color 0.2s ease; animation: fadeSlideUp 0.5s ease both; }
.card:hover { transform: translateY(-2px); box-shadow: 0 10px 36px rgba(0,0,0,0.6); border-color: rgba(59,130,246,0.28); }
.card .value { font-size: 2.2rem; font-weight: 700; line-height: 1.2; font-family: var(--font-display); }
.card .label { font-size: 0.7rem; color: var(--text-secondary); margin-top: 6px; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 500; }
.score-ring { width: 120px; height: 120px; margin: 0 auto 12px; position: relative; }
.score-ring svg { transform: rotate(-90deg); filter: drop-shadow(0 0 10px rgba(59,130,246,0.2)); }
.score-ring .score-text { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.6rem; font-weight: 700; font-family: var(--font-display); }
table { width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-bottom: 16px; }
thead th { background: rgba(27,45,68,0.7); color: var(--text-secondary); padding: 10px 12px; text-align: left; font-weight: 600; cursor: pointer; white-space: nowrap; user-select: none; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.07em; border-bottom: 1px solid rgba(59,130,246,0.15); }
thead th.sort-asc::after  { content: ' \25B2'; font-size: 0.65rem; color: var(--accent-cyan); }
thead th.sort-desc::after { content: ' \25BC'; font-size: 0.65rem; color: var(--accent-cyan); }
tbody td { padding: 9px 12px; border-bottom: 1px solid var(--border-subtle); vertical-align: top; }
tbody tr:hover { background: rgba(59,130,246,0.05); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.72rem; font-weight: 600; }
.badge-green { background: rgba(34,197,94,0.15); color: var(--accent-green); }
.badge-yellow { background: rgba(234,179,8,0.15); color: var(--accent-yellow); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--accent-red); }
.badge-blue { background: rgba(59,130,246,0.15); color: var(--accent-blue); }
.badge-purple { background: rgba(168,85,247,0.15); color: var(--accent-purple); }
.badge-gray { background: rgba(100,116,139,0.15); color: var(--text-muted); }
.badge-orange { background: rgba(249,115,22,0.15); color: var(--accent-orange); }
.badge-cyan { background: rgba(6,182,212,0.15); color: var(--accent-cyan); }
.badge-baseline-vansurksum { background: rgba(99,102,241,0.15); color: #818cf8; }
.badge-baseline-cisa { background: rgba(239,68,68,0.15); color: #f87171; }
.badge-baseline-maester { background: rgba(34,197,94,0.15); color: var(--accent-green); }
.badge-baseline-cis { background: rgba(249,115,22,0.15); color: var(--accent-orange); }
.badge-baseline-custom { background: rgba(168,85,247,0.15); color: var(--accent-purple); }
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
.filter-bar input, .filter-bar select { background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 7px 14px; border-radius: 8px; font-size: 0.81rem; font-family: var(--font-body); transition: border-color 0.2s, box-shadow 0.2s; }
.filter-bar input:focus, .filter-bar select:focus { outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(59,130,246,0.12); }
.filter-bar input { min-width: 200px; }
.progress-bar { height: 8px; background: var(--bg-hover); border-radius: 4px; overflow: hidden; margin: 4px 0; }
.progress-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }
.lic-table td:first-child { font-weight: 600; width: 250px; }
.lic-icon { font-size: 1.1rem; }
.footer { text-align: center; padding: 28px; color: var(--text-muted); font-size: 0.69rem; border-top: 1px solid var(--border); margin-top: 40px; font-family: var(--font-mono); letter-spacing: 0.05em; }
@keyframes fadeSlideUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: translateY(0); } }
.card-grid .card:nth-child(1) { animation-delay: 0.04s; }
.card-grid .card:nth-child(2) { animation-delay: 0.09s; }
.card-grid .card:nth-child(3) { animation-delay: 0.14s; }
.card-grid .card:nth-child(4) { animation-delay: 0.19s; }
.card-grid .card:nth-child(5) { animation-delay: 0.24s; }
.card-grid .card:nth-child(6) { animation-delay: 0.29s; }
.card-grid .card:nth-child(7) { animation-delay: 0.34s; }
@media print { body { background: #fff; color: #000; } .card { border: 1px solid #ccc; animation: none; } nav { display: none; } thead th { background: #eee; } }
@media (max-width: 768px) { .card-grid { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); } }
/* ── Policy Flow Visualizer ── */
.viz-grid { display: flex; flex-direction: column; gap: 12px; }
.viz-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; transition: border-color 0.2s, box-shadow 0.2s; box-shadow: var(--shadow-card); }
.viz-card:hover { border-color: rgba(59,130,246,0.4); box-shadow: 0 6px 28px rgba(0,0,0,0.55); }
.viz-state-disabled { opacity: 0.65; }
.viz-header { display: flex; align-items: center; gap: 12px; padding: 10px 16px; border-bottom: 1px solid var(--border); background: var(--bg-secondary); }
.viz-name { font-weight: 600; font-size: 0.88rem; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.viz-flow { display: flex; align-items: stretch; flex-wrap: nowrap; }
.viz-node { flex: 1; padding: 10px 14px; border-right: 1px solid var(--border); min-width: 0; }
.viz-node:last-child { border-right: none; }
.viz-node-label { font-size: 0.62rem; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.06em; margin-bottom: 6px; }
.viz-node-body { font-size: 0.78rem; }
.viz-item { padding: 1px 0; color: var(--text-secondary); word-break: break-word; }
.viz-excl { color: var(--text-muted); font-style: italic; font-size: 0.73rem; }
.viz-session { color: var(--accent-cyan); font-size: 0.73rem; margin-top: 3px; }
.viz-arrow { display: flex; align-items: center; justify-content: center; padding: 0 4px; color: var(--text-muted); font-size: 1.1rem; flex-shrink: 0; }
.viz-node-allow .viz-node-label { color: var(--accent-green); }
.viz-node-allow .viz-item:first-child { color: var(--accent-green); font-weight: 600; }
.viz-node-block { background: rgba(239,68,68,0.05); }
.viz-node-block .viz-node-label { color: var(--accent-red); }
.viz-node-block .viz-item { color: var(--accent-red); font-weight: 600; }
.viz-node-session .viz-node-label { color: var(--accent-cyan); }
@media (max-width: 900px) { .viz-flow { flex-direction: column; } .viz-node { border-right: none; border-bottom: 1px solid var(--border); } .viz-arrow { display: none; } }
/* ── Policy Flow Modal ── */
.flow-modal { position: fixed; inset: 0; z-index: 2000; display: none; align-items: center; justify-content: center; }
.flow-modal.open { display: flex; }
.flow-backdrop { position: absolute; inset: 0; background: rgba(0,0,0,0.82); backdrop-filter: blur(3px); }
.flow-box { position: relative; background: var(--bg-secondary); border: 1px solid rgba(99,102,241,0.3); border-radius: 16px; width: min(96vw, 880px); max-height: 90vh; display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 40px 100px rgba(0,0,0,0.9), 0 0 40px rgba(99,102,241,0.1); z-index: 1; }
.flow-titlebar { display: flex; align-items: center; padding: 14px 20px; border-bottom: 1px solid var(--border); background: var(--bg-primary); gap: 12px; flex-shrink: 0; }
.flow-titlebar h3 { flex: 1; font-size: 0.92rem; font-weight: 600; margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.flow-close-btn { background: none; border: 1px solid var(--border); color: var(--text-secondary); font-size: 0.82rem; cursor: pointer; padding: 5px 12px; border-radius: 6px; transition: all 0.15s; flex-shrink: 0; }
.flow-close-btn:hover { background: var(--bg-hover); color: var(--text-primary); }
.flow-scroll { overflow-y: auto; overflow-x: auto; padding: 32px 24px; display: flex; justify-content: center; }
/* ── Flow diagram SVG ── */
.flow-svg-wrap { display: flex; justify-content: center; overflow-x: auto; padding: 8px 0; }
/* View flow button on viz-cards */
.viz-flow-btn { background: rgba(99,102,241,0.1); border: 1px solid rgba(99,102,241,0.3); color: #a5b4fc; padding: 3px 10px; border-radius: 6px; font-size: 0.71rem; cursor: pointer; transition: all 0.15s; white-space: nowrap; flex-shrink: 0; margin-left: auto; }
.viz-flow-btn:hover { background: rgba(99,102,241,0.22); border-color: #818cf8; color: #e0e7ff; }
'@

    # ═══════════════════════════════════════════════════════════════════
    # HTML SECTIONS
    # ═══════════════════════════════════════════════════════════════════

    # ── Score colour ──
    $scoreColour = if ($complianceScore -ge 80) { 'var(--accent-green)' }
                   elseif ($complianceScore -ge 50) { 'var(--accent-yellow)' }
                   else { 'var(--accent-red)' }
    $dashArray   = [math]::Round(($complianceScore / 100) * 314, 1)

    # ── Per-baseline score cards (shown when All baselines selected) ──
    $perBaselineCardsHtml = ''
    if ($multiBaseline) {
        $bCards = foreach ($b in $perBaselineScores) {
            $bColour  = if ($b.Score -ge 80) { 'var(--accent-green)' } elseif ($b.Score -ge 50) { 'var(--accent-yellow)' } else { 'var(--accent-red)' }
            $bDash    = [math]::Round(($b.Score / 100) * 188, 1)
            $bClass   = 'badge-baseline-' + $b.Source.ToLower()
            @"
    <div class="card">
        <div style="width:80px;height:80px;margin:0 auto 8px;position:relative">
            <svg viewBox="0 0 80 80" width="80" height="80" style="transform:rotate(-90deg)">
                <circle cx="40" cy="40" r="30" fill="none" stroke="var(--bg-hover)" stroke-width="7"/>
                <circle cx="40" cy="40" r="30" fill="none" stroke="$bColour" stroke-width="7" stroke-dasharray="$bDash 188" stroke-linecap="round"/>
            </svg>
            <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.1rem;font-weight:700;color:$bColour">$($b.Score)%</div>
        </div>
        <div style="margin-bottom:4px"><span class="badge $bClass">$($b.Source)</span></div>
        <div style="font-size:0.72rem;color:var(--text-secondary)"><span style="color:var(--accent-green)">$($b.Matched) matched</span> &bull; <span style="color:var(--accent-yellow)">$($b.Partial) partial</span> &bull; <span style="color:var(--accent-red)">$($b.Missing) missing</span></div>
        <div class="label" style="margin-top:4px">Must Have ($($b.Total) checks)</div>
    </div>
"@
        }
        $perBaselineCardsHtml = @"
<div style="margin-top:24px">
<h3>Compliance Score by Baseline</h3>
<div class="card-grid">
$($bCards -join '')
</div>
</div>
"@
    }

    # ── Section 1: Executive Summary ──
    $scoreLabel = if ($multiBaseline) { 'Overall Must Have Compliance' } else { "Must Have Compliance ($activeBaseline)" }
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
        <div class="label">$scoreLabel</div>
    </div>
    <div class="card"><div class="value status-matched">$($summary.Matched)</div><div class="label">Matched</div></div>
    <div class="card"><div class="value status-partial">$($summary.Partial)</div><div class="label">Partial</div></div>
    <div class="card"><div class="value status-missing">$($summary.Missing)</div><div class="label">Missing</div></div>
    <div class="card"><div class="value status-na">$($summary.NotApplicable)</div><div class="label">Not Applicable</div></div>
    <div class="card"><div class="value" style="color:var(--accent-cyan)">$($summary.TotalTenant)</div><div class="label">Tenant Policies</div></div>
    <div class="card"><div class="value" style="color:var(--accent-purple)">$($summary.Custom)</div><div class="label">Custom Policies</div></div>
    $(if ($criticalFindings -gt 0) { "<div class='card'><div class='value' style='color:var(--accent-red)'>$criticalFindings</div><div class='label'>Critical Findings</div></div>" })
</div>
$perBaselineCardsHtml
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
                $panelRow   = "<tr class='diff-panel-row' id='diff-row-$bid' style='display:none'><td colspan='7' style='padding:0'>$panelHtml</td></tr>"
            }

            $bSource      = $r.BaselineSource ?? 'VanSurksum'
            $bSourceClass = 'badge-baseline-' + $bSource.ToLower()
            $bSourceBadge = "<span class='badge $bSourceClass'>$([System.Web.HttpUtility]::HtmlEncode($bSource))</span>"
            $refLinkHtml  = if ($r.ReferenceUrl) { " <a href='$([System.Web.HttpUtility]::HtmlEncode($r.ReferenceUrl))' target='_blank' title='Reference' style='font-size:0.75em;opacity:0.7'>&#x2197;</a>" } else { '' }

            [void]$gapRows.Append("<tr data-status='$($r.Status)' data-priority='$($r.Priority)' data-category='$cat' data-baseline='$bSource'><td><strong>$($r.BaselineId)</strong>$refLinkHtml</td><td>$bSourceBadge</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.BaselineName))</td><td>$priorityBadge</td><td>$statusBadge</td><td>$matchedName$compareBtn$diffHtml</td><td>$recText</td></tr>")
            if ($panelRow) { [void]$gapRows.Append($panelRow) }
        }
    }

    $baselineFilterOptions = '<option value="">All Baselines</option>'
    foreach ($src in $baselineSources) {
        $baselineFilterOptions += "<option value='$([System.Web.HttpUtility]::HtmlEncode($src))'>$([System.Web.HttpUtility]::HtmlEncode($src))</option>"
    }

    $sec4 = @"
<section id="gap-analysis">
<h2>Baseline Gap Analysis</h2>
<div class="filter-bar">
<input type="text" id="gapFilter" placeholder="Search baseline..." onkeyup="filterTable('gapTable','gapFilter')">
<select onchange="filterGapTable('status',this.value)"><option value="">All Statuses</option><option value="Matched">Matched</option><option value="Partial">Partial</option><option value="Missing">Missing</option><option value="NotApplicable">N/A</option></select>
<select onchange="filterGapTable('priority',this.value)"><option value="">All Priorities</option><option value="Must Have">Must Have</option><option value="Should Have">Should Have</option><option value="Could Have">Could Have</option></select>
<select onchange="filterGapTable('baseline',this.value)">$baselineFilterOptions</select>
</div>
<div style="overflow-x:auto"><table id="gapTable"><thead><tr><th onclick="sortTable('gapTable',0)">ID</th><th onclick="sortTable('gapTable',1)">Baseline</th><th onclick="sortTable('gapTable',2)">Baseline Policy</th><th onclick="sortTable('gapTable',3)">Priority</th><th onclick="sortTable('gapTable',4)">Status</th><th onclick="sortTable('gapTable',5)">Matched / Differences</th><th onclick="sortTable('gapTable',6)">Recommendation</th></tr></thead><tbody>
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

    # ── Section 8: Policy Flow Visualizer ──
    function Format-PolicyVizCard {
        param([object]$Policy, [hashtable]$IdentityLookup = @{})

        $enc        = [System.Web.HttpUtility]
        $stateLabel = $Policy.StateLabel ?? $Policy.state
        $stateCls   = switch ($Policy.state) {
            'enabled'                          { 'badge-green'  }
            'enabledForReportingButNotEnforced' { 'badge-yellow' }
            'disabled'                         { 'badge-gray'   }
            default                            { 'badge-gray'   }
        }
        $disabledCls = if ($Policy.state -eq 'disabled') { ' viz-state-disabled' } else { '' }
        $pName       = $enc::HtmlEncode($Policy.displayName)
        $stateBadge  = "<span class='badge $stateCls'>$($enc::HtmlEncode($stateLabel))</span>"

        # ── Users node ──
        $usrs      = $Policy.conditions.users
        $userLines = [System.Collections.Generic.List[string]]::new()
        if (($usrs.includeUsers ?? @()) -contains 'All') {
            $exCount = ($usrs.excludeUsers ?? @()).Count + ($usrs.excludeGroups ?? @()).Count
            $userLines.Add("All Users$(if ($exCount -gt 0) { " (-$exCount excl.)" })")
        } elseif ($usrs.includeGuestsOrExternalUsers -or (($usrs.includeUsers ?? @()) -contains 'GuestsOrExternalUsers')) {
            $userLines.Add('Guests / External Users')
        } else {
            $MAX_NAMES = 5
            $incGroups = @($usrs.includeGroups ?? @())
            $incRoles  = @($usrs.includeRoles  ?? @())
            $incUsers  = @(($usrs.includeUsers ?? @()) | Where-Object { $_ -notin @('All','None','GuestsOrExternalUsers') })
            foreach ($gid in ($incGroups | Select-Object -First $MAX_NAMES)) {
                $userLines.Add($(if ($IdentityLookup.ContainsKey($gid)) { $IdentityLookup[$gid] } else { $gid }))
            }
            if ($incGroups.Count -gt $MAX_NAMES) { $userLines.Add("+ $($incGroups.Count - $MAX_NAMES) more group(s)") }
            foreach ($rid in ($incRoles | Select-Object -First $MAX_NAMES)) {
                $rName = if ($IdentityLookup.ContainsKey($rid)) { $IdentityLookup[$rid] } else { $rid }
                $userLines.Add("Role: $rName")
            }
            if ($incRoles.Count -gt $MAX_NAMES) { $userLines.Add("+ $($incRoles.Count - $MAX_NAMES) more role(s)") }
            foreach ($uid in ($incUsers | Select-Object -First 3)) {
                $userLines.Add($(if ($IdentityLookup.ContainsKey($uid)) { $IdentityLookup[$uid] } else { $uid }))
            }
            if ($incUsers.Count -gt 3) { $userLines.Add("+ $($incUsers.Count - 3) more user(s)") }
        }
        if ($userLines.Count -eq 0) { $userLines.Add('Not configured') }
        $exclLines = [System.Collections.Generic.List[string]]::new()
        $excGroups = @($usrs.excludeGroups ?? @())
        $excUsers  = @(($usrs.excludeUsers ?? @()) | Where-Object { $_ -notin @('All','None','GuestsOrExternalUsers') })
        $excRoles  = @($usrs.excludeRoles  ?? @())
        foreach ($gid in ($excGroups | Select-Object -First 3)) {
            $exclLines.Add("Excl: $(if ($IdentityLookup.ContainsKey($gid)) { $IdentityLookup[$gid] } else { $gid })")
        }
        if ($excGroups.Count -gt 3) { $exclLines.Add("Excl: + $($excGroups.Count - 3) more group(s)") }
        foreach ($uid in ($excUsers | Select-Object -First 3)) {
            $exclLines.Add("Excl: $(if ($IdentityLookup.ContainsKey($uid)) { $IdentityLookup[$uid] } else { $uid })")
        }
        if ($excUsers.Count -gt 3) { $exclLines.Add("Excl: + $($excUsers.Count - 3) more user(s)") }
        foreach ($rid in ($excRoles | Select-Object -First 3)) {
            $rName = if ($IdentityLookup.ContainsKey($rid)) { $IdentityLookup[$rid] } else { $rid }
            $exclLines.Add("Excl role: $rName")
        }
        if ($excRoles.Count -gt 3) { $exclLines.Add("Excl: + $($excRoles.Count - 3) more role(s)") }
        $userHtml  = ($userLines | ForEach-Object { "<div class='viz-item'>$($enc::HtmlEncode($_))</div>" }) -join ''
        $userHtml += ($exclLines | ForEach-Object { "<div class='viz-item viz-excl'>$($enc::HtmlEncode($_))</div>" }) -join ''

        # ── Apps node ──
        $wellKnown = Get-WellKnownAppId
        $appsCond  = $Policy.conditions.applications
        $appLines  = [System.Collections.Generic.List[string]]::new()
        $incApps   = $appsCond.includeApplications ?? @()
        $incActions = @($appsCond.includeUserActions ?? @())
        $incAuthCtx = @($appsCond.includeAuthenticationContextClassReferences ?? @())
        if     ($incApps -contains 'All')       { $appLines.Add('All Cloud Apps') }
        elseif ($incApps -contains 'None')      { $appLines.Add('No Cloud Apps') }
        elseif ($incApps -contains 'Office365') { $appLines.Add('Office 365') }
        elseif ($incApps.Count -gt 0) {
            foreach ($appId in ($incApps | Select-Object -First 3)) {
                $appLines.Add($(if ($wellKnown.ContainsKey($appId)) { $wellKnown[$appId] } else { $appId }))
            }
            if ($incApps.Count -gt 3) { $appLines.Add("+ $($incApps.Count - 3) more") }
        }
        if ($incActions.Count -gt 0) {
            $appLines.Add("Action: $($incActions -join ', ')")
        }
        if ($incAuthCtx.Count -gt 0) {
            foreach ($ctx in ($incAuthCtx | Select-Object -First 3)) {
                $ctxId   = if ($ctx -is [string]) { $ctx } else { $ctx.id ?? $ctx.ToString() }
                $ctxName = if ($IdentityLookup.ContainsKey($ctxId)) { $IdentityLookup[$ctxId] } else { $ctxId }
                $appLines.Add("Auth context: $ctxName")
            }
            if ($incAuthCtx.Count -gt 3) { $appLines.Add("+ $($incAuthCtx.Count - 3) more context(s)") }
        }
        if ($appLines.Count -eq 0) { $appLines.Add('Not configured') }
        $appHtml = ($appLines | ForEach-Object { "<div class='viz-item'>$($enc::HtmlEncode($_))</div>" }) -join ''

        # ── Conditions node ──
        $condLines   = [System.Collections.Generic.List[string]]::new()
        $clientTypes = $Policy.conditions.clientAppTypes ?? @()
        if ($clientTypes.Count -gt 0) {
            if ($clientTypes -contains 'all') { $condLines.Add('Client: All') }
            else { $condLines.Add("Client: $($clientTypes -join ', ')") }
        }
        $plat = $Policy.conditions.platforms
        if ($plat -and ($plat.includePlatforms ?? @()).Count -gt 0) {
            $pp = $plat.includePlatforms
            if ($pp -contains 'all') { $condLines.Add('Platform: All') } else { $condLines.Add("Platform: $($pp -join ', ')") }
        }
        $loc = $Policy.conditions.locations
        if ($loc) {
            $li = $loc.includeLocations ?? @()
            $le = $loc.excludeLocations ?? @()
            if     ($li -contains 'All')       { $condLines.Add('Location: All') }
            elseif ($li.Count -gt 0)            { $condLines.Add("Location: $($li.Count) location(s)") }
            if     ($le -contains 'AllTrusted') { $condLines.Add('Excl: Trusted locations') }
            elseif ($le.Count -gt 0)            { $condLines.Add("Excl: $($le.Count) location(s)") }
        }
        $sir   = $Policy.conditions.signInRiskLevels   ?? @()
        $urisk = $Policy.conditions.userRiskLevels     ?? @()
        $irisk = $Policy.conditions.insiderRiskLevels  ?? @()
        if ($sir.Count   -gt 0) { $condLines.Add("Sign-in risk: $($sir   -join ', ')") }
        if ($urisk.Count -gt 0) { $condLines.Add("User risk: $($urisk    -join ', ')") }
        if ($irisk.Count -gt 0) { $condLines.Add("Insider risk: $($irisk -join ', ')") }
        $devs = $Policy.conditions.devices
        if ($devs -and $devs.deviceFilter -and $devs.deviceFilter.mode) {
            $fm = if ($devs.deviceFilter.mode -eq 'include') { 'Device filter: include' } else { 'Device filter: exclude' }
            $condLines.Add($fm)
        }
        $af = if ($Policy.conditions.authenticationFlows) { $Policy.conditions.authenticationFlows.transferMethods ?? @() } else { @() }
        if ($af.Count -gt 0) { $condLines.Add("Auth flow: $($af -join ', ')") }
        if ($condLines.Count -eq 0) { $condLines.Add('No additional conditions') }
        $condHtml = ($condLines | ForEach-Object { "<div class='viz-item'>$($enc::HtmlEncode($_))</div>" }) -join ''

        # ── Outcome node ──
        $isBlock        = ($Policy.grantControls.builtInControls ?? @()) -contains 'block'
        $grantStr       = Format-GrantControls  -Policy $Policy
        $sessionStr     = Format-SessionControls -Policy $Policy
        $hasSession     = $sessionStr -and $sessionStr -ne 'None'
        $outcomeNodeCls = if ($isBlock) { 'viz-node viz-node-block' }
                          elseif (-not $Policy.grantControls -and $hasSession) { 'viz-node viz-node-session' }
                          else { 'viz-node viz-node-allow' }
        $outcomeIcon    = if ($isBlock) { '&#x1F6AB;' } elseif (-not $Policy.grantControls -and $hasSession) { '&#x1F4CB;' } else { '&#x2705;' }
        $outcomeGrant   = "<div class='viz-item'>$outcomeIcon $($enc::HtmlEncode($grantStr))</div>"
        $outcomeSess    = if ($hasSession) { "<div class='viz-item viz-session'>&#x1F4CB; $($enc::HtmlEncode($sessionStr))</div>" } else { '' }

        $flowJson        = Format-PolicyFlowJson -Policy $Policy -IdentityLookup $IdentityLookup
        $flowJsonEncoded = [System.Web.HttpUtility]::HtmlEncode($flowJson)

        return @"
<div class="viz-card$disabledCls" data-state="$($enc::HtmlEncode($stateLabel))">
  <div class="viz-header">
    <span class="viz-name" title="$pName">$pName</span>
    $stateBadge
    <button class="viz-flow-btn" onclick="openFlowModal(this)">&#x1F4CA; Flow</button>
  </div>
  <div class="viz-flow">
    <div class="viz-node">
      <div class="viz-node-label">&#x1F464; Users</div>
      <div class="viz-node-body">$userHtml</div>
    </div>
    <div class="viz-arrow">&#x279C;</div>
    <div class="viz-node">
      <div class="viz-node-label">&#x2601;&#xFE0F; Apps</div>
      <div class="viz-node-body">$appHtml</div>
    </div>
    <div class="viz-arrow">&#x279C;</div>
    <div class="viz-node">
      <div class="viz-node-label">&#x1F50D; Conditions</div>
      <div class="viz-node-body">$condHtml</div>
    </div>
    <div class="viz-arrow">&#x279C;</div>
    <div class="$outcomeNodeCls">
      <div class="viz-node-label">&#x2696;&#xFE0F; Outcome</div>
      <div class="viz-node-body">$outcomeGrant$outcomeSess</div>
    </div>
  </div>
  <div class="viz-flow-data" style="display:none" data-type="json">$flowJsonEncoded</div>
</div>
"@
    }

    function Format-PolicyFlowJson {
        param([object]$Policy, [hashtable]$IdentityLookup = @{})

        # ── WHAT (Apps) ──
        $wellKnown  = Get-WellKnownAppId
        $appsCond   = $Policy.conditions.applications
        $incApps    = @($appsCond.includeApplications ?? @())
        $incActions = @($appsCond.includeUserActions ?? @())
        $incAuthCtx = @($appsCond.includeAuthenticationContextClassReferences ?? @())
        $appTitle   = if     ($incApps -contains 'All')       { 'All Cloud Apps' }
                      elseif ($incApps -contains 'Office365') { 'Office 365' }
                      elseif ($incApps -contains 'None')      { 'No Cloud Apps' }
                      elseif ($incApps.Count -eq 1)           { if ($wellKnown.ContainsKey($incApps[0])) { $wellKnown[$incApps[0]] } else { $incApps[0] } }
                      elseif ($incApps.Count -gt 1)           { "$($incApps.Count) applications" }
                      elseif ($incActions.Count -gt 0)        { "Action: $($incActions[0])" }
                      elseif ($incAuthCtx.Count -gt 0)        {
                          $ctxId   = if ($incAuthCtx[0] -is [string]) { $incAuthCtx[0] } else { $incAuthCtx[0].id ?? $incAuthCtx[0].ToString() }
                          $ctxName = if ($IdentityLookup.ContainsKey($ctxId)) { $IdentityLookup[$ctxId] } else { $ctxId }
                          if ($incAuthCtx.Count -gt 1) { "Auth Context: $ctxName + $($incAuthCtx.Count - 1) more" } else { "Auth Context: $ctxName" }
                      }
                      else                                    { 'Not configured' }
        $whatSub = [System.Collections.Generic.List[string]]::new()
        $excApps = @($appsCond.excludeApplications ?? @())
        if ($excApps.Count -gt 0) { $whatSub.Add("Excl: $($excApps.Count) app(s)") }
        foreach ($a in ($incActions | Select-Object -First 2)) { $whatSub.Add("Action: $a") }

        # ── WHO (Users) ──
        $usrs      = $Policy.conditions.users
        $incUsers  = @($usrs.includeUsers  ?? @())
        $incGroups = @($usrs.includeGroups ?? @())
        $incRoles  = @($usrs.includeRoles  ?? @())
        $excUsers  = @($usrs.excludeUsers  ?? @())
        $excGroups = @($usrs.excludeGroups ?? @())
        $excRoles  = @($usrs.excludeRoles  ?? @())
        $incSpecificUsers = @($incUsers | Where-Object { $_ -notin @('All','None','GuestsOrExternalUsers') })
        $whoTitle  = if ($incUsers -contains 'All') { 'All Users' }
                     elseif ($usrs.includeGuestsOrExternalUsers -or ($incUsers -contains 'GuestsOrExternalUsers')) { 'Guests / External Users' }
                     elseif ($incGroups.Count -gt 0) {
                         $n = if ($IdentityLookup.ContainsKey($incGroups[0])) { $IdentityLookup[$incGroups[0]] } else { $incGroups[0] }
                         if ($incGroups.Count -gt 1) { "$n + $($incGroups.Count - 1) more group(s)" } else { $n }
                     }
                     elseif ($incRoles.Count -gt 0) {
                         $n = if ($IdentityLookup.ContainsKey($incRoles[0])) { $IdentityLookup[$incRoles[0]] } else { $incRoles[0] }
                         if ($incRoles.Count -gt 1) { "Role: $n + $($incRoles.Count - 1) more" } else { "Role: $n" }
                     }
                     elseif ($incSpecificUsers.Count -gt 0) {
                         $n = if ($IdentityLookup.ContainsKey($incSpecificUsers[0])) { $IdentityLookup[$incSpecificUsers[0]] } else { $incSpecificUsers[0] }
                         if ($incSpecificUsers.Count -gt 1) { "$n + $($incSpecificUsers.Count - 1) more user(s)" } else { $n }
                     }
                     else { 'Not configured' }
        $whoSub    = [System.Collections.Generic.List[string]]::new()
        $totalExcl = $excUsers.Count + $excGroups.Count + $excRoles.Count
        if ($totalExcl -gt 0) { $whoSub.Add("Excl: $totalExcl identit$(if ($totalExcl -ne 1) { 'ies' } else { 'y' })") }

        # ── Conditions ──
        $condData    = [System.Collections.Generic.List[hashtable]]::new()
        $clientTypes = @($Policy.conditions.clientAppTypes ?? @())
        if ($clientTypes.Count -gt 0) {
            $items = if ($clientTypes -contains 'all') { @('All client types') } else { $clientTypes }
            $condData.Add(@{ title = 'Client apps'; items = @($items) })
        }
        $plat = $Policy.conditions.platforms
        if ($plat -and ($plat.includePlatforms ?? @()).Count -gt 0) {
            $pp    = @($plat.includePlatforms)
            $items = if ($pp -contains 'all') { @('All platforms') } else { $pp }
            $condData.Add(@{ title = 'Devices'; items = @($items) })
        }
        $loc = $Policy.conditions.locations
        if ($loc) {
            $li = @($loc.includeLocations ?? @())
            $le = @($loc.excludeLocations ?? @())
            if ($li.Count -gt 0 -or $le.Count -gt 0) {
                $locItems = [System.Collections.Generic.List[string]]::new()
                if     ($li -contains 'All')        { $locItems.Add('Include: All') }
                elseif ($li -contains 'AllTrusted') { $locItems.Add('Include: Trusted') }
                elseif ($li.Count -gt 0)            { $locItems.Add("Include: $($li.Count) location(s)") }
                if     ($le -contains 'AllTrusted') { $locItems.Add('Excl: Trusted network') }
                elseif ($le.Count -gt 0)            { $locItems.Add("Excl: $($le.Count) location(s)") }
                $condData.Add(@{ title = 'Locations'; items = @($locItems) })
            }
        }
        $sir   = @($Policy.conditions.signInRiskLevels  ?? @())
        $urisk = @($Policy.conditions.userRiskLevels    ?? @())
        $irisk = @($Policy.conditions.insiderRiskLevels ?? @())
        if ($sir.Count   -gt 0) { $condData.Add(@{ title = 'Sign-in risk'; items = @($sir)   }) }
        if ($urisk.Count -gt 0) { $condData.Add(@{ title = 'User risk';    items = @($urisk) }) }
        if ($irisk.Count -gt 0) { $condData.Add(@{ title = 'Insider risk'; items = @($irisk) }) }
        $devs = $Policy.conditions.devices
        if ($devs -and $devs.deviceFilter -and $devs.deviceFilter.mode) {
            $condData.Add(@{ title = 'Device filter'; items = @("$($devs.deviceFilter.mode) mode") })
        }
        $af = @(if ($Policy.conditions.authenticationFlows) { $Policy.conditions.authenticationFlows.transferMethods ?? @() } else { @() })
        if ($af.Count -gt 0) { $condData.Add(@{ title = 'Auth flow'; items = @($af) }) }

        # ── Grant ──
        $gc         = $Policy.grantControls
        $isBlock    = ($gc.builtInControls ?? @()) -contains 'block'
        $hasGrant   = $gc -and ($gc.builtInControls ?? @()).Count -gt 0
        $grantStr   = Format-GrantControls   -Policy $Policy
        $sessionStr = Format-SessionControls -Policy $Policy
        $hasSession = $sessionStr -and $sessionStr -ne 'None'
        $grantType  = if ($isBlock) { 'block' } elseif (-not $hasGrant -and $hasSession) { 'session' } else { 'grant' }
        $grantTitle = if ($isBlock) { 'Block Access' } elseif (-not $hasGrant -and $hasSession) { 'Session Controls' } else { $grantStr }
        $grantItems = [System.Collections.Generic.List[string]]::new()
        if ($gc) {
            foreach ($ctrl in ($gc.builtInControls ?? @())) { $grantItems.Add($ctrl) }
            if ($gc.authenticationStrength) { $grantItems.Add("Auth Strength: $($gc.authenticationStrength.displayName)") }
            if ($gc.operator -and $grantItems.Count -gt 1) { $grantItems.Add("Operator: $($gc.operator)") }
        }
        if (-not $hasGrant -and $hasSession) {
            foreach ($sp in ($sessionStr -split ', ')) { $grantItems.Add($sp) }
        }
        $isReportOnly = $Policy.state -eq 'enabledForReportingButNotEnforced'
        if ($isReportOnly) { $grantItems.Add('(report only)') }

        # ── Serialize ──
        $data = [ordered]@{
            name  = $Policy.displayName
            state = switch ($Policy.state) {
                'enabled'                          { 'enabled' }
                'enabledForReportingButNotEnforced' { 'reportOnly' }
                'disabled'                         { 'disabled' }
                default                            { $Policy.state }
            }
            what  = [ordered]@{ title = $appTitle; sub = @($whatSub) }
            who   = [ordered]@{ title = $whoTitle;  sub = @($whoSub)  }
            conds = @($condData)
            grant = [ordered]@{ type = $grantType; title = $grantTitle; items = @($grantItems) }
        }
        return $data | ConvertTo-Json -Depth 5 -Compress
    }

    # Resolve user/group/role GUIDs to display names for the visualizer
    $identityLookup = @{}
    try {
        $identityLookup = Resolve-CAPolicyIdentities -Policies $policies
        $authCtxKeys = @($identityLookup.Keys | Where-Object { $_ -match '^c\d+$' })
        Write-Host "[CA-BaselineAuditor] Resolved $($identityLookup.Count) identities for visualizer (auth contexts: $($authCtxKeys.Count): $($authCtxKeys -join ', '))" -ForegroundColor DarkGray
    } catch {
        Write-Host "[CA-BaselineAuditor] Identity resolution failed: $_" -ForegroundColor Yellow
    }

    $vizCards           = [System.Text.StringBuilder]::new()
    $vizCountEnabled    = 0
    $vizCountReportOnly = 0
    $vizCountDisabled   = 0
    foreach ($p in ($policies | Sort-Object displayName)) {
        switch ($p.state) {
            'enabled'                          { $vizCountEnabled++ }
            'enabledForReportingButNotEnforced' { $vizCountReportOnly++ }
            'disabled'                         { $vizCountDisabled++ }
        }
        [void]$vizCards.Append((Format-PolicyVizCard -Policy $p -IdentityLookup $identityLookup))
    }

    $secViz = @"
<section id="visualizer">
<h2>Policy Flow Visualizer ($($policies.Count) policies)</h2>
<div class="filter-bar">
  <input type="text" id="vizFilter" placeholder="Filter by name..." oninput="filterViz()">
  <select id="vizStateFilter" onchange="filterViz()">
    <option value="">All States ($($policies.Count))</option>
    <option value="Enabled">Enabled ($vizCountEnabled)</option>
    <option value="Report-Only">Report-Only ($vizCountReportOnly)</option>
    <option value="Disabled">Disabled ($vizCountDisabled)</option>
  </select>
</div>
<div class="viz-grid" id="vizGrid">
$($vizCards.ToString())
</div>
</section>
<!-- Policy Flow Modal -->
<div class="flow-modal" id="flowModal">
  <div class="flow-backdrop" onclick="closeFlowModal()"></div>
  <div class="flow-box">
    <div class="flow-titlebar">
      <h3 id="flowModalTitle">Policy Flow</h3>
      <button class="flow-close-btn" onclick="closeFlowModal()">&#x2715; Close</button>
    </div>
    <div class="flow-scroll">
      <div id="flowModalBody"></div>
    </div>
  </div>
</div>
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
function escXml(s) {
    return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function renderFlowSvg(d) {
    var NW=210,PAD=12,LBL_H=18,DIV_H=8,TTL_H=18,ITEM_H=16,GAP_Y=56,GAP_X=20,SIDE=28;
    var CC='#374151';
    var C={policy:['#1c2640','#6366f1','#818cf8'],target:['#0c2231','#0891b2','#22d3ee'],
           who:['#2a1024','#be185d','#f472b6'],decision:['#1e1040','#9333ea','#c084fc'],
           cond:['#1f1a08','#b45309','#f59e0b'],grant:['#1a0e3a','#7c3aed','#a78bfa'],
           block:['#2a0a0a','#dc2626','#f87171'],ok:['#0a2a0e','#16a34a','#4ade80'],
           deny:['#2a0a0a','#dc2626','#f87171'],session:['#0a2228','#0891b2','#22d3ee']};
    var LBL={policy:'POLICY',target:'TARGETS',who:'APPLIES TO',decision:'DECISION',
             cond:'CONDITION',grant:'GRANT',block:'GRANT',ok:'OUTCOME',deny:'OUTCOME',session:'OUTCOME'};
    var FONT="Poppins,system-ui,sans-serif";
    function wrap(txt,max){
        if(!txt)return[''];if(txt.length<=max)return[txt];
        var words=txt.split(' '),lines=[],cur='';
        for(var i=0;i<words.length;i++){var w=words[i],test=cur?cur+' '+w:w;
            if(test.length>max&&cur){lines.push(cur);cur=w;}else{cur=test;}}
        if(cur)lines.push(cur);
        if(lines.length>2){lines=lines.slice(0,2);lines[1]=lines[1].replace(/\s+\S+$/,'\u2026');}
        return lines;}
    function nodeH(tl,items){return PAD+LBL_H+DIV_H+tl.length*TTL_H+(items.length>0?10+items.length*ITEM_H:8)+PAD;}
    var levels=[],edges=[];
    var pTL=wrap(d.name,26);
    var pItems=d.state!=='enabled'?[d.state==='reportOnly'?'Report-Only':'Disabled']:[];
    levels.push([{type:'policy',tl:pTL,items:pItems}]);
    levels.push([{type:'target',tl:wrap(d.what.title,26),items:(d.what.sub||[]).slice(0,3)},
                 {type:'who',   tl:wrap(d.who.title, 26),items:(d.who.sub ||[]).slice(0,3)}]);
    edges.push({fl:0,fi:0,tl:1,ti:0});edges.push({fl:0,fi:0,tl:1,ti:1});
    var prevL=1,prevIs=[0,1];
    if(d.conds&&d.conds.length>0){
        levels.push([{type:'decision',tl:['Evaluate Conditions'],items:[d.conds.length+' condition(s) checked']}]);
        prevIs.forEach(function(i){edges.push({fl:prevL,fi:i,tl:prevL+1,ti:0});});
        prevL++;prevIs=[0];
        var cN=d.conds.map(function(c){return{type:'cond',tl:wrap(c.title,26),items:(c.items||[]).slice(0,4)};});
        levels.push(cN);
        for(var ci=0;ci<cN.length;ci++)edges.push({fl:prevL,fi:0,tl:prevL+1,ti:ci});
        prevL++;prevIs=cN.map(function(_,i){return i;});}
    var gt=d.grant.type;
    levels.push([{type:gt,tl:wrap(d.grant.title,26),items:(d.grant.items||[]).slice(0,4)}]);
    prevIs.forEach(function(i){edges.push({fl:prevL,fi:i,tl:prevL+1,ti:0});});
    prevL++;prevIs=[0];
    if(gt==='block'){levels.push([{type:'deny',tl:['Access Denied'],items:['Access blocked']}]);
    }else if(gt==='session'){levels.push([{type:'session',tl:['Session Applied'],items:['Controls active']}]);
    }else{levels.push([{type:'ok',tl:['Access Granted'],items:['Controls satisfied']},
                       {type:'deny',tl:['Access Denied'],items:['Controls not met']}]);
        edges.push({fl:prevL,fi:0,tl:prevL+1,ti:1});}
    edges.push({fl:prevL,fi:0,tl:prevL+1,ti:0});
    var lvlH=levels.map(function(l){return Math.max.apply(null,l.map(function(n){return nodeH(n.tl,n.items);}));});
    var lvlW=levels.map(function(l){return l.length*NW+Math.max(0,l.length-1)*GAP_X;});
    var W=Math.max.apply(null,lvlW)+2*SIDE;
    var lvlY=[],cy=SIDE;
    for(var i=0;i<levels.length;i++){lvlY.push(cy);cy+=lvlH[i]+GAP_Y;}
    var H=cy-GAP_Y+SIDE;
    var nx=levels.map(function(l,li){var sw=(W-lvlW[li])/2;return l.map(function(_,ni){return sw+ni*(NW+GAP_X);});});
    var ncx=function(li,ni){return nx[li][ni]+NW/2;};
    var nby=function(li){return lvlY[li]+lvlH[li];};
    var nty=function(li){return lvlY[li];};
    var svg=['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+W+' '+H+'" width="'+W+'" height="'+H+'" style="display:block">'];
    svg.push('<defs><marker id="cfxA" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto"><path d="M0,1.5 L8.5,5 L0,8.5 Z" fill="'+CC+'"/></marker></defs>');
    var eG={};
    edges.forEach(function(e){var k=e.fl+','+e.tl;(eG[k]=eG[k]||[]).push(e);});
    Object.keys(eG).forEach(function(k){
        var grp=eG[k],FL=grp[0].fl,TL=grp[0].tl;
        var fis=grp.map(function(e){return e.fi;}).filter(function(v,i,a){return a.indexOf(v)===i;});
        var tis=grp.map(function(e){return e.ti;}).filter(function(v,i,a){return a.indexOf(v)===i;});
        var midY=nby(FL)+GAP_Y/2;
        if(fis.length===1&&tis.length===1){
            var fx=ncx(FL,fis[0]),tx=ncx(TL,tis[0]);
            if(Math.abs(fx-tx)<1){svg.push('<line x1="'+fx+'" y1="'+nby(FL)+'" x2="'+tx+'" y2="'+nty(TL)+'" stroke="'+CC+'" stroke-width="1.5" marker-end="url(#cfxA)"/>');
            }else{svg.push('<path d="M'+fx+','+nby(FL)+' V'+midY+' H'+tx+' V'+nty(TL)+'" fill="none" stroke="'+CC+'" stroke-width="1.5" marker-end="url(#cfxA)"/>');}}
        else if(fis.length===1){
            var fx=ncx(FL,fis[0]),xs=tis.map(function(i){return ncx(TL,i);});
            svg.push('<line x1="'+fx+'" y1="'+nby(FL)+'" x2="'+fx+'" y2="'+midY+'" stroke="'+CC+'" stroke-width="1.5"/>');
            svg.push('<line x1="'+Math.min.apply(null,xs)+'" y1="'+midY+'" x2="'+Math.max.apply(null,xs)+'" y2="'+midY+'" stroke="'+CC+'" stroke-width="1.5"/>');
            xs.forEach(function(tx){svg.push('<line x1="'+tx+'" y1="'+midY+'" x2="'+tx+'" y2="'+nty(TL)+'" stroke="'+CC+'" stroke-width="1.5" marker-end="url(#cfxA)"/>');});
        }else{
            var fxs=fis.map(function(i){return ncx(FL,i);}),tx=ncx(TL,tis[0]);
            var mx=fxs.reduce(function(s,x){return s+x;},0)/fxs.length;
            fxs.forEach(function(fx){svg.push('<line x1="'+fx+'" y1="'+nby(FL)+'" x2="'+fx+'" y2="'+midY+'" stroke="'+CC+'" stroke-width="1.5"/>');});
            svg.push('<line x1="'+Math.min.apply(null,fxs)+'" y1="'+midY+'" x2="'+Math.max.apply(null,fxs)+'" y2="'+midY+'" stroke="'+CC+'" stroke-width="1.5"/>');
            svg.push('<path d="M'+mx+','+midY+' H'+tx+' V'+nty(TL)+'" fill="none" stroke="'+CC+'" stroke-width="1.5" marker-end="url(#cfxA)"/>');
        }});
    levels.forEach(function(lvl,li){lvl.forEach(function(node,ni){
        var x=nx[li][ni],y=lvlY[li],h=lvlH[li];
        var col=C[node.type]||C.policy,bg=col[0],border=col[1],lblCol=col[2];
        var lbl=LBL[node.type]||node.type.toUpperCase();
        svg.push('<rect x="'+x+'" y="'+y+'" width="'+NW+'" height="'+h+'" rx="10" fill="'+bg+'" stroke="'+border+'" stroke-width="1.5"/>');
        svg.push('<text x="'+(x+NW/2)+'" y="'+(y+PAD+13)+'" text-anchor="middle" fill="'+lblCol+'" font-size="8.5" font-weight="800" letter-spacing="1.3" font-family="'+FONT+'">'+escXml(lbl)+'</text>');
        svg.push('<line x1="'+(x+10)+'" y1="'+(y+PAD+LBL_H)+'" x2="'+(x+NW-10)+'" y2="'+(y+PAD+LBL_H)+'" stroke="'+border+'" stroke-width="0.75" opacity="0.4"/>');
        var ty=y+PAD+LBL_H+DIV_H;
        node.tl.forEach(function(line){ty+=TTL_H;svg.push('<text x="'+(x+NW/2)+'" y="'+ty+'" text-anchor="middle" fill="#e5e7eb" font-size="12" font-weight="600" font-family="'+FONT+'">'+escXml(line)+'</text>');});
        if(node.items.length>0){ty+=10;node.items.forEach(function(item){ty+=ITEM_H;
            var s=item.length>30?item.slice(0,29)+'\u2026':item;
            svg.push('<text x="'+(x+NW/2)+'" y="'+ty+'" text-anchor="middle" fill="#9ca3af" font-size="10" font-family="'+FONT+'">'+escXml(s)+'</text>');});}
    });});
    svg.push('</svg>');
    return svg.join('');
}
function filterViz() {
    var text  = document.getElementById('vizFilter').value.toLowerCase();
    var state = document.getElementById('vizStateFilter').value;
    document.querySelectorAll('#vizGrid .viz-card').forEach(function(c) {
        var matchText  = !text  || c.textContent.toLowerCase().includes(text);
        var matchState = !state || c.dataset.state === state;
        c.style.display = (matchText && matchState) ? '' : 'none';
    });
}
// ── Policy Flow Modal ──
function openFlowModal(btn) {
    var card  = btn.closest('.viz-card');
    var title = card.querySelector('.viz-name').textContent;
    var data  = card.querySelector('.viz-flow-data');
    document.getElementById('flowModalTitle').textContent = title;
    var body = document.getElementById('flowModalBody');
    if (data && data.dataset.type === 'json') {
        try {
            body.innerHTML = '<div class="flow-svg-wrap">' + renderFlowSvg(JSON.parse(data.textContent)) + '</div>';
        } catch(e) {
            body.innerHTML = '<p style="color:var(--text-muted);padding:20px">Error rendering flow diagram.</p>';
        }
    } else {
        body.innerHTML = data
            ? data.innerHTML
            : '<p style="color:var(--text-muted);padding:20px">No flow data available.</p>';
    }
    document.getElementById('flowModal').classList.add('open');
    document.body.style.overflow = 'hidden';
}
function closeFlowModal() {
    document.getElementById('flowModal').classList.remove('open');
    document.body.style.overflow = '';
}
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeFlowModal(); });
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Poppins:ital,wght@0,400;0,500;0,600;0,700;0,800;1,400&display=swap" rel="stylesheet">
<title>CA Baseline Audit — $([System.Web.HttpUtility]::HtmlEncode($tenantName))</title>
<style>$css</style>
</head>
<body>
<div class="header">
    <h1>&#x1F6E1;&#xFE0F; Conditional Access Baseline Audit</h1>
    <div class="meta">$([System.Web.HttpUtility]::HtmlEncode($tenantName)) ($($tenantCtx.TenantDomain)) &mdash; Generated $reportDate &mdash; Baseline: <strong>$([System.Web.HttpUtility]::HtmlEncode($activeBaseline))</strong></div>
</div>
<nav>
    <a href="#summary" class="active">Summary</a>
    <a href="#posture">Security Posture</a>
    <a href="#licensing">Licensing</a>
    <a href="#inventory">Policy Inventory</a>
    <a href="#gap-analysis">Gap Analysis</a>
    <a href="#recommendations">Recommendations</a>
    <a href="#visualizer">Visualizer</a>
</nav>
<div class="container">
$sec1
$sec6
$sec2
$sec3
$sec4
$sec7
$secViz
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
