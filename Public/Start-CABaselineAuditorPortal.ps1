function Start-CABaselineAuditorPortal {
    <#
    .SYNOPSIS
        Launches the CA-BaselineAuditor web portal.
    .DESCRIPTION
        Starts a local HTTP portal on 127.0.0.1 (default port 8080).
        Sign in to Microsoft Graph directly from the portal, choose your baseline
        and audit options, run the audit, and view the results — all from the browser.

        The portal opens automatically in your default browser. It blocks in the
        PowerShell session until you click "✕ Close" in the portal or press Ctrl+C.
    .PARAMETER Port
        Starting port for the portal server (default 8080). If the port is already in
        use the server automatically tries the next available port up to Port+9.
    .EXAMPLE
        Start-CABaselineAuditorPortal
    .EXAMPLE
        Start-CABaselineAuditorPortal -Port 9090
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1024, 65535)]
        [int]$Port = 8080
    )

    # ── Banner ────────────────────────────────────────────────────────────────
    $moduleVersion = $MyInvocation.MyCommand.Module.Version ?? '1.0.0'
    Write-Host ''
    Write-Host '  ╔═════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '  ║   CA-BaselineAuditor Portal             ║' -ForegroundColor Cyan
    Write-Host "  ║   Module version $moduleVersion$(' ' * [Math]::Max(0, 22 - "$moduleVersion".Length)) ║" -ForegroundColor Cyan
    Write-Host '  ╚═════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''

    # ── Reset portal state ────────────────────────────────────────────────────
    $script:PortalServerStop     = $false
    $script:PortalConnected      = $false
    $script:TenantName           = ''
    $script:TenantId             = ''
    $script:ConnectedAs          = ''
    $script:AuditStatus          = 'idle'
    $script:PortalLastReportPath = ''

    # ── Launch portal ─────────────────────────────────────────────────────────
    Write-Host '[1/1] Starting portal server…' -ForegroundColor Yellow

    # Open browser shortly after server starts
    $browserJob = Start-Job -ScriptBlock {
        Start-Sleep -Seconds 1
        Start-Process "http://127.0.0.1:$using:Port/"
    }

    # Start-AuditorServer is blocking — returns only when the user clicks Close
    Start-AuditorServer -PreferredPort $Port

    $browserJob | Remove-Job -Force -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host 'Portal closed.' -ForegroundColor Cyan
    Write-Host 'Done.' -ForegroundColor Cyan
}
