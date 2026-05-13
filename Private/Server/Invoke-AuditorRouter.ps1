function Invoke-AuditorRouter {
    <#
    .SYNOPSIS
        Reads an HTTP/1.1 request from a TcpClient, parses it, and dispatches to the
        correct handler.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Sockets.TcpClient]$Client,

        [Parameter(Mandatory)]
        [string]$ModuleRoot
    )

    $stream = $Client.GetStream()

    try {
        # ── Read request headers ──────────────────────────────────────────────
        $headerBytes     = [System.Collections.Generic.List[byte]]::new()
        $buf             = New-Object byte[] 1
        $crlfcrlfPattern = [byte[]]@(13, 10, 13, 10)  # \r\n\r\n

        while ($stream.CanRead) {
            $read = $stream.Read($buf, 0, 1)
            if ($read -eq 0) { break }
            $headerBytes.Add($buf[0])

            if ($headerBytes.Count -ge 4) {
                $tail = $headerBytes.GetRange($headerBytes.Count - 4, 4)
                if ($tail[0] -eq $crlfcrlfPattern[0] -and $tail[1] -eq $crlfcrlfPattern[1] -and
                    $tail[2] -eq $crlfcrlfPattern[2] -and $tail[3] -eq $crlfcrlfPattern[3]) {
                    break
                }
            }
            if ($headerBytes.Count -gt 16384) { break }  # guard against oversized headers
        }

        $rawHeader   = [System.Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
        $headerLines = $rawHeader -split '\r\n'

        if ($headerLines.Count -eq 0 -or -not $headerLines[0]) { return }

        # ── Parse request line ────────────────────────────────────────────────
        $requestLineParts = $headerLines[0].Split(' ')
        if ($requestLineParts.Count -lt 2) { return }

        $method   = $requestLineParts[0].ToUpper()
        $fullPath = $requestLineParts[1]

        $qMark = $fullPath.IndexOf('?')
        if ($qMark -ge 0) {
            $path        = $fullPath.Substring(0, $qMark)
            $queryString = $fullPath.Substring($qMark + 1)
        }
        else {
            $path        = $fullPath
            $queryString = ''
        }

        # ── Parse headers ─────────────────────────────────────────────────────
        $headers = @{}
        foreach ($line in $headerLines[1..($headerLines.Count - 1)]) {
            $colonIdx = $line.IndexOf(':')
            if ($colonIdx -gt 0) {
                $key         = $line.Substring(0, $colonIdx).Trim().ToLower()
                $val         = $line.Substring($colonIdx + 1).Trim()
                $headers[$key] = $val
            }
        }

        # ── Read body (POST) ──────────────────────────────────────────────────
        $body = $null
        if ($method -eq 'POST' -and $headers['content-length']) {
            $contentLength = [int]$headers['content-length']
            if ($contentLength -gt 0 -and $contentLength -le 1048576) {  # max 1 MB
                $bodyBytes = New-Object byte[] $contentLength
                $totalRead = 0
                while ($totalRead -lt $contentLength) {
                    $read = $stream.Read($bodyBytes, $totalRead, $contentLength - $totalRead)
                    if ($read -eq 0) { break }
                    $totalRead += $read
                }
                try {
                    $bodyStr = [System.Text.Encoding]::UTF8.GetString($bodyBytes, 0, $totalRead)
                    $body    = $bodyStr | ConvertFrom-Json -AsHashtable -ErrorAction Stop
                }
                catch {
                    $body = $null
                }
            }
        }

        # ── Dispatch ──────────────────────────────────────────────────────────
        $ctx = @{
            Method      = $method
            Path        = $path
            QueryString = $queryString
            Headers     = $headers
            Body        = $body
            Stream      = $stream
            ModuleRoot  = $ModuleRoot
        }

        Invoke-AuditorRoute -Context $ctx
    }
    finally {
        try { $stream.Close() } catch { Write-Verbose "Stream close suppressed: $_" }
    }
}

function Invoke-AuditorRoute {
    <#
    .SYNOPSIS
        Dispatches a parsed HTTP request context to the appropriate API handler.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    $method     = $Context.Method
    $path       = $Context.Path
    $stream     = $Context.Stream
    $body       = $Context.Body
    $moduleRoot = $Context.ModuleRoot

    try {
        switch -Regex ($path) {

            '^/$' {
                $indexPath = Join-Path $moduleRoot 'Assets' 'portal' 'index.html'
                Write-AuditorFileResponse -Stream $stream -FilePath $indexPath
                return
            }

            '^/static/(.+)$' {
                $requestedFile = $Matches[1]
                # Whitelist to prevent path traversal
                $allowed = @('app.js', 'style.css')
                if ($requestedFile -notin $allowed) {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Not found' -StatusCode 404
                    return
                }
                $filePath = Join-Path $moduleRoot 'Assets' 'portal' $requestedFile
                if (Test-Path $filePath) {
                    Write-AuditorFileResponse -Stream $stream -FilePath $filePath
                }
                else {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Static file not found' -StatusCode 404
                }
                return
            }

            '^/api/context$' {
                Write-AuditorJsonResponse -Stream $stream -Data @{
                    connected   = ($script:PortalConnected -eq $true)
                    tenantName  = [string]$script:TenantName
                    tenantId    = [string]$script:TenantId
                    connectedAs = [string]$script:ConnectedAs
                    auditStatus = [string]$script:AuditStatus
                }
                return
            }

            '^/api/connect$' {
                if ($method -ne 'POST') {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Method not allowed' -StatusCode 405
                    return
                }
                if ($script:PortalConnected) {
                    Write-AuditorJsonResponse -Stream $stream -Data @{
                        connected   = $true
                        tenantName  = [string]$script:TenantName
                        tenantId    = [string]$script:TenantId
                        connectedAs = [string]$script:ConnectedAs
                    }
                    return
                }
                try {
                    Connect-CABaselineAuditor

                    $ctx = Get-MgContext
                    try {
                        $orgResp           = Invoke-MgGraphRequest -Method GET `
                            -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,id' `
                            -ErrorAction Stop
                        $script:TenantName = $orgResp.value[0].displayName ?? $ctx.TenantId
                        $script:TenantId   = $orgResp.value[0].id          ?? $ctx.TenantId
                    }
                    catch {
                        $script:TenantName = $ctx.TenantId
                        $script:TenantId   = $ctx.TenantId
                    }

                    $script:ConnectedAs     = $ctx.Account ?? ''
                    $script:PortalConnected = $true
                    $script:AuditStatus     = 'idle'

                    Write-AuditorJsonResponse -Stream $stream -Data @{
                        connected   = $true
                        tenantName  = [string]$script:TenantName
                        tenantId    = [string]$script:TenantId
                        connectedAs = [string]$script:ConnectedAs
                    }
                }
                catch {
                    Write-AuditorJsonResponse -Stream $stream `
                        -Data @{ error = [string]$_.ToString() } -StatusCode 500
                }
                return
            }

            '^/api/run-audit$' {
                if ($method -ne 'POST') {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Method not allowed' -StatusCode 405
                    return
                }
                if (-not $script:PortalConnected) {
                    Write-AuditorJsonResponse -Stream $stream `
                        -Data @{ error = 'Not connected. Please connect first.' } -StatusCode 401
                    return
                }

                $baseline        = if ($body -and $body['baseline'])        { [string]$body['baseline'] }        else { 'VanSurksum' }
                $includeDisabled = if ($body -and $body['includeDisabled']) { [bool]$body['includeDisabled'] }   else { $false }
                $skipDevices     = if ($body -and $body['skipDevices'])     { [bool]$body['skipDevices'] }       else { $false }
                $skipTemplates   = if ($body -and $body['skipTemplates'])   { [bool]$body['skipTemplates'] }     else { $false }

                # Validate baseline value
                $validBaselines = @('VanSurksum', 'CISA', 'Maester', 'CIS', 'All')
                if ($baseline -notin $validBaselines) { $baseline = 'VanSurksum' }

                $script:AuditStatus = 'running'
                try {
                    $timestamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
                    $reportDir = Join-Path $moduleRoot 'Reports'
                    if (-not (Test-Path $reportDir)) {
                        New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
                    }
                    $reportPath  = Join-Path $reportDir "CA-Baseline-Audit_${timestamp}.html"

                    $auditParams = @{
                        OutputPath = $reportPath
                        Baseline   = $baseline
                    }
                    if ($includeDisabled) { $auditParams['IncludeDisabledPolicies'] = $true }
                    if ($skipDevices)     { $auditParams['SkipDeviceInventory']     = $true }
                    if ($skipTemplates)   { $auditParams['SkipMicrosoftTemplates']  = $true }

                    $auditData = Invoke-CABaselineAudit @auditParams

                    $script:PortalLastReportPath = $reportPath
                    $script:AuditStatus          = 'done'

                    # Build summary for the portal
                    $summary    = $auditData.Comparison.Summary
                    $appMusts   = @($auditData.Comparison.BaselineResults |
                                    Where-Object { $_.Priority -eq 'Must Have' -and $_.Status -ne 'NotApplicable' })
                    $matchMusts = @($appMusts | Where-Object { $_.Status -eq 'Matched' })
                    $score      = if ($appMusts.Count -gt 0) {
                                      [math]::Round(($matchMusts.Count / $appMusts.Count) * 100)
                                  } else { 0 }

                    $posturePass  = @($auditData.PostureChecks.Values | Where-Object { $_.Status -eq 'Pass' }).Count
                    $postureTotal = $auditData.PostureChecks.Count

                    Write-AuditorJsonResponse -Stream $stream -Data @{
                        success         = $true
                        baseline        = [string]$auditData.ActiveBaseline
                        tenantName      = [string]$auditData.TenantContext.TenantName
                        policyCount     = [int]$auditData.CurrentPolicies.Count
                        matched         = [int]$summary.Matched
                        partial         = [int]$summary.Partial
                        missing         = [int]$summary.Missing
                        notApplicable   = [int]$summary.NotApplicable
                        totalBaseline   = [int]$summary.TotalBaseline
                        complianceScore = [int]$score
                        posturePass     = [int]$posturePass
                        postureTotal    = [int]$postureTotal
                        reportPath      = [string]$reportPath
                    }
                }
                catch {
                    $script:AuditStatus = 'error'
                    Write-AuditorJsonResponse -Stream $stream `
                        -Data @{ error = [string]$_.ToString() } -StatusCode 500
                }
                return
            }

            '^/api/report$' {
                if (-not $script:PortalLastReportPath -or
                    -not (Test-Path $script:PortalLastReportPath)) {
                    Write-AuditorErrorResponse -Stream $stream `
                        -Message 'No report available. Run an audit first.' -StatusCode 404
                    return
                }
                $isDownload = ($Context.QueryString -match '(?:^|&)download=1(?:&|$)')
                if ($isDownload) {
                    Write-AuditorFileResponse -Stream $stream -FilePath $script:PortalLastReportPath -AsDownload
                } else {
                    Write-AuditorFileResponse -Stream $stream -FilePath $script:PortalLastReportPath
                }
                return
            }

            '^/api/disconnect$' {
                if ($method -ne 'POST') {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Method not allowed' -StatusCode 405
                    return
                }
                Write-Host '  Disconnecting from Microsoft Graph…' -ForegroundColor Cyan
                try {
                    Disconnect-MgGraph -ErrorAction Stop | Out-Null
                    Write-Host '  [OK] Microsoft Graph disconnected' -ForegroundColor Green
                }
                catch {
                    Write-Host "  [WARN] Graph disconnect: $_" -ForegroundColor Yellow
                }

                $script:PortalConnected      = $false
                $script:TenantName           = ''
                $script:TenantId             = ''
                $script:ConnectedAs          = ''
                $script:AuditStatus          = 'idle'
                $script:PortalLastReportPath = ''

                Write-AuditorJsonResponse -Stream $stream -Data @{ ok = $true }
                return
            }

            '^/api/close$' {
                if ($method -ne 'POST') {
                    Write-AuditorErrorResponse -Stream $stream -Message 'Method not allowed' -StatusCode 405
                    return
                }
                Write-AuditorJsonResponse -Stream $stream -Data @{ message = 'Server stopping…' }
                $script:PortalServerStop = $true
                return
            }

            default {
                Write-AuditorErrorResponse -Stream $stream -Message 'Not found' -StatusCode 404
            }
        }
    }
    catch {
        Write-Warning "Route error [$method $path]: $_"
        try {
            Write-AuditorErrorResponse -Stream $stream `
                -Message "Internal server error: $($_.ToString())" -StatusCode 500
        }
        catch { Write-Verbose "Could not send error response: $_" }
    }
}
