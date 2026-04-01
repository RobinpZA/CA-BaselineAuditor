function Connect-CABaselineAuditor {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with scopes required for CA baseline auditing.
    .DESCRIPTION
        Wraps Connect-MgGraph supporting interactive browser auth or app-based
        (ClientId + TenantId + CertificateThumbprint). Falls back to Config/auth.json
        when no explicit parameters are provided.
    .PARAMETER TenantId
        Tenant ID or domain (e.g. contoso.onmicrosoft.com).
    .PARAMETER ClientId
        Application (client) ID for app-based authentication.
    .PARAMETER CertificateThumbprint
        Certificate thumbprint for app-based authentication.
    .EXAMPLE
        Connect-CABaselineAuditor
    .EXAMPLE
        Connect-CABaselineAuditor -TenantId 'contoso.onmicrosoft.com' -ClientId '...' -CertificateThumbprint '...'
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$CertificateThumbprint
    )

    # If no explicit params, try Config/auth.json
    if (-not $ClientId -and -not $TenantId) {
        $configPath = Join-Path $script:ModuleRoot 'Config' 'auth.json'
        if (Test-Path $configPath) {
            Write-Host '[CA-BaselineAuditor] Loading credentials from Config/auth.json' -ForegroundColor DarkGray
            $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
            if ($config.ClientId -and $config.ClientId -ne 'YOUR-APPLICATION-CLIENT-ID') {
                $ClientId              = $config.ClientId
                $TenantId              = $config.TenantId
                $CertificateThumbprint = $config.CertificateThumbprint
            }
        }
    }

    $requiredScopes = @(
        'Policy.Read.All'
        'Directory.Read.All'
        'Device.Read.All'
        'DeviceManagementManagedDevices.Read.All'
        'Organization.Read.All'
    )

    $connectParams = @{ NoWelcome = $true }

    if ($ClientId -and $TenantId -and $CertificateThumbprint) {
        # App-based authentication
        $connectParams['ClientId']              = $ClientId
        $connectParams['TenantId']              = $TenantId
        $connectParams['CertificateThumbprint'] = $CertificateThumbprint
        Write-Host '[CA-BaselineAuditor] Connecting via app registration...' -ForegroundColor Cyan
    } else {
        # Interactive browser auth
        $connectParams['Scopes'] = $requiredScopes
        if ($TenantId) { $connectParams['TenantId'] = $TenantId }
        Write-Host '[CA-BaselineAuditor] Connecting interactively...' -ForegroundColor Cyan
    }

    Connect-MgGraph @connectParams

    $ctx = Get-MgContext
    if (-not $ctx) {
        throw 'Failed to connect to Microsoft Graph. Please check your credentials and try again.'
    }

    $script:CABAAuthContext = @{
        Mode     = if ($ClientId) { 'App' } else { 'Interactive' }
        TenantId = $ctx.TenantId
        Account  = $ctx.Account
    }

    Write-Host "[CA-BaselineAuditor] Connected to tenant: $($ctx.TenantId)" -ForegroundColor Green
    Write-Host "[CA-BaselineAuditor] Account: $($ctx.Account)" -ForegroundColor Green
    Write-Host "[CA-BaselineAuditor] Auth mode: $($script:CABAAuthContext.Mode)" -ForegroundColor DarkGray

    # Warn about any missing optional scopes (app auth gets scopes from the app registration,
    # not from the Scopes parameter, so mismatches surface here rather than at connect time).
    $grantedScopes = @($ctx.Scopes ?? @())
    $optionalScopes = @{
        'DeviceManagementManagedDevices.Read.All' = 'Intune device data will be unavailable — falling back to Entra isManaged field'
    }
    foreach ($scope in $optionalScopes.Keys) {
        if ($scope -notin $grantedScopes) {
            Write-Host "[CA-BaselineAuditor] Optional scope not granted: $scope — $($optionalScopes[$scope])" -ForegroundColor Yellow
        }
    }

    $ctx
}
