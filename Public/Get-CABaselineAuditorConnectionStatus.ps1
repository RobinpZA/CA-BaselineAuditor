function Get-CABaselineAuditorConnectionStatus {
    <#
    .SYNOPSIS
        Returns the current Microsoft Graph connection status for CA-BaselineAuditor.
    .EXAMPLE
        Get-CABaselineAuditorConnectionStatus
    #>
    [CmdletBinding()]
    param()

    $ctx = Get-MgContext
    if (-not $ctx) {
        Write-Warning 'Not connected to Microsoft Graph. Run Connect-CABaselineAuditor first.'
        return $null
    }

    [PSCustomObject]@{
        Connected = $true
        TenantId  = $ctx.TenantId
        Account   = $ctx.Account
        AuthMode  = if ($script:CABAAuthContext) { $script:CABAAuthContext.Mode } else { 'Unknown' }
        Scopes    = $ctx.Scopes
    }
}
