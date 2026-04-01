function Get-CACurrentPolicies {
    <#
    .SYNOPSIS
        Retrieves all Conditional Access policies from the tenant.
    .DESCRIPTION
        Fetches every CA policy via Microsoft Graph (enabled, report-only, and disabled)
        with full pagination support. Returns normalised policy objects with a friendly
        StateLabel property.
    .PARAMETER IncludeDisabled
        Include disabled policies in the output (included by default for the audit).
    .EXAMPLE
        $policies = Get-CACurrentPolicies
    #>
    [CmdletBinding()]
    param(
        [switch]$IncludeDisabled = $true
    )

    Write-Host '[CA-BaselineAuditor] Retrieving Conditional Access policies...' -ForegroundColor Cyan

    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
    $allPolicies = [System.Collections.Generic.List[object]]::new()

    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($policy in $response.value) {
            # Add friendly state label
            $policy['StateLabel'] = switch ($policy.state) {
                'enabled'                          { 'Enabled' }
                'enabledForReportingButNotEnforced' { 'Report-Only' }
                'disabled'                         { 'Disabled' }
                default                            { $policy.state }
            }
            $allPolicies.Add($policy)
        }
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    $enabled    = @($allPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    $reportOnly = @($allPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count
    $disabled   = @($allPolicies | Where-Object { $_.state -eq 'disabled' }).Count

    Write-Host "[CA-BaselineAuditor] Found $($allPolicies.Count) policies: $enabled enabled, $reportOnly report-only, $disabled disabled" -ForegroundColor Green

    if (-not $IncludeDisabled) {
        $allPolicies = [System.Collections.Generic.List[object]]@($allPolicies | Where-Object { $_.state -ne 'disabled' })
    }

    $allPolicies
}
