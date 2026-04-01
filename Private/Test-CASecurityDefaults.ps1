function Test-CASecurityDefaults {
    <#
    .SYNOPSIS
        Checks if Security Defaults are enabled (conflicts with CA policies).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $sd = $TenantContext.SecurityDefaults

    if (-not $sd) {
        return [PSCustomObject]@{
            Status   = 'Warning'
            Finding  = 'Could not retrieve Security Defaults status'
            Severity = 'Medium'
        }
    }

    $isEnabled = $sd.isEnabled -eq $true

    [PSCustomObject]@{
        Status   = if ($isEnabled) { 'Fail' } else { 'Pass' }
        Finding  = if ($isEnabled) {
            'Security Defaults are ENABLED. This conflicts with Conditional Access policies. Disable Security Defaults to use CA effectively.'
        } else {
            'Security Defaults are disabled (correct when using Conditional Access).'
        }
        Severity = if ($isEnabled) { 'Critical' } else { 'Info' }
    }
}
