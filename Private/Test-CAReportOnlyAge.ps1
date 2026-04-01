function Test-CAReportOnlyAge {
    <#
    .SYNOPSIS
        Flags policies stuck in report-only mode for more than 30 days.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies
    )

    $reportOnly = @($CurrentPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

    if ($reportOnly.Count -eq 0) {
        return [PSCustomObject]@{
            Status   = 'Pass'
            Finding  = 'No policies are in Report-Only mode'
            Severity = 'Info'
            StaleCount = 0
            StalePolicies = @()
        }
    }

    $now = Get-Date
    $stalePolicies = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $reportOnly) {
        $modified = $null
        $created  = $null

        if ($policy.modifiedDateTime) { $modified = [datetime]$policy.modifiedDateTime }
        if ($policy.createdDateTime)  { $created  = [datetime]$policy.createdDateTime }

        $referenceDate = $modified ?? $created
        $ageInDays = if ($referenceDate) { ($now - $referenceDate).Days } else { -1 }

        if ($ageInDays -gt 30 -or $ageInDays -eq -1) {
            $stalePolicies.Add([PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyId   = $policy.id
                AgeInDays  = $ageInDays
                LastModified = $referenceDate
            })
        }
    }

    $status = if ($stalePolicies.Count -gt 0) { 'Warning' } else { 'Pass' }

    [PSCustomObject]@{
        Status        = $status
        Finding       = if ($stalePolicies.Count -gt 0) {
            "$($stalePolicies.Count) of $($reportOnly.Count) report-only policies are older than 30 days. Review and either enable or remove them."
        } else {
            "$($reportOnly.Count) report-only policies exist, all recently modified (< 30 days)."
        }
        Severity      = if ($stalePolicies.Count -gt 3) { 'High' } elseif ($stalePolicies.Count -gt 0) { 'Medium' } else { 'Info' }
        StaleCount    = $stalePolicies.Count
        StalePolicies = @($stalePolicies)
    }
}
