function Test-CAPolicyExclusions {
    <#
    .SYNOPSIS
        Analyses exclusion patterns across all CA policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies
    )

    $enabledPolicies = @($CurrentPolicies | Where-Object { $_.state -eq 'enabled' })
    $findings = [System.Collections.Generic.List[string]]::new()
    $overExcluded = [System.Collections.Generic.List[object]]::new()

    foreach ($policy in $enabledPolicies) {
        $excludedUsers  = ($policy.conditions.users.excludeUsers ?? @()).Count
        $excludedGroups = ($policy.conditions.users.excludeGroups ?? @()).Count
        $excludedRoles  = ($policy.conditions.users.excludeRoles ?? @()).Count
        $totalExclusions = $excludedUsers + $excludedGroups + $excludedRoles

        if ($totalExclusions -gt 10) {
            $overExcluded.Add([PSCustomObject]@{
                PolicyName     = $policy.displayName
                PolicyId       = $policy.id
                ExcludedUsers  = $excludedUsers
                ExcludedGroups = $excludedGroups
                ExcludedRoles  = $excludedRoles
                Total          = $totalExclusions
            })
        }
    }

    # Check for policies with no target (empty include)
    $emptyTarget = @($enabledPolicies | Where-Object {
        -not $_.conditions.users.includeUsers -and
        -not $_.conditions.users.includeGroups -and
        -not $_.conditions.users.includeRoles -and
        -not $_.conditions.users.includeGuestsOrExternalUsers
    })

    $status = if ($overExcluded.Count -gt 0 -or $emptyTarget.Count -gt 0) { 'Warning' } else { 'Pass' }

    if ($overExcluded.Count -gt 0) {
        $findings.Add("$($overExcluded.Count) policies have >10 exclusions (potential over-exclusion)")
    }
    if ($emptyTarget.Count -gt 0) {
        $findings.Add("$($emptyTarget.Count) policies have no user/group targeting (may not apply to anyone)")
    }
    if ($findings.Count -eq 0) {
        $findings.Add('Exclusion patterns look healthy across all enabled policies')
    }

    [PSCustomObject]@{
        Status         = $status
        Finding        = $findings -join '; '
        Severity       = if ($overExcluded.Count -gt 3) { 'High' } elseif ($overExcluded.Count -gt 0) { 'Medium' } else { 'Info' }
        OverExcluded   = @($overExcluded)
        EmptyTargets   = $emptyTarget.Count
    }
}
