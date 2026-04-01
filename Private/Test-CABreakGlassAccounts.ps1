function Test-CABreakGlassAccounts {
    <#
    .SYNOPSIS
        Identifies break-glass/emergency access accounts by analysing policy exclusions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies,

        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $enabledPolicies = @($CurrentPolicies | Where-Object { $_.state -eq 'enabled' })
    if ($enabledPolicies.Count -eq 0) {
        return [PSCustomObject]@{
            Status        = 'Warning'
            Finding       = 'No enabled CA policies found — cannot identify break-glass accounts'
            BreakGlass    = @()
            Severity      = 'High'
        }
    }

    # Count how many enabled policies each excluded user appears in
    $userExclusions = @{}
    foreach ($policy in $enabledPolicies) {
        $excludedUsers = $policy.conditions.users.excludeUsers ?? @()
        foreach ($userId in $excludedUsers) {
            if ($userId -eq 'GuestsOrExternalUsers') { continue }
            if (-not $userExclusions.ContainsKey($userId)) { $userExclusions[$userId] = 0 }
            $userExclusions[$userId]++
        }
    }

    # Accounts excluded from >= 80% of enabled policies are likely break-glass
    $threshold = [math]::Max(1, [math]::Floor($enabledPolicies.Count * 0.8))
    $breakGlassIds = @($userExclusions.Keys | Where-Object { $userExclusions[$_] -ge $threshold })

    # Resolve display names from admin role members
    $breakGlassAccounts = foreach ($bgId in $breakGlassIds) {
        $adminMatch = $TenantContext.AdminRoleMembers | Where-Object { $_.UserId -eq $bgId } | Select-Object -First 1
        [PSCustomObject]@{
            UserId            = $bgId
            DisplayName       = $adminMatch.DisplayName ?? 'Unknown'
            UserPrincipalName = $adminMatch.UserPrincipalName ?? 'Unknown'
            ExcludedFrom      = $userExclusions[$bgId]
            TotalPolicies     = $enabledPolicies.Count
        }
    }

    $status  = if ($breakGlassAccounts.Count -ge 2) { 'Pass' }
               elseif ($breakGlassAccounts.Count -eq 1) { 'Warning' }
               else { 'Fail' }

    $finding = switch ($status) {
        'Pass'    { "$($breakGlassAccounts.Count) break-glass accounts detected (excluded from $threshold+ of $($enabledPolicies.Count) policies)" }
        'Warning' { 'Only 1 potential break-glass account detected. Best practice is to have at least 2.' }
        'Fail'    { 'No break-glass accounts detected. Emergency access accounts should be excluded from CA policies.' }
    }

    [PSCustomObject]@{
        Status     = $status
        Finding    = $finding
        BreakGlass = @($breakGlassAccounts)
        Severity   = switch ($status) { 'Pass' { 'Info' } 'Warning' { 'Medium' } 'Fail' { 'Critical' } }
    }
}
