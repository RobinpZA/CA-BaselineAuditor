function Test-CAPolicyConflicts {
    <#
    .SYNOPSIS
        Detects potential conflicts between CA policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies
    )

    $enabledPolicies = @($CurrentPolicies | Where-Object { $_.state -eq 'enabled' })
    $conflicts = [System.Collections.Generic.List[object]]::new()

    # Check for block + grant overlap on same scope
    $blockPolicies = @($enabledPolicies | Where-Object { $_.grantControls.builtInControls -contains 'block' })
    $grantPolicies = @($enabledPolicies | Where-Object {
        $_.grantControls.builtInControls -and
        $_.grantControls.builtInControls -notcontains 'block'
    })

    foreach ($block in $blockPolicies) {
        foreach ($grant in $grantPolicies) {
            # Simple overlap check: same application scope and overlapping user scope
            $blockApps = $block.conditions.applications.includeApplications ?? @()
            $grantApps = $grant.conditions.applications.includeApplications ?? @()
            $appOverlap = ($blockApps -contains 'All' -and $grantApps -contains 'All') -or
                          ($blockApps -contains 'All' -or $grantApps -contains 'All') -or
                          (Compare-StringArrayOverlap $blockApps $grantApps)

            $blockUsers = $block.conditions.users.includeUsers ?? @()
            $grantUsers = $grant.conditions.users.includeUsers ?? @()
            $userOverlap = ($blockUsers -contains 'All' -and $grantUsers -contains 'All')

            if ($appOverlap -and $userOverlap) {
                # Check if the block has narrower conditions (e.g., client app type, risk, platform)
                # This is expected for policies like "Block legacy auth" + "Require MFA for all"
                $blockClients = $block.conditions.clientAppTypes ?? @()
                $grantClients = $grant.conditions.clientAppTypes ?? @()
                $sameClients = ($blockClients -join ',') -eq ($grantClients -join ',')

                if ($sameClients) {
                    $conflicts.Add([PSCustomObject]@{
                        Type           = 'Block+Grant Overlap'
                        BlockPolicy    = $block.displayName
                        BlockPolicyId  = $block.id
                        GrantPolicy    = $grant.displayName
                        GrantPolicyId  = $grant.id
                        Description    = "Both policies target the same users, apps, and client types with conflicting controls."
                    })
                }
            }
        }
    }

    # Check for duplicate policies (same name pattern)
    $nameGroups = $enabledPolicies | Group-Object { ($_.displayName -replace '\s*v\d+\.\d+$', '').Trim() } | Where-Object { $_.Count -gt 1 }
    foreach ($group in $nameGroups) {
        $conflicts.Add([PSCustomObject]@{
            Type        = 'Potential Duplicate'
            Policies    = $group.Group.displayName -join ' | '
            PolicyIds   = $group.Group.id -join ', '
            Description = "Multiple policies with similar names may be redundant."
        })
    }

    [PSCustomObject]@{
        Status    = if ($conflicts.Count -gt 0) { 'Warning' } else { 'Pass' }
        Finding   = if ($conflicts.Count -gt 0) {
            "$($conflicts.Count) potential conflicts or duplicates detected"
        } else {
            'No policy conflicts detected'
        }
        Severity  = if ($conflicts.Count -gt 3) { 'High' } elseif ($conflicts.Count -gt 0) { 'Medium' } else { 'Info' }
        Conflicts = @($conflicts)
    }
}
