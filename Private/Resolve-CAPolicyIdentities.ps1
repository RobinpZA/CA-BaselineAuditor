function Resolve-CAPolicyIdentities {
    <#
    .SYNOPSIS
        Resolves user, group, and role GUIDs in CA policies to display names.
    .DESCRIPTION
        Collects all unique object IDs referenced in Conditional Access policy user
        conditions, then resolves them via the Microsoft Graph API. Roles are resolved
        with a single roleDefinitions call; users and groups are resolved in batches
        of up to 20 using the Graph batch endpoint. Returns a case-insensitive hashtable
        mapping each GUID to its display name for use in the Policy Flow Visualizer.
    .PARAMETER Policies
        Array of CA policy objects as returned by Get-CACurrentPolicies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Policies
    )

    $lookup = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Special placeholder values that are not resolvable GUIDs
    $specialValues = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]@('All', 'None', 'GuestsOrExternalUsers'),
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $userIds    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $groupIds   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $roleIds    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $authCtxIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($policy in $Policies) {
        $u = $policy.conditions.users
        if ($null -eq $u) { continue }
        foreach ($id in ($u.includeUsers  ?? @())) { if (-not $specialValues.Contains($id)) { [void]$userIds.Add($id)  } }
        foreach ($id in ($u.excludeUsers  ?? @())) { if (-not $specialValues.Contains($id)) { [void]$userIds.Add($id)  } }
        foreach ($id in ($u.includeGroups ?? @())) { [void]$groupIds.Add($id) }
        foreach ($id in ($u.excludeGroups ?? @())) { [void]$groupIds.Add($id) }
        foreach ($id in ($u.includeRoles  ?? @())) { [void]$roleIds.Add($id)  }
        foreach ($id in ($u.excludeRoles  ?? @())) { [void]$roleIds.Add($id)  }
        $apps = $policy.conditions.applications
        if (-not $apps) {
            # Try hashtable-style access in case the policy is an OrderedDictionary
            $conds = if ($policy -is [System.Collections.IDictionary]) { $policy['conditions'] } else { $policy.conditions }
            $apps  = if ($conds -is [System.Collections.IDictionary]) { $conds['applications'] } else { $conds?.applications }
        }
        if ($apps) {
            $authCtxRefs = if ($apps -is [System.Collections.IDictionary]) {
                @($apps['includeAuthenticationContextClassReferences'] ?? @())
            } else {
                @($apps.includeAuthenticationContextClassReferences ?? @())
            }
            foreach ($ctx in $authCtxRefs) {
                $ctxId = if ($ctx -is [string]) { $ctx }
                         elseif ($ctx -is [System.Collections.IDictionary]) { $ctx['id'] }
                         else { $ctx.id ?? $null }
                if ($ctxId) { [void]$authCtxIds.Add($ctxId) }
            }
        }
    }

    Write-Verbose "[Resolve-CAPolicyIdentities] Resolving $($userIds.Count) users, $($groupIds.Count) groups, $($roleIds.Count) roles, $($authCtxIds.Count) auth contexts"

    # ── Auth context class references ──
    # Fetch all tenant auth contexts unconditionally — cheap single GET, avoids missing any
    # due to extraction edge cases. Requires Policy.Read.All.
    try {
        $uri     = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences'
        $ctxPage = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        # Normalise regardless of whether the SDK returns Hashtable, OrderedDictionary, or PSCustomObject
        $ctxRaw  = if ($ctxPage -is [System.Collections.IDictionary]) { $ctxPage['value'] } else { $ctxPage.value }
        $ctxList = @($ctxRaw ?? @())
        foreach ($c in $ctxList) {
            $cId   = if ($c -is [System.Collections.IDictionary]) { $c['id'] }   else { $c.id }
            $cName = if ($c -is [System.Collections.IDictionary]) { $c['displayName'] } else { $c.displayName }
            if ($cId -and $cName) {
                $lookup[$cId] = $cName
            }
        }
        Write-Host "[CA-BaselineAuditor] Auth context class references loaded: $($ctxList.Count) (resolved: $(($ctxList | Where-Object { ($_ -is [System.Collections.IDictionary] -and $_['id'] -and $_['displayName']) -or ($_.id -and $_.displayName) }).Count))" -ForegroundColor DarkGray
    } catch {
        Write-Host "[CA-BaselineAuditor] Auth context class references call failed: $_" -ForegroundColor Yellow
    }

    # ── Roles: directoryRoleTemplates — the .id here IS the template ID used in CA policies ──
    if ($roleIds.Count -gt 0) {
        try {
            $uri      = 'https://graph.microsoft.com/v1.0/directoryRoleTemplates?$select=id,displayName'
            $rolePage = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($r in $rolePage.value) {
                if ($r.id -and $r.displayName) { $lookup[$r.id] = $r.displayName }
            }
        } catch {
            Write-Verbose "[Resolve-CAPolicyIdentities] directoryRoleTemplates call failed: $_"
        }
    }

    # ── Users and groups: Graph batch API, 20 requests per call ──
    $targets = @(
        [pscustomobject]@{ Type = 'users';  Ids = @($userIds);  Select = 'displayName,userPrincipalName' }
        [pscustomobject]@{ Type = 'groups'; Ids = @($groupIds); Select = 'displayName' }
    )

    foreach ($target in $targets) {
        if ($target.Ids.Count -eq 0) { continue }
        for ($i = 0; $i -lt $target.Ids.Count; $i += 20) {
            $slice    = $target.Ids[$i..[Math]::Min($i + 19, $target.Ids.Count - 1)]
            $requests = @(for ($j = 0; $j -lt $slice.Count; $j++) {
                @{ id = [string]$j; method = 'GET'; url = "/$($target.Type)/$($slice[$j])?`$select=$($target.Select)" }
            })
            try {
                $json     = @{ requests = $requests } | ConvertTo-Json -Depth 5 -Compress
                $batchOut = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                    -Body $json -ContentType 'application/json' -ErrorAction Stop
                foreach ($resp in $batchOut.responses) {
                    if ($resp.status -eq 200 -or $resp.status -eq '200') {
                        $oid  = $slice[[int]$resp.id]
                        $body = $resp.body
                        if ($body) {
                            $name = if ($target.Type -eq 'users') {
                                $body.displayName ?? $body.userPrincipalName
                            } else {
                                $body.displayName
                            }
                            if ($name) { $lookup[$oid] = $name }
                        }
                    }
                }
            } catch {
                Write-Verbose "[Resolve-CAPolicyIdentities] Batch call failed for $($target.Type) at offset $i`: $_"
            }
        }
    }

    Write-Verbose "[Resolve-CAPolicyIdentities] Resolved $($lookup.Count) identities total"
    return $lookup
}
