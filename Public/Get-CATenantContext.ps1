function Get-CATenantContext {
    <#
    .SYNOPSIS
        Gathers supplementary tenant context needed for security posture checks.
    .DESCRIPTION
        Collects named locations, directory role assignments, authentication methods
        policy, security defaults status, guest user count, and break-glass account
        candidates to support the full CA audit.
    .EXAMPLE
        $context = Get-CATenantContext
    #>
    [CmdletBinding()]
    param()

    Write-Host '[CA-BaselineAuditor] Collecting tenant context...' -ForegroundColor Cyan

    # ── Named locations ──
    $namedLocations = [System.Collections.Generic.List[object]]::new()
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations'
        foreach ($loc in $resp.value) { $namedLocations.Add($loc) }
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve named locations: $($_.Exception.Message)"
    }

    # ── Directory roles and members (admin accounts) ──
    $adminRoleMembers = [System.Collections.Generic.List[object]]::new()
    $criticalRoles = @(
        'Global Administrator', 'Privileged Role Administrator', 'Security Administrator',
        'Conditional Access Administrator', 'Exchange Administrator', 'SharePoint Administrator',
        'User Administrator', 'Authentication Administrator', 'Billing Administrator',
        'Cloud Application Administrator', 'Application Administrator', 'Intune Administrator',
        'Helpdesk Administrator', 'Password Administrator'
    )
    try {
        $roles = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/directoryRoles?$select=id,displayName').value
        foreach ($role in $roles) {
            if ($role.displayName -notin $criticalRoles) { continue }
            try {
                $members = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName,userPrincipalName").value
                foreach ($m in $members) {
                    $adminRoleMembers.Add([PSCustomObject]@{
                        RoleName           = $role.displayName
                        UserId             = $m.id
                        DisplayName        = $m.displayName
                        UserPrincipalName  = $m.userPrincipalName
                    })
                }
            } catch {
                # Some roles may not have members endpoint
            }
        }
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve directory roles: $($_.Exception.Message)"
    }

    # ── Authentication methods policy ──
    $authMethodsPolicy = $null
    try {
        $authMethodsPolicy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve auth methods policy: $($_.Exception.Message)"
    }

    # ── Security defaults ──
    $securityDefaults = $null
    try {
        $securityDefaults = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve security defaults: $($_.Exception.Message)"
    }

    # ── Guest user count ──
    $guestCount = 0
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/`$count?`$filter=userType eq 'Guest'" -Headers @{ ConsistencyLevel = 'eventual' }
        $guestCount = [int]$resp
    } catch {
        try {
            # Fallback: fetch a page and use @odata.count
            $resp = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$count=true&`$top=1&`$select=id" -Headers @{ ConsistencyLevel = 'eventual' }
            $guestCount = $resp.'@odata.count'
        } catch {
            Write-Warning "[CA-BaselineAuditor] Could not count guest users: $($_.Exception.Message)"
        }
    }

    # ── Tenant info (org name) ──
    $tenantName = 'Unknown Tenant'
    $tenantDomain = ''
    try {
        $org = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName,verifiedDomains').value[0]
        $tenantName = $org.displayName
        $primary = $org.verifiedDomains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
        if ($primary) { $tenantDomain = $primary.name }
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve org info: $($_.Exception.Message)"
    }

    $result = [PSCustomObject]@{
        TenantName        = $tenantName
        TenantDomain      = $tenantDomain
        NamedLocations    = $namedLocations
        AdminRoleMembers  = $adminRoleMembers
        UniqueAdminCount  = @($adminRoleMembers | Select-Object -Property UserId -Unique).Count
        AuthMethodsPolicy = $authMethodsPolicy
        SecurityDefaults  = $securityDefaults
        GuestUserCount    = $guestCount
    }

    Write-Host "[CA-BaselineAuditor] Tenant: $tenantName | Named locations: $($namedLocations.Count) | Admins: $($result.UniqueAdminCount) | Guests: $guestCount" -ForegroundColor Green

    $result
}
