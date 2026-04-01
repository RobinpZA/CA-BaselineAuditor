function Test-CAAdminCoverage {
    <#
    .SYNOPSIS
        Checks if admin roles are specifically targeted by CA policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies,

        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $enabledPolicies = @($CurrentPolicies | Where-Object { $_.state -eq 'enabled' })
    $adminMembers = $TenantContext.AdminRoleMembers

    # Find policies that specifically target admin roles
    $adminPolicies = @($enabledPolicies | Where-Object {
        ($_.conditions.users.includeRoles -and $_.conditions.users.includeRoles.Count -gt 0)
    })

    # Find policies that target all users (also cover admins)
    $allUserPolicies = @($enabledPolicies | Where-Object {
        $_.conditions.users.includeUsers -contains 'All'
    })

    # Check for MFA + compliance policies targeting admins
    $adminMfaPolicy = @($adminPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa' -or
        $_.grantControls.authenticationStrength
    })

    $adminCompliancePolicy = @($adminPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'compliantDevice' -or
        $_.grantControls.builtInControls -contains 'domainJoinedDevice'
    })

    $findings = [System.Collections.Generic.List[string]]::new()
    $status = 'Pass'

    if ($adminPolicies.Count -eq 0 -and $allUserPolicies.Count -eq 0) {
        $status = 'Fail'
        $findings.Add('No CA policies target admin roles or all users')
    }

    if ($adminMfaPolicy.Count -eq 0) {
        if ($status -ne 'Fail') { $status = 'Warning' }
        $findings.Add('No admin-specific MFA policy found (CAU008 recommended)')
    }

    if ($adminCompliancePolicy.Count -eq 0) {
        if ($status -ne 'Fail') { $status = 'Warning' }
        $findings.Add('No admin-specific device compliance policy found (CAD012 recommended)')
    }

    if ($status -eq 'Pass') {
        $findings.Add("$($adminPolicies.Count) admin-targeted policies found ($($adminMfaPolicy.Count) MFA, $($adminCompliancePolicy.Count) compliance)")
    }

    [PSCustomObject]@{
        Status              = $status
        Finding             = $findings -join '; '
        Severity            = switch ($status) { 'Fail' { 'Critical' } 'Warning' { 'High' } 'Pass' { 'Info' } }
        AdminPolicyCount    = $adminPolicies.Count
        UniqueAdminCount    = $TenantContext.UniqueAdminCount
        AdminMfaPolicies    = $adminMfaPolicy.Count
        AdminDevicePolicies = $adminCompliancePolicy.Count
    }
}
