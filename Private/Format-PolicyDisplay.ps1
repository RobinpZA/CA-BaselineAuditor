function Get-WellKnownAppId {
    <#
    .SYNOPSIS
        Returns a hashtable mapping well-known application IDs to friendly names.
    #>
    [CmdletBinding()]
    param()

    @{
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '67ad5377-2d78-4ac2-a867-6300cda00e85' = 'Office 365'
        '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'
        'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Azure Service Management'
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Azure CLI'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Azure PowerShell'
        '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
        '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'
        'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment'
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Microsoft 365 Compliance Center'
        '00000007-0000-0ff1-ce00-000000000000' = 'Microsoft Power BI'
        'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams'
        '5e3ce6c0-2b1f-4285-8d4b-75ee78787346' = 'Microsoft Teams Web Client'
        '00000015-0000-0000-c000-000000000000' = 'Microsoft Dynamics CRM'
        'fc780465-2017-40d4-a0c5-307022471b92' = 'Microsoft Exchange REST API'
        '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management APIs'
        '09abbdfd-ed23-44ee-a2d9-a627aa1c90f3' = 'Microsoft Defender for Cloud Apps'
        '00000002-0000-0000-c000-000000000000' = 'Azure Active Directory (legacy)'
        'Office365'                             = 'Office 365 (Suite)'
        'MicrosoftAdminPortals'                 = 'Microsoft Admin Portals'
        'All'                                   = 'All Cloud Apps'
        'None'                                  = 'No Cloud Apps'
    }
}

function Format-GrantControls {
    <#
    .SYNOPSIS
        Formats grant controls from a CA policy into a human-readable string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy
    )

    if (-not $Policy.grantControls) {
        return 'None (Session controls only)'
    }

    $gc = $Policy.grantControls
    $controls = @()

    if ($gc.builtInControls) {
        foreach ($ctrl in $gc.builtInControls) {
            switch ($ctrl) {
                'mfa'                 { $controls += 'Require MFA' }
                'block'               { $controls += 'Block Access' }
                'compliantDevice'     { $controls += 'Require Compliant Device' }
                'domainJoinedDevice'  { $controls += 'Require Hybrid Azure AD Join' }
                'approvedApplication' { $controls += 'Require Approved App' }
                'compliantApplication' { $controls += 'Require App Protection Policy' }
                'passwordChange'      { $controls += 'Require Password Change' }
                default               { $controls += $ctrl }
            }
        }
    }

    if ($gc.authenticationStrength) {
        $name = $gc.authenticationStrength.displayName ?? 'Custom'
        $controls += "Auth Strength: $name"
    }

    if ($gc.termsOfUse -and $gc.termsOfUse.Count -gt 0) {
        $controls += "Terms of Use ($($gc.termsOfUse.Count))"
    }

    $operator = if ($gc.operator) { " $($gc.operator) " } else { ' AND ' }
    ($controls -join $operator).Trim()
}

function Format-SessionControls {
    <#
    .SYNOPSIS
        Formats session controls from a CA policy into a human-readable string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy
    )

    if (-not $Policy.sessionControls) { return 'None' }

    $sc = $Policy.sessionControls
    $controls = @()

    if ($sc.signInFrequency.isEnabled) {
        $controls += "Sign-in frequency: $($sc.signInFrequency.value) $($sc.signInFrequency.type)"
    }

    if ($sc.persistentBrowser.isEnabled) {
        $controls += "Persistent browser: $($sc.persistentBrowser.mode)"
    }

    if ($sc.applicationEnforcedRestrictions.isEnabled) {
        $controls += 'App enforced restrictions'
    }

    if ($sc.cloudAppSecurity.isEnabled) {
        $type = $sc.cloudAppSecurity.cloudAppSecurityType ?? 'enabled'
        $controls += "MDCA routing ($type)"
    }

    if ($sc.continuousAccessEvaluation.mode) {
        $controls += "CAE: $($sc.continuousAccessEvaluation.mode)"
    }

    if ($controls.Count -eq 0) { return 'None' }
    $controls -join ', '
}

function Format-TargetApps {
    <#
    .SYNOPSIS
        Formats application targeting from a CA policy into a compact display string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy
    )

    $appMap = Get-WellKnownAppId
    $apps = $Policy.conditions.applications

    if ($apps.includeUserActions -and $apps.includeUserActions.Count -gt 0) {
        $actions = foreach ($a in $apps.includeUserActions) {
            switch ($a) {
                'urn:user:registerdevice'         { 'Register/Join Devices' }
                'urn:user:registersecurityinfo'    { 'Register Security Info' }
                default                           { $a }
            }
        }
        return "Actions: $($actions -join ', ')"
    }

    $included = $apps.includeApplications ?? @()
    if ($included -contains 'All') { return 'All Cloud Apps' }
    if ($included -contains 'Office365') { return 'Office 365' }
    if ($included -contains 'MicrosoftAdminPortals') { return 'Microsoft Admin Portals' }

    $names = foreach ($id in $included) {
        if ($appMap.ContainsKey($id)) { $appMap[$id] } else { $id.Substring(0, [math]::Min(8, $id.Length)) + '...' }
    }

    if ($names.Count -le 3) { return $names -join ', ' }
    return "$($names[0..1] -join ', ') +$($names.Count - 2) more"
}

function Format-TargetUsers {
    <#
    .SYNOPSIS
        Formats user targeting from a CA policy into a compact display string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Policy
    )

    $users = $Policy.conditions.users

    if ($users.includeUsers -contains 'All') {
        $excludeCount = ($users.excludeUsers ?? @()).Count + ($users.excludeGroups ?? @()).Count
        if ($excludeCount -gt 0) { return "All users (-$excludeCount exclusions)" }
        return 'All users'
    }

    if ($users.includeGuestsOrExternalUsers) { return 'Guests / External Users' }

    $parts = @()
    if ($users.includeRoles -and $users.includeRoles.Count -gt 0) {
        $parts += "$($users.includeRoles.Count) admin roles"
    }
    if ($users.includeGroups -and $users.includeGroups.Count -gt 0) {
        $parts += "$($users.includeGroups.Count) groups"
    }
    if ($users.includeUsers -and $users.includeUsers.Count -gt 0) {
        $parts += "$($users.includeUsers.Count) users"
    }

    if ($parts.Count -eq 0) { return 'None specified' }
    $parts -join ', '
}
