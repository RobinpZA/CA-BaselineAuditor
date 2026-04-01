function Test-CAGuestPolicies {
    <#
    .SYNOPSIS
        Checks whether guest/external users are covered by CA policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies,

        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $enabledPolicies = @($CurrentPolicies | Where-Object { $_.state -eq 'enabled' })
    $guestCount = $TenantContext.GuestUserCount

    # Find policies targeting guests
    $guestPolicies = @($enabledPolicies | Where-Object {
        $_.conditions.users.includeGuestsOrExternalUsers -or
        ($_.conditions.users.includeUsers -contains 'GuestsOrExternalUsers')
    })

    # Find policies targeting all users (also cover guests unless excluded)
    $allUserPoliciesExcludingGuests = @($enabledPolicies | Where-Object {
        ($_.conditions.users.includeUsers -contains 'All') -and
        ($_.conditions.users.excludeGuestsOrExternalUsers)
    })

    $guestMfaPolicies = @($guestPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'mfa'
    })

    $guestBlockPolicies = @($guestPolicies | Where-Object {
        $_.grantControls.builtInControls -contains 'block'
    })

    $status = if ($guestCount -eq 0) { 'Pass' }
              elseif ($guestPolicies.Count -eq 0) { 'Fail' }
              elseif ($guestMfaPolicies.Count -eq 0) { 'Warning' }
              else { 'Pass' }

    $finding = if ($guestCount -eq 0) {
        'No guest users in tenant — guest policies are not currently critical.'
    } elseif ($guestPolicies.Count -eq 0) {
        "$guestCount guest users exist but no CA policies specifically target guests. Deploy CAU001 (Guest MFA) and CAU003 (Guest app blocking)."
    } elseif ($guestMfaPolicies.Count -eq 0) {
        "$($guestPolicies.Count) guest-targeted policies exist but none require MFA. Deploy CAU001."
    } else {
        "$($guestPolicies.Count) guest-targeted policies ($($guestMfaPolicies.Count) MFA, $($guestBlockPolicies.Count) block). $guestCount guest users covered."
    }

    [PSCustomObject]@{
        Status           = $status
        Finding          = $finding
        Severity         = switch ($status) { 'Fail' { 'High' } 'Warning' { 'Medium' } 'Pass' { 'Info' } }
        GuestCount       = $guestCount
        GuestPolicyCount = $guestPolicies.Count
        GuestMfaPolicies = $guestMfaPolicies.Count
    }
}
