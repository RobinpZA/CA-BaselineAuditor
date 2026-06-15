function Test-CABreakGlassAccounts {
    <#
    .SYNOPSIS
        Identifies break-glass/emergency access accounts by combining policy-exclusion
        analysis with best-practice account characteristics.
    .DESCRIPTION
        Candidates are accounts excluded from most enabled CA policies — directly via
        excludeUsers, or indirectly via an excluded group (excludeGroups) or directory
        role (excludeRoles). Each candidate is then scored against Microsoft emergency-
        access best practices:

          - excluded from the majority of enabled policies (entry criterion)
          - permanent (standing) Global Administrator assignment
          - sign-in on the tenant initial *.onmicrosoft.com domain
          - cloud-only account (not synced from on-premises)
          - password set never to expire
          - strong/phishing-resistant auth registered (FIDO2 or certificate)

        The weighted score yields a confidence rating (Confirmed/Likely/Possible),
        reducing false positives from broadly-scoped regular admins and closing the
        false-negative gap where accounts are excluded via a dedicated group/role.
    .PARAMETER CurrentPolicies
        The tenant's current Conditional Access policies.
    .PARAMETER TenantContext
        Tenant context from Get-CATenantContext (InitialDomain, PermanentGlobalAdmins,
        AdminRoleMembers).
    .EXAMPLE
        Test-CABreakGlassAccounts -CurrentPolicies $policies -TenantContext $context
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
            Status     = 'Warning'
            Finding    = 'No enabled CA policies found — cannot identify break-glass accounts'
            BreakGlass = @()
            Severity   = 'High'
        }
    }

    # ── Resolve excluded group/role members to user IDs (cached across policies) ──
    $memberCache = @{}
    function Resolve-ExcludedMembers {
        param([ValidateSet('group', 'role')] [string]$Kind, [string]$Id)
        $key = "${Kind}:${Id}"
        if ($memberCache.ContainsKey($key)) { return $memberCache[$key] }
        $ids = [System.Collections.Generic.List[string]]::new()
        try {
            $uri = if ($Kind -eq 'group') {
                "https://graph.microsoft.com/v1.0/groups/$Id/members?`$select=id&`$top=999"
            } else {
                "https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId='$Id')/members?`$select=id&`$top=999"
            }
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            foreach ($m in $resp.value) { if ($m.id) { $ids.Add([string]$m.id) } }
        } catch {
            Write-Verbose "[BreakGlass] Could not resolve $Kind ${Id}: $($_.Exception.Message)"
        }
        $memberCache[$key] = $ids
        $ids
    }

    # ── Tally per-user effective exclusions across enabled policies ──
    # Within a single policy each user is counted once, whether excluded directly,
    # by group, or by role.
    $userExclusions = @{}
    foreach ($policy in $enabledPolicies) {
        $effective = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($u in @($policy.conditions.users.excludeUsers)) {
            if (-not $u -or $u -eq 'GuestsOrExternalUsers') { continue }
            [void]$effective.Add([string]$u)
        }
        foreach ($g in @($policy.conditions.users.excludeGroups)) {
            if (-not $g) { continue }
            foreach ($mid in (Resolve-ExcludedMembers -Kind 'group' -Id $g)) { [void]$effective.Add($mid) }
        }
        foreach ($r in @($policy.conditions.users.excludeRoles)) {
            if (-not $r) { continue }
            foreach ($mid in (Resolve-ExcludedMembers -Kind 'role' -Id $r)) { [void]$effective.Add($mid) }
        }

        foreach ($id in $effective) {
            if (-not $userExclusions.ContainsKey($id)) { $userExclusions[$id] = 0 }
            $userExclusions[$id]++
        }
    }

    # Accounts excluded from >= 80% of enabled policies are break-glass candidates.
    $threshold    = [math]::Max(1, [math]::Floor($enabledPolicies.Count * 0.8))
    $candidateIds = @($userExclusions.Keys | Where-Object { $userExclusions[$_] -ge $threshold })

    $initialDomain = ([string]$TenantContext.InitialDomain).ToLowerInvariant()
    $permanentGAs  = @($TenantContext.PermanentGlobalAdmins)

    # ── Enrich each candidate with best-practice signals and score confidence ──
    $breakGlassAccounts = foreach ($id in $candidateIds) {
        $adminMatch  = $TenantContext.AdminRoleMembers | Where-Object { $_.UserId -eq $id } | Select-Object -First 1
        $displayName = $adminMatch.DisplayName ?? 'Unknown'
        $upn         = $adminMatch.UserPrincipalName ?? 'Unknown'

        $cloudOnly = $false
        $pwdNeverExpires = $false
        $strongAuth = $false

        # User object: resolve UPN, sync status, password policy.
        try {
            $user = Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
                -Uri "https://graph.microsoft.com/v1.0/users/$id`?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,passwordPolicies,accountEnabled"
            if ($user.displayName) { $displayName = $user.displayName }
            if ($user.userPrincipalName) { $upn = $user.userPrincipalName }
            $cloudOnly = -not [bool]$user.onPremisesSyncEnabled
            $pwdNeverExpires = ([string]$user.passwordPolicies) -match 'DisablePasswordExpiration'
        } catch {
            Write-Verbose "[BreakGlass] Could not read user ${id}: $($_.Exception.Message)"
        }

        # Authentication methods: FIDO2 or certificate == phishing-resistant.
        try {
            $methods = (Invoke-MgGraphRequest -Method GET -ErrorAction Stop `
                -Uri "https://graph.microsoft.com/v1.0/users/$id/authentication/methods").value
            $strongAuth = @($methods | Where-Object {
                $_.'@odata.type' -in @(
                    '#microsoft.graph.fido2AuthenticationMethod',
                    '#microsoft.graph.x509CertificateAuthenticationMethod'
                )
            }).Count -gt 0
        } catch {
            Write-Verbose "[BreakGlass] Could not read auth methods for ${id}: $($_.Exception.Message)"
        }

        $initialDomainUpn = $false
        if ($initialDomain -and $upn -and $upn -ne 'Unknown') {
            $initialDomainUpn = ([string]$upn).ToLowerInvariant().EndsWith("@$initialDomain")
        }
        $permanentGA = $permanentGAs -contains $id

        # ── Weighted confidence score (max 100) ──
        $score = 25  # baseline: excluded from the majority of enabled policies
        if ($permanentGA)      { $score += 25 }
        if ($initialDomainUpn) { $score += 20 }
        if ($cloudOnly)        { $score += 15 }
        if ($strongAuth)       { $score += 10 }
        if ($pwdNeverExpires)  { $score += 5 }

        $confidence = if ($score -ge 70) { 'Confirmed' }
                      elseif ($score -ge 45) { 'Likely' }
                      else { 'Possible' }

        [PSCustomObject]@{
            UserId               = $id
            DisplayName          = $displayName
            UserPrincipalName    = $upn
            ExcludedFrom         = $userExclusions[$id]
            TotalPolicies        = $enabledPolicies.Count
            PermanentGlobalAdmin = $permanentGA
            InitialDomainUpn     = $initialDomainUpn
            CloudOnly            = $cloudOnly
            PasswordNeverExpires = $pwdNeverExpires
            StrongAuthRegistered = $strongAuth
            ConfidenceScore      = $score
            Confidence           = $confidence
        }
    }

    $breakGlassAccounts = @($breakGlassAccounts | Sort-Object -Property ConfidenceScore -Descending)
    $count              = $breakGlassAccounts.Count
    $highConfidence     = @($breakGlassAccounts | Where-Object { $_.ConfidenceScore -ge 45 }).Count

    $status = if ($count -ge 2) { 'Pass' }
              elseif ($count -eq 1) { 'Warning' }
              else { 'Fail' }

    $finding = switch ($status) {
        'Pass'    { "$count break-glass accounts detected ($highConfidence high-confidence), excluded from $threshold+ of $($enabledPolicies.Count) enabled policies." }
        'Warning' { "Only 1 potential break-glass account detected (confidence: $($breakGlassAccounts[0].Confidence)). Best practice is to have at least 2." }
        'Fail'    { 'No break-glass accounts detected. Emergency access accounts should be excluded from CA policies.' }
    }

    [PSCustomObject]@{
        Status     = $status
        Finding    = $finding
        BreakGlass = @($breakGlassAccounts)
        Severity   = switch ($status) { 'Pass' { 'Info' } 'Warning' { 'Medium' } 'Fail' { 'Critical' } }
    }
}
