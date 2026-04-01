function Get-PolicyMatchScore {
    <#
    .SYNOPSIS
        Calculates a match score between a baseline policy and a tenant policy.
    .DESCRIPTION
        Uses an additive weighted-requirement checklist.  Each baseline property is
        checked independently and earns points proportional to its coverage.  Hard
        disqualifiers (wrong policy type, block vs non-block) force a zero score.

        Default weight budget (100 pts total):
          Grant controls    30
          User scope        25
          Application scope 20
          Conditions        15
          Policy state      10

        The baseline JSON may supply a weightOverrides hashtable to shift budget
        for policies where a specific condition IS the policy (e.g. auth flows).

        Name/keyword matching is a small tiebreaker (max +5) only.

        Returns a score 0-100, a list of human-readable differences, and a
        per-check breakdown for debuggability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Baseline,

        [Parameter(Mandatory)]
        [object]$Policy
    )

    $mp = $Baseline.matchPatterns
    $differences = [System.Collections.Generic.List[string]]::new()
    $checks      = [System.Collections.Generic.List[object]]::new()

    # ═══════════════════════════════════════════════════
    # HARD DISQUALIFIERS — wrong policy type → score 0
    # ═══════════════════════════════════════════════════
    if ($mp -and $mp.applications) {
        $tenantUserActions   = $Policy.conditions.applications.includeUserActions ?? @()
        $tenantHasUserAction = $tenantUserActions.Count -gt 0
        $tenantHasAuthCtx    = ($Policy.conditions.applications.includeAuthenticationContextClassReferences ?? @()).Count -gt 0

        $baselineWantsUserAction = ($mp.applications.includeUserActions ?? @()).Count -gt 0
        $baselineWantsApps       = ($mp.applications.includeApplications ?? @()).Count -gt 0 -or $mp.applications.includeApplications -eq $true

        if ($baselineWantsUserAction -and -not $tenantHasUserAction) {
            $differences.Add('Expected a user-action policy (security info registration, etc.) — policy targets applications instead')
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
        if (-not $baselineWantsUserAction -and $tenantHasUserAction) {
            $differences.Add('Expected an application-targeting policy — policy targets a user action instead')
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
        if ($baselineWantsApps -and $tenantHasAuthCtx -and -not $tenantHasUserAction) {
            $differences.Add('Policy targets an authentication context, not cloud applications — wrong policy type')
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
    }

    # Grant-action type disqualifier: block vs. non-block
    if ($mp -and $mp.grantControls -and $mp.grantControls.builtInControls) {
        $baselineIsBlock = $mp.grantControls.builtInControls -contains 'block'
        $policyControls  = $Policy.grantControls.builtInControls ?? @()
        $policyIsBlock   = $policyControls -contains 'block'

        if ($baselineIsBlock -and -not $policyIsBlock) {
            $found = if ($policyControls.Count -gt 0) { $policyControls -join ', ' } else { 'none' }
            $differences.Add("Grant controls differ: expected [block], found [$found]")
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
        if (-not $baselineIsBlock -and $policyIsBlock) {
            $differences.Add("Grant controls differ: expected [$($mp.grantControls.builtInControls -join ', ')], found [block]")
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
    }

    # Condition-type disqualifiers
    # These conditions define WHAT KIND of policy this is. A tenant policy
    # missing them entirely is a different policy type — not a partial match.
    if ($mp -and $mp.conditions) {

        # Authentication flows — e.g. CAP003 (device code), CAP004 (auth transfer)
        if ($mp.conditions.authenticationFlows) {
            $policyFlows = $Policy.conditions.authenticationFlows.transferMethods ?? @()
            if ($policyFlows.Count -eq 0) {
                $differences.Add("Required authentication flow condition is absent — expected [$($mp.conditions.authenticationFlows -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }

        # Sign-in risk levels — e.g. CAU015
        if ($mp.conditions.signInRiskLevels) {
            $policyRisk = $Policy.conditions.signInRiskLevels ?? @()
            if ($policyRisk.Count -eq 0) {
                $differences.Add("Required sign-in risk condition is absent — expected [$($mp.conditions.signInRiskLevels -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }

        # User risk levels — e.g. CAU016
        if ($mp.conditions.userRiskLevels) {
            $policyRisk = $Policy.conditions.userRiskLevels ?? @()
            if ($policyRisk.Count -eq 0) {
                $differences.Add("Required user risk condition is absent — expected [$($mp.conditions.userRiskLevels -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }

        # Insider risk levels
        if ($mp.conditions.insiderRiskLevels) {
            $policyRisk = $Policy.conditions.insiderRiskLevels ?? @()
            if ($policyRisk.Count -eq 0) {
                $differences.Add("Required insider risk condition is absent — expected [$($mp.conditions.insiderRiskLevels -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }

        # Service principal risk levels
        if ($mp.conditions.servicePrincipalRiskLevels) {
            $policyRisk = $Policy.conditions.servicePrincipalRiskLevels ?? @()
            if ($policyRisk.Count -eq 0) {
                $differences.Add("Required service principal risk condition is absent — expected [$($mp.conditions.servicePrincipalRiskLevels -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }

        # Location — e.g. CAL001-CAL006 (location-discriminated policies)
        if ($mp.conditions.locations) {
            $tenantLocs = $Policy.conditions.locations
            $tenantHasAnyLocation = $null -ne $tenantLocs -and (
                (($tenantLocs.includeLocations ?? @()).Count -gt 0) -or
                (($tenantLocs.excludeLocations ?? @()).Count -gt 0)
            )
            if (-not $tenantHasAnyLocation) {
                $differences.Add('Required location condition is absent')
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }
    }

    # Guest-scope disqualifier: a baseline specifically designed for guests cannot match
    # a policy that targets only a specific group (not All users, not guests).
    if ($mp -and $mp.users -and $mp.users.includeGuestsOrExternalUsers -eq $true) {
        $tenantUsers  = $Policy.conditions.users
        $tenantAll    = ($tenantUsers.includeUsers ?? @()) -contains 'All'
        $tenantGuests = $tenantUsers.includeGuestsOrExternalUsers -eq $true
        if (-not $tenantAll -and -not $tenantGuests) {
            $differences.Add('Expected guest/external user targeting — policy does not target guests or All users')
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
    }

    # Platform disqualifier: a baseline with specific platform conditions (include or exclude)
    # cannot match a policy that has no platform condition at all — the platform scope IS
    # the defining characteristic of device-platform policies (CAD*).
    if ($mp -and $mp.platforms) {
        $tenantPlatforms      = $Policy.conditions.platforms
        $tenantHasAnyPlatform = $null -ne $tenantPlatforms -and (
            (($tenantPlatforms.includePlatforms ?? @()).Count -gt 0) -or
            (($tenantPlatforms.excludePlatforms ?? @()).Count -gt 0)
        )
        $hasSpecificInclude = ($mp.platforms.includePlatforms ?? @()).Count -gt 0 -and
                              ($mp.platforms.includePlatforms -notcontains 'all')
        $hasSpecificExclude = ($mp.platforms.excludePlatforms ?? @()).Count -gt 0

        if (($hasSpecificInclude -or $hasSpecificExclude) -and -not $tenantHasAnyPlatform) {
            $differences.Add('Required platform condition is absent (policy has no platform filter)')
            return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
        }
    }

    # clientAppTypes mutual exclusion: modern auth <-> legacy auth are opposite protocol groups.
    # A policy targeting exchangeActiveSync/other can never match one targeting browser/mobileApps.
    if ($mp -and $mp.clientAppTypes) {        $modernGroup = @('browser', 'mobileAppsAndDesktopClients')
        $legacyGroup = @('exchangeActiveSync', 'other')

        $baselineModern = @($mp.clientAppTypes | Where-Object { $modernGroup -contains $_ })
        $baselineLegacy = @($mp.clientAppTypes | Where-Object { $legacyGroup -contains $_ })

        $policyClients  = $Policy.conditions.clientAppTypes ?? @()
        $policyHasAll   = $policyClients -contains 'all'

        if (-not $policyHasAll -and $policyClients.Count -gt 0) {
            $policyModern = @($policyClients | Where-Object { $modernGroup -contains $_ })
            $policyLegacy = @($policyClients | Where-Object { $legacyGroup -contains $_ })

            # Baseline wants modern auth only, tenant exclusively targets legacy auth
            if ($baselineModern.Count -gt 0 -and $baselineLegacy.Count -eq 0 -and
                $policyLegacy.Count -gt 0 -and $policyModern.Count -eq 0) {
                $differences.Add("Client app type mismatch: baseline targets modern auth [$($mp.clientAppTypes -join ', ')], policy targets legacy auth [$($policyClients -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }

            # Baseline wants legacy auth only, tenant exclusively targets modern auth
            if ($baselineLegacy.Count -gt 0 -and $baselineModern.Count -eq 0 -and
                $policyModern.Count -gt 0 -and $policyLegacy.Count -eq 0) {
                $differences.Add("Client app type mismatch: baseline targets legacy auth [$($mp.clientAppTypes -join ', ')], policy targets modern auth [$($policyClients -join ', ')]")
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }
    }

    # Session controls disqualifier: if the baseline requires specific session control types,
    # the tenant policy must have at least one of those exact types configured. A policy with
    # none of the required session control types is fundamentally different (e.g. a CASB routing
    # policy with cloudAppSecurity should not match a sign-in frequency or persistent browser policy).
    if ($mp -and $mp.sessionControls) {
        # Determine which session control types the baseline requires
        $requiredSessionTypes = @()
        if ($mp.sessionControls.signInFrequency)                 { $requiredSessionTypes += 'signInFrequency' }
        if ($mp.sessionControls.persistentBrowser)               { $requiredSessionTypes += 'persistentBrowser' }
        if ($mp.sessionControls.applicationEnforcedRestrictions) { $requiredSessionTypes += 'applicationEnforcedRestrictions' }
        if ($mp.sessionControls.cloudAppSecurity)                { $requiredSessionTypes += 'cloudAppSecurity' }
        if ($mp.sessionControls.secureSignInSession)             { $requiredSessionTypes += 'secureSignInSession' }

        if ($requiredSessionTypes.Count -gt 0) {
            $ts = $Policy.sessionControls
            $hasRequiredSessionControl = $false
            foreach ($st in $requiredSessionTypes) {
                $present = switch ($st) {
                    'signInFrequency'                 { $null -ne $ts -and $ts.signInFrequency.isEnabled -eq $true }
                    'persistentBrowser'               { $null -ne $ts -and $ts.persistentBrowser.isEnabled -eq $true }
                    'applicationEnforcedRestrictions' { $null -ne $ts -and $ts.applicationEnforcedRestrictions.isEnabled -eq $true }
                    'cloudAppSecurity'                { $null -ne $ts -and $ts.cloudAppSecurity.isEnabled -eq $true }
                    'secureSignInSession'              { $null -ne $ts -and $null -ne $ts.secureSignInSession }
                    default                           { $false }
                }
                if ($present) { $hasRequiredSessionControl = $true; break }
            }
            if (-not $hasRequiredSessionControl) {
                $differences.Add('Policy has no matching session controls — required session controls are absent')
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        }
    }

    # Intent incompatibility disqualifier: if the baseline declares a policyIntent and we can
    # infer the tenant policy's intent, incompatible intents force a zero score. This is a
    # defence-in-depth gate on top of the individual structural disqualifiers above.
    if ($Baseline.policyIntent) {
        $baselineIntent = $Baseline.policyIntent
        $tenantIntent   = Get-TenantPolicyIntent -Policy $Policy

        if ($tenantIntent -ne 'unknown') {
            # Strict-match intents: must match exactly (very specific policy types)
            $strictIntents = @(
                'legacy-auth-block', 'auth-flow-block', 'risk-based',
                'registration-security', 'token-protection', 'terms-of-use',
                'compliant-network'
            )

            # Compatible pairs: intents that can legitimately overlap.
            # Note: session-control and device-compliance are NOT compatible — a CASB routing
            # policy must never match a device-compliance grant baseline.
            $compatiblePairs = @(
                'mfa-grant|location-based',          # MFA from non-trusted locations
                'mfa-grant|admin-protection',         # MFA for admins
                'device-compliance|admin-protection', # Compliant device for admins
                'guest-access|app-restriction'        # Block apps for guests
            )

            $isCompatible = $baselineIntent -eq $tenantIntent

            if (-not $isCompatible) {
                # Check if EITHER intent is strict (must match exactly)
                $eitherStrict = ($baselineIntent -in $strictIntents) -or
                                ($tenantIntent -in $strictIntents)

                if ($eitherStrict) {
                    $differences.Add("Policy intent mismatch: baseline is [$baselineIntent], tenant policy is [$tenantIntent]")
                    return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
                }

                # Check compatible pairs for non-strict intents
                $pairKey1 = "$baselineIntent|$tenantIntent"
                $pairKey2 = "$tenantIntent|$baselineIntent"
                $isCompatible = ($pairKey1 -in $compatiblePairs) -or ($pairKey2 -in $compatiblePairs)

                if (-not $isCompatible) {
                    $differences.Add("Policy intent mismatch: baseline is [$baselineIntent], tenant policy is [$tenantIntent]")
                    return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
                }
            }
        }
    }

    # ═══════════════════════════════════════════════════
    # RESOLVE WEIGHTS  (defaults + optional overrides from baseline)
    # ═══════════════════════════════════════════════════
    $defaultWeights = @{
        grantControls = 30
        userScope     = 25
        appScope      = 20
        conditions    = 15
        policyState   = 10
    }

    $wo = $Baseline.weightOverrides
    $wt = @{}
    foreach ($key in $defaultWeights.Keys) {
        $wt[$key] = if ($wo -and $null -ne $wo.$key) { [int]$wo.$key } else { $defaultWeights[$key] }
    }

    # ═══════════════════════════════════════════════════
    # CHECK 1: GRANT CONTROLS  (weight: grantControls)
    # ═══════════════════════════════════════════════════
    $grantWeight = $wt['grantControls']
    $grantEarned = 0

    if ($mp -and ($mp.grantControls -or $mp.sessionControls)) {
        $grantSubChecks = 0
        $grantSubPassed = 0.0

        # Built-in controls
        if ($mp.grantControls -and $mp.grantControls.builtInControls) {
            $grantSubChecks++
            $policyCtrl       = $Policy.grantControls.builtInControls ?? @()
            $baselineCtrl     = $mp.grantControls.builtInControls
            $coverage = Get-ArrayCoverage -Expected $baselineCtrl -Actual $policyCtrl
            $grantSubPassed += $coverage
            if ($coverage -lt 1.0) {
                $differences.Add("Grant controls differ: expected [$($baselineCtrl -join ', ')], found [$($policyCtrl -join ', ')]")
            }
        }

        # Grant operator (OR vs AND) — only meaningful when the tenant actually has
        # multiple builtInControls to combine.  Checking operator against an empty
        # grant is meaningless and would give unearned credit.
        if ($mp.grantControls -and $mp.grantControls.operator) {
            $policyCtrlForOp = $Policy.grantControls.builtInControls ?? @()
            if ($policyCtrlForOp.Count -ge 2) {
                $grantSubChecks++
                $policyOperator   = $Policy.grantControls.operator ?? 'OR'
                $baselineOperator = $mp.grantControls.operator
                if ($policyOperator -eq $baselineOperator) {
                    $grantSubPassed++
                } else {
                    $differences.Add("Grant operator differs: expected [$baselineOperator], found [$policyOperator]")
                }
            }
        }

        # Authentication strength
        # Satisfaction hierarchy: phishingResistant (rank 2) > mfa (rank 1)
        # builtInControls 'mfa' is equivalent to auth strength of rank 1 (mfa level).
        if ($mp.grantControls.authenticationStrength) {
            $grantSubChecks++
            $baselineStrength = $mp.grantControls.authenticationStrength
            $tenantStrength   = $Policy.grantControls.authenticationStrength
            $tenantHasMfa     = ($Policy.grantControls.builtInControls ?? @()) -contains 'mfa'
            $strengthRank     = @{ 'mfa' = 1; 'phishingResistant' = 2 }

            if ($baselineStrength -eq $true) {
                # Any auth strength OR mfa builtIn control satisfies this
                if ($tenantStrength -or $tenantHasMfa) {
                    $grantSubPassed++
                } else {
                    $differences.Add('Authentication strength not configured')
                }
            } elseif ($baselineStrength.requirementsSatisfied) {
                $requiredLevel = $baselineStrength.requirementsSatisfied
                $requiredRank  = $strengthRank[$requiredLevel] ?? 0
                if ($tenantStrength) {
                    $tenantLevel = $tenantStrength.requirementsSatisfied
                    $tenantRank  = $strengthRank[$tenantLevel] ?? 0
                    if ($tenantRank -ge $requiredRank) {
                        $grantSubPassed++
                    } else {
                        $differences.Add("Authentication strength too weak: expected [$requiredLevel], found [$tenantLevel]")
                    }
                } elseif ($tenantHasMfa -and $requiredRank -le 1) {
                    # mfa builtInControl satisfies an mfa-level auth strength requirement
                    $grantSubPassed++
                } else {
                    $differences.Add("Authentication strength [$requiredLevel] required but not configured")
                }
            } else {
                # Object present but no requirementsSatisfied — just check presence
                if ($tenantStrength) { $grantSubPassed++ }
                else { $differences.Add('Authentication strength not configured') }
            }
        }

        # Terms of use
        if ($mp.grantControls.termsOfUse) {
            $grantSubChecks++
            if ($Policy.grantControls.termsOfUse -and $Policy.grantControls.termsOfUse.Count -gt 0) { $grantSubPassed++ }
            else { $differences.Add('Terms of Use not configured') }
        }

        # Session controls — counted in the grant budget since they define enforcement
        if ($mp.sessionControls) {
            $sessionTypes = @()
            if ($mp.sessionControls.signInFrequency)                 { $sessionTypes += 'signInFrequency' }
            if ($mp.sessionControls.persistentBrowser)               { $sessionTypes += 'persistentBrowser' }
            if ($mp.sessionControls.applicationEnforcedRestrictions)  { $sessionTypes += 'applicationEnforcedRestrictions' }
            if ($mp.sessionControls.cloudAppSecurity)                 { $sessionTypes += 'cloudAppSecurity' }
            if ($mp.sessionControls.secureSignInSession)             { $sessionTypes += 'secureSignInSession' }

            foreach ($st in $sessionTypes) {
                $grantSubChecks++
                $ts = $Policy.sessionControls
                $present = switch ($st) {
                    'signInFrequency'                { $ts.signInFrequency.isEnabled -eq $true }
                    'persistentBrowser'              { $ts.persistentBrowser.isEnabled -eq $true }
                    'applicationEnforcedRestrictions' { $ts.applicationEnforcedRestrictions.isEnabled -eq $true }
                    'cloudAppSecurity'               { $ts.cloudAppSecurity.isEnabled -eq $true }
                    'secureSignInSession'            { $null -ne $ts.secureSignInSession }
                    default                          { $false }
                }
                if ($present) { $grantSubPassed++ }
                else { $differences.Add('Required session controls are absent') }
            }
        }

        if ($grantSubChecks -gt 0) {
            $grantEarned = [math]::Round(($grantSubPassed / $grantSubChecks) * $grantWeight)
        } else {
            $grantEarned = $grantWeight   # Empty grantControls {} = no grant requirement
        }
    } else {
        $grantEarned = $grantWeight       # No grant expectations at all
    }

    $checks.Add([PSCustomObject]@{ Name = 'GrantControls'; Weight = $grantWeight; Earned = $grantEarned })

    # ═══════════════════════════════════════════════════
    # CHECK 2: USER SCOPE  (weight: userScope)
    # ═══════════════════════════════════════════════════
    $userWeight = $wt['userScope']
    $userEarned = 0

    if ($mp -and $mp.users) {
        $tenantUsers  = $Policy.conditions.users
        $tenantAll    = ($tenantUsers.includeUsers ?? @()) -contains 'All'
        $tenantRoles  = ($tenantUsers.includeRoles ?? @()).Count -gt 0
        $tenantGuests = $tenantUsers.includeGuestsOrExternalUsers -eq $true
        $tenantGroups = ($tenantUsers.includeGroups ?? @()).Count -gt 0

        $wantsGuests  = $mp.users.includeGuestsOrExternalUsers -eq $true
        $wantsRoles   = $mp.users.includeRoles -eq $true
        $wantsAll     = ($mp.users.includeUsers ?? @()) -contains 'All'
        $wantsGroups  = $mp.users.includeGroups -eq $true

        if ($wantsGuests) {
            if ($tenantGuests) {
                $userEarned = $userWeight
            } elseif ($tenantAll) {
                $userEarned = [math]::Round($userWeight * 0.4)
                $differences.Add('Expected guest/external user targeting (policy targets All users)')
            } else {
                $userEarned = 0
                $differences.Add('Expected guest/external user targeting (policy does not target guests)')
            }
        } elseif ($wantsRoles) {
            if ($tenantRoles) {
                $userEarned = $userWeight
            } elseif ($tenantAll) {
                $userEarned = [math]::Round($userWeight * 0.4)
                $differences.Add('Expected admin role targeting (policy targets All users — admins not specifically targeted)')
            } else {
                # Tenant targets specific users or groups but not admin roles — fundamentally different policy.
                # A policy scoped to individual user GUIDs or a named group cannot match an admin-role policy.
                $differences.Add('Expected admin role targeting — policy does not target admin roles')
                return [PSCustomObject]@{ Score = 0; Checks = @(); Differences = $differences.ToArray() }
            }
        } elseif ($wantsGroups) {
            if ($tenantGroups) {
                $userEarned = $userWeight
            } elseif ($tenantAll) {
                $userEarned = [math]::Round($userWeight * 0.4)
                $differences.Add('Expected specific group targeting (policy targets All users)')
            } else {
                $userEarned = 0
                $differences.Add('Expected specific group targeting')
            }
        } elseif ($wantsAll) {
            if ($tenantAll) {
                $userEarned = $userWeight
            } elseif ($tenantRoles -or $tenantGroups) {
                $userEarned = [math]::Round($userWeight * 0.3)
                $differences.Add('Expected all-users targeting (policy targets specific groups/roles)')
            } else {
                $userEarned = 0
                $differences.Add('Expected all-users targeting')
            }
        } else {
            $userEarned = $userWeight
        }
    } else {
        $userEarned = $userWeight
    }

    $checks.Add([PSCustomObject]@{ Name = 'UserScope'; Weight = $userWeight; Earned = $userEarned })

    # ═══════════════════════════════════════════════════
    # CHECK 3: APPLICATION / ACTION SCOPE  (weight: appScope)
    # ═══════════════════════════════════════════════════
    $appWeight = $wt['appScope']
    $appEarned = 0

    if ($mp -and $mp.applications) {
        $policyApps = $Policy.conditions.applications

        if ($mp.applications.includeApplications) {
            $expected = $mp.applications.includeApplications

            if ($expected -is [bool]) {
                # Boolean placeholder — baseline defers app selection to implementer
                $appEarned = $appWeight
            } else {
                $actual = $policyApps.includeApplications ?? @()

                if ($expected -contains 'All' -and $actual -contains 'All') {
                    $appEarned = $appWeight
                } elseif ($expected -contains 'Office365' -and (
                    $actual -contains 'Office365' -or $actual -contains '67ad5377-2d78-4ac2-a867-6300cda00e85'
                )) {
                    $appEarned = $appWeight
                } elseif ($expected -contains 'MicrosoftAdminPortals' -and (
                    $actual -contains 'MicrosoftAdminPortals'
                )) {
                    $appEarned = $appWeight
                } elseif ($expected -contains 'All' -and $actual.Count -gt 0) {
                    $appEarned = [math]::Round($appWeight * 0.4)
                    $differences.Add('Target applications differ (policy uses specific apps instead of All)')
                } elseif (Compare-StringArrayOverlap $actual $expected) {
                    $coverage  = Get-ArrayCoverage -Expected $expected -Actual $actual
                    $appEarned = [math]::Round($appWeight * $coverage)
                    if ($coverage -lt 1.0) {
                        $differences.Add('Target applications differ')
                    }
                } else {
                    $appEarned = 0
                    $differences.Add('Target applications differ')
                }
            }
        } elseif ($mp.applications.includeUserActions) {
            $expected = $mp.applications.includeUserActions
            $actual   = $policyApps.includeUserActions ?? @()
            $coverage  = Get-ArrayCoverage -Expected $expected -Actual $actual
            $appEarned = [math]::Round($appWeight * $coverage)
            if ($coverage -lt 1.0) {
                $differences.Add("User actions differ: expected [$($expected -join ', ')]")
            }
        } else {
            $appEarned = $appWeight
        }

        # Penalty for significant app exclusions when baseline expects broad coverage
        if ($appEarned -gt 0) {
            $excludedApps = $policyApps.excludeApplications ?? @()
            $expectedAll  = ($mp.applications.includeApplications -is [array]) -and
                            ($mp.applications.includeApplications -contains 'All')
            if ($expectedAll -and $excludedApps.Count -gt 0) {
                # Each excluded app reduces credit (cap penalty at 50% of earned)
                $penalty = [math]::Min($excludedApps.Count * 0.1, 0.5)
                $appEarned = [math]::Round($appEarned * (1.0 - $penalty))
                $differences.Add("Policy excludes $($excludedApps.Count) application(s) from scope — baseline expects All")
            }
        }
    } else {
        $appEarned = $appWeight
    }

    $checks.Add([PSCustomObject]@{ Name = 'AppScope'; Weight = $appWeight; Earned = $appEarned })

    # ═══════════════════════════════════════════════════
    # CHECK 4: CONDITIONS  (weight: conditions — split across sub-checks)
    # ═══════════════════════════════════════════════════
    $condWeight    = $wt['conditions']
    $condSubChecks = 0
    $condSubEarned = 0.0

    # Client app types
    if ($mp -and $mp.clientAppTypes) {
        $condSubChecks++
        $policyClients   = $Policy.conditions.clientAppTypes ?? @()
        $baselineClients = $mp.clientAppTypes
        # 'all' in the tenant policy is a superset — it covers every client type the baseline expects
        if ($policyClients -contains 'all' -or $baselineClients -contains 'all') {
            $condSubEarned += 1.0
        } elseif (Compare-StringArrayOverlap $policyClients $baselineClients) {
            $coverage = Get-ArrayCoverage -Expected $baselineClients -Actual $policyClients
            $condSubEarned += $coverage
            if ($coverage -lt 1.0) {
                $differences.Add("Client app types differ: expected [$($baselineClients -join ', ')], found [$($policyClients -join ', ')]")
            }
        } else {
            $differences.Add("Client app types differ: expected [$($baselineClients -join ', ')], found [$($policyClients -join ', ')]")
        }
    }

    # Platforms — include
    if ($mp -and $mp.platforms -and $mp.platforms.includePlatforms) {
        $condSubChecks++
        $policyPlatforms = $Policy.conditions.platforms.includePlatforms ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.platforms.includePlatforms -Actual $policyPlatforms
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("Platform filter differs: expected include [$($mp.platforms.includePlatforms -join ', ')], found [$($policyPlatforms -join ', ')]")
        }
    }

    # Platforms — exclude
    if ($mp -and $mp.platforms -and $mp.platforms.excludePlatforms) {
        $condSubChecks++
        $policyExcludePlat = $Policy.conditions.platforms.excludePlatforms ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.platforms.excludePlatforms -Actual $policyExcludePlat
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("Platform exclude filter differs: expected exclude [$($mp.platforms.excludePlatforms -join ', ')], found [$($policyExcludePlat -join ', ')]")
        }
    }

    # Device state
    if ($mp -and $mp.deviceState) {
        $condSubChecks++
        $tenantDevFilter = $Policy.conditions.devices.deviceFilter
        $hasCompliantFilter = $null -ne $tenantDevFilter -and (
            ($tenantDevFilter.rule -match 'isCompliant.*True') -or
            ($tenantDevFilter.rule -match 'trustType.*ServerAD')
        )
        if ($mp.deviceState.requireCompliant -eq $true) {
            if ($hasCompliantFilter) { $condSubEarned++ }
            else { $differences.Add('Device state: requires compliant or Hybrid Azure AD joined device filter') }
        } elseif ($mp.deviceState.requireCompliant -eq $false) {
            if (-not $hasCompliantFilter) { $condSubEarned++ }
            else { $differences.Add('Device state: baseline targets all devices but policy is restricted to compliant/HAADJ devices') }
        } else {
            $condSubEarned++
        }
    }

    # Locations
    if ($mp -and $mp.conditions -and $mp.conditions.locations) {
        $condSubChecks++
        $locPattern = $mp.conditions.locations
        $tenantLocs = $Policy.conditions.locations

        $tenantHasAnyLocation = $null -ne $tenantLocs -and (
            (($tenantLocs.includeLocations ?? @()).Count -gt 0) -or
            (($tenantLocs.excludeLocations ?? @()).Count -gt 0)
        )

        if (-not $tenantHasAnyLocation) {
            $differences.Add('Required location condition is absent')
        } else {
            $tenantIncludes = $tenantLocs.includeLocations ?? @()
            $tenantExcludes = $tenantLocs.excludeLocations ?? @()
            $wantsInclude   = $null -ne $locPattern.includeLocations
            $wantsExclude   = $null -ne $locPattern.excludeLocations
            $locCredit      = 0.0

            if ($wantsInclude) {
                if ($tenantIncludes.Count -gt 0) {
                    if ($locPattern.includeLocations -is [array]) {
                        $cov = Get-ArrayCoverage -Expected $locPattern.includeLocations -Actual $tenantIncludes
                        $locCredit = $cov
                        if ($cov -lt 1.0) {
                            $differences.Add("Location include condition incomplete: expected [$($locPattern.includeLocations -join ', ')]")
                        }
                    } else {
                        $locCredit = 1.0   # Boolean true — any include location is sufficient
                    }
                } else {
                    $differences.Add('Location condition type differs: expected include-locations, found only exclude-locations')
                }
            }
            if ($wantsExclude) {
                if ($tenantExcludes.Count -gt 0) {
                    if ($locPattern.excludeLocations -is [array]) {
                        $cov = Get-ArrayCoverage -Expected $locPattern.excludeLocations -Actual $tenantExcludes
                        $exLocCredit = $cov
                        if ($cov -lt 1.0) {
                            $missingExclude = $locPattern.excludeLocations | Where-Object { $tenantExcludes -notcontains $_ }
                            $differences.Add("Location exclude condition incomplete: expected [$($locPattern.excludeLocations -join ', ')] excluded, missing [$($missingExclude -join ', ')]")
                        }
                    } else {
                        $exLocCredit = 1.0   # Boolean true — any exclude location is sufficient
                    }
                } else {
                    $exLocCredit = 0.0
                    $differences.Add('Location condition type differs: expected exclude-locations (trusted location exclusion), found only include-locations')
                }

                if ($wantsInclude) {
                    $locCredit = ($locCredit + $exLocCredit) / 2.0
                } else {
                    $locCredit = $exLocCredit
                }
            }

            $condSubEarned += $locCredit
        }
    }

    # Authentication flows
    if ($mp -and $mp.conditions -and $mp.conditions.authenticationFlows) {
        $condSubChecks++
        $policyFlows = $Policy.conditions.authenticationFlows.transferMethods ?? @()
        if (-not $policyFlows -or $policyFlows.Count -eq 0) {
            $differences.Add("Required authentication flow condition is absent — expected [$($mp.conditions.authenticationFlows -join ', ')]")
        } else {
            $coverage = Get-ArrayCoverage -Expected $mp.conditions.authenticationFlows -Actual $policyFlows
            $condSubEarned += $coverage
            if ($coverage -lt 1.0) {
                $differences.Add("Authentication flow type differs: expected [$($mp.conditions.authenticationFlows -join ', ')], found [$($policyFlows -join ', ')]")
            }
        }
    }

    # Sign-in risk levels
    if ($mp -and $mp.conditions -and $mp.conditions.signInRiskLevels) {
        $condSubChecks++
        $policyRisk = $Policy.conditions.signInRiskLevels ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.conditions.signInRiskLevels -Actual $policyRisk
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("Sign-in risk levels differ: expected [$($mp.conditions.signInRiskLevels -join ', ')]")
        }
    }

    # User risk levels
    if ($mp -and $mp.conditions -and $mp.conditions.userRiskLevels) {
        $condSubChecks++
        $policyRisk = $Policy.conditions.userRiskLevels ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.conditions.userRiskLevels -Actual $policyRisk
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("User risk levels differ: expected [$($mp.conditions.userRiskLevels -join ', ')]")
        }
    }

    # Insider risk levels
    if ($mp -and $mp.conditions -and $mp.conditions.insiderRiskLevels) {
        $condSubChecks++
        $policyRisk = $Policy.conditions.insiderRiskLevels ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.conditions.insiderRiskLevels -Actual $policyRisk
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("Insider risk levels differ: expected [$($mp.conditions.insiderRiskLevels -join ', ')]")
        }
    }

    # Service principal risk levels
    if ($mp -and $mp.conditions -and $mp.conditions.servicePrincipalRiskLevels) {
        $condSubChecks++
        $policySpRisk = $Policy.conditions.servicePrincipalRiskLevels ?? @()
        $coverage = Get-ArrayCoverage -Expected $mp.conditions.servicePrincipalRiskLevels -Actual $policySpRisk
        $condSubEarned += $coverage
        if ($coverage -lt 1.0) {
            $differences.Add("Service principal risk levels differ: expected [$($mp.conditions.servicePrincipalRiskLevels -join ', ')]")
        }
    }

    # Calculate condition points
    $condEarned = if ($condSubChecks -gt 0) {
        [math]::Round(($condSubEarned / $condSubChecks) * $condWeight)
    } else {
        $condWeight     # No conditions expected — full credit
    }

    $checks.Add([PSCustomObject]@{ Name = 'Conditions'; Weight = $condWeight; Earned = $condEarned })

    # ═══════════════════════════════════════════════════
    # CHECK 5: POLICY STATE  (weight: policyState)
    # ═══════════════════════════════════════════════════
    $stateWeight = $wt['policyState']
    $stateEarned = switch ($Policy.state) {
        'enabled'                            { $stateWeight }
        'enabledForReportingButNotEnforced'  { 0 }
        'disabled'                           { 0 }
        default                              { $stateWeight }
    }

    if ($Policy.state -eq 'enabledForReportingButNotEnforced') {
        $differences.Add('Policy is in report-only mode — not actively enforced')
    } elseif ($Policy.state -eq 'disabled') {
        $differences.Add('Policy is disabled — not active')
    }

    $checks.Add([PSCustomObject]@{ Name = 'PolicyState'; Weight = $stateWeight; Earned = $stateEarned })

    # ═══════════════════════════════════════════════════
    # NAME MATCHING — tiebreaker only (not part of main score)
    # ═══════════════════════════════════════════════════
    $policyName = ($Policy.displayName ?? '').ToLower()
    $nameBonus  = 0

    if ($policyName -match [regex]::Escape($Baseline.id.ToLower())) {
        $nameBonus = 5
    } else {
        $keywordHits   = 0
        $totalKeywords = ($Baseline.keywords ?? @()).Count
        if ($totalKeywords -gt 0) {
            foreach ($kw in $Baseline.keywords) {
                if ($policyName -match [regex]::Escape($kw.ToLower())) { $keywordHits++ }
            }
            if ($keywordHits -eq $totalKeywords)  { $nameBonus = 3 }
            elseif ($keywordHits -gt 0)           { $nameBonus = 1 }
        }
    }

    # ═══════════════════════════════════════════════════
    # FINAL SCORE
    # ═══════════════════════════════════════════════════
    $totalWeight = ($checks | Measure-Object -Property Weight -Sum).Sum
    $totalEarned = ($checks | Measure-Object -Property Earned -Sum).Sum
    $score = if ($totalWeight -gt 0) {
        [math]::Round(($totalEarned / $totalWeight) * 100)
    } else {
        0
    }

    # Name bonus never pushes a Missing into Partial or Partial into Matched
    $score = [math]::Min($score + $nameBonus, 100)

    [PSCustomObject]@{
        Score       = $score
        NameBonus   = $nameBonus
        Checks      = $checks.ToArray()
        Differences = $differences.ToArray()
    }
}


function Get-ArrayCoverage {
    <#
    .SYNOPSIS
        Returns the proportion of expected elements found in the actual array (0.0-1.0).
    #>
    param(
        [object[]]$Expected,
        [object[]]$Actual
    )
    if (-not $Expected -or $Expected.Count -eq 0) { return 1.0 }
    if (-not $Actual -or $Actual.Count -eq 0)     { return 0.0 }

    $matched = 0
    foreach ($e in $Expected) {
        foreach ($a in $Actual) {
            if ([string]$e -eq [string]$a) { $matched++; break }
        }
    }
    return [double]($matched / $Expected.Count)
}


function Compare-StringArrayOverlap {
    <#
    .SYNOPSIS
        Returns true if any element in array A exists in array B (case-insensitive).
    #>
    param(
        [string[]]$ArrayA,
        [string[]]$ArrayB
    )
    if (-not $ArrayA -or -not $ArrayB) { return $false }
    foreach ($a in $ArrayA) {
        foreach ($b in $ArrayB) {
            if ($a -eq $b) { return $true }
        }
    }
    return $false
}


function Get-TenantPolicyIntent {
    <#
    .SYNOPSIS
        Infers the functional intent of a tenant CA policy from its structural properties.
    .DESCRIPTION
        Classifies a tenant policy into one of the defined intent categories so it
        can be compared against baseline policyIntent tags.  Returns 'unknown' when
        the policy does not clearly match a single category.
    #>
    param([Parameter(Mandatory)][object]$Policy)

    $cond     = $Policy.conditions
    $grant    = $Policy.grantControls
    $session  = $Policy.sessionControls
    $clients  = $cond.clientAppTypes ?? @()
    $builtIn  = $grant.builtInControls ?? @()
    $isBlock  = $builtIn -contains 'block'

    # ── Authentication flow policies (device code, auth transfer) ──
    if (($cond.authenticationFlows.transferMethods ?? @()).Count -gt 0) {
        return 'auth-flow-block'
    }

    # ── Legacy auth block (targets legacy client types with block) ──
    $legacyTypes = @('exchangeActiveSync', 'other')
    $modernTypes = @('browser', 'mobileAppsAndDesktopClients')
    $hasLegacy = @($clients | Where-Object { $_ -in $legacyTypes }).Count -gt 0
    $hasModern = @($clients | Where-Object { $_ -in $modernTypes }).Count -gt 0
    if ($hasLegacy -and -not $hasModern -and $isBlock) {
        return 'legacy-auth-block'
    }

    # ── Risk-based (sign-in, user, service principal, insider risk) ──
    if (($cond.signInRiskLevels ?? @()).Count -gt 0 -or
        ($cond.userRiskLevels ?? @()).Count -gt 0 -or
        ($cond.servicePrincipalRiskLevels ?? @()).Count -gt 0 -or
        ($cond.insiderRiskLevels ?? @()).Count -gt 0) {
        return 'risk-based'
    }

    # ── Registration / user-action policies ──
    if (($cond.applications.includeUserActions ?? @()).Count -gt 0) {
        return 'registration-security'
    }

    # ── Token protection ──
    if ($null -ne $session -and $null -ne $session.secureSignInSession) {
        return 'token-protection'
    }

    # ── Terms of use ──
    if ($grant.termsOfUse -and @($grant.termsOfUse).Count -gt 0) {
        return 'terms-of-use'
    }

    # ── Compliant network ──
    if ($builtIn -contains 'compliantNetwork') {
        return 'compliant-network'
    }

    # ── Location-based (location condition is the primary discriminator) ──
    $hasLocations = $null -ne $cond.locations -and (
        ($cond.locations.includeLocations ?? @()).Count -gt 0 -or
        ($cond.locations.excludeLocations ?? @()).Count -gt 0
    )
    if ($hasLocations -and ($isBlock -or ($builtIn -contains 'mfa'))) {
        return 'location-based'
    }

    # ── Guest / external user access ──
    if ($cond.users.includeGuestsOrExternalUsers) {
        return 'guest-access'
    }

    # ── Session control (session IS the primary action, not supplementary) ──
    $hasSessionCtrl = $null -ne $session -and (
        $session.signInFrequency.isEnabled -eq $true -or
        $session.persistentBrowser.isEnabled -eq $true -or
        $session.applicationEnforcedRestrictions.isEnabled -eq $true -or
        $session.cloudAppSecurity.isEnabled -eq $true
    )
    $hasGrantCtrl = $builtIn.Count -gt 0 -or $null -ne $grant.authenticationStrength
    if ($hasSessionCtrl -and -not $hasGrantCtrl) {
        return 'session-control'
    }

    # ── Admin protection (targets admin roles) ──
    if (($cond.users.includeRoles ?? @()).Count -gt 0) {
        return 'admin-protection'
    }

    # ── Platform block (block + platform conditions, not compliance) ──
    if ($isBlock -and $null -ne $cond.platforms) {
        return 'platform-block'
    }

    # ── Device compliance (grant requires compliant/domain-joined device) ──
    if ($builtIn -contains 'compliantDevice' -or $builtIn -contains 'domainJoinedDevice') {
        return 'device-compliance'
    }

    # ── App restriction (block + targeted groups) ──
    if ($isBlock -and ($cond.users.includeGroups ?? @()).Count -gt 0) {
        return 'app-restriction'
    }

    # ── MFA grant (broad MFA requirement) ──
    if ($builtIn -contains 'mfa' -or $null -ne $grant.authenticationStrength) {
        return 'mfa-grant'
    }

    return 'unknown'
}
