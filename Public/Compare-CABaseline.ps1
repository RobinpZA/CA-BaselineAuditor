function Compare-CABaseline {
    <#
    .SYNOPSIS
        Compares tenant CA policies against the baseline definitions.
    .DESCRIPTION
        For each baseline policy, uses fuzzy matching (name patterns, structural
        similarity, and keyword matching) to classify tenant policies as Matched,
        Partial, Missing, or NotApplicable.
    .PARAMETER CurrentPolicies
        Array of current CA policies from Get-CACurrentPolicies.
    .PARAMETER BaselinePolicies
        Array of baseline policy definitions from the JSON file.
    .PARAMETER Licensing
        Licensing detection result from Get-CATenantLicensing.
    .PARAMETER DeviceInfo
        Device inventory from Get-CATenantDevices.
    .EXAMPLE
        $results = Compare-CABaseline -CurrentPolicies $policies -BaselinePolicies $baseline -Licensing $lic -DeviceInfo $devices
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$CurrentPolicies,

        [Parameter(Mandatory)]
        [object[]]$BaselinePolicies,

        [Parameter(Mandatory)]
        [object]$Licensing,

        [Parameter(Mandatory)]
        [object]$DeviceInfo
    )

    Write-Host '[CA-BaselineAuditor] Comparing policies against baseline...' -ForegroundColor Cyan

    $results = [System.Collections.Generic.List[object]]::new()
    $matchedPolicyIds = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($baseline in $BaselinePolicies) {
        # ── Check license applicability ──
        $applicable = Test-BaselineLicenseApplicability -Baseline $baseline -Licensing $Licensing

        # ── Check platform relevance ──
        if ($applicable -and $baseline.relevantPlatforms -and $baseline.relevantPlatforms.Count -gt 0) {
            $platformMatch = $false
            foreach ($p in $baseline.relevantPlatforms) {
                if ($p -in $DeviceInfo.DetectedPlatforms) { $platformMatch = $true; break }
            }
            if (-not $platformMatch) {
                $applicable = $false
            }
        }

        if (-not $applicable) {
            $results.Add([PSCustomObject]@{
                BaselineId            = $baseline.id
                BaselineName          = $baseline.name
                BaselineFullName      = $baseline.fullName
                Category              = $baseline.category
                Priority              = $baseline.priority
                Description           = $baseline.description
                Status                = 'NotApplicable'
                MatchScore            = 0
                MatchedPolicy         = $null
                MatchedPolicyId       = $null
                MatchedPolicyObject   = $null
                BaselineMatchPatterns = $baseline.matchPatterns
                Differences           = @('License or feature not available in tenant')
                Recommendation        = $baseline.description
            })
            continue
        }

        # ── Find best matching policy ──
        $bestMatch = $null
        $bestScore = 0
        $bestDiffs = @()

        foreach ($policy in $CurrentPolicies) {
            $matchResult = Get-PolicyMatchScore -Baseline $baseline -Policy $policy
            if ($matchResult.Score -gt $bestScore) {
                $bestScore = $matchResult.Score
                $bestMatch = $policy
                $bestDiffs = $matchResult.Differences
            }
        }

        # ── Classify the result ──
        $status = 'Missing'
        $recommendation = $baseline.description

        if ($bestScore -ge 80) {
            if ($bestMatch.state -eq 'enabled') {
                if ($bestDiffs.Count -eq 0) {
                    $status = 'Matched'
                    $recommendation = ''
                } else {
                    $status = 'Partial'
                    $recommendation = "Policy '$($bestMatch.displayName)' closely matches but has configuration differences. Review highlighted items."
                }
            } elseif ($bestMatch.state -eq 'enabledForReportingButNotEnforced') {
                $status = 'Partial'
                $recommendation = "Policy '$($bestMatch.displayName)' exists but is in Report-Only mode. Consider enabling it."
                $bestDiffs += 'Policy is in Report-Only mode'
            } else {
                $status = 'Partial'
                $recommendation = "Policy '$($bestMatch.displayName)' exists but is Disabled. Review and enable it."
                $bestDiffs += 'Policy is Disabled'
            }
            [void]$matchedPolicyIds.Add($bestMatch.id)
        } elseif ($bestScore -ge 60) {
            $status = 'Partial'
            $recommendation = "A similar policy exists ('$($bestMatch.displayName)') but does not fully match. Score: $bestScore%. Review configuration."
        }

        # Missing = no usable match, so suppress any differences from the failed candidate
        if ($status -eq 'Missing') { $bestDiffs = @() }

        # ── Platform-aware recommendation: filter platform lists to detected devices ──
        $mp = $baseline.matchPatterns
        if (($status -eq 'Missing' -or $status -eq 'Partial') -and $mp -and $mp.platforms) {
            $detectedLower = @($DeviceInfo.DetectedPlatforms | ForEach-Object { $_.ToLower() })

            # For excludePlatforms baselines: note which platforms weren't detected
            if ($mp.platforms.excludePlatforms) {
                $notDetected = @($mp.platforms.excludePlatforms | Where-Object { $detectedLower -notcontains $_.ToLower() })
                if ($notDetected.Count -gt 0 -and $notDetected.Count -lt $mp.platforms.excludePlatforms.Count) {
                    $recommendation += " Platform(s) not found in Entra inventory — may not need excluding: $($notDetected -join ', ')."
                }
            }

            # For includePlatforms baselines: note if the target platforms aren't detected
            if ($mp.platforms.includePlatforms -and $mp.platforms.includePlatforms -notcontains 'all') {
                $notDetected = @($mp.platforms.includePlatforms | Where-Object { $detectedLower -notcontains $_.ToLower() })
                if ($notDetected.Count -gt 0 -and $notDetected.Count -lt $mp.platforms.includePlatforms.Count) {
                    $recommendation += " Platform(s) not found in Entra inventory — policy may have limited impact: $($notDetected -join ', ')."
                }
            }
        }

        $results.Add([PSCustomObject]@{
            BaselineId       = $baseline.id
            BaselineName     = $baseline.name
            BaselineFullName = $baseline.fullName
            Category         = $baseline.category
            Priority         = $baseline.priority
            Description      = $baseline.description
            Status           = $status
            MatchScore       = $bestScore
            MatchedPolicy    = if ($bestScore -ge 60 -and $bestMatch) { $bestMatch.displayName } else { $null }
            MatchedPolicyId       = if ($bestScore -ge 60 -and $bestMatch) { $bestMatch.id } else { $null }
            MatchedPolicyObject   = if ($bestScore -ge 60) { $bestMatch } else { $null }
            BaselineMatchPatterns = $baseline.matchPatterns
            Differences           = $bestDiffs
            Recommendation        = $recommendation
        })
    }

    # ── Tag unmatched existing policies as Custom ──
    $customPolicies = @($CurrentPolicies | Where-Object { $_.id -notin $matchedPolicyIds })

    $matched = @($results | Where-Object { $_.Status -eq 'Matched' }).Count
    $partial = @($results | Where-Object { $_.Status -eq 'Partial' }).Count
    $missing = @($results | Where-Object { $_.Status -eq 'Missing' }).Count
    $na      = @($results | Where-Object { $_.Status -eq 'NotApplicable' }).Count

    Write-Host "[CA-BaselineAuditor] Results: $matched matched, $partial partial, $missing missing, $na N/A | $($customPolicies.Count) custom policies" -ForegroundColor Green

    [PSCustomObject]@{
        BaselineResults = $results
        CustomPolicies  = $customPolicies
        Summary         = [PSCustomObject]@{
            Matched       = $matched
            Partial       = $partial
            Missing       = $missing
            NotApplicable = $na
            Custom        = $customPolicies.Count
            TotalBaseline = $BaselinePolicies.Count
            TotalTenant   = $CurrentPolicies.Count
        }
    }
}
