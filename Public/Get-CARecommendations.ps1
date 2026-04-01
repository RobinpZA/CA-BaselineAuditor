function Get-CARecommendations {
    <#
    .SYNOPSIS
        Produces a prioritised recommendation list from baseline comparison results.
    .DESCRIPTION
        Filters and sorts the baseline gap analysis results into actionable
        recommendations grouped by category and priority.
    .PARAMETER ComparisonResult
        Output from Compare-CABaseline.
    .PARAMETER Licensing
        Licensing detection result from Get-CATenantLicensing.
    .EXAMPLE
        $recs = Get-CARecommendations -ComparisonResult $comparison -Licensing $lic
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$ComparisonResult,

        [Parameter(Mandatory)]
        [object]$Licensing
    )

    Write-Host '[CA-BaselineAuditor] Generating recommendations...' -ForegroundColor Cyan

    $priorityOrder = @{ 'Must Have' = 1; 'Should Have' = 2; 'Could Have' = 3 }
    $categoryOrder = @{ 'Prerequisite' = 1; 'User' = 2; 'Device' = 3; 'Location' = 4 }

    $recommendations = [System.Collections.Generic.List[object]]::new()

    foreach ($result in $ComparisonResult.BaselineResults) {
        if ($result.Status -eq 'Matched') { continue }

        $severity = switch ($result.Status) {
            'Missing' {
                switch ($result.Priority) {
                    'Must Have'   { 'Critical' }
                    'Should Have' { 'High' }
                    'Could Have'  { 'Medium' }
                }
            }
            'Partial' {
                switch ($result.Priority) {
                    'Must Have'   { 'High' }
                    'Should Have' { 'Medium' }
                    'Could Have'  { 'Low' }
                }
            }
            'NotApplicable' { 'Info' }
        }

        $effort = Get-ImplementationEffort -BaselineId $result.BaselineId -Status $result.Status

        $recommendations.Add([PSCustomObject]@{
            BaselineId     = $result.BaselineId
            BaselineName   = $result.BaselineName
            Category       = $result.Category
            Priority       = $result.Priority
            Status         = $result.Status
            Severity       = $severity
            MatchedPolicy  = $result.MatchedPolicy
            Differences    = $result.Differences
            Recommendation = $result.Recommendation
            Description    = $result.Description
            Effort         = $effort
            SortKey        = ($categoryOrder[$result.Category] ?? 9) * 100 + ($priorityOrder[$result.Priority] ?? 9) * 10 + $(switch ($result.Status) { 'Missing' { 1 } 'Partial' { 2 } 'NotApplicable' { 3 } default { 4 }})
        })
    }

    # Sort by category → priority → status
    $sorted = $recommendations | Sort-Object SortKey

    # ── License upgrade recommendations ──
    $licenseRecs = [System.Collections.Generic.List[object]]::new()

    $naResults = @($ComparisonResult.BaselineResults | Where-Object { $_.Status -eq 'NotApplicable' })
    if ($naResults.Count -gt 0) {
        $missingLicenses = @{}
        foreach ($na in $naResults) {
            $baselineDef = $na  # Already has the info from comparison
            if ($na.Differences -and $na.Differences[0] -match 'License') {
                # Group by what license would unlock it
                $key = 'licensing'
                if (-not $missingLicenses.ContainsKey($key)) {
                    $missingLicenses[$key] = [System.Collections.Generic.List[string]]::new()
                }
                $missingLicenses[$key].Add("$($na.BaselineId): $($na.BaselineName)")
            }
        }

        if (-not $Licensing.HasEntraP2) {
            $p2Policies = @($naResults | Where-Object { $_.BaselineId -match 'CAU006|CAU007|CAU014|CAU015|CAU016' })
            if ($p2Policies.Count -gt 0) {
                $licenseRecs.Add([PSCustomObject]@{
                    License       = 'Entra ID P2'
                    PolicyCount   = $p2Policies.Count
                    Policies      = $p2Policies.BaselineId -join ', '
                    Impact        = 'Enables risk-based conditional access (sign-in risk, user risk, workload identity protection)'
                    Recommendation = 'Consider Entra ID P2 licensing to enable risk-based CA policies'
                })
            }
        }

        if (-not $Licensing.HasIntune) {
            $intunePolicies = @($naResults | Where-Object { $_.BaselineId -match 'CAD' })
            if ($intunePolicies.Count -gt 0) {
                $licenseRecs.Add([PSCustomObject]@{
                    License       = 'Microsoft Intune'
                    PolicyCount   = $intunePolicies.Count
                    Policies      = $intunePolicies.BaselineId -join ', '
                    Impact        = 'Enables device compliance-based CA policies for managed devices'
                    Recommendation = 'Consider Intune licensing to enable device compliance policies'
                })
            }
        }

        if (-not $Licensing.HasMDCA) {
            $mdcaPolicies = @($naResults | Where-Object { $_.BaselineId -match 'CAU004|CAU005' })
            if ($mdcaPolicies.Count -gt 0) {
                $licenseRecs.Add([PSCustomObject]@{
                    License       = 'Microsoft Defender for Cloud Apps'
                    PolicyCount   = $mdcaPolicies.Count
                    Policies      = $mdcaPolicies.BaselineId -join ', '
                    Impact        = 'Enables session routing and real-time monitoring through MDCA'
                    Recommendation = 'Consider MDCA licensing for session control capabilities'
                })
            }
        }
    }

    $criticalCount = @($sorted | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount     = @($sorted | Where-Object { $_.Severity -eq 'High' }).Count

    Write-Host "[CA-BaselineAuditor] Recommendations: $criticalCount critical, $highCount high, $($sorted.Count) total" -ForegroundColor Green

    [PSCustomObject]@{
        Recommendations    = @($sorted)
        LicenseUpgrades    = @($licenseRecs)
        CriticalCount      = $criticalCount
        HighCount          = $highCount
        TotalCount         = $sorted.Count
    }
}

function Get-ImplementationEffort {
    <#
    .SYNOPSIS
        Estimates implementation effort for a baseline policy.
    #>
    param(
        [string]$BaselineId,
        [string]$Status
    )

    if ($Status -eq 'Partial') { return 'Quick Win' }
    if ($Status -eq 'NotApplicable') { return 'N/A' }

    # Simple categorisation based on policy type
    switch -Regex ($BaselineId) {
        '^CAP'     { return 'Quick Win' }        # Block policies are straightforward
        'CAU002'   { return 'Quick Win' }        # Basic MFA for all
        'CAU001'   { return 'Quick Win' }        # Guest MFA
        'CAU009'   { return 'Quick Win' }        # Admin portal MFA
        'CAL002'   { return 'Moderate' }         # Needs named locations
        'CAL00[34]' { return 'Moderate' }        # Needs named locations + groups
        'CAU008|CAU013' { return 'Complex' }     # Phishing-resistant MFA rollout
        'CAU006|CAU007' { return 'Moderate' }    # Risk-based (needs P2 tuning)
        'CAD0'     { return 'Moderate' }         # Device policies need compliance policies
        default    { return 'Moderate' }
    }
}
