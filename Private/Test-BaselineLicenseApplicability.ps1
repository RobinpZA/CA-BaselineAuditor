function Test-BaselineLicenseApplicability {
    <#
    .SYNOPSIS
        Checks whether a baseline policy is applicable given tenant licensing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Baseline,

        [Parameter(Mandatory)]
        [object]$Licensing
    )

    $licenseMap = @{
        'EntraP1'          = $Licensing.HasEntraP1
        'EntraP2'          = $Licensing.HasEntraP2
        'Intune'           = $Licensing.HasIntune
        'MDCA'             = $Licensing.HasMDCA
        'WorkloadIdentity' = $Licensing.HasWorkloadIdentity
        'CloudPC'          = $Licensing.HasCloudPC
        'DefenderForEndpoint' = $Licensing.HasDefenderForEndpoint
    }

    # All required licenses must be present
    foreach ($lic in $Baseline.requiredLicenses) {
        if ($licenseMap.ContainsKey($lic) -and -not $licenseMap[$lic]) {
            return $false
        }
    }

    # Feature checks (soft — warn but don't exclude for most)
    foreach ($feat in $Baseline.requiredFeatures) {
        switch ($feat) {
            'IdentityProtection' {
                if (-not $Licensing.HasEntraP2) { return $false }
            }
            'WorkloadIdentityProtection' {
                if (-not $Licensing.HasWorkloadIdentity) { return $false }
            }
            'MDCA' {
                if (-not $Licensing.HasMDCA) { return $false }
            }
        }
    }

    return $true
}
