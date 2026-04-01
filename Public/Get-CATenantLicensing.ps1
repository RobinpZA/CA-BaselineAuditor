function Get-CATenantLicensing {
    <#
    .SYNOPSIS
        Detects tenant licensing relevant to Conditional Access policy applicability.
    .DESCRIPTION
        Queries subscribedSkus and checks for specific SKUs and service plans
        to determine which CA features are available.
    .EXAMPLE
        $licensing = Get-CATenantLicensing
        if ($licensing.HasEntraP2) { 'Risk-based policies available' }
    #>
    [CmdletBinding()]
    param()

    Write-Host '[CA-BaselineAuditor] Detecting tenant licensing...' -ForegroundColor Cyan

    $skus = (Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus').value

    # Collect all active service plan names and SKU part numbers
    $activeSkuPartNumbers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $activeServicePlans   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($sku in $skus) {
        if ($sku.consumedUnits -le 0) { continue }
        [void]$activeSkuPartNumbers.Add($sku.skuPartNumber)
        foreach ($sp in $sku.servicePlans) {
            if ($sp.provisioningStatus -eq 'Success' -or $sp.provisioningStatus -eq 'PendingActivation') {
                [void]$activeServicePlans.Add($sp.servicePlanName)
            }
        }
    }

    # ── Helper: check if any value in a list matches ──
    $hasAny = {
        param([string[]]$Names, [System.Collections.Generic.HashSet[string]]$Set)
        foreach ($n in $Names) { if ($Set.Contains($n)) { return $true } }
        return $false
    }

    # ── Entra ID P1 ──
    $entraP1Skus   = @('AAD_PREMIUM', 'AAD_PREMIUM_P2', 'EMS', 'EMSPREMIUM', 'SPE_E3', 'SPE_E5', 'SPE_F1', 'SPP', 'IDENTITY_THREAT_PROTECTION', 'IDENTITY_THREAT_PROTECTION_PREVIEW')
    $entraP1Plans  = @('AAD_PREMIUM', 'AAD_PREMIUM_P2', 'EXCHANGE_S_ENTERPRISE')
    $hasEntraP1    = (& $hasAny $entraP1Skus $activeSkuPartNumbers) -or (& $hasAny $entraP1Plans $activeServicePlans)

    # ── Entra ID P2 ──
    $entraP2Skus   = @('AAD_PREMIUM_P2', 'EMSPREMIUM', 'SPE_E5', 'IDENTITY_THREAT_PROTECTION', 'IDENTITY_THREAT_PROTECTION_PREVIEW')
    $entraP2Plans  = @('AAD_PREMIUM_P2')
    $hasEntraP2    = (& $hasAny $entraP2Skus $activeSkuPartNumbers) -or (& $hasAny $entraP2Plans $activeServicePlans)

    # ── Intune ──
    $intuneSkus    = @('INTUNE_A', 'EMS', 'EMSPREMIUM', 'SPE_E3', 'SPE_E5', 'SPP', 'INTUNE_SMB', 'Intune_EDU')
    $intunePlans   = @('INTUNE_A', 'INTUNE_A_D', 'INTUNE_SMBIZ')
    $hasIntune     = (& $hasAny $intuneSkus $activeSkuPartNumbers) -or (& $hasAny $intunePlans $activeServicePlans)

    # ── Microsoft Defender for Cloud Apps (MDCA) ──
    $mdcaSkus      = @('ADALLOM_STANDALONE', 'ATA', 'SPE_E5')
    $mdcaPlans     = @('ADALLOM_S_STANDALONE', 'ADALLOM_S_O365')
    $hasMDCA       = (& $hasAny $mdcaSkus $activeSkuPartNumbers) -or (& $hasAny $mdcaPlans $activeServicePlans)

    # ── Workload Identity Premium ──
    $wlidPlans     = @('MICROSOFT_ENTRA_WORKLOAD_IDENTITY_PREMIUM')
    $hasWorkloadId = & $hasAny $wlidPlans $activeServicePlans

    # ── Windows 365 / Cloud PC ──
    $cloudPcPlans  = @('CPC_B_1C_2RAM_64GB', 'CPC_B_2C_4RAM_64GB', 'CPC_B_2C_8RAM_128GB', 'CPC_E_1C_2GB_64GB', 'CPC_E_2C_4GB_64GB', 'WINDOWS_365_S_2C_4GB_64GB')
    $hasCloudPC    = & $hasAny $cloudPcPlans $activeServicePlans

    # ── Defender for Endpoint ──
    $mdePlans      = @('WINDEFATP', 'DEFENDER_ENDPOINT_P1', 'MDE_SMB', 'MDE_LITE', 'WIN_DEF_ATP')
    $hasMDE        = & $hasAny $mdePlans $activeServicePlans

    $result = [PSCustomObject]@{
        HasEntraP1         = [bool]$hasEntraP1
        HasEntraP2         = [bool]$hasEntraP2
        HasIntune          = [bool]$hasIntune
        HasMDCA            = [bool]$hasMDCA
        HasWorkloadIdentity = [bool]$hasWorkloadId
        HasCloudPC         = [bool]$hasCloudPC
        HasDefenderForEndpoint = [bool]$hasMDE
        ActiveSkus         = @($skus | Where-Object { $_.consumedUnits -gt 0 } | ForEach-Object {
            [PSCustomObject]@{
                SkuPartNumber = $_.skuPartNumber
                SkuId         = $_.skuId
                ConsumedUnits = $_.consumedUnits
                PrepaidUnits  = $_.prepaidUnits.enabled
            }
        })
        RawServicePlans    = $activeServicePlans
    }

    Write-Host "[CA-BaselineAuditor] Licensing: P1=$($result.HasEntraP1) P2=$($result.HasEntraP2) Intune=$($result.HasIntune) MDCA=$($result.HasMDCA) CloudPC=$($result.HasCloudPC)" -ForegroundColor Green

    $result
}
