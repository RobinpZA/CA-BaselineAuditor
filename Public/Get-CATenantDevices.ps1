function Get-CATenantDevices {
    <#
    .SYNOPSIS
        Retrieves and summarises device inventory from Entra ID and Intune.
    .DESCRIPTION
        Queries Entra registered devices and (if Intune is licensed) managed devices
        to build a platform breakdown used to determine which device-specific CA
        baseline policies are relevant.
    .PARAMETER HasIntune
        Whether the tenant has Intune licensing. When false, skips Intune device query.
    .EXAMPLE
        $devices = Get-CATenantDevices -HasIntune $true
    #>
    [CmdletBinding()]
    param(
        [bool]$HasIntune = $false
    )

    Write-Host '[CA-BaselineAuditor] Collecting device inventory...' -ForegroundColor Cyan

    # ── Entra devices ──
    $entraDevices = [System.Collections.Generic.List[object]]::new()
    $uri = 'https://graph.microsoft.com/v1.0/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,isCompliant,isManaged,trustType,registrationDateTime,approximateLastSignInDateTime&$top=999'

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($d in $response.value) { $entraDevices.Add($d) }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve Entra devices: $($_.Exception.Message)"
    }

    # ── Normalise OS names ──
    $normOs = {
        param([string]$os)
        if (-not $os) { return 'Unknown' }
        $lower = $os.ToLower()
        if ($lower -match 'windows')  { return 'Windows' }
        if ($lower -match 'macos|mac os') { return 'macOS' }
        if ($lower -match 'ios|iphone|ipad') { return 'iOS' }
        if ($lower -match 'android')  { return 'Android' }
        if ($lower -match 'linux')    { return 'Linux' }
        return $os
    }

    # ── Intune managed devices ──
    # azureADDeviceId links each Intune record back to its Entra device object.
    $intuneDevices = [System.Collections.Generic.List[object]]::new()
    if ($HasIntune) {
        $uri = 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,operatingSystem,osVersion,complianceState,managementAgent,ownerType,enrolledDateTime,lastSyncDateTime&$top=999'
        try {
            do {
                $response = Invoke-MgGraphRequest -Method GET -Uri $uri
                foreach ($d in $response.value) { $intuneDevices.Add($d) }
                $uri = $response.'@odata.nextLink'
            } while ($uri)
        } catch {
            $errMsg = $_.Exception.Message
            $isPermissionIssue = $errMsg -match 'Forbidden|Unauthorized|AuthorizationRequestDenied|BadRequest|Insufficient'
            if ($isPermissionIssue) {
                Write-Host "[CA-BaselineAuditor] Intune device data unavailable — DeviceManagementManagedDevices.Read.All scope not consented. Falling back to Entra isManaged data." -ForegroundColor Yellow
            } else {
                Write-Warning "[CA-BaselineAuditor] Could not retrieve Intune devices: $errMsg"
            }
        }
    }

    # ── Build Intune lookup sets ──
    # HashSet of Entra device IDs known to Intune, used to cross-reference
    # per-platform so the report can show "Entra: 4 | Intune: 4" per OS.
    $intuneEntraIds       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $intunePlatformCounts = @{}
    $corporateCount       = 0
    $personalCount        = 0

    foreach ($d in $intuneDevices) {
        if ($d.azureADDeviceId -and $d.azureADDeviceId -ne '00000000-0000-0000-0000-000000000000') {
            [void]$intuneEntraIds.Add($d.azureADDeviceId)
        }
        $os = & $normOs $d.operatingSystem
        $intunePlatformCounts[$os] = ($intunePlatformCounts[$os] ?? 0) + 1
        if ($d.ownerType -eq 'company') { $corporateCount++ } else { $personalCount++ }
    }

    # ── Aggregate from Entra ──
    $platformCounts            = @{}
    $intuneEnrolledPerPlatform = @{}
    $managedPerPlatform        = @{}   # fallback: isManaged=true from Entra
    $managedCount              = 0
    $unmanagedCount            = 0
    $compliantCount            = 0
    $nonCompliantCount         = 0

    foreach ($d in $entraDevices) {
        $os = & $normOs $d.operatingSystem
        $platformCounts[$os] = ($platformCounts[$os] ?? 0) + 1

        # Cross-reference: is this Entra device also in Intune?
        if ($intuneEntraIds.Contains($d.id)) {
            $intuneEnrolledPerPlatform[$os] = ($intuneEnrolledPerPlatform[$os] ?? 0) + 1
        }

        # Fallback: Entra marks isManaged=true when enrolled in any MDM (including Intune)
        if ($d.isManaged -eq $true) {
            $managedPerPlatform[$os] = ($managedPerPlatform[$os] ?? 0) + 1
            $managedCount++
        } else {
            $unmanagedCount++
        }
        if ($d.isCompliant -eq $true) { $compliantCount++ } else { $nonCompliantCount++ }
    }

    # When Intune API returned no data, fall back to isManaged per platform from Entra
    if ($intuneDevices.Count -eq 0 -and $managedCount -gt 0) {
        $intuneEnrolledPerPlatform = $managedPerPlatform
    }

    # ── Aggregate from Intune (ownership) ──
    $corporateCount = 0
    $personalCount  = 0
    foreach ($d in $intuneDevices) {
        if ($d.ownerType -eq 'company') { $corporateCount++ } else { $personalCount++ }
    }

    $detectedPlatforms = @($platformCounts.Keys | Where-Object { $platformCounts[$_] -gt 0 })

    $result = [PSCustomObject]@{
        EntraDeviceCount           = $entraDevices.Count
        IntuneDeviceCount          = if ($intuneDevices.Count -gt 0) { $intuneDevices.Count } else { $managedCount }
        PlatformCounts             = [PSCustomObject]$platformCounts
        IntunePlatformCounts       = [PSCustomObject]$intunePlatformCounts
        IntuneEnrolledPerPlatform  = [PSCustomObject]$intuneEnrolledPerPlatform
        DetectedPlatforms          = $detectedPlatforms
        ManagedCount               = $managedCount
        UnmanagedCount             = $unmanagedCount
        CompliantCount             = $compliantCount
        NonCompliantCount          = $nonCompliantCount
        CorporateOwned             = $corporateCount
        PersonalBYOD               = $personalCount
        HasIntuneData              = ($intuneDevices.Count -gt 0 -or $managedCount -gt 0)
    }

    Write-Host "[CA-BaselineAuditor] Devices: $($entraDevices.Count) Entra, $($intuneDevices.Count) Intune | Platforms: $($detectedPlatforms -join ', ')" -ForegroundColor Green

    $result
}
