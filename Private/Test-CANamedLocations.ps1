function Test-CANamedLocations {
    <#
    .SYNOPSIS
        Checks whether named locations are configured (required for CAL policies).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $locations = $TenantContext.NamedLocations ?? @()
    $trustedCount = @($locations | Where-Object { $_.isTrusted -eq $true }).Count
    $ipLocations = @($locations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.ipNamedLocation' }).Count
    $countryLocations = @($locations | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.countryNamedLocation' }).Count

    $status = if ($locations.Count -eq 0) { 'Fail' }
              elseif ($trustedCount -eq 0) { 'Warning' }
              else { 'Pass' }

    $finding = switch ($status) {
        'Fail'    { 'No named locations configured. Location-based CA policies (CAL001-CAL006) require named locations.' }
        'Warning' { "$($locations.Count) named locations exist but none are marked as trusted. CAL policies require trusted locations." }
        'Pass'    { "$($locations.Count) named locations configured ($trustedCount trusted, $ipLocations IP-based, $countryLocations country-based)." }
    }

    [PSCustomObject]@{
        Status         = $status
        Finding        = $finding
        Severity       = switch ($status) { 'Fail' { 'High' } 'Warning' { 'Medium' } 'Pass' { 'Info' } }
        TotalLocations = $locations.Count
        TrustedCount   = $trustedCount
        IpLocations    = $ipLocations
        CountryLocations = $countryLocations
    }
}
