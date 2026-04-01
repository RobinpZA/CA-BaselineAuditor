function Test-CAAuthMethodReadiness {
    <#
    .SYNOPSIS
        Checks if phishing-resistant MFA methods are enabled in the tenant.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$TenantContext
    )

    $methods = $TenantContext.AuthMethodsPolicy
    if (-not $methods) {
        return [PSCustomObject]@{
            Status   = 'Warning'
            Finding  = 'Could not retrieve authentication methods policy'
            Severity = 'Medium'
            Methods  = @()
        }
    }

    $enabledMethods = [System.Collections.Generic.List[object]]::new()
    $phishingResistant = @()

    foreach ($config in ($methods.authenticationMethodConfigurations ?? @())) {
        $isEnabled = $config.state -eq 'enabled'
        $enabledMethods.Add([PSCustomObject]@{
            Method  = $config.id
            Enabled = $isEnabled
        })

        if ($isEnabled -and $config.id -in @('Fido2', 'WindowsHelloForBusiness', 'X509Certificate')) {
            $phishingResistant += $config.id
        }
    }

    $hasFido2 = 'Fido2' -in $phishingResistant
    $hasWHfB  = 'WindowsHelloForBusiness' -in $phishingResistant
    $hasCBA   = 'X509Certificate' -in $phishingResistant

    $status = if ($phishingResistant.Count -ge 1) { 'Pass' }
              else { 'Warning' }

    $finding = if ($phishingResistant.Count -eq 0) {
        'No phishing-resistant MFA methods enabled. Required for CAU008 (admin) and CAU013 (all users). Enable FIDO2, Windows Hello, or Certificate-based auth.'
    } else {
        "Phishing-resistant methods enabled: $($phishingResistant -join ', '). Ready for CAU008/CAU013."
    }

    [PSCustomObject]@{
        Status             = $status
        Finding            = $finding
        Severity           = if ($phishingResistant.Count -eq 0) { 'High' } else { 'Info' }
        PhishingResistant  = $phishingResistant
        HasFido2           = $hasFido2
        HasWindowsHello    = $hasWHfB
        HasCertificateAuth = $hasCBA
        AllMethods         = @($enabledMethods)
    }
}
