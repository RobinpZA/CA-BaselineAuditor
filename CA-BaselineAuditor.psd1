@{
    RootModule        = 'CA-BaselineAuditor.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a3c7e8f1-5b2d-4a9e-8c6f-1d3e5a7b9c2d'
    Author            = 'Robin Pieterse'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Audits Microsoft Entra Conditional Access policies against industry baselines (Kenneth van Surksum 2025-10 + Microsoft templates), filters recommendations by tenant licensing and device platforms, and generates an interactive HTML gap-analysis report.'

    PowerShellVersion = '7.2'

    RequiredModules   = @()

    FunctionsToExport = @(
        # Connection management
        'Connect-CABaselineAuditor'
        'Disconnect-CABaselineAuditor'
        'Get-CABaselineAuditorConnectionStatus'

        # Data collection
        'Get-CACurrentPolicies'
        'Get-CATenantLicensing'
        'Get-CATenantDevices'
        'Get-CAMicrosoftTemplates'
        'Get-CATenantContext'

        # Comparison & recommendations
        'Compare-CABaseline'
        'Get-CARecommendations'

        # Report generation
        'Export-CABaselineReport'

        # Main orchestrator
        'Invoke-CABaselineAudit'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('ConditionalAccess', 'Security', 'Audit', 'Baseline', 'EntraID', 'MicrosoftGraph', 'HTML', 'Report')
            ProjectUri   = ''
            LicenseUri   = ''
            ReleaseNotes = 'Initial release — baseline audit, license-aware filtering, HTML gap-analysis report.'

            ExternalModuleDependencies = @(
                'Microsoft.Graph.Authentication'
            )
        }
    }
}
