@{
    RootModule        = 'CA-BaselineAuditor.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'a3c7e8f1-5b2d-4a9e-8c6f-1d3e5a7b9c2d'
    Author            = 'Robin Pieterse'
    CompanyName       = 'Unknown'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Audits Microsoft Entra Conditional Access policies against multiple industry baselines: Kenneth van Surksum Oct 2025, CISA SCuBA (MS.AAD), Maester MT.1xxx, and CIS M365 Foundations Benchmark. Filters recommendations by tenant licensing and device platforms, and generates an interactive HTML gap-analysis report with per-baseline filtering.'

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

        # Web portal
        'Start-CABaselineAuditorPortal'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('ConditionalAccess', 'Security', 'Audit', 'Baseline', 'EntraID', 'MicrosoftGraph', 'HTML', 'Report', 'CISA', 'SCuBA', 'Maester', 'CIS', 'VanSurksum')
            ProjectUri   = ''
            LicenseUri   = ''
            ReleaseNotes = 'v1.1.0 — Added multi-baseline support: CISA SCuBA (MS.AAD), Maester MT.1xxx, and CIS M365 Foundations Benchmark. New -Baseline parameter on Invoke-CABaselineAudit. HTML report now includes per-baseline source column, colour-coded badges, and a baseline filter dropdown.'

            ExternalModuleDependencies = @(
                'Microsoft.Graph.Authentication'
            )
        }
    }
}
