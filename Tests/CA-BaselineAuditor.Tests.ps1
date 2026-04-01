BeforeAll {
    $ModuleRoot = Split-Path $PSScriptRoot -Parent
    Import-Module "$ModuleRoot\CA-BaselineAuditor.psd1" -Force
}

Describe 'CA-BaselineAuditor Module' {
    It 'Should import without errors' {
        { Import-Module "$ModuleRoot\CA-BaselineAuditor.psd1" -Force } | Should -Not -Throw
    }

    It 'Should export expected public functions' {
        $expected = @(
            'Connect-CABaselineAuditor', 'Disconnect-CABaselineAuditor', 'Get-CABaselineAuditorConnectionStatus',
            'Get-CACurrentPolicies', 'Get-CATenantLicensing', 'Get-CATenantDevices',
            'Get-CAMicrosoftTemplates', 'Get-CATenantContext',
            'Compare-CABaseline', 'Get-CARecommendations',
            'Export-CABaselineReport', 'Invoke-CABaselineAudit'
        )
        $module = Get-Module CA-BaselineAuditor
        foreach ($fn in $expected) {
            $module.ExportedFunctions.Keys | Should -Contain $fn
        }
    }

    It 'Should not export private functions' {
        $module = Get-Module CA-BaselineAuditor
        $module.ExportedFunctions.Keys | Should -Not -Contain 'Get-PolicyMatchScore'
        $module.ExportedFunctions.Keys | Should -Not -Contain 'Test-CABreakGlassAccounts'
        $module.ExportedFunctions.Keys | Should -Not -Contain 'Format-PolicyDisplay'
    }
}

Describe 'Baseline JSON' {
    BeforeAll {
        $baselinePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Baselines' 'vansurksum-202510.json'
        $baseline = Get-Content $baselinePath -Raw | ConvertFrom-Json
    }

    It 'Should contain 50 policies' {
        $baseline.policies.Count | Should -Be 50
    }

    It 'Should have policyIntent on all policies' {
        $validIntents = @(
            'legacy-auth-block', 'auth-flow-block', 'risk-based',
            'registration-security', 'token-protection', 'terms-of-use',
            'compliant-network', 'mfa-grant', 'admin-protection',
            'guest-access', 'device-compliance', 'session-control',
            'platform-block', 'location-based', 'app-restriction'
        )
        foreach ($p in $baseline.policies) {
            $p.policyIntent | Should -Not -BeNullOrEmpty
            $p.policyIntent | Should -BeIn $validIntents
        }
    }

    It 'Should have all required fields per policy' {
        foreach ($p in $baseline.policies) {
            $p.id              | Should -Not -BeNullOrEmpty
            $p.name            | Should -Not -BeNullOrEmpty
            $p.category        | Should -Not -BeNullOrEmpty
            $p.priority        | Should -Not -BeNullOrEmpty
            $p.requiredLicenses | Should -Not -BeNull
        }
    }

    It 'Should have valid categories' {
        $valid = @('Prerequisite', 'User', 'Device', 'Location')
        foreach ($p in $baseline.policies) {
            $p.category | Should -BeIn $valid
        }
    }

    It 'Should have valid priorities' {
        $valid = @('Must Have', 'Should Have', 'Could Have')
        foreach ($p in $baseline.policies) {
            $p.priority | Should -BeIn $valid
        }
    }
}

Describe 'Get-PolicyMatchScore' {
    BeforeAll {
        # Dot-source private functions for testing
        . "$ModuleRoot\Private\Get-PolicyMatchScore.ps1"
    }

    It 'Should return 0 for completely unrelated policies' {
        $baseline = @{
            id = 'CAP001'; name = 'Block Legacy Authentication'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('block') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            keywords = @('block', 'legacy')
        }
        $tenant = @{
            displayName = 'Require MFA for Admins'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -BeLessThan 50
    }

    It 'Should return high score for structurally matching policy' {
        $baseline = @{
            id = 'CAP001'; name = 'Block Legacy Authentication'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('block') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            keywords = @('block', 'legacy')
        }
        $tenant = @{
            displayName = 'CAP001: Block Legacy Auth'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -BeGreaterOrEqual 80
    }

    It 'Should disqualify block vs non-block mismatch' {
        $baseline = @{
            id = 'CAP001'; name = 'Block Legacy'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('block') }
                applications = @{ includeApplications = @('All') }
            }
            keywords = @('block', 'legacy')
        }
        $tenant = @{
            displayName = 'CAP001: Block Legacy Auth'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -Be 0
        $result.Differences | Should -Contain 'Grant controls differ: expected [block], found [mfa]'
    }

    It 'Should return Checks array with per-check breakdown' {
        $baseline = @{
            id = 'CAP001'; name = 'Test'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('mfa') }
                applications = @{ includeApplications = @('All') }
            }
            keywords = @('test')
        }
        $tenant = @{
            displayName = 'Test Policy'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Checks | Should -Not -BeNullOrEmpty
        $result.Checks.Name | Should -Contain 'GrantControls'
        $result.Checks.Name | Should -Contain 'UserScope'
        $result.Checks.Name | Should -Contain 'AppScope'
        $result.Checks.Name | Should -Contain 'PolicyState'
    }

    It 'Should disqualify incompatible policy intents' {
        $baseline = @{
            id = 'CAU006'; name = 'Risk Sign-in MFA'
            policyIntent = 'risk-based'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('mfa') }
                applications = @{ includeApplications = @('All') }
                conditions = @{ signInRiskLevels = @('medium', 'high') }
            }
            keywords = @('risk', 'mfa')
        }
        # Tenant policy is a legacy auth block — completely different intent
        $tenant = @{
            displayName = 'Block Legacy Auth'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -Be 0
    }

    It 'Should disqualify admin-role baseline matched against specific-user tenant policy' {
        # Baseline requires admin role targeting; tenant targets specific user GUIDs (not roles, not All).
        # Even if all other checks match, this is a fundamentally different policy scope.
        $baseline = @{
            id = 'CAU008'; name = 'Phishing Resistant MFA for Admins'
            policyIntent = 'admin-protection'
            matchPatterns = @{
                users = @{ includeRoles = $true }
                grantControls = @{ authenticationStrength = @{ requirementsSatisfied = 'phishingResistant' } }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            keywords = @('phishing', 'admin')
        }
        # Tenant policy targets specific user GUIDs — not admin roles
        $tenant = @{
            displayName = 'Device Compliance Policy'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('6230834d-4d5c-4c28-bfe2-1674fdc9e7be', 'c62ffd29-0c0c-40f9-b043-53153ae934eb') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            grantControls = @{ authenticationStrength = @{ requirementsSatisfied = 'phishingResistant' } }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -Be 0
        $result.Differences | Should -Contain 'Expected admin role targeting — policy does not target admin roles'
    }

    It 'Should penalise admin-role tenant policy against All-users baseline' {
        # CAU009-style: baseline targets All users at admin portals.
        # Tenant policy targets admin roles instead — user scope should be penalised (not disqualified).
        $baseline = @{
            id = 'CAU009'; name = 'MFA for Admin Portals for All Users'
            policyIntent = 'mfa-grant'
            matchPatterns = @{
                users = @{ includeUsers = @('All') }
                grantControls = @{ builtInControls = @('mfa'); authenticationStrength = $true }
                applications = @{ includeApplications = @('MicrosoftAdminPortals', '797f4846-ba00-4fd7-ba43-dac1f8f63013') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            keywords = @('admin portal', 'mfa')
        }
        $tenantAdminRoles = @{
            displayName = 'Require MFA for admins'; state = 'enabled'
            conditions = @{
                users = @{ includeRoles = @('62e90394-69f5-4237-9190-012177145e10', '194ae4cb-b126-40b2-bd5b-6091b380977d') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantAdminRoles
        # Score should be penalised (not a full match) due to wrong user targeting
        $result.Score | Should -BeLessThan 80
        $result.Differences | Should -Contain 'Expected all-users targeting (policy targets specific groups/roles)'
    }


    It 'Should accept mfa builtInControl as satisfying mfa-level auth strength requirement' {
        # Baseline requires authStrength.requirementsSatisfied = mfa.
        # Tenant uses traditional mfa builtInControl instead — equivalent, should pass.
        $baseline = @{
            id = 'CAU009'; name = 'MFA for Admin Portals'
            matchPatterns = @{
                grantControls = @{
                    builtInControls = @('mfa')
                    authenticationStrength = @{ requirementsSatisfied = 'mfa' }
                }
                applications = @{ includeApplications = @('MicrosoftAdminPortals') }
                users = @{ includeUsers = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            keywords = @('admin portal', 'mfa')
        }
        $tenantMfaBuiltIn = @{
            displayName = 'Require MFA for all users'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('MicrosoftAdminPortals') }
                clientAppTypes = @('all')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantMfaBuiltIn
        $result.Differences | Should -Not -Contain 'Authentication strength not configured'
        $result.Differences | Should -Not -BeLike '*Authentication strength*required*'
    }

    It 'Should reject mfa-only for phishingResistant auth strength requirement' {
        # Baseline requires phishingResistant. Tenant only has mfa grant — weaker, should diff.
        $baseline = @{
            id = 'CAU008'; name = 'Phishing Resistant MFA for Admins'
            matchPatterns = @{
                grantControls = @{ authenticationStrength = @{ requirementsSatisfied = 'phishingResistant' } }
                users = @{ includeRoles = $true }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            keywords = @('phishing', 'admin')
        }
        $tenantMfaOnly = @{
            displayName = 'Require MFA for admins'; state = 'enabled'
            conditions = @{
                users = @{ includeRoles = @('62e90394-69f5-4237-9190-012177145e10') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            grantControls = @{ builtInControls = @('mfa') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantMfaOnly
        $result.Differences | Should -BeLike '*Authentication strength*phishingResistant*'
    }

    It 'Should accept phishingResistant auth strength when mfa level required (stronger satisfies)' {
        $baseline = @{
            id = 'CAU002'; name = 'MFA for All Users'
            matchPatterns = @{
                grantControls = @{ authenticationStrength = @{ requirementsSatisfied = 'mfa' } }
                applications = @{ includeApplications = @('All') }
                users = @{ includeUsers = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            keywords = @('mfa', 'all users')
        }
        $tenantPhishResistant = @{
            displayName = 'Require Phishing Resistant MFA'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser', 'mobileAppsAndDesktopClients')
            }
            grantControls = @{ authenticationStrength = @{ requirementsSatisfied = 'phishingResistant' } }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantPhishResistant
        $result.Differences | Should -Not -BeLike '*Authentication strength*'
        $result.Score | Should -BeGreaterOrEqual 80
    }

    It 'Should disqualify wrong session control type' {
        # Baseline requires signInFrequency; tenant only has cloudAppSecurity (CASB routing).
        # These are fundamentally different session controls — should score 0.
        $baseline = @{
            id = 'CAD008'; name = 'Sign-in Frequency for Browser and Non-Compliant'
            policyIntent = 'session-control'
            matchPatterns = @{
                sessionControls = @{ signInFrequency = $true }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser')
            }
            keywords = @('sign-in frequency')
        }
        $tenant = @{
            displayName = 'Onboard Apps to CASB'; state = 'enabledForReportingButNotEnforced'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('browser')
            }
            sessionControls = @{
                cloudAppSecurity = @{ isEnabled = $true; cloudAppSecurityType = 'mcasConfigured' }
            }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -Be 0
    }

    It 'Should check grant operator (OR vs AND)' {
        # Operator is only meaningful when there are 2+ controls to combine.
        # Baseline: compliantDevice OR domainJoinedDevice (satisfy either).
        # A tenant requiring BOTH (AND) is stricter — operator should differ.
        $baseline = @{
            id = 'CAD001'; name = 'macOS Compliant'
            matchPatterns = @{
                grantControls = @{
                    builtInControls = @('compliantDevice', 'domainJoinedDevice')
                    operator = 'OR'
                }
                applications = @{ includeApplications = @('Office365') }
                platforms = @{ includePlatforms = @('macOS') }
            }
            keywords = @('macos', 'compliant')
        }
        $tenantOR = @{
            displayName = 'macOS Compliant OR'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('Office365') }
                clientAppTypes = @('mobileAppsAndDesktopClients')
                platforms = @{ includePlatforms = @('macOS') }
            }
            grantControls = @{ builtInControls = @('compliantDevice', 'domainJoinedDevice'); operator = 'OR' }
        }
        $tenantAND = @{
            displayName = 'macOS Compliant AND'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('Office365') }
                clientAppTypes = @('mobileAppsAndDesktopClients')
                platforms = @{ includePlatforms = @('macOS') }
            }
            grantControls = @{ builtInControls = @('compliantDevice', 'domainJoinedDevice'); operator = 'AND' }
        }
        $resultOR  = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantOR
        $resultAND = Get-PolicyMatchScore -Baseline $baseline -Policy $tenantAND
        $resultOR.Score | Should -BeGreaterThan $resultAND.Score
        $resultAND.Differences | Should -Contain 'Grant operator differs: expected [OR], found [AND]'
    }

    It 'Should apply weightOverrides from baseline' {
        $baseline = @{
            id = 'CAP003'; name = 'Block device code flow'
            matchPatterns = @{
                grantControls = @{ builtInControls = @('block') }
                applications = @{ includeApplications = @('All') }
                conditions = @{ authenticationFlows = @('deviceCodeFlow') }
            }
            weightOverrides = @{
                grantControls = 20; userScope = 15; appScope = 15; conditions = 40; policyState = 10
            }
            keywords = @('device code', 'block')
        }
        $tenant = @{
            displayName = 'Block device code'; state = 'enabled'
            conditions = @{
                users = @{ includeUsers = @('All') }
                applications = @{ includeApplications = @('All') }
                clientAppTypes = @('all')
                authenticationFlows = @{ transferMethods = @('deviceCodeFlow') }
            }
            grantControls = @{ builtInControls = @('block') }
        }
        $result = Get-PolicyMatchScore -Baseline $baseline -Policy $tenant
        $result.Score | Should -BeGreaterOrEqual 80
        $condCheck = $result.Checks | Where-Object { $_.Name -eq 'Conditions' }
        $condCheck.Weight | Should -Be 40
    }
}

Describe 'Test-BaselineLicenseApplicability' {
    BeforeAll {
        . "$ModuleRoot\Private\Test-BaselineLicenseApplicability.ps1"
    }

    It 'Should return applicable when no licenses required' {
        $bl = @{ requiredLicenses = @(); requiredFeatures = @() }
        $licensing = [PSCustomObject]@{ HasEntraP1 = $false; HasEntraP2 = $false; HasIntune = $false; HasMDCA = $false }
        $result = Test-BaselineLicenseApplicability -Baseline $bl -Licensing $licensing
        $result | Should -BeTrue
    }

    It 'Should return not applicable when P2 required but missing' {
        $bl = @{ requiredLicenses = @('EntraP2'); requiredFeatures = @() }
        $licensing = [PSCustomObject]@{ HasEntraP1 = $true; HasEntraP2 = $false; HasIntune = $false; HasMDCA = $false; HasWorkloadIdentity = $false }
        $result = Test-BaselineLicenseApplicability -Baseline $bl -Licensing $licensing
        $result | Should -BeFalse
    }

    It 'Should return applicable when all required licenses present' {
        $bl = @{ requiredLicenses = @('EntraP2', 'Intune'); requiredFeatures = @() }
        $licensing = [PSCustomObject]@{ HasEntraP1 = $true; HasEntraP2 = $true; HasIntune = $true; HasMDCA = $true; HasWorkloadIdentity = $true }
        $result = Test-BaselineLicenseApplicability -Baseline $bl -Licensing $licensing
        $result | Should -BeTrue
    }
}

Describe 'Export-CABaselineReport' {
    It 'Should generate an HTML file' {
        $tempPath = Join-Path $TestDrive 'test-report.html'
        $mockAudit = [PSCustomObject]@{
            Comparison = [PSCustomObject]@{
                BaselineResults = @()
                UnmatchedTenantPolicies = @()
                Summary = [PSCustomObject]@{ TotalBaseline = 0; Matched = 0; Partial = 0; Missing = 0; NotApplicable = 0; TotalTenant = 0; Custom = 0 }
            }
            Recommendations    = [PSCustomObject]@{ Recommendations = @(); LicenseUpgrades = @(); TotalCount = 0 }
            CurrentPolicies    = @()
            Licensing          = [PSCustomObject]@{ HasEntraP1 = $true; HasEntraP2 = $false; HasIntune = $false; HasMDCA = $false; HasWorkloadIdentity = $false; HasCloudPC = $false; HasDefenderForEndpoint = $false }
            DeviceInfo         = [PSCustomObject]@{ EntraDeviceCount = 0; IntuneDeviceCount = 0; CompliantCount = 0; NonCompliantCount = 0; CorporateOwned = 0; PersonalBYOD = 0; PlatformCounts = [PSCustomObject]@{} }
            TenantContext      = [PSCustomObject]@{ TenantName = 'Test'; TenantDomain = 'test.onmicrosoft.com'; GuestCount = 0 }
            MicrosoftTemplates = @()
            PostureChecks      = @{}
        }
        $result = Export-CABaselineReport -AuditData $mockAudit -OutputPath $tempPath
        Test-Path $result | Should -BeTrue
        $content = Get-Content $result -Raw
        $content | Should -Match '<!DOCTYPE html>'
        $content | Should -Match 'CA Baseline Audit'
    }
}
