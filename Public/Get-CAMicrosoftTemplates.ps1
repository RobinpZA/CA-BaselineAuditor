function Get-CAMicrosoftTemplates {
    <#
    .SYNOPSIS
        Retrieves Microsoft's built-in Conditional Access policy templates.
    .DESCRIPTION
        Fetches the CA templates from Graph API which represent Microsoft's recommended
        baseline policies, categorised by scenario (secureFoundation, zeroTrust, etc.).
    .EXAMPLE
        $templates = Get-CAMicrosoftTemplates
    #>
    [CmdletBinding()]
    param()

    Write-Host '[CA-BaselineAuditor] Retrieving Microsoft CA templates...' -ForegroundColor Cyan

    $templates = [System.Collections.Generic.List[object]]::new()
    $uri = 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/templates'

    try {
        do {
            $response = Invoke-MgGraphRequest -Method GET -Uri $uri
            foreach ($t in $response.value) {
                $templates.Add([PSCustomObject]@{
                    Id          = $t.id
                    Name        = $t.name
                    Description = $t.description
                    Scenarios   = $t.scenarios
                    Details     = $t.details
                })
            }
            $uri = $response.'@odata.nextLink'
        } while ($uri)
    } catch {
        Write-Warning "[CA-BaselineAuditor] Could not retrieve CA templates: $($_.Exception.Message)"
    }

    Write-Host "[CA-BaselineAuditor] Found $($templates.Count) Microsoft CA templates" -ForegroundColor Green

    $templates
}
