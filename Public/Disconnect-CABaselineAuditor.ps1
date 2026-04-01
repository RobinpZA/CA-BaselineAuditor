function Disconnect-CABaselineAuditor {
    <#
    .SYNOPSIS
        Disconnects from Microsoft Graph and clears module auth state.
    .EXAMPLE
        Disconnect-CABaselineAuditor
    #>
    [CmdletBinding()]
    param()

    Disconnect-MgGraph -ErrorAction SilentlyContinue
    $script:CABAAuthContext = $null
    Write-Host '[CA-BaselineAuditor] Disconnected from Microsoft Graph.' -ForegroundColor Green
}
