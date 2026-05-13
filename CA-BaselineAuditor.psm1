#region Module state
$script:CABAAuthContext = $null
$script:ModuleRoot = $PSScriptRoot
#endregion

#region Dot-source all function files
$Private = @(Get-ChildItem -Path "$PSScriptRoot/Private" -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue)
$Public  = @(Get-ChildItem -Path "$PSScriptRoot/Public"  -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue)

foreach ($file in @($Private + $Public)) {
    try {
        . $file.FullName
    } catch {
        Write-Error "Failed to import $($file.FullName): $_"
    }
}
#endregion
