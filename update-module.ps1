param (
    [string]$ModuleName
)

# try {
#     Update-ModuleIfOldOrMissing -ModuleName $ModuleName
#     $moduleInfo = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
#     $moduleDetails = [pscustomobject]@{
#         Name    = $ModuleName
#         Version = $moduleInfo.Version
#         Path    = $moduleInfo.ModuleBase
#     }
#     Write-EnhancedLog -Message "Success: $(ConvertTo-Json $moduleDetails)"
# }
# catch {
#     $moduleDetails = [pscustomobject]@{
#         Name    = $ModuleName
#         Version = "N/A"
#         Path    = "N/A"
#     }
#     Write-EnhancedLog -Message "Failure: $(ConvertTo-Json $moduleDetails)"
# }

    # Create lists for success and failed modules
    $moduleSuccessCount = 0
    $moduleFailCount = 0
    $successModules = [System.Collections.Generic.List[PSCustomObject]]::new()
    $failedModules = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    Update-ModuleIfOldOrMissing -ModuleName $moduleName
    $moduleInfo = Get-Module -Name $moduleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $moduleDetails = [PSCustomObject]@{
        Name    = $moduleName
        Version = $moduleInfo.Version
        Path    = $moduleInfo.ModuleBase
    }
    $successModules.Add($moduleDetails)
    Write-EnhancedLog -Message "Successfully installed/updated module: $moduleName" -Level "INFO"
    $moduleSuccessCount++
}
catch {
    $moduleDetails = [PSCustomObject]@{
        Name    = $moduleName
        Version = "N/A"
        Path    = "N/A"
    }
    $failedModules.Add($moduleDetails)
    Write-EnhancedLog -Message "Failed to install/update module: $moduleName. Error: $_" -Level "ERROR"
    $moduleFailCount++
}