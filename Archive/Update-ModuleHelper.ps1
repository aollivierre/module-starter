# function Update-ModuleHelper {
#     param (
#         [string]$moduleName,
#         [ref]$successModules,
#         [ref]$failedModules,
#         [ref]$moduleSuccessCount,
#         [ref]$moduleFailCount
#     )

#     try {
#         Update-ModuleIfOldOrMissing -ModuleName $moduleName
#         $moduleInfo = Get-Module -Name $moduleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
#         $moduleDetails = [PSCustomObject]@{
#             Name    = $moduleName
#             Version = $moduleInfo.Version
#             Path    = $moduleInfo.ModuleBase
#         }
#         $successModules.Value.Add($moduleDetails)
#         Write-EnhancedLog -Message "Successfully installed/updated module: $moduleName" -Level "INFO"
#         $moduleSuccessCount.Value++
#     }
#     catch {
#         $moduleDetails = [PSCustomObject]@{
#             Name    = $moduleName
#             Version = "N/A"
#             Path    = "N/A"
#         }
#         $failedModules.Value.Add($moduleDetails)
#         Write-EnhancedLog -Message "Failed to install/update module: $moduleName. Error: $_" -Level "ERROR"
#         $moduleFailCount.Value++
#     }
# } 




# function Update-ModuleHelper {
#     param (
#         [string]$moduleName
#     )

#     $moduleDetails = [PSCustomObject]@{
#         Name    = $moduleName
#         Version = "N/A"
#         Path    = "N/A"
#         Success = $false
#     }

#     try {
#         Update-ModuleIfOldOrMissing -ModuleName $moduleName
#         $moduleInfo = Get-Module -Name $moduleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

#         if ($null -eq $moduleInfo) {
#             Write-EnhancedLog -Message "Failed to retrieve module information for: $moduleName" -Level "ERROR"
#         } else {
#             $moduleDetails.Version = $moduleInfo.Version
#             $moduleDetails.Path    = $moduleInfo.ModuleBase
#             $moduleDetails.Success = $true
#             Write-EnhancedLog -Message "Successfully installed/updated module: $moduleName" -Level "INFO"
#         }
#     }
#     catch {
#         Write-EnhancedLog -Message "Failed to install/update module: $moduleName. Error: $_" -Level "ERROR"
#     }

#     return $moduleDetails
# }
