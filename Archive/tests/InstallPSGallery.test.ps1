# $mode = $env:EnvironmentMode

#region FIRING UP MODULE STARTER
#################################################################################################
#                                                                                               #
#                                 FIRING UP MODULE STARTER                                      #
#                                                                                               #
#################################################################################################


Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1")

# Define a hashtable for splatting
$moduleStarterParams = @{
    Mode                   = 'dev'
    SkipPSGalleryModules   = $true
    SkipCheckandElevate    = $true
    SkipPowerShell7Install = $true
    SkipEnhancedModules    = $true
    SkipGitRepos           = $true
}

# Call the function using the splat
Invoke-ModuleStarter @moduleStarterParams

#endregion FIRING UP MODULE STARTER

# Example usage
# Invoke-InPowerShell5 -ScriptPath "C:\Scripts\MyScript.ps1"
# Invoke-InPowerShell5 -ScriptPath $PSScriptRoot

# Invoke-InPowerShell5

# Reset-ModulePaths

# # Install-ModuleInPS5 -ModuleName "PSWindowsUpdate"

# $params = @{
#     ModuleName = "PSWindowsUpdate"
# }
# Install-ModuleInPS5 @params

# Write-Host 'hello from PS7'


# Import-Module 'C:\code\Modulesv2\EnhancedModuleStarterAO\EnhancedModuleStarterAO.psm1'

InstallAndImportModulesPSGallery -modulePsd1Path 'C:\code\module-starter\Enhanced-modules.psd1'