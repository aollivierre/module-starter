# Fetch the script content
# $scriptContent = Invoke-RestMethod "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1"

# # Define replacements in a hashtable
# $replacements = @{
#     '\$Mode = "dev"'                     = '$Mode = "dev"'
#     '\$SkipPSGalleryModules = \$false'   = '$SkipPSGalleryModules = $true'
#     '\$SkipCheckandElevate = \$false'    = '$SkipCheckandElevate = $true'
#     '\$SkipAdminCheck = \$false'         = '$SkipAdminCheck = $true'
#     '\$SkipPowerShell7Install = \$false' = '$SkipPowerShell7Install = $true'
#     '\$SkipModuleDownload = \$false'     = '$SkipModuleDownload = $true'
#     '\$SkipGitrepos = \$false'           = '$SkipGitrepos = $true'
# }

# # Apply the replacements
# foreach ($pattern in $replacements.Keys) {
#     $scriptContent = $scriptContent -replace $pattern, $replacements[$pattern]
# }

# # Execute the script
# Invoke-Expression $scriptContent




# Define a hashtable for splatting
$moduleStarterParams = @{
    Mode                   = "dev"
    SkipPSGalleryModules   = $true
    SkipCheckandElevate    = $true
    SkipPowerShell7Install = $true
    SkipEnhancedModules    = $true
    SkipGitRepos           = $true
}

# Call the function using the splat
Invoke-ModuleStarter @moduleStarterParams