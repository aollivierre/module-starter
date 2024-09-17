
# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1") -replace '\$Mode = "dev"', '$Mode = "prod"' -replace 'SkipPSGalleryModules\s*=\s*false', 'SkipPSGalleryModules = false')

# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1") -replace '\$Mode = "dev"', '$Mode = "dev"' -replace 'SkipPSGalleryModules\s*=\s*false', 'SkipPSGalleryModules = false')


# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1") -replace '\$Mode = "dev"', '$Mode = "dev"' -replace 'SkipPSGalleryModules\s*=\s*false', 'SkipPSGalleryModules = false' -replace '\$SkipCheckandElevate = \$false', '$SkipCheckandElevate = $true')


# iex (irm 'https://raw.githubusercontent.com/aollivierre/module-starter/main/Clone-EnhancedRepos.ps1')


# # Fetch the script content
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








# # Fetch the script content
# $scriptContent = Invoke-RestMethod "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1"

# # Define replacements in a hashtable
# $replacements = @{
#     '\$Mode = "dev"'                     = '$Mode = "prod"'
#     '\$SkipPSGalleryModules = \$false'   = '$SkipPSGalleryModules = $false'
#     '\$SkipCheckandElevate = \$false'    = '$SkipCheckandElevate = $false'
#     '\$SkipAdminCheck = \$false'         = '$SkipAdminCheck = $false'
#     '\$SkipPowerShell7Install = \$false' = '$SkipPowerShell7Install = $false'
#     '\$SkipModuleDownload = \$false'     = '$SkipModuleDownload = $false'
#     '\$SkipGitrepos = \$false'           = '$SkipGitrepos = $false'
# }

# # Apply the replacements
# foreach ($pattern in $replacements.Keys) {
#     $scriptContent = $scriptContent -replace $pattern, $replacements[$pattern]
# }

# # Execute the script
# Invoke-Expression $scriptContent


# Set environment variable globally for all users
[System.Environment]::SetEnvironmentVariable('EnvironmentMode', 'prod', 'Machine')

# Retrieve the environment mode (default to 'prod' if not set)
$mode = $env:EnvironmentMode

#region FIRING UP MODULE STARTER
#################################################################################################
#                                                                                               #
#                                 FIRING UP MODULE STARTER                                      #
#                                                                                               #
#################################################################################################

Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1")

# Wait-Debugger

# Define a hashtable for splatting
$moduleStarterParams = @{
    Mode                   = 'prod'
    SkipPSGalleryModules   = $false
    SkipCheckandElevate    = $false
    SkipPowerShell7Install = $false
    SkipEnhancedModules    = $false
    SkipGitRepos           = $true
}

# Call the function using the splat
Invoke-ModuleStarter @moduleStarterParams


# Wait-Debugger

#endregion FIRING UP MODULE STARTER

# Toggle based on the environment mode
switch ($mode) {
    'dev' {
        Write-EnhancedLog -Message "Running in development mode" -Level 'WARNING'
        # Your development logic here
    }
    'prod' {
        Write-EnhancedLog -Message "Running in production mode" -ForegroundColor Green
        # Your production logic here
    }
    default {
        Write-EnhancedLog -Message "Unknown mode. Defaulting to production." -ForegroundColor Red
        # Default to production
    }
}


























# Set environment variable globally for all users
[System.Environment]::SetEnvironmentVariable('EnvironmentMode', 'dev', 'Machine')

# Retrieve the environment mode (default to 'prod' if not set)
$mode = $env:EnvironmentMode

#region FIRING UP MODULE STARTER
#################################################################################################
#                                                                                               #
#                                 FIRING UP MODULE STARTER                                      #
#                                                                                               #
#################################################################################################

Invoke-Expression (Invoke-RestMethod "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1")

# Wait-Debugger

# Define a hashtable for splatting
$moduleStarterParams = @{
    Mode                   = 'dev'
    SkipPSGalleryModules   = $false
    SkipCheckandElevate    = $false
    SkipPowerShell7Install = $false
    SkipEnhancedModules    = $false
    SkipGitRepos           = $false
}

# Call the function using the splat
Invoke-ModuleStarter @moduleStarterParams


# Wait-Debugger

#endregion FIRING UP MODULE STARTER

# Toggle based on the environment mode
switch ($mode) {
    'dev' {
        Write-EnhancedLog -Message "Running in development mode" -Level 'WARNING'
        # Your development logic here
    }
    'prod' {
        Write-EnhancedLog -Message "Running in production mode" -ForegroundColor Green
        # Your production logic here
    }
    default {
        Write-EnhancedLog -Message "Unknown mode. Defaulting to production." -ForegroundColor Red
        # Default to production
    }
}