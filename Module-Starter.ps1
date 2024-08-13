# Function to test if the script is running as an administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function for logging with color coding
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Green }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        default { Write-Host $logMessage -ForegroundColor White }
    }

    # Append to log file
    $logFilePath = [System.IO.Path]::Combine($env:TEMP, 'install-scripts.log')
    $logMessage | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

# Function to get the platform
function Get-Platform {
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return $PSVersionTable.Platform
    }
    else {
        return [System.Environment]::OSVersion.Platform
    }
}

# Function to set up global paths
function Setup-GlobalPaths {
    if ($env:DOCKER_ENV -eq $true) {
        $global:scriptBasePath = $env:SCRIPT_BASE_PATH
        $global:modulesBasePath = $env:MODULES_BASE_PATH
    }
    else {
        $global:scriptBasePath = $PSScriptRoot
        $global:modulesBasePath = "C:\code\modules"
        if (-Not (Test-Path $global:modulesBasePath)) {
            $global:modulesBasePath = "$PSScriptRoot\modules"
        }
    }
}

# Function to download modules
function Download-Modules {
    param (
        [string]$scriptPath = "C:\Code\CB\ModuleBuilder\GitHub\2-Clone-Modulesv2.ps1"
    )
    
    if (Test-Path $scriptPath) {
        Write-Log "Executing script to download modules: $scriptPath" -Level "INFO"
        & $scriptPath
    }
    else {
        Write-Log "Module download script not found at $scriptPath" -Level "ERROR"
    }
}

# Function to handle Win32 apps
function Handle-Win32Apps {
    Write-Log "Handling Win32 Apps..." -Level "INFO"
    $global:AOscriptDirectory = Join-Path -Path $global:scriptBasePath -ChildPath "Win32Apps-DropBox"
    $global:directoryPath = Join-Path -Path $global:scriptBasePath -ChildPath "Win32Apps-DropBox"
    $global:Repo_Path = $global:scriptBasePath
    $global:Repo_winget = "$Repo_Path\Win32Apps-DropBox"
    
    Write-Log "Win32Apps Directory: $global:directoryPath" -Level "INFO"
    Write-Log "Win32Apps Repo Path: $global:Repo_winget" -Level "INFO"
}

# Function to import Enhanced modules directly within the script
function Import-EnhancedModules {
    $modulesToImport = @(
        "EnhancedAO.Graph.SignInLogs",
        "EnhancedDeviceMigrationAO",
        "EnhancedFileManagerAO",
        "EnhancedGraphAO",
        "EnhancedHyperVAO",
        "EnhancedLoggingAO",
        "EnhancedPSADTAO",
        "EnhancedSchedTaskAO",
        "EnhancedSPOAO",
        "EnhancedVPNAO",
        "EnhancedWin32DeployerAO"
    )

    foreach ($moduleName in $modulesToImport) {
        Write-Log "Importing module: $moduleName" -Level "INFO"
        Import-Module -Name $moduleName -Verbose -Force:$true -Global:$true
    }
}

# Modified Initialize-Environment function to include optional module import in prod mode
function Initialize-Environment {
    param (
        [string]$Mode = "dev",  # Accepts either 'dev' or 'prod'
        [string]$WindowsModulePath = "EnhancedBoilerPlateAO\2.0.0\EnhancedBoilerPlateAO.psm1",
        [switch]$HandleWin32Apps = $false  # Optional switch to handle Win32 apps, turned off by default
    )

    Setup-GlobalPaths

    if ($Mode -eq "dev") {
        if (-Not (Test-Path "C:\code\modulesv2")) {
            Write-Log "Modules not found at C:\code\modulesv2. Initiating download..." -Level "INFO"
            Download-Modules
        }
        else {
            Write-Log "Modules already exist at C:\code\modulesv2" -Level "INFO"
        }
    }
    elseif ($Mode -eq "prod") {
        Write-Log "Production mode selected. Importing modules..." -Level "INFO"
        Import-EnhancedModules
    }

    # Construct the paths dynamically using the base paths
    $modulePath = Join-Path -Path $global:modulesBasePath -ChildPath $WindowsModulePath
    $global:modulePath = $modulePath

    # Import the module using the dynamically constructed path
    Import-Module -Name $global:modulePath -Verbose -Force:$true -Global:$true

    # Log the paths to verify
    Write-Log "Module Path: $global:modulePath" -Level "INFO"

    # Handle Win32 apps if the switch is specified
    if ($HandleWin32Apps) {
        Handle-Win32Apps
    }
}

# Example usage
Initialize-Environment -Mode "dev"
