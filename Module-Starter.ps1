$processList = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$scriptDetails = @(
    @{ Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Clone-EnhancedRepos.ps1" }
)

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


function Test-Url {
    param (
        [string]$url
    )
    try {
        Invoke-RestMethod -Uri $url -Method Head -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}


function Get-PowerShellPath {
    if (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe") {
        return "C:\Program Files\PowerShell\7\pwsh.exe"
    }
    elseif (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe") {
        return "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    }
    else {
        throw "Neither PowerShell 7 nor PowerShell 5 was found on this system."
    }
}

function Download-Modules {
    param (
        [array]$scriptDetails  # Array of script details, including URLs
    )

    $powerShellPath = Get-PowerShellPath
    $processList = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

    foreach ($scriptDetail in $scriptDetails) {
        $url = $scriptDetail.Url

        Write-Log "Validating URL: $url" -Level "INFO"

        if (Test-Url -url $url) {
            Write-Log "Running script from URL: $url" -Level "INFO"
            $process = Start-Process -FilePath $powerShellPath -ArgumentList @("-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Invoke-Expression (Invoke-RestMethod -Uri '$url')") -Verb RunAs -PassThru
            $processList.Add($process)
        }
        else {
            Write-Log "URL $url is not accessible" -Level "ERROR"
        }
    }

    # Optionally wait for all processes to complete
    foreach ($process in $processList) {
        $process.WaitForExit()
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


function Install-EnhancedModule {
    param (
        [string]$ModuleName
    )

    # Example: Logic to install the module (this might involve downloading and installing the module from a repository)
    Write-Log "Installing module: $ModuleName" -Level "INFO"

    # Replace this with the actual installation command for your environment
    # Example using PowerShell Gallery (assuming modules are published there):
    try {
        Install-Module -Name $ModuleName -Force -Scope AllUsers
    }
    catch {
        Write-Log "Failed to install module $ModuleName. Error: $_" -Level "ERROR"
    }
}

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
        if (-Not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Module $moduleName is not installed. Attempting to install..." -Level "INFO"
            Install-EnhancedModule -ModuleName $moduleName
        }

        Write-Log "Importing module: $moduleName" -Level "INFO"
        try {
            Import-Module -Name $moduleName -Verbose -Force -Global
        }
        catch {
            Write-Log "Failed to import module $moduleName. Error: $_" -Level "ERROR"
        }
    }
}


function Setup-GlobalPaths {
    param (
        [string]$ScriptBasePath, # Path to the script base directory
        [string]$ModulesBasePath       # Path to the modules directory
    )

    # Set the script base path and create if it doesn't exist
    if (-Not (Test-Path $ScriptBasePath)) {
        Write-Log "ScriptBasePath '$ScriptBasePath' does not exist. Creating directory..." -Level "INFO"
        New-Item -Path $ScriptBasePath -ItemType Directory -Force
    }
    $global:scriptBasePath = $ScriptBasePath

    # Set the modules base path and create if it doesn't exist
    if (-Not (Test-Path $ModulesBasePath)) {
        Write-Log "ModulesBasePath '$ModulesBasePath' does not exist. Creating directory..." -Level "INFO"
        New-Item -Path $ModulesBasePath -ItemType Directory -Force
    }
    $global:modulesBasePath = $ModulesBasePath

    # Log the paths for verification
    Write-Log "Script Base Path: $global:scriptBasePath" -Level "INFO"
    Write-Log "Modules Base Path: $global:modulesBasePath" -Level "INFO"
}

function Initialize-Environment {
    param (
        [string]$Mode, # Accepts either 'dev' or 'prod'
        [string]$WindowsModulePath, # Path to the Windows module
        [string]$ScriptBasePath, # Custom script base path
        [string]$ModulesBasePath, # Custom modules base path
        [switch]$HandleWin32Apps = $false  # Optional switch to handle Win32 apps, turned off by default
    )

 
    if ($Mode -eq "dev") {

        # Call Setup-GlobalPaths with custom paths
        Setup-GlobalPaths -ScriptBasePath $ScriptBasePath -ModulesBasePath $ModulesBasePath
        # Check if the directory exists and contains any files (not just the directory existence)
        if (-Not (Test-Path "$global:modulesBasePath\*.*")) {
            Write-Log "Modules not found or directory is empty at $global:modulesBasePath. Initiating download..." -Level "INFO"
            Download-Modules -scriptDetails $scriptDetails

            # Re-check after download attempt
            if (-Not (Test-Path "$global:modulesBasePath\*.*")) {
                throw "Download failed or the modules were not placed in the expected directory."
            }
        }
        else {
            Write-Log "Modules already exist at $global:modulesBasePath" -Level "INFO"
        }

        # The following block will ONLY run in dev mode
        # Construct the paths dynamically using the base paths
    

        $modulePath = Join-Path -Path $global:modulesBasePath -ChildPath $WindowsModulePath
        $global:modulePath = $modulePath

        # Re-check that the module exists before attempting to import
        if (-Not (Test-Path $global:modulePath)) {
            throw "The specified module '$global:modulePath' does not exist after download. Cannot import module."
        }

        # Import the module using the dynamically constructed path
        Import-Module -Name $global:modulePath -Verbose -Force:$true -Global:$true

        # Log the paths to verify
        Write-Log "Module Path: $global:modulePath" -Level "INFO"

        # Handle Win32 apps if the switch is specified
        if ($HandleWin32Apps) {
            Handle-Win32Apps
        }

        Write-Host "Starting to call Import-LatestModulesLocalRepository..."
        Import-ModulesFromLocalRepository -ModulesFolderPath $global:modulesBasePath -ScriptPath $PSScriptRoot
    }
    elseif ($Mode -eq "prod") {
        Write-Log "Production mode selected. Importing modules..." -Level "INFO"
        Import-EnhancedModules
    }
}


# Elevate to administrator if not already
if (-not (Test-Admin)) {
    Write-Log "Restarting script with elevated permissions..."
    $startProcessParams = @{
        FilePath     = "powershell.exe"
        ArgumentList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
        Verb         = "RunAs"
    }
    Start-Process @startProcessParams
    exit
}

# Example usage of Initialize-Environment
$initializeParams = @{
    Mode              = "prod"
    WindowsModulePath = "EnhancedBoilerPlateAO\EnhancedBoilerPlateAO.psm1"
    ScriptBasePath    = "$PSScriptRoot"          # Custom script base path
    ModulesBasePath   = "C:\code\modulesv2" # Custom modules base path
    HandleWin32Apps   = $false
}

Initialize-Environment @initializeParams

###############################################################################################################################
############################################### END MODULE LOADING ############################################################
###############################################################################################################################

# Execute InstallAndImportModulesPSGallery function
# InstallAndImportModulesPSGallery -modulePsd1Path "$PSScriptRoot/modules.psd1"

# Example usage to download and use the PSD1 file from a GitHub repo
$psd1Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/modules.psd1"
$localPsd1Path = "$env:TEMP\modules.psd1"  # Save the PSD1 file to a temporary location

# Download the PSD1 file
Download-Psd1File -url $psd1Url -destinationPath $localPsd1Path

# Call the function to install and import modules using the downloaded PSD1 file
InstallAndImportModulesPSGallery -modulePsd1Path $localPsd1Path


###############################################################################################################################
############################################### END MODULE LOADING ############################################################
###############################################################################################################################

# Setup logging
Write-EnhancedLog -Message "Script Started" -Level "INFO"

################################################################################################################################
################################################################################################################################
################################################################################################################################


# # ################################################################################################################################
# # ############### CALLING AS SYSTEM to simulate Intune deployment as SYSTEM (Uncomment for debugging) ############################
# # ################################################################################################################################

# # Example usage
# $privateFolderPath = Join-Path -Path $PSScriptRoot -ChildPath "private"
# $PsExec64Path = Join-Path -Path $privateFolderPath -ChildPath "PsExec64.exe"
# $ScriptToRunAsSystem = $MyInvocation.MyCommand.Path

# Ensure-RunningAsSystem -PsExec64Path $PsExec64Path -ScriptPath $ScriptToRunAsSystem -TargetFolder $privateFolderPath