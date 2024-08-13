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

# Function to download modules
function Download-Modules {
    param (
        [string]$scriptUrl = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Clone-EnhancedRepos.ps1"
    )
    
    try {
        Write-Log "Validating URL: $scriptUrl" -Level "INFO"

        # Validate the URL before proceeding
        if (Test-Url -url $scriptUrl) {
            Write-Log "Downloading and executing script from: $scriptUrl" -Level "INFO"
            
            # Download and execute the script from the URL
            $scriptContent = Invoke-RestMethod -Uri $scriptUrl -UseBasicParsing
            Invoke-Expression $scriptContent
        }
        else {
            Write-Log "The URL $scriptUrl is not valid or accessible." -Level "ERROR"
        }
    }
    catch {
        Write-Log "Failed to download or execute the script from $scriptUrl" -Level "ERROR"
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
        [string]$Mode , # Accepts either 'dev' or 'prod'
        [string]$WindowsModulePath,
        [string]$ModulesPath , # Default path to modules
        [switch]$HandleWin32Apps = $false  # Optional switch to handle Win32 apps, turned off by default
    )

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


    Setup-GlobalPaths

    if ($Mode -eq "dev") {
        if (-Not (Test-Path $ModulesPath)) {
            Write-Log "Modules not found at $ModulesPath. Initiating download..." -Level "INFO"
            Download-Modules
        }
        else {
            Write-Log "Modules already exist at $ModulesPath" -Level "INFO"
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

# Example usage with splatting
$initializeParams = @{
    Mode              = "dev"
    ModulesPath       = "C:\code\modulesv2-beta1"  # Custom path
    WindowsModulePath = "EnhancedBoilerPlateAO\EnhancedBoilerPlateAO.psm1"
    HandleWin32Apps   = $false
}

Initialize-Environment @initializeParams