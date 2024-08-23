param (
    [string]$Mode = "prod",
    [bool]$SkipPSGalleryModules = $false
)

Write-Host "The script is running in mode: $Mode"
Write-Host "The SkipPSGalleryModules is set to: $SkipPSGalleryModules"

# Script to report the current PowerShell version

# Get the PowerShell version details
$psVersion = $PSVersionTable.PSVersion

# Output the PowerShell version
Write-Host "Current PowerShell Version: $psVersion" -ForegroundColor Green

# Output additional details
Write-Host "Full PowerShell Version Details:"
$PSVersionTable | Format-Table -AutoSize



$processList = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$ScriptPath = $MyInvocation.MyCommand.Definition
$scriptDetails = @(
    @{ Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Clone-EnhancedRepos.ps1" }
)

# Function to test if the script is running as an administrator
function CheckAndElevate {
    <#
    .SYNOPSIS
    Checks if the script is running with administrative privileges and optionally elevates it if not.

    .DESCRIPTION
    The CheckAndElevate function checks whether the current PowerShell session is running with administrative privileges. 
    It can either return the administrative status or attempt to elevate the script if it is not running as an administrator.

    .PARAMETER ElevateIfNotAdmin
    If set to $true, the function will attempt to elevate the script if it is not running with administrative privileges. 
    If set to $false, the function will simply return the administrative status without taking any action.

    .EXAMPLE
    CheckAndElevate -ElevateIfNotAdmin $true

    Checks the current session for administrative privileges and elevates if necessary.

    .EXAMPLE
    $isAdmin = CheckAndElevate -ElevateIfNotAdmin $false
    if (-not $isAdmin) {
        Write-Host "The script is not running with administrative privileges."
    }

    Checks the current session for administrative privileges and returns the status without elevating.
    
    .NOTES
    If the script is elevated, it will restart with administrative privileges. Ensure that any state or data required after elevation is managed appropriately.
    #>

    [CmdletBinding()]
    param (
        [bool]$ElevateIfNotAdmin = $true
    )

    Begin {
        Write-Log -Message "Starting CheckAndElevate function" -Level "NOTICE"

        # Use .NET classes for efficiency
        try {
            $isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-Log -Message "Checking for administrative privileges..." -Level "INFO"
        }
        catch {
            Write-Log -Message "Error determining administrative status: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    Process {
        if (-not $isAdmin) {
            if ($ElevateIfNotAdmin) {
                try {
                    Write-Log -Message "The script is not running with administrative privileges. Attempting to elevate..." -Level "WARNING"

                    $powerShellPath = Get-PowerShellPath
                    # Define the parameters for starting a new PowerShell process
                    $startProcessParams = @{
                        FilePath     = $powerShellPath              # Path to the PowerShell executable
                        ArgumentList = @(
                            "-NoProfile", # Do not load the user's PowerShell profile
                            "-ExecutionPolicy", "Bypass", # Set the execution policy to Bypass
                            "-File", "`"$PSCommandPath`""           # Run the specified script file
                        )
                        Verb         = "RunAs"                      # Run the process with elevated privileges
                    }

                    # Start the process with the defined parameters
                    Start-Process @startProcessParams

                    Write-Log -Message "Script re-launched with administrative privileges. Exiting current session." -Level "INFO"
                    exit
                }
                catch {
                    Write-Log -Message "Failed to elevate privileges: $($_.Exception.Message)" -Level "ERROR"
                    Handle-Error -ErrorRecord $_
                    throw $_
                }
            }
            else {
                Write-Log -Message "The script is not running with administrative privileges and will continue without elevation." -Level "INFO"
            }
        }
        else {
            Write-Log -Message "Script is already running with administrative privileges." -Level "INFO"
        }
    }

    End {
        Write-Log -Message "Exiting CheckAndElevate function" -Level "NOTICE"
        return $isAdmin
    }
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

function Invoke-WebScript {
    param (
        [string]$url
    )

    $powerShellPath = Get-PowerShellPath

    Write-Log "Validating URL: $url" -Level "INFO"

    if (Test-Url -url $url) {
        Write-Log "Running script from URL: $url" -Level "INFO"

        $startProcessParams = @{
            FilePath     = $powerShellPath
            ArgumentList = @(
                # "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-Command", "Invoke-Expression (Invoke-RestMethod -Uri '$url')"
            )
            Verb         = "RunAs"
            PassThru     = $true
        }
        
        $process = Start-Process @startProcessParams
        
        return $process
    }
    else {
        Write-Log "URL $url is not accessible" -Level "ERROR"
        return $null
    }
}

function Validate-SoftwareInstallation {
    [CmdletBinding()]
    param (
        [string]$SoftwareName,
        [version]$MinVersion = [version]"0.0.0.0",
        [string]$RegistryPath = "",
        [string]$ExePath = "",
        [int]$MaxRetries = 3,
        [int]$DelayBetweenRetries = 5
    )

    Begin {
        Write-Log -Message "Starting Validate-SoftwareInstallation function" -Level "NOTICE"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    Process {
        $retryCount = 0
        $validationSucceeded = $false

        while ($retryCount -lt $MaxRetries -and -not $validationSucceeded) {
            # Registry-based validation
            if ($RegistryPath -or $SoftwareName) {
                $registryPaths = @(
                    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
                )

                if ($RegistryPath) {
                    if (Test-Path $RegistryPath) {
                        $app = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
                        if ($app -and $app.DisplayName -like "*$SoftwareName*") {
                            $installedVersion = [version]$app.DisplayVersion.Split(" ")[0]  # Extract only the version number
                            if ($installedVersion -ge $MinVersion) {
                                $validationSucceeded = $true
                                return @{
                                    IsInstalled = $true
                                    Version     = $installedVersion
                                    ProductCode = $app.PSChildName
                                }
                            }
                        }
                    }
                }
                else {
                    foreach ($path in $registryPaths) {
                        $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                        foreach ($item in $items) {
                            $app = Get-ItemProperty -Path $item.PsPath -ErrorAction SilentlyContinue
                            if ($app.DisplayName -like "*$SoftwareName*") {
                                $installedVersion = [version]$app.DisplayVersion.Split(" ")[0]  # Extract only the version number
                                if ($installedVersion -ge $MinVersion) {
                                    $validationSucceeded = $true
                                    return @{
                                        IsInstalled = $true
                                        Version     = $installedVersion
                                        ProductCode = $app.PSChildName
                                    }
                                }
                            }
                        }
                    }
                }
            }

            # File-based validation
            if ($ExePath) {
                if (Test-Path $ExePath) {
                    $appVersionString = (Get-ItemProperty -Path $ExePath).VersionInfo.ProductVersion.Split(" ")[0]  # Extract only the version number
                    $appVersion = [version]$appVersionString

                    if ($appVersion -ge $MinVersion) {
                        Write-Log -Message "Validation successful: $SoftwareName version $appVersion is installed at $ExePath." -Level "INFO"
                        return @{
                            IsInstalled = $true
                            Version     = $appVersion
                            Path        = $ExePath
                        }
                    }
                    else {
                        Write-Log -Message "Validation failed: $SoftwareName version $appVersion does not meet the minimum version requirement ($MinVersion)." -Level "ERROR"
                    }
                }
                else {
                    Write-Log -Message "Validation failed: $SoftwareName executable was not found at $ExePath." -Level "ERROR"
                }
            }

            $retryCount++
            Write-Log -Message "Validation attempt $retryCount failed: $SoftwareName not found or version does not meet the minimum requirement ($MinVersion). Retrying in $DelayBetweenRetries seconds..." -Level "WARNING"
            Start-Sleep -Seconds $DelayBetweenRetries
        }

        return @{ IsInstalled = $false }
    }

    End {
        Write-Log -Message "Exiting Validate-SoftwareInstallation function" -Level "NOTICE"
    }
}

function Install-PowerShell7FromWeb {
    param (
        [string]$url = "https://raw.githubusercontent.com/aollivierre/setuplab/main/Install-PowerShell7.ps1"
    )

    Write-Log -Message "Attempting to install PowerShell 7 from URL: $url" -Level "INFO"

    $process = Invoke-WebScript -url $url
    if ($process) {
        $process.WaitForExit()

        # Perform post-installation validation
        $validationParams = @{
            SoftwareName        = "PowerShell"
            MinVersion          = [version]"7.4.4"
            RegistryPath        = "HKLM:\SOFTWARE\Microsoft\PowerShellCore"
            ExePath             = "C:\Program Files\PowerShell\7\pwsh.exe"
            MaxRetries          = 3  # Single retry after installation
            DelayBetweenRetries = 5
        }

        $postValidationResult = Validate-SoftwareInstallation @validationParams
        if ($postValidationResult.IsInstalled -and $postValidationResult.Version -ge $validationParams.MinVersion) {
            Write-Log -Message "PowerShell 7 successfully installed and validated." -Level "INFO"
            return $true
        }
        else {
            Write-Log -Message "PowerShell 7 installation validation failed." -Level "ERROR"
            return $false
        }
    }
    else {
        Write-Log -Message "Failed to start the installation process for PowerShell 7." -Level "ERROR"
        return $false
    }
}


function Get-PowerShellPath {
    [CmdletBinding()]
    param ()

    Begin {
        Write-Log -Message "Starting Get-PowerShellPath function" -Level "NOTICE"
    }

    Process {
        $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
        $pwsh5Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $maxAttempts = 3
        $attempt = 0

        # Check for PowerShell 7
        while ($attempt -lt $maxAttempts) {
            if (Test-Path $pwsh7Path) {
                Write-Log -Message "PowerShell 7 found at $pwsh7Path" -Level "INFO"
                return $pwsh7Path
            }
            else {
                Write-Log -Message "PowerShell 7 not found. Attempting to install (Attempt $($attempt + 1) of $maxAttempts)..." -Level "WARNING"
                $success = Install-PowerShell7FromWeb
                if ($success) {
                    Write-Log -Message "PowerShell 7 installed successfully." -Level "INFO"
                    return $pwsh7Path
                }
            }
            $attempt++
        }

        # Fallback to PowerShell 5 if installation of PowerShell 7 fails
        if (Test-Path $pwsh5Path) {
            Write-Log -Message "PowerShell 7 installation failed after $maxAttempts attempts. Falling back to PowerShell 5 at $pwsh5Path" -Level "WARNING"
            return $pwsh5Path
        }
        else {
            $errorMessage = "Neither PowerShell 7 nor PowerShell 5 was found on this system."
            Write-Log -Message $errorMessage -Level "ERROR"
            throw $errorMessage
        }
    }

    End {
        Write-Log -Message "Exiting Get-PowerShellPath function" -Level "NOTICE"
    }
}



function Download-Modules {
    param (
        [array]$scriptDetails  # Array of script details, including URLs
    )

    $processList = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

    foreach ($scriptDetail in $scriptDetails) {
        $process = Invoke-WebScript -url $scriptDetail.Url
        if ($process) {
            $processList.Add($process)
        }
    }

    # Optionally wait for all processes to complete
    foreach ($process in $processList) {
        $process.WaitForExit()
    }
}

function Invoke-InPowerShell5 {
    param (
        [string]$ScriptPath
    )

    if ($PSVersionTable.PSVersion.Major -ne 5) {
        Write-Log "Relaunching script in PowerShell 5 (x64)..." -Level "WARNING"

        # Get the path to PowerShell 5 (x64)
        $ps5x64Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

        # Launch in PowerShell 5 (x64)
        $startProcessParams64 = @{
            FilePath     = $ps5x64Path
            ArgumentList = @(
                "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", "`"$ScriptPath`""
            )
            Verb         = "RunAs"
            PassThru     = $true
        }

        Write-Log "Starting PowerShell 5 (x64) to perform the update..." -Level "NOTICE"
        $process64 = Start-Process @startProcessParams64
        $process64.WaitForExit()

        Write-Log "PowerShell 5 (x64) process completed." -Level "NOTICE"
        Exit
    }
}

function Reset-ModulePaths {
    [CmdletBinding()]
    param ()

    begin {
        # Initialization block, typically used for setup tasks
        Write-Log "Initializing Reset-ModulePaths function..." -Level "DEBUG"
    }

    process {
        try {
            # Log the start of the process
            Write-Log "Resetting module paths to default values..." -Level "INFO"

            # Get the current user's Documents path
            $userModulesPath = [System.IO.Path]::Combine($env:USERPROFILE, 'Documents\WindowsPowerShell\Modules')

            # Define the default module paths
            $defaultModulePaths = @(
                "C:\Program Files\WindowsPowerShell\Modules",
                $userModulesPath,
                "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
            )

            # Attempt to reset the PSModulePath environment variable
            $env:PSModulePath = [string]::Join(';', $defaultModulePaths)
            Write-Log "PSModulePath successfully set to: $($env:PSModulePath -split ';' | Out-String)" -Level "INFO"

            # Optionally persist the change for the current user
            [Environment]::SetEnvironmentVariable("PSModulePath", $env:PSModulePath, [EnvironmentVariableTarget]::User)
            Write-Log "PSModulePath environment variable set for the current user." -Level "INFO"
        }
        catch {
            # Capture and log any errors that occur during the process
            $errorMessage = $_.Exception.Message
            Write-Log "Error resetting module paths: $errorMessage" -Level "ERROR"

            # Optionally, you could throw the error to halt the script
            throw $_
        }
    }

    end {
        # Finalization block, typically used for cleanup tasks
        Write-Log "Reset-ModulePaths function completed." -Level "DEBUG"
    }
}

function Install-EnhancedModule {
    param (
        [string]$ModuleName
    )

    # Log the start of the module installation process
    Write-Log "Starting the module installation process for: $ModuleName" -Level "NOTICE"

    # Check if the current PowerShell version is not 5
    # if ($PSVersionTable.PSVersion.Major -ne 5) {
    # Write-Log "Current PowerShell version is $($PSVersionTable.PSVersion). PowerShell 5 is required." -Level "WARNING"

    # # Get the path to PowerShell 5
    # $ps5Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Write-Log "PowerShell 5 path: $ps5Path" -Level "INFO"

    # # Construct the command to install the module in PowerShell 5
    # $command = "& '$ps5Path' -ExecutionPolicy Bypass -Command `"Install-Module -Name '$ModuleName' -Force -SkipPublisherCheck -Scope AllUsers`""
    # Write-Log "Constructed command for PowerShell 5: $command" -Level "DEBUG"

    # # Launch PowerShell 5 to run the module installation
    # Write-Log "Launching PowerShell 5 to install the module: $ModuleName" -Level "INFO"
    # Invoke-Expression $command

    # Write-Log "Module installation command executed in PowerShell 5. Exiting current session." -Level "NOTICE"
    # return

    # Path to the current script
    # $ScriptPath = $MyInvocation.MyCommand.Definition

    # # Check if we need to re-launch in PowerShell 5
    # Invoke-InPowerShell5 -ScriptPath $ScriptPath

    # # If running in PowerShell 5, reset the module paths and proceed with the rest of the script
    # Reset-ModulePaths

    # }

    # If already in PowerShell 5, install the module
    Write-Log "Current PowerShell version is 5. Proceeding with module installation." -Level "INFO"
    Write-Log "Installing module: $ModuleName in PowerShell 5" -Level "NOTICE"

    try {
        Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Scope AllUsers
        Write-Log "Module $ModuleName installed successfully in PowerShell 5." -Level "INFO"
    }
    catch {
        Write-Log "Failed to install module $ModuleName. Error: $_" -Level "ERROR"
    }
}



function Import-EnhancedModules {
    param (
        [string]$modulePsd1Path, # Path to the PSD1 file containing the list of modules to install and import
        [string]$ScriptPath  # Path to the PSD1 file containing the list of modules to install and import
    )

    # Validate PSD1 file path
    if (-not (Test-Path -Path $modulePsd1Path)) {
        Write-Log "modules.psd1 file not found at path: $modulePsd1Path" -Level "ERROR"
        throw "modules.psd1 file not found."
    }


    # Check if we need to re-launch in PowerShell 5
    Invoke-InPowerShell5 -ScriptPath $ScriptPath

    # If running in PowerShell 5, reset the module paths and proceed with the rest of the script
    Reset-ModulePaths

    # Import the PSD1 data
    $moduleData = Import-PowerShellDataFile -Path $modulePsd1Path
    $modulesToImport = $moduleData.requiredModules

    foreach ($moduleName in $modulesToImport) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Log "Module $moduleName is not installed. Attempting to install..." -Level "INFO"
            Install-EnhancedModule -ModuleName $moduleName -ScriptPath $ScriptPath
        }

        Write-Log "Importing module: $moduleName" -Level "INFO"
        try {
            Import-Module -Name $moduleName -Verbose:$true -Force:$true -Global:$true
        }
        catch {
            Write-Log "Failed to import module $moduleName. Error: $_" -Level "ERROR"
        }
    }
}

function Setup-GlobalPaths {
    param (
        [string]$ModulesBasePath       # Path to the modules directory
    )

    # Set the modules base path and create if it doesn't exist
    if (-Not (Test-Path $ModulesBasePath)) {
        Write-Log "ModulesBasePath '$ModulesBasePath' does not exist. Creating directory..." -Level "INFO"
        New-Item -Path $ModulesBasePath -ItemType Directory -Force
    }
    $global:modulesBasePath = $ModulesBasePath

    # Log the paths for verification
    Write-Log "Modules Base Path: $global:modulesBasePath" -Level "INFO"
}


function Download-Psd1File {
    <#
    .SYNOPSIS
    Downloads a PSD1 file from a specified URL and saves it to a local destination.

    .DESCRIPTION
    This function downloads a PowerShell Data file (PSD1) from a given URL and saves it to the specified local path. 
    If the download fails, an error is logged and the function throws an exception.

    .PARAMETER url
    The URL of the PSD1 file to be downloaded.

    .PARAMETER destinationPath
    The local path where the PSD1 file will be saved.

    .EXAMPLE
    Download-Psd1File -url "https://example.com/modules.psd1" -destinationPath "$env:TEMP\modules.psd1"
    Downloads the PSD1 file from the specified URL and saves it to the provided local path.

    .NOTES
    This function requires internet access to download the PSD1 file from the specified URL.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$url,

        [Parameter(Mandatory = $true)]
        [string]$destinationPath
    )

    begin {
        Write-Log -Message "Starting Download-Psd1File function" -Level "NOTICE"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Validate destination directory
        $destinationDirectory = [System.IO.Path]::GetDirectoryName($destinationPath)
        if (-not (Test-Path -Path $destinationDirectory)) {
            Write-Log -Message "Destination directory not found at path: $destinationDirectory" -Level "ERROR"
            throw "Destination directory not found."
        }

        Write-Log -Message "Validated destination directory at path: $destinationDirectory" -Level "INFO"
    }

    process {
        try {
            Write-Log -Message "Downloading PSD1 file from URL: $url" -Level "INFO"
            Invoke-WebRequest -Uri $url -OutFile $destinationPath -UseBasicParsing
            Write-Log -Message "Downloaded PSD1 file to: $destinationPath" -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to download PSD1 file from $url. Error: $_" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        Write-Log -Message "Download-Psd1File function execution completed." -Level "NOTICE"
    }
}



function Ensure-NuGetProvider {
    # Ensure NuGet provider and PowerShellGet module are installed if running in PowerShell 5
    if ($PSVersionTable.PSVersion.Major -eq 5) {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Confirm:$false
            Install-Module -Name PowerShellGet -Force -AllowClobber
            Write-Log "NuGet provider installed successfully." -Level "INFO"
        }
        else {
            Write-Log "NuGet provider is already installed." -Level "INFO"
        }
    }
    else {
        Write-Log "This script is running in PowerShell version $($PSVersionTable.PSVersion) which is not version 5. No action is taken for NuGet" -Level "INFO"
    }
}


function Initialize-Environment {
    param (
        [string]$Mode, # Accepts either 'dev' or 'prod'
        [string]$WindowsModulePath, # Path to the Windows module
        [string]$ModulesBasePath # Custom modules base path
    )

 
    if ($Mode -eq "dev") {

        # Call Setup-GlobalPaths with custom paths
        Setup-GlobalPaths -ModulesBasePath $ModulesBasePath
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
            Write-Log "Source Modules already exist at $global:modulesBasePath" -Level "INFO"
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

        Write-Host "Starting to call Import-LatestModulesLocalRepository..."
        Import-ModulesFromLocalRepository -ModulesFolderPath $global:modulesBasePath
    }
    elseif ($Mode -eq "prod") {
        # Log the start of the process
        Write-Log "Production mode selected. Importing modules..." -Level "INFO"

        # Path to the current script
        # $ScriptPath = $MyInvocation.MyCommand.Definition

        # Re-launch the script in PowerShell 5 if not already running in PS5
        Invoke-InPowerShell5 -ScriptPath $ScriptPath

        # Reset the module paths and proceed with the rest of the script in PS5
        Reset-ModulePaths

        # Ensure NuGet provider is installed
        Ensure-NuGetProvider

        # Install essential modules
        Install-Module -Name EnhancedBoilerPlateAO -Force -SkipPublisherCheck -Scope AllUsers -Verbose
        Install-Module -Name EnhancedLoggingAO -Force -SkipPublisherCheck -Scope AllUsers -Verbose

        # Define the PSD1 file URLs and local paths
        $psd1Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Enhanced-modules.psd1"
        $localPsd1Path = "$env:TEMP\enhanced-modules.psd1"

        # Download the PSD1 file
        Download-Psd1File -url $psd1Url -destinationPath $localPsd1Path

        # Install and import modules based on the PSD1 file
        InstallAndImportModulesPSGallery -modulePsd1Path $localPsd1Path

        # Handle third-party PS Gallery modules
        if ($SkipPSGalleryModules) {
            Write-Log "Skipping third-party PS Gallery Modules" -Level "INFO"
        }
        else {
            Write-Log "Starting PS Gallery Module installation" -Level "INFO"

            # Re-launch the script in PowerShell 5 if not already running in PS5
            Invoke-InPowerShell5 -ScriptPath $ScriptPath

            # Reset the module paths in PS5
            Reset-ModulePaths

            # Ensure NuGet provider is installed
            Ensure-NuGetProvider

            # Download and process the third-party modules PSD1 file
            $psd1Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/modules.psd1"
            $localPsd1Path = "$env:TEMP\modules.psd1"
    
            Download-Psd1File -url $psd1Url -destinationPath $localPsd1Path
            InstallAndImportModulesPSGallery -modulePsd1Path $localPsd1Path
        }

    }
}


# Elevate to administrator if not already
# Example usage to check and optionally elevate:
CheckAndElevate -ElevateIfNotAdmin $true


# Example usage of Initialize-Environment
$initializeParams = @{
    Mode              = $Mode
    WindowsModulePath = "EnhancedBoilerPlateAO\EnhancedBoilerPlateAO.psm1"
    ModulesBasePath   = "C:\code\modulesv2" # Custom modules base path
}

Initialize-Environment @initializeParams

###############################################################################################################################
############################################### END MODULE LOADING ############################################################
###############################################################################################################################

# Execute InstallAndImportModulesPSGallery function
# InstallAndImportModulesPSGallery -modulePsd1Path "$PSScriptRoot/modules.psd1"


###############################################################################################################################
############################################### END MODULE LOADING ############################################################
###############################################################################################################################

# Setup logging
Write-EnhancedLog -Message "Script Started in $mode mode" -Level "INFO"

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