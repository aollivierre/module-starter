param (
    [string]$Mode = "dev",
    [bool]$SkipPSGalleryModules = $false,
    [bool]$SkipCheckandElevate = $false
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
# function Get-Platform {
#     if ($PSVersionTable.PSVersion.Major -ge 7) {
#         return $PSVersionTable.Platform
#     }
#     else {
#         return [System.Environment]::OSVersion.Platform
#     }
# }


function Get-PowerShellPath {
    [CmdletBinding()]
    param (
        [switch]$ForcePowerShell5
    )

    Begin {
        Write-Log -Message "Starting Get-PowerShellPath function" -Level "NOTICE"
    }

    Process {
        $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
        $pwsh5Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        $maxAttempts = 3
        $attempt = 0

        # Check if PowerShell 5 is being forced
        if ($ForcePowerShell5) {
            if (Test-Path $pwsh5Path) {
                Write-Log -Message "Forcing use of PowerShell 5 at $pwsh5Path" -Level "INFO"
                return $pwsh5Path
            }
            else {
                $errorMessage = "PowerShell 5 was forced, but it was not found on this system."
                Write-Log -Message $errorMessage -Level "ERROR"
                throw $errorMessage
            }
        }

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

                    $powerShellPath = Get-PowerShellPath -ForcePowerShell5
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


# Install the PSFramework module if not already installed
# Install-Module -Name PSFramework -Scope AllUsers -Force -AllowClobber -SkipPublisherCheck -Verbose


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


function Ensure-ModuleIsLatest {
    param (
        [string]$ModuleName
    )

    Write-Log -Message "Checking if the latest version of $ModuleName is installed..." -Level "INFO"

    try {

        if ($SkipCheckandElevate) {
            Write-EnhancedLog -Message "Skipping CheckAndElevate due to SkipCheckandElevate parameter." -Level "INFO"
        }
        else {
            CheckAndElevate -ElevateIfNotAdmin $true
        }
        
        Invoke-InPowerShell5

        Reset-ModulePaths

        # Get the installed version of the module, if any
        $installedModule = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1

        # Get the latest available version of the module from PSGallery
        $latestModule = Find-Module -Name $ModuleName

        if ($installedModule) {
            if ($installedModule.Version -lt $latestModule.Version) {
                Write-Log -Message "$ModuleName version $($installedModule.Version) is installed, but version $($latestModule.Version) is available. Updating module..." -Level "WARNING"
                Install-Module -Name $ModuleName -Scope AllUsers -Force -SkipPublisherCheck -Verbose
            }
            else {
                Write-Log -Message "The latest version of $ModuleName is already installed. Version: $($installedModule.Version)" -Level "INFO"
            }
        }
        else {
            Write-Log -Message "$ModuleName is not installed. Installing the latest version $($latestModule.Version)..." -Level "WARNING"
            Install-Module -Name $ModuleName -Scope AllUsers -Force -SkipPublisherCheck -Verbose -AllowClobber
        }
    }
    catch {
        Write-Log -Message "Error occurred while checking or installing $ModuleName $_" -Level "ERROR"
        throw
    }
}

# Function for logging with color coding
function Write-EnhancedLog {
    param (
        [string]$Message,
        [string]$Level = 'INFO'
    )

    # Get the PowerShell call stack to determine the actual calling function
    $callStack = Get-PSCallStack
    $callerFunction = if ($callStack.Count -ge 2) { $callStack[1].Command } else { '<Unknown>' }

    # Prepare the formatted message with the actual calling function information
    $formattedMessage = "[$Level] $Message"

    # Map custom levels to PSFramework levels
    $psfLevel = switch ($Level.ToUpper()) {
        'DEBUG' { 'Debug' }
        'INFO' { 'Host' }
        'NOTICE' { 'Important' }
        'WARNING' { 'Warning' }
        'ERROR' { 'Error' }
        'CRITICAL' { 'Critical' }
        'IMPORTANT' { 'Important' }
        'OUTPUT' { 'Output' }
        'SIGNIFICANT' { 'Significant' }
        'VERYVERBOSE' { 'VeryVerbose' }
        'VERBOSE' { 'Verbose' }
        'SOMEWHATVERBOSE' { 'SomewhatVerbose' }
        'SYSTEM' { 'System' }
        'INTERNALCOMMENT' { 'InternalComment' }
        default { 'Host' }
    }

    # Log the message using PSFramework with the actual calling function name
    Write-PSFMessage -Level $psfLevel -Message $formattedMessage -FunctionName $callerFunction
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

    $powerShellPath = Get-PowerShellPath -ForcePowerShell5

    Write-EnhancedLog "Validating URL: $url" -Level "INFO"

    if (Test-Url -url $url) {
        Write-EnhancedLog "Running script from URL: $url" -Level "INFO"

        $startProcessParams = @{
            FilePath     = $powerShellPath
            ArgumentList = @(
                "-NoExit",
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
        Write-EnhancedLog "URL $url is not accessible" -Level "ERROR"
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
        Write-EnhancedLog -Message "Starting Validate-SoftwareInstallation function" -Level "NOTICE"
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
                            $installedVersion = Sanitize-VersionString -versionString $app.DisplayVersion
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
                                $installedVersion = Sanitize-VersionString -versionString $app.DisplayVersion
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
                    $appVersion = Sanitize-VersionString -versionString $appVersionString

                    if ($appVersion -ge $MinVersion) {
                        Write-EnhancedLog -Message "Validation successful: $SoftwareName version $appVersion is installed at $ExePath." -Level "INFO"
                        return @{
                            IsInstalled = $true
                            Version     = $appVersion
                            Path        = $ExePath
                        }
                    }
                    else {
                        Write-EnhancedLog -Message "Validation failed: $SoftwareName version $appVersion does not meet the minimum version requirement ($MinVersion)." -Level "ERROR"
                    }
                }
                else {
                    Write-EnhancedLog -Message "Validation failed: $SoftwareName executable was not found at $ExePath." -Level "ERROR"
                }
            }

            $retryCount++
            Write-EnhancedLog -Message "Validation attempt $retryCount failed: $SoftwareName not found or version does not meet the minimum requirement ($MinVersion). Retrying in $DelayBetweenRetries seconds..." -Level "WARNING"
            Start-Sleep -Seconds $DelayBetweenRetries
        }

        return @{ IsInstalled = $false }
    }

    End {
        Write-EnhancedLog -Message "Exiting Validate-SoftwareInstallation function" -Level "NOTICE"
    }
}

function Sanitize-VersionString {
    param (
        [string]$versionString
    )

    try {
        # Remove any non-numeric characters and additional segments like ".windows"
        $sanitizedVersion = $versionString -replace '[^0-9.]', '' -replace '\.\.+', '.'

        # Convert to System.Version
        $version = [version]$sanitizedVersion
        return $version
    }
    catch {
        Write-EnhancedLog -Message "Failed to convert version string: $versionString. Error: $_" -Level "ERROR"
        return $null
    }
}


function Install-PowerShell7FromWeb {
    param (
        [string]$url = "https://raw.githubusercontent.com/aollivierre/setuplab/main/Install-PowerShell7.ps1"
    )

    Write-EnhancedLog -Message "Attempting to install PowerShell 7 from URL: $url" -Level "INFO"

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
            Write-EnhancedLog -Message "PowerShell 7 successfully installed and validated." -Level "INFO"
            return $true
        }
        else {
            Write-EnhancedLog -Message "PowerShell 7 installation validation failed." -Level "ERROR"
            return $false
        }
    }
    else {
        Write-EnhancedLog -Message "Failed to start the installation process for PowerShell 7." -Level "ERROR"
        return $false
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




function Install-EnhancedModule {
    param (
        [string]$ModuleName
    )

    # Log the start of the module installation process
    Write-EnhancedLog "Starting the module installation process for: $ModuleName" -Level "NOTICE"

    # Check if the current PowerShell version is not 5
    # if ($PSVersionTable.PSVersion.Major -ne 5) {
    # Write-EnhancedLog "Current PowerShell version is $($PSVersionTable.PSVersion). PowerShell 5 is required." -Level "WARNING"

    # # Get the path to PowerShell 5
    # $ps5Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Write-EnhancedLog "PowerShell 5 path: $ps5Path" -Level "INFO"

    # # Construct the command to install the module in PowerShell 5
    # $command = "& '$ps5Path' -ExecutionPolicy Bypass -Command `"Install-Module -Name '$ModuleName' -Force -SkipPublisherCheck -Scope AllUsers`""
    # Write-EnhancedLog "Constructed command for PowerShell 5: $command" -Level "DEBUG"

    # # Launch PowerShell 5 to run the module installation
    # Write-EnhancedLog "Launching PowerShell 5 to install the module: $ModuleName" -Level "INFO"
    # Invoke-Expression $command

    # Write-EnhancedLog "Module installation command executed in PowerShell 5. Exiting current session." -Level "NOTICE"
    # return

    # Path to the current script
    # $ScriptPath = $MyInvocation.MyCommand.Definition

    # # Check if we need to re-launch in PowerShell 5
    # Invoke-InPowerShell5 -ScriptPath $ScriptPath

    # # If running in PowerShell 5, reset the module paths and proceed with the rest of the script
    # Reset-ModulePaths

    # }

    # If already in PowerShell 5, install the module
    Write-EnhancedLog "Current PowerShell version is 5. Proceeding with module installation." -Level "INFO"
    Write-EnhancedLog "Installing module: $ModuleName in PowerShell 5" -Level "NOTICE"

    try {
        Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Scope AllUsers
        Write-EnhancedLog "Module $ModuleName installed successfully in PowerShell 5." -Level "INFO"
    }
    catch {
        Write-EnhancedLog "Failed to install module $ModuleName. Error: $_" -Level "ERROR"
    }
}



function Import-EnhancedModules {
    param (
        [string]$modulePsd1Path, # Path to the PSD1 file containing the list of modules to install and import
        [string]$ScriptPath  # Path to the PSD1 file containing the list of modules to install and import
    )

    # Validate PSD1 file path
    if (-not (Test-Path -Path $modulePsd1Path)) {
        Write-EnhancedLog "modules.psd1 file not found at path: $modulePsd1Path" -Level "ERROR"
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
            Write-EnhancedLog "Module $moduleName is not installed. Attempting to install..." -Level "INFO"
            Install-EnhancedModule -ModuleName $moduleName -ScriptPath $ScriptPath
        }

        Write-EnhancedLog "Importing module: $moduleName" -Level "INFO"
        try {
            Import-Module -Name $moduleName -Verbose:$true -Force:$true -Global:$true
        }
        catch {
            Write-EnhancedLog "Failed to import module $moduleName. Error: $_" -Level "ERROR"
        }
    }
}

function Setup-GlobalPaths {
    param (
        [string]$ModulesBasePath       # Path to the modules directory
    )

    # Set the modules base path and create if it doesn't exist
    if (-Not (Test-Path $ModulesBasePath)) {
        Write-EnhancedLog "ModulesBasePath '$ModulesBasePath' does not exist. Creating directory..." -Level "INFO"
        New-Item -Path $ModulesBasePath -ItemType Directory -Force
    }
    $global:modulesBasePath = $ModulesBasePath

    # Log the paths for verification
    Write-EnhancedLog "Modules Base Path: $global:modulesBasePath" -Level "INFO"
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
        Write-EnhancedLog -Message "Starting Download-Psd1File function" -Level "NOTICE"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Validate destination directory
        $destinationDirectory = [System.IO.Path]::GetDirectoryName($destinationPath)
        if (-not (Test-Path -Path $destinationDirectory)) {
            Write-EnhancedLog -Message "Destination directory not found at path: $destinationDirectory" -Level "ERROR"
            throw "Destination directory not found."
        }

        Write-EnhancedLog -Message "Validated destination directory at path: $destinationDirectory" -Level "INFO"
    }

    process {
        try {
            Write-EnhancedLog -Message "Downloading PSD1 file from URL: $url" -Level "INFO"
            Invoke-WebRequest -Uri $url -OutFile $destinationPath -UseBasicParsing
            Write-EnhancedLog -Message "Downloaded PSD1 file to: $destinationPath" -Level "INFO"
        }
        catch {
            Write-EnhancedLog -Message "Failed to download PSD1 file from $url. Error: $_" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        Write-EnhancedLog -Message "Download-Psd1File function execution completed." -Level "NOTICE"
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

function Ensure-GitIsInstalled {
    param (
        [version]$MinVersion = [version]"2.46.0",
        [string]$RegistryPath = "HKLM:\SOFTWARE\GitForWindows",
        [string]$ExePath = "C:\Program Files\Git\bin\git.exe"
    )

    Write-EnhancedLog -Message "Checking if Git is installed and meets the minimum version requirement." -Level "INFO"

    # Use the Validate-SoftwareInstallation function to check if Git is installed and meets the version requirement
    $validationResult = Validate-SoftwareInstallation -SoftwareName "Git" -MinVersion $MinVersion -RegistryPath $RegistryPath -ExePath $ExePath

    if ($validationResult.IsInstalled) {
        Write-EnhancedLog -Message "Git version $($validationResult.Version) is installed and meets the minimum version requirement." -Level "INFO"
        return $true
    }
    else {
        Write-EnhancedLog -Message "Git is not installed or does not meet the minimum version requirement. Installing Git..." -Level "WARNING"
        $installSuccess = Install-GitFromWeb
        return $installSuccess
    }
}


function Install-GitFromWeb {
    param (
        [string]$url = "https://raw.githubusercontent.com/aollivierre/setuplab/main/Install-Git.ps1"
    )

    Write-EnhancedLog -Message "Attempting to install Git from URL: $url" -Level "INFO"

    $process = Invoke-WebScript -url $url
    if ($process) {
        $process.WaitForExit()

        # Perform post-installation validation
        $validationParams = @{
            SoftwareName        = "Git"
            MinVersion          = [version]"2.46.0"
            RegistryPath        = "HKLM:\SOFTWARE\GitForWindows"
            ExePath             = "C:\Program Files\Git\bin\git.exe"
            MaxRetries          = 3  # Single retry after installation
            DelayBetweenRetries = 5
        }

        $postValidationResult = Validate-SoftwareInstallation @validationParams
        if ($postValidationResult.IsInstalled -and $postValidationResult.Version -ge $validationParams.MinVersion) {
            Write-EnhancedLog -Message "Git successfully installed and validated." -Level "INFO"
            return $true
        }
        else {
            Write-EnhancedLog -Message "Git installation validation failed." -Level "ERROR"
            return $false
        }
    }
    else {
        Write-EnhancedLog -Message "Failed to start the installation process for Git." -Level "ERROR"
        return $false
    }
}

function Get-GitPath {
    <#
    .SYNOPSIS
    Discovers the path to the Git executable on the system.

    .DESCRIPTION
    This function attempts to find the Git executable by checking common installation directories and the system's PATH environment variable.

    .EXAMPLE
    $gitPath = Get-GitPath
    if ($gitPath) {
        Write-Host "Git found at: $gitPath"
    } else {
        Write-Host "Git not found."
    }
    #>

    [CmdletBinding()]
    param ()

    try {
        # Common Git installation paths
        $commonPaths = @(
            "C:\Program Files\Git\bin\git.exe",
            "C:\Program Files (x86)\Git\bin\git.exe"
        )

        # Check the common paths
        foreach ($path in $commonPaths) {
            if (Test-Path -Path $path) {
                Write-EnhancedLog -Message "Git found at: $path" -Level "INFO"
                return $path
            }
        }

        # If not found, check if Git is in the system PATH
        $gitPathInEnv = (Get-Command git -ErrorAction SilentlyContinue).Source
        if ($gitPathInEnv) {
            Write-EnhancedLog -Message "Git found in system PATH: $gitPathInEnv" -Level "INFO"
            return $gitPathInEnv
        }

        # If Git is still not found, return $null
        Write-EnhancedLog -Message "Git executable not found." -Level "ERROR"
        return $null
    }
    catch {
        Write-EnhancedLog -Message "Error occurred while trying to find Git path: $_" -Level "ERROR"
        return $null
    }
}


function Manage-GitRepositories {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModulesBasePath
    )

    begin {
        Write-EnhancedLog -Message "Starting Manage-GitRepositories function" -Level "INFO"

        # Initialize lists for tracking repository statuses
        $reposWithPushChanges = [System.Collections.Generic.List[string]]::new()
        $reposSummary = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Validate ModulesBasePath
        if (-not (Test-Path -Path $ModulesBasePath)) {
            Write-EnhancedLog -Message "Modules base path not found: $ModulesBasePath" -Level "ERROR"
            throw "Modules base path not found."
        }

        Write-EnhancedLog -Message "Found modules base path: $ModulesBasePath" -Level "INFO"

        # Get the Git path
        $GitPath = Get-GitPath
        if (-not $GitPath) {
            throw "Git executable not found."
        }
    }

    process {
        try {
            $repos = Get-ChildItem -Path $ModulesBasePath -Directory

            foreach ($repo in $repos) {
                Set-Location -Path $repo.FullName

                # Add the repository to Git's safe directories
                & "$GitPath" config --global --add safe.directory "$($repo.FullName)"

                # Fetch the latest changes
                $fetchOutput = & "$GitPath" fetch
                if ($fetchOutput -match "fatal:") {
                    Write-EnhancedLog -Message "Error during fetch in repository $($repo.Name): $fetchOutput" -Level "ERROR"
                    continue
                }

                # Check for pending changes
                $status = & "$GitPath" status
                if ($status -match "fatal:") {
                    Write-EnhancedLog -Message "Error during status check in repository $($repo.Name): $status" -Level "ERROR"
                    continue
                }

                $repoStatus = "Up to Date"
                if ($status -match "Your branch is behind") {
                    Write-EnhancedLog -Message "Repository $($repo.Name) is behind the remote. Pulling changes..." -Level "INFO"
                    $pullOutput = & "$GitPath" pull
                    if ($pullOutput -match "fatal:") {
                        Write-EnhancedLog -Message "Error during pull in repository $($repo.Name): $pullOutput" -Level "ERROR"
                        continue
                    }
                    $repoStatus = "Pulled"
                }

                if ($status -match "Your branch is ahead") {
                    Write-EnhancedLog -Message "Repository $($repo.Name) has unpushed changes." -Level "WARNING"
                    $reposWithPushChanges.Add($repo.FullName)
                    $repoStatus = "Pending Push"
                }

                # Add the repository status to the summary list
                $reposSummary.Add([pscustomobject]@{
                        RepositoryName = $repo.Name
                        Status         = $repoStatus
                        LastChecked    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                    })
            }

            # Summary of repositories with pending push changes
            if ($reposWithPushChanges.Count -gt 0) {
                Write-EnhancedLog -Message "The following repositories have pending push changes:" -Level "WARNING"
                $reposWithPushChanges | ForEach-Object { Write-EnhancedLog -Message $_ -Level "WARNING" }

                Write-EnhancedLog -Message "Please manually commit and push the changes in these repositories." -Level "WARNING"
            }
            else {
                Write-EnhancedLog -Message "All repositories are up to date." -Level "INFO"
            }
        }
        catch {
            Write-EnhancedLog -Message "An error occurred while managing Git repositories: $_" -Level "ERROR"
            throw $_
        }
    }

    end {
        # Summary output in the console with color coding
        $totalRepos = $reposSummary.Count
        $pulledRepos = $reposSummary | Where-Object { $_.Status -eq "Pulled" }
        $pendingPushRepos = $reposSummary | Where-Object { $_.Status -eq "Pending Push" }
        $upToDateRepos = $reposSummary | Where-Object { $_.Status -eq "Up to Date" }

        Write-Host "---------- Summary Report ----------" -ForegroundColor Cyan
        Write-Host "Total Repositories: $totalRepos" -ForegroundColor Cyan
        Write-Host "Repositories Pulled: $($pulledRepos.Count)" -ForegroundColor Green
        Write-Host "Repositories with Pending Push: $($pendingPushRepos.Count)" -ForegroundColor Yellow
        Write-Host "Repositories Up to Date: $($upToDateRepos.Count)" -ForegroundColor Green

        # Return to the original location
        Set-Location -Path $ModulesBasePath

        Write-EnhancedLog -Message "Manage-GitRepositories function execution completed." -Level "INFO"
    }
}

function Initialize-Environment {
    param (
        [string]$Mode, # Accepts either 'dev' or 'prod'
        [string]$WindowsModulePath, # Path to the Windows module
        [string]$ModulesBasePath # Custom modules base path
    )

 
    if ($Mode -eq "dev") {


        $gitInstalled = Ensure-GitIsInstalled
        if ($gitInstalled) {
            Write-EnhancedLog -Message "Git installation check completed successfully." -Level "INFO"
        }
        else {
            Write-EnhancedLog -Message "Failed to install Git." -Level "ERROR"
        }


        Manage-GitRepositories -ModulesBasePath 'C:\Code\modulesv2'

        $DBG

        # Call Setup-GlobalPaths with custom paths
        Setup-GlobalPaths -ModulesBasePath $ModulesBasePath
        # Check if the directory exists and contains any files (not just the directory existence)
        if (-Not (Test-Path "$global:modulesBasePath\*.*")) {
            Write-EnhancedLog "Modules not found or directory is empty at $global:modulesBasePath. Initiating download..." -Level "INFO"
            Download-Modules -scriptDetails $scriptDetails

            # Re-check after download attempt
            if (-Not (Test-Path "$global:modulesBasePath\*.*")) {
                throw "Download failed or the modules were not placed in the expected directory."
            }
        }
        else {
            Write-EnhancedLog "Source Modules already exist at $global:modulesBasePath" -Level "INFO"
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
        Write-EnhancedLog "Module Path: $global:modulePath" -Level "INFO"

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

        

        # # Install essential modules
        # Install-Module -Name EnhancedBoilerPlateAO -Force -SkipPublisherCheck -Scope AllUsers -Verbose
        # Install-Module -Name EnhancedLoggingAO -Force -SkipPublisherCheck -Scope AllUsers -Verbose

        # Ensure that the latest versions of the essential modules are installed
        Ensure-ModuleIsLatest -ModuleName "PSFramework"
        Ensure-ModuleIsLatest -ModuleName "EnhancedBoilerPlateAO"
        Ensure-ModuleIsLatest -ModuleName "EnhancedLoggingAO"

        # Define the PSD1 file URLs and local paths
        $psd1Url = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Enhanced-modules.psd1"
        $localPsd1Path = "$env:TEMP\enhanced-modules.psd1"

        # Download the PSD1 file
        Download-Psd1File -url $psd1Url -destinationPath $localPsd1Path

        # Install and import modules based on the PSD1 file
        InstallAndImportModulesPSGallery -modulePsd1Path $localPsd1Path

        # Handle third-party PS Gallery modules
        if ($SkipPSGalleryModules) {
            Write-EnhancedLog "Skipping third-party PS Gallery Modules" -Level "INFO"
        }
        else {
            Write-EnhancedLog "Starting PS Gallery Module installation" -Level "INFO"

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

# Example usage of Initialize-Environment
$initializeParams = @{
    Mode              = $Mode
    WindowsModulePath = "EnhancedBoilerPlateAO\EnhancedBoilerPlateAO.psm1"
    ModulesBasePath   = "C:\code\modulesv2" # Custom modules base path
}

# Elevate to administrator if not already
# Example usage to check and optionally elevate:
if ($SkipCheckandElevate) {
    Write-EnhancedLog -Message "Skipping CheckAndElevate due to SkipCheckandElevate parameter." -Level "INFO"
}
else {
    CheckAndElevate -ElevateIfNotAdmin $true
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