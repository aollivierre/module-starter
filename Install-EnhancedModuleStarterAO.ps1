# param (
#     [Switch]$SimulatingIntune = $false
# )

if (-not (Test-Path Variable:SimulatingIntune)) {
    New-Variable -Name 'SimulatingIntune' -Value $false -Option None
}
else {
    Set-Variable -Name 'SimulatingIntune' -Value $false
}

function Get-ParentScriptName {
    [CmdletBinding()]
    param ()

    try {
        # Get the current call stack
        $callStack = Get-PSCallStack

        # If there is a call stack, return the top-most script name
        if ($callStack.Count -gt 0) {
            foreach ($frame in $callStack) {
                if ($frame.ScriptName) {
                    $parentScriptName = $frame.ScriptName
                    # Write-EnhancedModuleStarterLog -Message "Found script in call stack: $parentScriptName" -Level "INFO"
                }
            }

            if (-not [string]::IsNullOrEmpty($parentScriptName)) {
                $parentScriptName = [System.IO.Path]::GetFileNameWithoutExtension($parentScriptName)
                return $parentScriptName
            }
        }

        # If no script name was found, return 'UnknownScript'
        # Write-EnhancedModuleStarterLog -Message "No script name found in the call stack." -Level "WARNING"
        return "UnknownScript"
    }
    catch {
        # Write-EnhancedModuleStarterLog -Message "An error occurred while retrieving the parent script name: $_" -Level "ERROR"
        return "UnknownScript"
    }
}

function Write-EnhancedModuleStarterLog {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )

    # Get the PowerShell call stack to determine the actual calling function
    $callStack = Get-PSCallStack
    $callerFunction = if ($callStack.Count -ge 2) { $callStack[1].Command } else { '<Unknown>' }

    # Get the parent script name
    $parentScriptName = Get-ParentScriptName

    # Prepare the formatted message with the actual calling function information
    $formattedMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] [$parentScriptName.$callerFunction] $Message"

    # Display the log message based on the log level using Write-Host
    switch ($Level.ToUpper()) {
        "DEBUG" { Write-Host $formattedMessage -ForegroundColor DarkGray }
        "INFO" { Write-Host $formattedMessage -ForegroundColor Green }
        "NOTICE" { Write-Host $formattedMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $formattedMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $formattedMessage -ForegroundColor Red }
        "CRITICAL" { Write-Host $formattedMessage -ForegroundColor Magenta }
        default { Write-Host $formattedMessage -ForegroundColor White }
    }

    # Append to log file
    $logFilePath = [System.IO.Path]::Combine($env:TEMP, 'Module-Starter.log')
    $formattedMessage | Out-File -FilePath $logFilePath -Append -Encoding utf8
}

Write-EnhancedModuleStarterLog "Starting Install-EnhancedModuleStarterAO.ps1..." -Level 'WARNING'

function Reset-ModulePaths {
    [CmdletBinding()]
    param ()

    begin {
        # Initialization block, typically used for setup tasks
        Write-EnhancedModuleStarterLog "Initializing Reset-ModulePaths function..."
    }

    process {
        try {
            # Log the start of the process
            Write-EnhancedModuleStarterLog "Resetting module paths to default values..."

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
            Write-EnhancedModuleStarterLog "PSModulePath successfully set to: $($env:PSModulePath -split ';' | Out-String)"

            # Optionally persist the change for the current user
            [Environment]::SetEnvironmentVariable("PSModulePath", $env:PSModulePath, [EnvironmentVariableTarget]::User)
            Write-EnhancedModuleStarterLog "PSModulePath environment variable set for the current user."
        }
        catch {
            # Capture and log any errors that occur during the process
            $errorMessage = $_.Exception.Message
            Write-EnhancedModuleStarterLog "Error resetting module paths: $errorMessage"

            # Optionally, you could throw the error to halt the script
            throw $_
        }
    }

    end {
        # Finalization block, typically used for cleanup tasks
        Write-EnhancedModuleStarterLog "Reset-ModulePaths function completed."
    }
}

Reset-ModulePaths

$currentExecutionPolicy = Get-ExecutionPolicy

# If it's not already set to Bypass, change it
if ($currentExecutionPolicy -ne 'Bypass') {
    Write-EnhancedModuleStarterLog "Setting Execution Policy to Bypass..."
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}
else {
    Write-EnhancedModuleStarterLog "Execution Policy is already set to Bypass."
}


function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


#region CHECKING IF RUNNING AS WEB SCRIPT
#################################################################################################
#                                                                                               #
#                                 CHECKING IF RUNNING AS WEB SCRIPT                             #
#                                                                                               #
#################################################################################################


# Create a time-stamped folder in the temp directory
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$tempFolder = [System.IO.Path]::Combine($env:TEMP, "Ensure-RunningAsSystem_$timestamp")

# Ensure the temp folder exists
if (-not (Test-Path -Path $tempFolder)) {
    New-Item -Path $tempFolder -ItemType Directory | Out-Null
}


# Use the time-stamped temp folder for your paths
$privateFolderPath = Join-Path -Path $tempFolder -ChildPath "private"
$PsExec64Path = Join-Path -Path $privateFolderPath -ChildPath "PsExec64.exe"

# function Get-LocalScriptPath {
#     param (
#         [string]$ScriptUri = "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1"
#     )

#     # Create a time-stamped folder in the temp directory
#     $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
#     $tempFolder = [System.IO.Path]::Combine($env:TEMP, "Ensure-RunningAsSystem_$timestamp")

#     # Ensure the temp folder exists
#     if (-not (Test-Path -Path $tempFolder)) {
#         New-Item -Path $tempFolder -ItemType Directory | Out-Null
#     }

#     # Check if running as a web script (no $MyInvocation.MyCommand.Path)
#     if (-not $MyInvocation.MyCommand.Path) {
#         Write-EnhancedModuleStarterLog "Running as web script, downloading and executing locally..." -Level 'WARNING'

#         # Ensure TLS 1.2 is used for the download
#         [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#         # Create a time-stamped folder in the temp directory
#         $downloadFolder = Join-Path -Path $env:TEMP -ChildPath "Install-EnhancedModuleStarterAO_$timestamp"

#         # Ensure the folder exists
#         if (-not (Test-Path -Path $downloadFolder)) {
#             New-Item -Path $downloadFolder -ItemType Directory | Out-Null
#         }

#         # Download the script to the time-stamped folder
#         $localScriptPath = Join-Path -Path $downloadFolder -ChildPath "Install-EnhancedModuleStarterAO.ps1"
#         Invoke-WebRequest -Uri $ScriptUri -OutFile $localScriptPath

#         # Return the local script path
#         return $localScriptPath
#     } else {
#         # If running in a regular context, use the actual path of the script
#         Write-EnhancedModuleStarterLog "Not Running as web script, executing locally..."
#         return $MyInvocation.MyCommand.Path
#     }
# }










#region CHECKING IF RUNNING AS WEB SCRIPT
#################################################################################################
#                                                                                               #
#                                 CHECKING IF RUNNING AS WEB SCRIPT                             #
#                                                                                               #
#################################################################################################

# Check if running as a web script (no $MyInvocation.MyCommand.Path)
if (-not $MyInvocation.MyCommand.Path) {
    Write-EnhancedModuleStarterLog -Message "Running as web script, downloading and executing locally..." -Level "NOTICE"

    # Ensure TLS 1.2 is used for secure downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Create a time-stamped folder in the temp directory
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $downloadFolder = Join-Path -Path $env:TEMP -ChildPath "Install-EnhancedModuleStarterAO_$timestamp"
    New-Item -Path $downloadFolder -ItemType Directory | Out-Null

    # Download the script to the time-stamped folder
    $localScriptPath = Join-Path -Path $downloadFolder -ChildPath "Install-EnhancedModuleStarterAO.ps1"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1" -OutFile $localScriptPath

    Write-EnhancedModuleStarterLog -Message "Re-running the script locally from: $localScriptPath" -Level "NOTICE"
    
    # Re-run the script locally with elevation if needed
    if (-not (Test-Admin)) {
        Write-EnhancedModuleStarterLog -Message "Relaunching downloaded script with elevated permissions..." -Level "NOTICE"
        $startProcessParams = @{
            FilePath     = "powershell.exe"
            ArgumentList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $localScriptPath)
            Verb         = "RunAs"
        }
        Start-Process @startProcessParams
        exit
    }
    else {
        & $localScriptPath
    }

    Exit # Exit after running the script locally
}
else {
    Write-EnhancedModuleStarterLog -Message "Running in regular context locally..." -Level "INFO"



    # # Elevate to administrator if not already
    if (-not (Test-Admin)) {
        Write-EnhancedModuleStarterLog -Message "Restarting script with elevated permissions..." -Level "NOTICE"
        $startProcessParams = @{
            FilePath     = "powershell.exe"
            ArgumentList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
            Verb         = "RunAs"
        }
        Start-Process @startProcessParams
        exit
    }
}






# Set Execution Policy to Bypass if not already set
$currentExecutionPolicy = Get-ExecutionPolicy
if ($currentExecutionPolicy -ne 'Bypass') {
    Write-EnhancedModuleStarterLog -Message "Setting Execution Policy to Bypass..." -Level "NOTICE"
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
}
else {
    Write-EnhancedModuleStarterLog -Message "Execution Policy is already set to Bypass." -Level "INFO"
}


#endregion CHECKING IF RUNNING AS WEB SCRIPT







# Example usage:
# $scriptObject = Get-LocalScriptPath
# $scriptObject.Path | Relaunch-InPowerShell5






# # Create a time-stamped folder in the temp directory
# $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
# $tempFolder = [System.IO.Path]::Combine($env:TEMP, "Ensure-RunningAsSystem_$timestamp")

# # Ensure the temp folder exists
# if (-not (Test-Path -Path $tempFolder)) {
#     New-Item -Path $tempFolder -ItemType Directory | Out-Null
# }

# # Use the time-stamped temp folder for your paths
# $privateFolderPath = Join-Path -Path $tempFolder -ChildPath "private"
# $PsExec64Path = Join-Path -Path $privateFolderPath -ChildPath "PsExec64.exe"

# # Check if running as a web script (no $MyInvocation.MyCommand.Path)
# if (-not $MyInvocation.MyCommand.Path) {
#     Write-EnhancedModuleStarterLog "Running as web script, downloading and executing locally..." -Level 'WARNING'

#     # Ensure TLS 1.2 is used for the download
#     [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#     # Create a time-stamped folder in the temp directory
#     $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
#     $downloadFolder = Join-Path -Path $env:TEMP -ChildPath "Install-EnhancedModuleStarterAO_$timestamp"

#     # Ensure the folder exists
#     if (-not (Test-Path -Path $downloadFolder)) {
#         New-Item -Path $downloadFolder -ItemType Directory | Out-Null
#     }

#     # Download the script to the time-stamped folder
#     $localScriptPath = Join-Path -Path $downloadFolder -ChildPath "Install-EnhancedModuleStarterAO.ps1"
#     Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aollivierre/module-starter/main/Install-EnhancedModuleStarterAO.ps1" -OutFile $localScriptPath

#     # Write-EnhancedModuleStarterLog "Downloading config.psd1 file..."

#     # # Download the config.psd1 file to the time-stamped folder
#     # $configFilePath = Join-Path -Path $downloadFolder -ChildPath "config.psd1"
#     # Invoke-WebRequest -Uri "https://raw.githubusercontent.com/aollivierre/WinUpdates/main/PR4B_TriggerWindowsUpdates-v4/config.psd1" -OutFile $configFilePath

#     # Execute the script locally
#     & $localScriptPath

#     Write-EnhancedModuleStarterLog "Exiting Web Script"
#     Exit # Exit after running the script locally
# }

# else {
#     # If running in a regular context, use the actual path of the script
#     Write-EnhancedModuleStarterLog "Not Running as web script, executing locally..."
#     $ScriptToRunAsSystem = $MyInvocation.MyCommand.Path
#     Write-EnhancedModuleStarterLog "Script path is $ScriptToRunAsSystem"
# }


# Wait-Debugger

#endregion CHECKING IF RUNNING AS WEB SCRIPT
#################################################################################################
#                                                                                               #
#                                 CHECKING IF RUNNING AS WEB SCRIPT                             #
#                                                                                               #
#################################################################################################




function Relaunch-InPowerShell5 {
    param (
        [string]$ScriptPath
    )

    process {
        # Default to $PSCommandPath or fallback to the provided path
        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $ScriptPath }

        if (-not $scriptPath) {
            Write-EnhancedModuleStarterLog "Script path not found, attempting to get it via Get-LocalScriptPath..." -Level 'WARNING'
            $scriptPath = Get-LocalScriptPath
        }

        Write-EnhancedModuleStarterLog "Script path to Launch in PowerShell 5 is '$scriptPath'"

        # Check the current version of PowerShell
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Write-EnhancedModuleStarterLog "Hello from PowerShell 7"

            $ps5Path = "$($env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe"

            # Build the argument to relaunch this script in PowerShell 5 with -NoExit
            $ps5Args = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

            Write-EnhancedModuleStarterLog "Relaunching in PowerShell 5..."
            Start-Process -FilePath $ps5Path -ArgumentList $ps5Args

            # Exit the current PowerShell 7 session to allow PowerShell 5 to take over
            exit
        }

        # If relaunching in PowerShell 5
        Write-EnhancedModuleStarterLog "Hello from PowerShell 5"
    }
}

# Example usage:
# Get the script path and pass it directly to Relaunch-InPowerShell5
# $scriptPath = Get-LocalScriptPath
# Relaunch-InPowerShell5 -ScriptPath $scriptPath


# function Relaunch-InPowerShell5 {
#     # Check the current version of PowerShell
#     if ($PSVersionTable.PSVersion.Major -ge 7) {
#         Write-EnhancedModuleStarterLog "Hello from PowerShell 7"

#         # Get the script path (works inside a function as well)
#         # $scriptPath = $PSCommandPath
#         $scriptPath = $MyInvocation.MyCommand.Path

#         Write-EnhancedModuleStarterLog "Script path to Launch in PowerShell 5 is "$scriptPath""

#         # $scriptPath = $MyInvocation.MyCommand.Definition
#         $ps5Path = "$($env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe"

#         # Build the argument to relaunch this script in PowerShell 5 with -NoExit
#         $ps5Args = "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

#         Write-EnhancedModuleStarterLog "Relaunching in PowerShell 5..."
#         Start-Process -FilePath $ps5Path -ArgumentList $ps5Args

#         # Exit the current PowerShell 7 session to allow PowerShell 5 to take over
#         exit
#     }

#     # If relaunching in PowerShell 5
#     Write-EnhancedModuleStarterLog "Hello from PowerShell 5"
    
# }

# Relaunch-InPowerShell5


# ################################################################################################################################
# ################################################ END Setting Execution Policy ##################################################
# ################################################################################################################################


# Ensure the private folder exists before continuing
if (-not (Test-Path -Path $privateFolderPath)) {
    New-Item -Path $privateFolderPath -ItemType Directory | Out-Null
}



# Conditional check for SimulatingIntune switch
if ($SimulatingIntune) {
    # If not running as a web script, run as SYSTEM using PsExec
    Write-EnhancedModuleStarterLog "Simulating Intune environment. Running script as SYSTEM..."

    Write-EnhancedModuleStarterLog "Running as SYSTEM..."


    # Call the function to run as SYSTEM
    $EnsureRunningAsSystemParams = @{
        PsExec64Path = $PsExec64Path
        ScriptPath   = $ScriptToRunAsSystem
        TargetFolder = $privateFolderPath
    }

    # Run Ensure-RunningAsSystem only if SimulatingIntune is set
    Ensure-RunningAsSystem @EnsureRunningAsSystemParams
}
else {
    Write-EnhancedModuleStarterLog "Not simulating Intune. Skipping SYSTEM execution."
}


function Get-PowerShellPath {
    <#
    .SYNOPSIS
        Retrieves the path to the installed PowerShell executable, defaulting to PowerShell 5.

    .DESCRIPTION
        This function checks for the existence of PowerShell 5 and PowerShell 7 on the system.
        By default, it returns the path to PowerShell 5 unless the -UsePS7 switch is provided.
        If the specified version is not found, an error is thrown.

    .PARAMETER UsePS7
        Optional switch to prioritize PowerShell 7 over PowerShell 5.

    .EXAMPLE
        $pwshPath = Get-PowerShellPath
        Write-EnhancedModuleStarterLog "PowerShell found at: $pwshPath"

    .EXAMPLE
        $pwshPath = Get-PowerShellPath -UsePS7
        Write-EnhancedModuleStarterLog "PowerShell found at: $pwshPath"

    .NOTES
        Author: Abdullah Ollivierre
        Date: 2024-08-15
    #>

    [CmdletBinding()]
    param (
        [switch]$UsePS7
    )

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Get-PowerShellPath function" -Level "NOTICE"
    }

    Process {
        $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
        $pwsh5Path = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

        if ($UsePS7) {
            if (Test-Path $pwsh7Path) {
                Write-EnhancedModuleStarterLog -Message "PowerShell 7 found at $pwsh7Path" -Level "INFO"
                return $pwsh7Path
            }
            elseif (Test-Path $pwsh5Path) {
                Write-EnhancedModuleStarterLog -Message "PowerShell 7 not found, falling back to PowerShell 5 at $pwsh5Path" -Level "WARNING"
                return $pwsh5Path
            }
        }
        else {
            if (Test-Path $pwsh5Path) {
                Write-EnhancedModuleStarterLog -Message "PowerShell 5 found at $pwsh5Path" -Level "INFO"
                return $pwsh5Path
            }
            elseif (Test-Path $pwsh7Path) {
                Write-EnhancedModuleStarterLog -Message "PowerShell 5 not found, falling back to PowerShell 7 at $pwsh7Path" -Level "WARNING"
                return $pwsh7Path
            }
        }

        $errorMessage = "Neither PowerShell 7 nor PowerShell 5 was found on this system."
        Write-EnhancedModuleStarterLog -Message $errorMessage -Level "ERROR"
        throw $errorMessage
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Get-PowerShellPath function" -Level "NOTICE"
    }
}

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
        Write-EnhancedModuleStarterLog "The script is not running with administrative privileges."
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
        Write-EnhancedModuleStarterLog -Message "Starting CheckAndElevate function" -Level "NOTICE"

        # Use .NET classes for efficiency
        try {
            $isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            Write-EnhancedModuleStarterLog -Message "Checking for administrative privileges..." -Level "INFO"
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error determining administrative status: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    Process {
        if (-not $isAdmin) {
            if ($ElevateIfNotAdmin) {
                try {
                    Write-EnhancedModuleStarterLog -Message "The script is not running with administrative privileges. Attempting to elevate..." -Level "WARNING"

                    $powerShellPath = Get-PowerShellPath
                    $startProcessParams = @{
                        FilePath     = $powerShellPath
                        ArgumentList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
                        Verb         = "RunAs"
                    }
                    Start-Process @startProcessParams

                    Write-EnhancedModuleStarterLog -Message "Script re-launched with administrative privileges. Exiting current session." -Level "INFO"
                    exit
                }
                catch {
                    Write-EnhancedModuleStarterLog -Message "Failed to elevate privileges: $($_.Exception.Message)" -Level "ERROR"
                    Handle-Error -ErrorRecord $_
                    throw $_
                }
            }
            else {
                Write-EnhancedModuleStarterLog -Message "The script is not running with administrative privileges and will continue without elevation." -Level "INFO"
            }
        }
        else {
            Write-EnhancedModuleStarterLog -Message "Script is already running with administrative privileges." -Level "INFO"
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting CheckAndElevate function" -Level "NOTICE"
        return $isAdmin
    }
}

function Test-RunningAsSystem {
    <#
    .SYNOPSIS
    Checks if the current session is running under the SYSTEM account.

    .DESCRIPTION
    The Test-RunningAsSystem function checks whether the current PowerShell session is running under the Windows SYSTEM account. 
    This is determined by comparing the security identifier (SID) of the current user with the SID of the SYSTEM account.

    .EXAMPLE
    $isSystem = Test-RunningAsSystem
    if ($isSystem) {
        Write-Host "The script is running under the SYSTEM account."
    } else {
        Write-Host "The script is not running under the SYSTEM account."
    }

    Checks if the current session is running under the SYSTEM account and returns the status.

    .NOTES
    This function is useful when determining if the script is being executed by a service or task running under the SYSTEM account.
    #>

    [CmdletBinding()]
    param ()

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Test-RunningAsSystem function" -Level "NOTICE"

        # Initialize variables
        $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    }

    Process {
        try {
            Write-EnhancedModuleStarterLog -Message "Checking if the script is running under the SYSTEM account..." -Level "INFO"

            $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

            if ($currentSid -eq $systemSid) {
                Write-EnhancedModuleStarterLog -Message "The script is running under the SYSTEM account." -Level "INFO"
            }
            else {
                Write-EnhancedModuleStarterLog -Message "The script is not running under the SYSTEM account." -Level "WARNING"
            }
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error determining if running as SYSTEM: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Test-RunningAsSystem function" -Level "NOTICE"
        return $currentSid -eq $systemSid
    }
}


function Sanitize-LogFilePath {
    [CmdletBinding()]
    param (
        [string]$LogFilePath
    )

    try {
        Write-EnhancedModuleStarterLog -Message "Starting Sanitize-LogFilePath function..." -Level "NOTICE"
        Write-EnhancedModuleStarterLog -Message "Original LogFilePath: $LogFilePath" -Level "INFO"

        # Trim leading and trailing whitespace
        $LogFilePath = $LogFilePath.Trim()
        Write-EnhancedModuleStarterLog -Message "LogFilePath after trim: $LogFilePath" -Level "INFO"

        # Replace multiple spaces with a single space
        $LogFilePath = $LogFilePath -replace '\s+', ' '
        Write-EnhancedModuleStarterLog -Message "LogFilePath after removing multiple spaces: $LogFilePath" -Level "INFO"

        # Replace illegal characters (preserve drive letter and colon)
        if ($LogFilePath -match '^([a-zA-Z]):\\') {
            $drive = $matches[1]
            $LogFilePath = $LogFilePath -replace '[<>:"|?*]', '_'
            $LogFilePath = "$drive`:$($LogFilePath.Substring(2))"
        }
        else {
            # Handle cases where the path doesn't start with a drive letter
            $LogFilePath = $LogFilePath -replace '[<>:"|?*]', '_'
        }
        Write-EnhancedModuleStarterLog -Message "LogFilePath after replacing invalid characters: $LogFilePath" -Level "INFO"

        # Replace multiple backslashes with a single backslash
        $LogFilePath = [System.Text.RegularExpressions.Regex]::Replace($LogFilePath, '\\+', '\')
        Write-EnhancedModuleStarterLog -Message "LogFilePath after replacing multiple slashes: $LogFilePath" -Level "INFO"

        # Ensure the path is still rooted
        if (-not [System.IO.Path]::IsPathRooted($LogFilePath)) {
            throw "The LogFilePath is not rooted: $LogFilePath"
        }

        Write-EnhancedModuleStarterLog -Message "Sanitized LogFilePath: $LogFilePath" -Level "INFO"
        Write-EnhancedModuleStarterLog -Message "Exiting Sanitize-LogFilePath function" -Level "NOTICE"
        return $LogFilePath
    }
    catch {
        Write-EnhancedModuleStarterLog -Message "An error occurred in Sanitize-LogFilePath: $_" -Level "ERROR"
        Handle-Error -ErrorRecord $_
        throw $_  # Re-throw the error after logging it
    }
}
function Validate-LogFilePath {
    [CmdletBinding()]
    param (
        [string]$LogFilePath
    )

    try {
        Write-EnhancedModuleStarterLog -Message "Starting Validate-LogFilePath function..." -Level "NOTICE"
        Write-EnhancedModuleStarterLog -Message "Validating LogFilePath: $LogFilePath" -Level "INFO"

        # Check for invalid characters in the file path
        if ($LogFilePath -match "[<>""|?*]") {
            Write-EnhancedModuleStarterLog -Message "Warning: The LogFilePath contains invalid characters." -Level "WARNING"
        }

        # Check for double backslashes which may indicate an error in path generation
        if ($LogFilePath -match "\\\\") {
            Write-EnhancedModuleStarterLog -Message "Warning: The LogFilePath contains double backslashes." -Level "WARNING"
        }

        Write-EnhancedModuleStarterLog -Message "Validation complete for LogFilePath: $LogFilePath" -Level "INFO"
        Write-EnhancedModuleStarterLog -Message "Exiting Validate-LogFilePath function" -Level "NOTICE"
    }
    catch {
        Write-EnhancedModuleStarterLog -Message "An error occurred in Validate-LogFilePath: $_" -Level "ERROR"
        Handle-Error -ErrorRecord $_
        throw $_  # Re-throw the error after logging it
    }
}

function Get-PSFCSVLogFilePath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Specify the base path where the logs will be stored.")]
        [string]$LogsPath,

        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Specify the job name to be used in the log file name.")]
        [string]$JobName,

        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Specify the name of the parent script.")]
        [string]$parentScriptName
    )

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Get-PSFCSVLogFilePath function..." -Level "NOTICE"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Ensure the destination directory exists
        if (-not (Test-Path -Path $LogsPath)) {
            New-Item -ItemType Directory -Path $LogsPath -Force | Out-Null
            Write-EnhancedModuleStarterLog -Message "Created Logs directory at: $LogsPath" -Level "INFO"
        }
    }

    Process {
        try {
            # Get the current username
            $username = if ($env:USERNAME) { $env:USERNAME } else { "UnknownUser" }
            Write-EnhancedModuleStarterLog -Message "Current username: $username" -Level "INFO"

            # Log the parent script name
            Write-EnhancedModuleStarterLog -Message "Script name: $parentScriptName" -Level "INFO"

            # Check if running as SYSTEM
            $isSystem = Test-RunningAsSystem
            Write-EnhancedModuleStarterLog -Message "Is running as SYSTEM: $isSystem" -Level "INFO"

            # Get the current date for folder creation
            $currentDate = Get-Date -Format "yyyy-MM-dd"

            # Construct the hostname and timestamp for the log filename
            $hostname = $env:COMPUTERNAME
            $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
            $logFolderPath = "$LogsPath\$currentDate\$parentScriptName"

            # Ensure the log directory exists
            if (-not (Test-Path -Path $logFolderPath)) {
                New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
                Write-EnhancedModuleStarterLog -Message "Created directory for log file: $logFolderPath" -Level "INFO"
            }

            # Generate log file path based on context
            $logFilePath = if ($isSystem) {
                "$logFolderPath\$hostname-$JobName-SYSTEM-$parentScriptName-log-$timestamp.csv"
            }
            else {
                "$logFolderPath\$hostname-$JobName-$username-$parentScriptName-log-$timestamp.csv"
            }

            $logFilePath = Sanitize-LogFilePath -LogFilePath $logFilePath

            # Validate the log file path before using it
            Validate-LogFilePath -LogFilePath $logFilePath

            Write-EnhancedModuleStarterLog -Message "Generated PSFramework CSV log file path: $logFilePath" -Level "INFO"
            return $logFilePath
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "An error occurred in Get-PSFCSVLogFilePath: $_" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_  # Re-throw the error after logging it
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Get-PSFCSVLogFilePath function" -Level "NOTICE"
    }
}

function Get-TranscriptFilePath {
    <#
    .SYNOPSIS
    Generates a file path for storing PowerShell transcripts.

    .DESCRIPTION
    The Get-TranscriptFilePath function constructs a unique transcript file path based on the provided transcript directory, job name, and parent script name. It ensures the transcript directory exists, handles context (e.g., SYSTEM account), and logs each step of the process.

    .PARAMETER TranscriptsPath
    The base directory where transcript files will be stored.

    .PARAMETER JobName
    The name of the job or task, used to distinguish different log files.

    .PARAMETER ParentScriptName
    The name of the parent script that is generating the transcript.

    .EXAMPLE
    $params = @{
        TranscriptsPath  = 'C:\Transcripts'
        JobName          = 'BackupJob'
        ParentScriptName = 'BackupScript.ps1'
    }
    Get-TranscriptFilePath @params
    Generates a transcript file path for a script called BackupScript.ps1.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Provide the base path for transcripts.")]
        [ValidateNotNullOrEmpty()]
        [string]$TranscriptsPath,

        [Parameter(Mandatory = $true, HelpMessage = "Provide the job name.")]
        [ValidateNotNullOrEmpty()]
        [string]$JobName,

        [Parameter(Mandatory = $true, HelpMessage = "Provide the parent script name.")]
        [ValidateNotNullOrEmpty()]
        [string]$ParentScriptName
    )

    Begin {
        # Log the start of the function
        Write-EnhancedModuleStarterLog -Message "Starting Get-TranscriptFilePath function..." -Level "NOTICE"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Ensure the destination directory exists
        if (-not (Test-Path -Path $TranscriptsPath)) {
            New-Item -ItemType Directory -Path $TranscriptsPath -Force | Out-Null
            Write-EnhancedModuleStarterLog -Message "Created Transcripts directory at: $TranscriptsPath" -Level "INFO"
        }
    }

    Process {
        try {
            # Get the current username or fallback to "UnknownUser"
            $username = if ($env:USERNAME) { $env:USERNAME } else { "UnknownUser" }
            Write-EnhancedModuleStarterLog -Message "Current username: $username" -Level "INFO"

            # Log the provided parent script name
            Write-EnhancedModuleStarterLog -Message "Parent script name: $ParentScriptName" -Level "INFO"

            # Check if running as SYSTEM
            $isSystem = Test-RunningAsSystem
            Write-EnhancedModuleStarterLog -Message "Is running as SYSTEM: $isSystem" -Level "INFO"

            # Get the current date for folder structure
            $currentDate = Get-Date -Format "yyyy-MM-dd"
            Write-EnhancedModuleStarterLog -Message "Current date for transcript folder: $currentDate" -Level "INFO"

            # Construct the hostname and timestamp for the log file name
            $hostname = $env:COMPUTERNAME
            $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
            $logFolderPath = Join-Path -Path $TranscriptsPath -ChildPath "$currentDate\$ParentScriptName"

            # Ensure the log directory exists
            if (-not (Test-Path -Path $logFolderPath)) {
                New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
                Write-EnhancedModuleStarterLog -Message "Created directory for transcript logs: $logFolderPath" -Level "INFO"
            }

            # Generate log file path based on context (SYSTEM or user)
            $logFilePath = if ($isSystem) {
                "$logFolderPath\$hostname-$JobName-SYSTEM-$ParentScriptName-transcript-$timestamp.log"
            }
            else {
                "$logFolderPath\$hostname-$JobName-$username-$ParentScriptName-transcript-$timestamp.log"
            }

            Write-EnhancedModuleStarterLog -Message "Constructed log file path: $logFilePath" -Level "INFO"

            # Sanitize and validate the log file path
            $logFilePath = Sanitize-LogFilePath -LogFilePath $logFilePath
            Validate-LogFilePath -LogFilePath $logFilePath
            Write-EnhancedModuleStarterLog -Message "Log file path sanitized and validated: $logFilePath" -Level "INFO"

            # Return the constructed file path
            return $logFilePath
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "An error occurred in Get-TranscriptFilePath: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Get-TranscriptFilePath function" -Level "NOTICE"
    }
}


function Log-Params {
    <#
    .SYNOPSIS
    Logs the provided parameters and their values with the parent function name appended.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Params
    )

    Begin {
        # Get the name of the parent function
        $parentFunctionName = (Get-PSCallStack)[1].Command

        # Write-EnhancedModuleStarterLog -Message "Starting Log-Params function in $parentFunctionName" -Level "INFO"
    }

    Process {
        try {
            foreach ($key in $Params.Keys) {
                # Append the parent function name to the key
                $enhancedKey = "$parentFunctionName.$key"
                Write-EnhancedModuleStarterLog -Message "$enhancedKey $($Params[$key])" -Level "INFO"
            }
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "An error occurred while logging parameters in $parentFunctionName $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw
        }
    }

    End {
        # Write-EnhancedModuleStarterLog -Message "Exiting Log-Params function in $parentFunctionName" -Level "INFO"
    }
}

function Handle-Error {
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $fullErrorDetails = Get-Error -InputObject $ErrorRecord | Out-String
        }
        else {
            $fullErrorDetails = $ErrorRecord.Exception | Format-List * -Force | Out-String
        }

        Write-EnhancedModuleStarterLog -Message "Exception Message: $($ErrorRecord.Exception.Message)" -Level "ERROR"
        Write-EnhancedModuleStarterLog -Message "Full Exception: $fullErrorDetails" -Level "ERROR"
    }
    catch {
        # Fallback error handling in case of an unexpected error in the try block
        Write-EnhancedModuleStarterLog -Message "An error occurred while handling another error. Original Exception: $($ErrorRecord.Exception.Message)" -Level "CRITICAL"
        Write-EnhancedModuleStarterLog -Message "Handler Exception: $($_.Exception.Message)" -Level "CRITICAL"
        Write-EnhancedModuleStarterLog -Message "Handler Full Exception: $($_ | Out-String)" -Level "CRITICAL"
    }
}
function Remove-EnhancedModules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ModuleNamePrefix = "Enhanced"
    )

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting removal of modules with prefix '$ModuleNamePrefix'." -Level "NOTICE"
    }

    Process {
        try {
            # Get all installed modules that start with the specified prefix
            $modules = Get-Module -ListAvailable | Where-Object { $_.Name -like "$ModuleNamePrefix*" }

            if ($modules.Count -eq 0) {
                Write-EnhancedModuleStarterLog -Message "No modules found with prefix '$ModuleNamePrefix'." -Level "INFO"
                return
            }

            foreach ($module in $modules) {
                Write-EnhancedModuleStarterLog -Message "Removing module '$($module.Name)' version '$($module.Version)'." -Level "INFO"

                try {
                    # Attempt to uninstall the module
                    Uninstall-Module -Name $module.Name -AllVersions -Force -ErrorAction Stop
                    Write-EnhancedModuleStarterLog -Message "Module '$($module.Name)' removed successfully." -Level "INFO"
                }
                catch {
                    Write-EnhancedModuleStarterLog -Message "Failed to remove module '$($module.Name)': $_" -Level "ERROR"
                }
            }
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error during module removal process: $_" -Level "CRITICAL"
            throw
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Completed removal of modules with prefix '$ModuleNamePrefix'." -Level "NOTICE"
    }
}

function Remove-OldVersions {
    <#
    .SYNOPSIS
    Removes older versions of a specified PowerShell module.

    .DESCRIPTION
    The Remove-OldVersions function removes all but the latest version of the specified PowerShell module. It ensures that only the most recent version is retained.

    .PARAMETER ModuleName
    The name of the module for which older versions will be removed.

    .EXAMPLE
    Remove-OldVersions -ModuleName "Pester"
    Removes all but the latest version of the Pester module.

    .NOTES
    This function requires administrative access to manage modules and assumes that the CheckAndElevate function is defined elsewhere in the script.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    begin {
        Write-EnhancedModuleStarterLog -Message "Starting Remove-OldVersions function for module: $ModuleName" -Level "INFO"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        # Get all versions except the latest one
        # $allVersions = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version
        # $latestVersion = $allVersions | Select-Object -Last 1
        # $olderVersions = $allVersions | Where-Object { $_.Version -ne $latestVersion.Version }


        # Retrieve all versions of the module
        Write-EnhancedModuleStarterLog -Message "Retrieving all available versions of module: $ModuleName" -Level "INFO"
        $allVersions = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version

        if ($allVersions -and $allVersions.Count -gt 0) {
            Write-EnhancedModuleStarterLog -Message "Found $($allVersions.Count) versions of the module: $ModuleName" -Level "INFO"
        }
        else {
            Write-EnhancedModuleStarterLog -Message "No versions of the module: $ModuleName were found." -Level "ERROR"
            return
        }

        # Identify the latest version
        $latestVersion = $allVersions | Select-Object -Last 1
        Write-EnhancedModuleStarterLog -Message "Latest version of the module: $ModuleName is $($latestVersion.Version)" -Level "INFO"

        # Identify the older versions
        $olderVersions = $allVersions | Where-Object { $_.Version -ne $latestVersion.Version }
        if ($olderVersions.Count -gt 0) {
            Write-EnhancedModuleStarterLog -Message "Found $($olderVersions.Count) older versions of the module: $ModuleName" -Level "INFO"
        }
        else {
            Write-EnhancedModuleStarterLog -Message "No older versions of the module: $ModuleName found." -Level "INFO"
        }


        foreach ($version in $olderVersions) {
            try {
                Write-EnhancedModuleStarterLog -Message "Removing older version $($version.Version) of $ModuleName..." -Level "INFO"
                $modulePath = $version.ModuleBase

                Write-EnhancedModuleStarterLog -Message "Starting takeown and icacls for $modulePath" -Level "INFO"
                Write-EnhancedModuleStarterLog -Message "Checking and elevating to admin if needed" -Level "INFO"
                CheckAndElevate -ElevateIfNotAdmin $true
                & takeown.exe /F $modulePath /A /R
                & icacls.exe $modulePath /reset
                & icacls.exe $modulePath /grant "*S-1-5-32-544:F" /inheritance:d /T
                Remove-Item -Path $modulePath -Recurse -Force -Confirm:$false

                Write-EnhancedModuleStarterLog -Message "Removed $($version.Version) successfully." -Level "INFO"
            }
            catch {
                Write-EnhancedModuleStarterLog -Message "Failed to remove version $($version.Version) of $ModuleName at $modulePath. Error: $_" -Level "ERROR"
                Handle-Error -ErrorRecord $_
            }
        }
    }

    end {
        Write-EnhancedModuleStarterLog -Message "Remove-OldVersions function execution completed for module: $ModuleName" -Level "INFO"
    }
}           

function Install-ModuleInPS5 {
    <#
    .SYNOPSIS
    Installs a PowerShell module in PowerShell 5 and validates the installation.

    .DESCRIPTION
    The Install-ModuleInPS5 function installs a specified PowerShell module using PowerShell 5. It ensures that the module is installed in the correct environment and logs the entire process. It handles errors gracefully and validates the installation after completion.

    .PARAMETER ModuleName
    The name of the PowerShell module to install in PowerShell 5.

    .EXAMPLE
    $params = @{
        ModuleName = "Az"
    }
    Install-ModuleInPS5 @params
    Installs the specified PowerShell module using PowerShell 5 and logs the process.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Provide the name of the module to install.")]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Install-ModuleInPS5 function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        Reset-ModulePaths

        # Ensure-NuGetProvider

        CheckAndElevate -ElevateIfNotAdmin $true


        # Path to PowerShell 5
        $ps5Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

        # Validate if PowerShell 5 exists
        if (-not (Test-Path $ps5Path)) {
            throw "PowerShell 5 executable not found: $ps5Path"
        }
    }

    Process {
        try {
            if ($PSVersionTable.PSVersion.Major -eq 5) {
                # If already in PowerShell 5, install the module directly
                Write-EnhancedModuleStarterLog -Message "Already running in PowerShell 5, installing module directly." -Level "INFO"
                Install-Module -Name $ModuleName -Scope AllUsers -SkipPublisherCheck -AllowClobber -Force -Confirm:$false
            }
            else {
                # If not in PowerShell 5, use Start-Process to switch to PowerShell 5
                Write-EnhancedModuleStarterLog -Message "Preparing to install module: $ModuleName in PowerShell 5" -Level "INFO"

                $ps5Command = "Install-Module -Name $ModuleName -Scope AllUsers -SkipPublisherCheck -AllowClobber -Force -Confirm:`$false"

                # Splatting for Start-Process
                $startProcessParams = @{
                    FilePath     = $ps5Path
                    ArgumentList = "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $ps5Command
                    Wait         = $true
                    NoNewWindow  = $true
                    PassThru     = $true
                }

                Write-EnhancedModuleStarterLog -Message "Starting installation of module $ModuleName in PowerShell 5" -Level "INFO"
                $process = Start-Process @startProcessParams

                if ($process.ExitCode -eq 0) {
                    Write-EnhancedModuleStarterLog -Message "Module '$ModuleName' installed successfully in PS5" -Level "INFO"
                }
                else {
                    Write-EnhancedModuleStarterLog -Message "Error occurred during module installation. Exit Code: $($process.ExitCode)" -Level "ERROR"
                }
            }
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error installing module: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw
        }
        finally {
            Write-EnhancedModuleStarterLog -Message "Exiting Install-ModuleInPS5 function" -Level "Notice"
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Validating module installation in PS5" -Level "INFO"

        if ($PSVersionTable.PSVersion.Major -eq 5) {
            # Validate directly in PowerShell 5
            $module = Get-Module -ListAvailable -Name $ModuleName
        }
        else {
            # Use Start-Process to validate in PowerShell 5
            $ps5ValidateCommand = "Get-Module -ListAvailable -Name $ModuleName"

            $validateProcessParams = @{
                FilePath     = $ps5Path
                ArgumentList = "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $ps5ValidateCommand
                NoNewWindow  = $true
                PassThru     = $true
                Wait         = $true
            }

            $moduleInstalled = Start-Process @validateProcessParams
            if ($moduleInstalled.ExitCode -ne 0) {
                Write-EnhancedModuleStarterLog -Message "Module $ModuleName validation failed in PS5" -Level "ERROR"
                throw "Module $ModuleName installation could not be validated in PS5"
            }
        }

        Write-EnhancedModuleStarterLog -Message "Module $ModuleName validated successfully in PS5" -Level "INFO"
    }
}

function Ensure-NuGetProvider {
    <#
    .SYNOPSIS
    Ensures that the NuGet provider and PowerShellGet module are installed when running in PowerShell 5.

    .DESCRIPTION
    This function checks if the NuGet provider is installed when running in PowerShell 5. If not, it installs the NuGet provider and ensures that the PowerShellGet module is installed as well.

    .EXAMPLE
    Ensure-NuGetProvider
    Ensures the NuGet provider is installed on a PowerShell 5 system.
    #>

    [CmdletBinding()]
    param ()

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Ensure-NuGetProvider function" -Level "Notice"

        Reset-ModulePaths
        
        # Log the current PowerShell version
        Write-EnhancedModuleStarterLog -Message "Running PowerShell version: $($PSVersionTable.PSVersion)" -Level "INFO"

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }

    Process {
        try {
            # Check if running in PowerShell 5
            if ($PSVersionTable.PSVersion.Major -eq 5) {
                Write-EnhancedModuleStarterLog -Message "Running in PowerShell version 5, checking NuGet provider..." -Level "INFO"

                # Use -ListAvailable to only check installed providers without triggering installation
                if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                    Write-EnhancedModuleStarterLog -Message "NuGet provider not found. Installing NuGet provider..." -Level "INFO"

                    # Install the NuGet provider with ForceBootstrap to bypass the prompt

                    Install-PackageProvider -Name NuGet -ForceBootstrap -Force -Confirm:$false
                    Write-EnhancedModuleStarterLog -Message "NuGet provider installed successfully." -Level "INFO"
                    
                    # Install the PowerShellGet module
                    $params = @{
                        ModuleName = "PowerShellGet"
                    }
                    Install-ModuleInPS5 @params

                }
                else {
                    Write-EnhancedModuleStarterLog -Message "NuGet provider is already installed." -Level "INFO"
                }
            }
            else {
                Write-EnhancedModuleStarterLog -Message "This script is running in PowerShell version $($PSVersionTable.PSVersion), which is not version 5. No action is taken for NuGet." -Level "INFO"
            }
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error encountered during NuGet provider installation: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Ensure-NuGetProvider function" -Level "Notice"
    }
}

function Check-ModuleVersionStatus {
    <#
    .SYNOPSIS
    Checks the installed and latest versions of PowerShell modules.

    .DESCRIPTION
    The Check-ModuleVersionStatus function checks if the specified PowerShell modules are installed and compares their versions with the latest available version in the PowerShell Gallery. It logs the checking process and handles errors gracefully.

    .PARAMETER ModuleNames
    The names of the PowerShell modules to check for version status.

    .EXAMPLE
    $params = @{
        ModuleNames = @('Pester', 'AzureRM', 'PowerShellGet')
    }
    Check-ModuleVersionStatus @params
    Checks the version status of the specified modules.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Provide the names of the modules to check.")]
        [ValidateNotNullOrEmpty()]
        [string[]]$ModuleNames
    )

    Begin {
        Write-EnhancedModuleStarterLog -Message "Starting Check-ModuleVersionStatus function" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Ensure-NuGetProvider

        # Import PowerShellGet if it's not already loaded
        Write-EnhancedModuleStarterLog -Message "Importing necessary modules (PowerShellGet)." -Level "INFO"
        try {
            Import-Module -Name PowerShellGet -ErrorAction SilentlyContinue
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Failed to import PowerShellGet: $($_.Exception.Message)" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw
        }

        # Initialize a list to hold the results
        $results = [System.Collections.Generic.List[PSObject]]::new()
    }

    Process {
        foreach ($ModuleName in $ModuleNames) {
            try {
                Write-EnhancedModuleStarterLog -Message "Checking module: $ModuleName" -Level "INFO"
                
                # Get installed module details
                $installedModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
                
                # Get latest module version from the PowerShell Gallery
                $latestModule = Find-Module -Name $ModuleName -ErrorAction SilentlyContinue

                if ($installedModule -and $latestModule) {
                    if ($installedModule.Version -lt $latestModule.Version) {
                        $results.Add([PSCustomObject]@{
                                ModuleName       = $ModuleName
                                Status           = "Outdated"
                                InstalledVersion = $installedModule.Version
                                LatestVersion    = $latestModule.Version
                            })
                        Write-EnhancedModuleStarterLog -Message "Module $ModuleName is outdated. Installed: $($installedModule.Version), Latest: $($latestModule.Version)" -Level "INFO"
                    }
                    else {
                        $results.Add([PSCustomObject]@{
                                ModuleName       = $ModuleName
                                Status           = "Up-to-date"
                                InstalledVersion = $installedModule.Version
                                LatestVersion    = $installedModule.Version
                            })
                        Write-EnhancedModuleStarterLog -Message "Module $ModuleName is up-to-date. Version: $($installedModule.Version)" -Level "INFO"
                    }
                }
                elseif (-not $installedModule) {
                    $results.Add([PSCustomObject]@{
                            ModuleName       = $ModuleName
                            Status           = "Not Installed"
                            InstalledVersion = $null
                            LatestVersion    = $null
                        })
                    Write-EnhancedModuleStarterLog -Message "Module $ModuleName is not installed." -Level "INFO"
                }
                else {
                    $results.Add([PSCustomObject]@{
                            ModuleName       = $ModuleName
                            Status           = "Not Found in Gallery"
                            InstalledVersion = $installedModule.Version
                            LatestVersion    = $null
                        })
                    Write-EnhancedModuleStarterLog -Message "Module $ModuleName is installed but not found in the PowerShell Gallery." -Level "WARNING"
                }
            }
            catch {
                Write-EnhancedModuleStarterLog -Message "Error occurred while checking module '$ModuleName': $($_.Exception.Message)" -Level "ERROR"
                Handle-Error -ErrorRecord $_
                throw
            }
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Check-ModuleVersionStatus function" -Level "Notice"
        # Return the results
        return $results
    }
}

function Update-ModuleIfOldOrMissing {
    <#
    .SYNOPSIS
    Updates or installs a specified PowerShell module if it is outdated or missing.

    .DESCRIPTION
    The Update-ModuleIfOldOrMissing function checks the status of a specified PowerShell module and updates it if it is outdated. If the module is not installed, it installs the latest version. It also removes older versions after the update.

    .PARAMETER ModuleName
    The name of the module to be checked and updated or installed.

    .EXAMPLE
    Update-ModuleIfOldOrMissing -ModuleName "Pester"
    Checks and updates the Pester module if it is outdated or installs it if not present.

    .NOTES
    This function requires administrative access to manage modules and assumes that the CheckAndElevate, Check-ModuleVersionStatus, and Remove-OldVersions functions are defined elsewhere in the script.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    begin {
        Write-EnhancedModuleStarterLog -Message "Starting Update-ModuleIfOldOrMissing function for module: $ModuleName" -Level "Notice"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        Reset-ModulePaths

        # Ensure-NuGetProvider
    }

    process {
        $moduleStatus = Check-ModuleVersionStatus -ModuleNames @($ModuleName)
        foreach ($status in $moduleStatus) {
            switch ($status.Status) {
                "Outdated" {
                    Write-EnhancedModuleStarterLog -Message "Updating $ModuleName from version $($status.InstalledVersion) to $($status.LatestVersion)." -Level "WARNING"

                    # Remove older versions
                    Remove-OldVersions -ModuleName $ModuleName

                    # Install the latest version of the module
                    # Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Scope AllUsers

                    

                    # Invoke-InPowerShell5 -ScriptPath $PSScriptRoot
                    # Invoke-InPowerShell5

                    $params = @{
                        ModuleName = "$ModuleName"
                    }
                    Install-ModuleInPS5 @params

                    # Install-ModuleWithPowerShell5Fallback -ModuleName $ModuleName

                    Write-EnhancedModuleStarterLog -Message "$ModuleName has been updated to the latest version." -Level "INFO"
                }
                "Up-to-date" {
                    Write-EnhancedModuleStarterLog -Message "$ModuleName version $($status.InstalledVersion) is up-to-date. No update necessary." -Level "INFO"
                    Remove-OldVersions -ModuleName $ModuleName
                }
                "Not Installed" {
                    Write-EnhancedModuleStarterLog -Message "$ModuleName is not installed. Installing the latest version..." -Level "WARNING"
                    # Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Scope AllUsers

                    # $DBG


                    $params = @{
                        ModuleName = "$ModuleName"
                    }
                    Install-ModuleInPS5 @params

                    # Invoke-InPowerShell5
                    # Install-ModuleWithPowerShell5Fallback -ModuleName $ModuleName
                    Write-EnhancedModuleStarterLog -Message "$ModuleName has been installed." -Level "INFO"
                }
                "Not Found in Gallery" {
                    Write-EnhancedModuleStarterLog -Message "Unable to find '$ModuleName' in the PowerShell Gallery." -Level "ERROR"
                }
            }
        }
    }

    end {
        Write-EnhancedModuleStarterLog -Message "Update-ModuleIfOldOrMissing function execution completed for module: $ModuleName" -Level "Notice"
    }
}


#region HANDLE PSF MODERN LOGGING
#################################################################################################
#                                                                                               #
#                            HANDLE PSF MODERN LOGGING                                          #
#                                                                                               #
#################################################################################################
# Set-PSFConfig -Fullname 'PSFramework.Logging.FileSystem.ModernLog' -Value $true -PassThru | Register-PSFConfig -Scope SystemDefault

# Define the base logs path and job name
$JobName = "Install-EnhancedModuleStarterAO"
$parentScriptName = Get-ParentScriptName
Write-EnhancedModuleStarterLog -Message "Parent Script Name: $parentScriptName"

# Call the Get-PSFCSVLogFilePath function to generate the dynamic log file path
$GetPSFCSVLogFilePathParam = @{
    LogsPath         = 'C:\Logs\PSF'
    JobName          = $jobName
    parentScriptName = $parentScriptName
}

$csvLogFilePath = Get-PSFCSVLogFilePath @GetPSFCSVLogFilePathParam
Write-EnhancedModuleStarterLog -Message "Generated Log File Path: $csvLogFilePath"

#region HANDLE Transript LOGGING
#################################################################################################
#                                                                                               #
#                            HANDLE Transript LOGGING                                           #
#                                                                                               #
#################################################################################################
# Start the script with error handling
try {
    # Generate the transcript file path
    $GetTranscriptFilePathParams = @{
        TranscriptsPath  = "C:\Logs\Transcript"
        JobName          = $jobName
        parentScriptName = $parentScriptName
    }
    $transcriptPath = Get-TranscriptFilePath @GetTranscriptFilePathParams
    
    # Start the transcript
    Write-EnhancedModuleStarterLog -Message "Starting transcript at: $transcriptPath" -Level 'INFO'
    Start-Transcript -Path $transcriptPath
}
catch {
    Write-EnhancedModuleStarterLog -Message "An error occurred during script execution: $_" -Level 'ERROR'
    if ($transcriptPath) {
        Stop-Transcript
        Write-EnhancedModuleStarterLog "Transcript stopped." -Level 'WARNING'
        # Stop logging in the finally block

    }
    else {
        Write-EnhancedModuleStarterLog "Transcript was not started due to an earlier error." -Level 'ERROR'
    }

    # Stop PSF Logging

    # Ensure the log is written before proceeding
    # Wait-PSFMessage

    # Stop logging in the finally block by disabling the provider
    # Set-PSFLoggingProvider -Name 'logfile' -InstanceName $instanceName -Enabled $false

    Handle-Error -ErrorRecord $_
    throw $_  # Re-throw the error after logging it
} 
#endregion HANDLE Transript LOGGING

# $DBG

try {


    #region Script Logic
    #################################################################################################
    #                                                                                               #
    #                                    Script Logic                                               #
    #                                                                                               #
    #################################################################################################

    Ensure-NuGetProvider
    Remove-EnhancedModules
    Update-ModuleIfOldOrMissing -ModuleName 'PSFramework'
    Update-ModuleIfOldOrMissing -ModuleName 'EnhancedModuleStarterAO'

    #endregion
}
catch {
    Write-EnhancedModuleStarterLog -Message "An error occurred during script execution: $_" -Level 'ERROR'
    if ($transcriptPath) {
        Stop-Transcript
        Write-EnhancedModuleStarterLog "Transcript stopped." -Level 'WARNING'
        # Stop logging in the finally block
    }

    # Stop PSF Logging

    # Ensure the log is written before proceeding
    # Wait-PSFMessage

    # Stop logging in the finally block by disabling the provider
    # Set-PSFLoggingProvider -Name 'logfile' -InstanceName $instanceName -Enabled $false

    Handle-Error -ErrorRecord $_
    throw $_  # Re-throw the error after logging it
} 
finally {
    # Ensure that the transcript is stopped even if an error occurs
    if ($transcriptPath) {
        Stop-Transcript
        Write-EnhancedModuleStarterLog "Transcript stopped." -Level 'WARNING'
        # Stop logging in the finally block

    }
    else {
        Write-EnhancedModuleStarterLog "Transcript was not started due to an earlier error." -Level 'ERROR'
    }
    
    # Ensure the log is written before proceeding
    # Wait-PSFMessage

    # Stop logging in the finally block by disabling the provider
    # Set-PSFLoggingProvider -Name 'logfile' -InstanceName $instanceName -Enabled $false
    Write-EnhancedModuleStarterLog "Exiting Install-EnhancedModuleStarterAO.ps1..." -Level 'WARNING'
}