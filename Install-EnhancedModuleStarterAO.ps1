function Is-RunningInPS5 {
    return ($PSVersionTable.PSVersion.Major -eq 5)
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

function Reset-ModulePaths {
    [CmdletBinding()]
    param ()

    begin {
        # Initialization block, typically used for setup tasks
        Write-EnhancedModuleStarterLog -Message "Initializing Reset-ModulePaths function..." -Level "DEBUG"
    }

    process {
        try {
            # Log the start of the process
            Write-EnhancedModuleStarterLog -Message "Resetting module paths to default values..." -Level "INFO"

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
            Write-EnhancedModuleStarterLog "PSModulePath successfully set to: $($env:PSModulePath -split ';' | Out-String)" -Level "INFO"

            # Optionally persist the change for the current user
            [Environment]::SetEnvironmentVariable("PSModulePath", $env:PSModulePath, [EnvironmentVariableTarget]::User)
            Write-EnhancedModuleStarterLog -Message "PSModulePath environment variable set for the current user." -Level "INFO"
        }
        catch {
            # Capture and log any errors that occur during the process
            $errorMessage = $_.Exception.Message
            Write-EnhancedModuleStarterLog -Message "Error resetting module paths: $errorMessage" -Level "ERROR"

            # Optionally, you could throw the error to halt the script
            throw $_
        }
    }

    end {
        # Finalization block, typically used for cleanup tasks
        Write-EnhancedModuleStarterLog -Message "Reset-ModulePaths function completed." -Level "DEBUG"
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
        } else {
            $fullErrorDetails = $ErrorRecord.Exception | Format-List * -Force | Out-String
        }

        Write-EnhancedModuleStarterLog -Message "Exception Message: $($ErrorRecord.Exception.Message)" -Level "ERROR"
        Write-EnhancedModuleStarterLog -Message "Full Exception: $fullErrorDetails" -Level "ERROR"
    } catch {
        # Fallback error handling in case of an unexpected error in the try block
        Write-EnhancedModuleStarterLog -Message "An error occurred while handling another error. Original Exception: $($ErrorRecord.Exception.Message)" -Level "CRITICAL"
        Write-EnhancedModuleStarterLog -Message "Handler Exception: $($_.Exception.Message)" -Level "CRITICAL"
        Write-EnhancedModuleStarterLog -Message "Handler Full Exception: $($_ | Out-String)" -Level "CRITICAL"
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
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        # Get all versions except the latest one
        $allVersions = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version
        $latestVersion = $allVersions | Select-Object -Last 1
        $olderVersions = $allVersions | Where-Object { $_.Version -ne $latestVersion.Version }

        foreach ($version in $olderVersions) {
            try {
                Write-EnhancedModuleStarterLog -Message "Removing older version $($version.Version) of $ModuleName..." -Level "INFO"
                $modulePath = $version.ModuleBase

                Write-EnhancedModuleStarterLog -Message "Starting takeown and icacls for $modulePath" -Level "INFO"
                Write-EnhancedModuleStarterLog -Message "Checking and elevating to admin if needed" -Level "INFO"
                CheckAndElevate
                & takeown.exe /F $modulePath /A /R
                & icacls.exe $modulePath /reset
                & icacls.exe $modulePath /grant "*S-1-5-32-544:F" /inheritance:d /T
                Remove-Item -Path $modulePath -Recurse -Force -Confirm:$false

                Write-EnhancedModuleStarterLog -Message "Removed $($version.Version) successfully." -Level "INFO"
            } catch {
                Write-EnhancedModuleStarterLog -Message "Failed to remove version $($version.Version) of $ModuleName at $modulePath. Error: $_" -Level "ERROR"
                Handle-Error -ErrorRecord $_
            }
        }
    }

    end {
        Write-EnhancedModuleStarterLog -Message "Remove-OldVersions function execution completed for module: $ModuleName" -Level "INFO"
    }
}

function Invoke-InPowerShell5 {
    param (
        [string]$ScriptPath
    )

    if ($PSVersionTable.PSVersion.Major -ne 5) {
        Write-EnhancedModuleStarterLog -Message "Relaunching script in PowerShell 5 (x64)..." -Level "WARNING"

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

        Write-EnhancedModuleStarterLog -Message "Starting PowerShell 5 (x64) to perform the update..." -Level "NOTICE"
        $process64 = Start-Process @startProcessParams64
        $process64.WaitForExit()

        Write-EnhancedModuleStarterLog -Message "PowerShell 5 (x64) process completed." -Level "NOTICE"
        Exit
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
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
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

                    Reset-ModulePaths

                    Invoke-InPowerShell5 -ScriptPath $PSScriptRoot

                    Install-ModuleWithPowerShell5Fallback -ModuleName $ModuleName

                    Write-EnhancedModuleStarterLog -Message "$ModuleName has been updated to the latest version." -Level "INFO"
                }
                "Up-to-date" {
                    Write-EnhancedModuleStarterLog -Message "$ModuleName version $($status.InstalledVersion) is up-to-date. No update necessary." -Level "INFO"
                    Remove-OldVersions -ModuleName $ModuleName
                }
                "Not Installed" {
                    Write-EnhancedModuleStarterLog -Message "$ModuleName is not installed. Installing the latest version..." -Level "WARNING"
                    # Install-Module -Name $ModuleName -Force -SkipPublisherCheck -Scope AllUsers

                    $DBG
                    Install-ModuleWithPowerShell5Fallback -ModuleName $ModuleName
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


Update-ModuleIfOldOrMissing -ModuleName 'PSFramework'
Update-ModuleIfOldOrMissing -ModuleName 'EnhancedModuleStarterAO'

# function Install-EnhancedModuleStarterAO {
#     <#
#     .SYNOPSIS
#     Installs the 'enhancedmodulestarterAO' module if it's not already installed, ensuring it's done in PowerShell 5 with 'AllUsers' scope and force.

#     .DESCRIPTION
#     This function checks if the 'enhancedmodulestarterAO' module is installed. If not, it ensures the system is running PowerShell 5 to install it with the 'AllUsers' scope and force. If not in PowerShell 5, it launches a new PS5 session to install and import the module.

#     .EXAMPLE
#     Install-EnhancedModuleStarterAO
#     Installs the module 'enhancedmodulestarterAO' if not installed and ensures it's running in PowerShell 5.
#     #>

#     [CmdletBinding()]
#     param ()

#     # Helper function to detect PowerShell version
   

#     Begin {

#         Write-EnhancedModuleStarterLog -Message "Starting Install-EnhancedModuleStarterAO function" -Level "Notice"


#         Reset-ModulePaths

#         # Check if the module is already installed
#         $module = Get-Module -ListAvailable -Name "enhancedmodulestarterAO"
#         if ($module) {
#             Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' is already installed." -Level "INFO"
#             return
#         }
#         Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' is not installed." -Level "INFO"
#     }

#     Process {
#         # Check if running in PowerShell 5
#         if (-not (Is-RunningInPS5)) {
#             Write-EnhancedModuleStarterLog -Message "Not running in PowerShell 5, launching PS5 to install module." -Level "INFO"

#             # Get the path to PowerShell 5
#             $PS5Path = "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe"

#             # Define the arguments for the Start-Process
#             $arguments = @(
#                 # '-NoExit'
#                 '-NoProfile'
#                 '-ExecutionPolicy'
#                 'Bypass'
#                 '-Command'
#                 'Install-Module -Name ''enhancedmodulestarterAO'' -Scope AllUsers -Force; Import-Module ''enhancedmodulestarterAO''; Write-Host ''Module installed and imported in PS5'''
#             )

#             # Launch a new PowerShell 5 process to install the module
#             Start-Process -FilePath $PS5Path -ArgumentList $arguments -Verb RunAs -Wait
#             return
#         }

#         # Install and import the module in PowerShell 5
#         try {
#             Write-EnhancedModuleStarterLog -Message "Running in PowerShell 5, installing module." -Level "INFO"
#             Install-Module -Name "enhancedmodulestarterAO" -Scope AllUsers -Force

#             # Import the module after installation
#             Import-Module "enhancedmodulestarterAO"
#             Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' installed and imported." -Level "INFO"
#         }
#         catch {
#             Write-EnhancedModuleStarterLog -Message "Error installing or importing module: $($_.Exception.Message)" -Level "ERROR"
#             # Handle-Error -ErrorRecord $_
#             throw
#         }
#     }

#     End {
#         Write-EnhancedModuleStarterLog -Message "Exiting Install-EnhancedModuleStarterAO function" -Level "Notice"
#     }
# }

# # Example usage
# Install-EnhancedModuleStarterAO