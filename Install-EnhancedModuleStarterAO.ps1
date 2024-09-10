function Is-RunningInPS5 {
    return ($PSVersionTable.PSVersion.Major -eq 5)
}

function Reset-ModulePaths {
    [CmdletBinding()]
    param ()

    begin {
        # Initialization block, typically used for setup tasks
        Write-EnhancedModuleStarterLog "Initializing Reset-ModulePaths function..." -Level "DEBUG"
    }

    process {
        try {
            # Log the start of the process
            Write-EnhancedModuleStarterLog "Resetting module paths to default values..." -Level "INFO"

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
            Write-EnhancedModuleStarterLog "PSModulePath environment variable set for the current user." -Level "INFO"
        }
        catch {
            # Capture and log any errors that occur during the process
            $errorMessage = $_.Exception.Message
            Write-EnhancedModuleStarterLog "Error resetting module paths: $errorMessage" -Level "ERROR"

            # Optionally, you could throw the error to halt the script
            throw $_
        }
    }

    end {
        # Finalization block, typically used for cleanup tasks
        Write-EnhancedModuleStarterLog "Reset-ModulePaths function completed." -Level "DEBUG"
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

function Install-EnhancedModuleStarterAO {
    <#
    .SYNOPSIS
    Installs the 'enhancedmodulestarterAO' module if it's not already installed, ensuring it's done in PowerShell 5 with 'AllUsers' scope and force.

    .DESCRIPTION
    This function checks if the 'enhancedmodulestarterAO' module is installed. If not, it ensures the system is running PowerShell 5 to install it with the 'AllUsers' scope and force. If not in PowerShell 5, it launches a new PS5 session to install and import the module.

    .EXAMPLE
    Install-EnhancedModuleStarterAO
    Installs the module 'enhancedmodulestarterAO' if not installed and ensures it's running in PowerShell 5.
    #>

    [CmdletBinding()]
    param ()

    # Helper function to detect PowerShell version
   

    Begin {

        Write-EnhancedModuleStarterLog -Message "Starting Install-EnhancedModuleStarterAO function" -Level "Notice"


        Reset-ModulePaths

        # Check if the module is already installed
        $module = Get-Module -ListAvailable -Name "enhancedmodulestarterAO"
        if ($module) {
            Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' is already installed." -Level "INFO"
            return
        }
        Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' is not installed." -Level "INFO"
    }

    Process {
        # Check if running in PowerShell 5
        if (-not (Is-RunningInPS5)) {
            Write-EnhancedModuleStarterLog -Message "Not running in PowerShell 5, launching PS5 to install module." -Level "INFO"

            # Get the path to PowerShell 5
            $PS5Path = "${env:SystemRoot}\System32\WindowsPowerShell\v1.0\powershell.exe"

            # Define the arguments for the Start-Process
            $arguments = @(
                '-NoExit'
                '-NoProfile'
                '-ExecutionPolicy'
                'Bypass'
                '-Command'
                'Install-Module -Name ''enhancedmodulestarterAO'' -Scope AllUsers -Force; Import-Module ''enhancedmodulestarterAO''; Write-Host ''Module installed and imported in PS5'''
            )

            # Launch a new PowerShell 5 process to install the module
            Start-Process -FilePath $PS5Path -ArgumentList $arguments -Verb RunAs -Wait
            return
        }

        # Install and import the module in PowerShell 5
        try {
            Write-EnhancedModuleStarterLog -Message "Running in PowerShell 5, installing module." -Level "INFO"
            Install-Module -Name "enhancedmodulestarterAO" -Scope AllUsers -Force

            # Import the module after installation
            Import-Module "enhancedmodulestarterAO"
            Write-EnhancedModuleStarterLog -Message "Module 'enhancedmodulestarterAO' installed and imported." -Level "INFO"
        }
        catch {
            Write-EnhancedModuleStarterLog -Message "Error installing or importing module: $($_.Exception.Message)" -Level "ERROR"
            # Handle-Error -ErrorRecord $_
            throw
        }
    }

    End {
        Write-EnhancedModuleStarterLog -Message "Exiting Install-EnhancedModuleStarterAO function" -Level "Notice"
    }
}

# Example usage
Install-EnhancedModuleStarterAO