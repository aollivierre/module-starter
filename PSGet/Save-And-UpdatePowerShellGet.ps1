# Logging function
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message"
}

# Function to relaunch the script in PowerShell 5 if not already running in PS5
function Invoke-InPowerShell5 {
    param (
        [string]$ScriptPath
    )

    if ($PSVersionTable.PSVersion.Major -ne 5) {
        Write-Log "Relaunching script in PowerShell 5..." -Level "WARNING"

        # Get the path to PowerShell 5 (both x86 and x64)
        $ps5x64Path = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $ps5x86Path = "$env:SystemRoot\SysWow64\WindowsPowerShell\v1.0\powershell.exe"

        # Launch in both x86 and x64 PowerShell 5
        $startProcessParams64 = @{
            FilePath     = $ps5x64Path
            ArgumentList = @(
                "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $ScriptPath
            )
            Verb         = "RunAs"
            PassThru     = $true
        }

        $startProcessParams86 = @{
            FilePath     = $ps5x86Path
            ArgumentList = @(
                "-NoExit",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", $ScriptPath
            )
            Verb         = "RunAs"
            PassThru     = $true
        }

        Write-Log "Starting PowerShell 5 (x64) to perform the update..." -Level "NOTICE"
        $process64 = Start-Process @startProcessParams64
        $process64.WaitForExit()

        Write-Log "Starting PowerShell 5 (x86) to perform the update..." -Level "NOTICE"
        $process86 = Start-Process @startProcessParams86
        $process86.WaitForExit()

        Write-Log "PowerShell 5 process completed." -Level "NOTICE"
        Exit
    }
}

# Function to update PowerShellGet and PackageManagement
function Save-And-UpdatePowerShellGet {
    param (
        [string]$ModuleName = "PowerShellGet",
        [string]$TempPath = "C:\Temp\PowerShellGet",
        [string]$DestinationPath = "C:\Program Files\WindowsPowerShell\Modules"
    )

    # Ensure TLS 1.2 is enabled
    Write-Log "Enabling TLS 1.2 for secure connection..." -Level "INFO"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # Ensure .NET Framework 4.5 or above is installed
    $dotNetVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
    if ($dotNetVersion -lt 378389) {
        Write-Log "Error: .NET Framework 4.5 or higher is required. Please install the latest version." -Level "ERROR"
        return
    } else {
        Write-Log ".NET Framework 4.5 or higher detected." -Level "INFO"
    }

    try {
        # Update for both x86 and x64
        foreach ($arch in @("x86", "x64")) {
            $archPath = if ($arch -eq "x64") {
                "$env:SystemRoot\System32\WindowsPowerShell\v1.0"
            } else {
                "$env:SystemRoot\SysWow64\WindowsPowerShell\v1.0"
            }

            Write-Log "Processing PowerShell $arch at $archPath" -Level "INFO"

            # Ensure PackageManagement is available
            Write-Log "Importing PackageManagement module for PowerShell $arch..." -Level "INFO"
            & "$archPath\powershell.exe" -NoProfile -Command "Import-Module PackageManagement -Force -ErrorAction Stop"

            # Check if the NuGet provider is already installed
            $nugetInstalled = & "$archPath\powershell.exe" -NoProfile -Command {
                Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue
            }

            if (-not $nugetInstalled) {
                Write-Log "NuGet provider not found in PowerShell $arch. Installing NuGet provider..." -Level "NOTICE"
                & "$archPath\powershell.exe" -NoProfile -Command {
                    Install-PackageProvider -Name NuGet -Force -Confirm:$false
                }
                Write-Log "NuGet provider installed successfully in PowerShell $arch." -Level "INFO"
            } else {
                Write-Log "NuGet provider is already installed in PowerShell $arch." -Level "INFO"
            }

            # Check current versions of PowerShellGet and PackageManagement
            $installedModules = & "$archPath\powershell.exe" -NoProfile -Command {
                Get-Module PowerShellGet, PackageManagement -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
            }
            $powerShellGetVersion = ($installedModules | Where-Object { $_.Name -eq "PowerShellGet" }).Version
            $packageManagementVersion = ($installedModules | Where-Object { $_.Name -eq "PackageManagement" }).Version

            Write-Log "Installed PowerShellGet version in PowerShell $arch $powerShellGetVersion" -Level "INFO"
            Write-Log "Installed PackageManagement version in PowerShell $arch $packageManagementVersion" -Level "INFO"

            # Update PowerShellGet and PackageManagement if necessary
            if ($powerShellGetVersion -lt [version]"2.2.5" -or $packageManagementVersion -lt [version]"1.4.8.1") {
                Write-Log "Updating PowerShellGet and PackageManagement to the latest versions in PowerShell $arch..." -Level "NOTICE"
                & "$archPath\powershell.exe" -NoProfile -Command {
                    Install-Module -Name PowerShellGet -Force -AllowClobber
                }
                Write-Log "PowerShellGet updated successfully in PowerShell $arch." -Level "INFO"
            } else {
                Write-Log "PowerShellGet and PackageManagement are already up to date in PowerShell $arch." -Level "INFO"
            }

            # Register PSGallery as a trusted repository
            Write-Log "Registering PSGallery as a trusted repository in PowerShell $arch..." -Level "INFO"
            & "$archPath\powershell.exe" -NoProfile -Command {
                Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            }
            Write-Log "PSGallery is now a trusted repository in PowerShell $arch." -Level "INFO"
        }

        Write-Log "Please restart your PowerShell session to ensure the new module versions are loaded." -Level "NOTICE"
    }
    catch {
        Write-Log "Failed to update module $ModuleName. Error: $_" -Level "ERROR"
    }
}

# Check if we need to fallback to PowerShell 5
Invoke-InPowerShell5 -ScriptPath $PSCommandPath

# Run the function to ensure PowerShellGet is updated for both architectures
Save-And-UpdatePowerShellGet
