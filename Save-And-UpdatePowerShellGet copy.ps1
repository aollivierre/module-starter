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

# Function to update PowerShellGet and PackageManagement in a specific architecture
function Update-ModulesForArchitecture {
    param (
        [string]$Architecture,
        [string]$PowerShellPath
    )

    Write-Log "Processing PowerShell $Architecture at $PowerShellPath" -Level "INFO"

    try {
        Write-Log "Ensuring NuGet provider is installed for PowerShell $Architecture..." -Level "INFO"
        & "$PowerShellPath\powershell.exe" -NoProfile -Command {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Confirm:$false
            }
        }

        Write-Log "Installing or updating PowerShellGet and PackageManagement for PowerShell $Architecture..." -Level "INFO"
        & "$PowerShellPath\powershell.exe" -NoProfile -Command {
            Install-Module -Name PowerShellGet -Force -AllowClobber
            Install-Module -Name PackageManagement -Force -AllowClobber
        }

        Write-Log "Registering PSGallery as a trusted repository for PowerShell $Architecture..." -Level "INFO"
        & "$PowerShellPath\powershell.exe" -NoProfile -Command {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
        }
    }
    catch {
        Write-Log "Error occurred while processing PowerShell $Architecture $_" -Level "ERROR"
    }
}

# Check if we need to fallback to PowerShell 5
Invoke-InPowerShell5 -ScriptPath $PSCommandPath

# Ensure TLS 1.2 is enabled
Write-Log "Enabling TLS 1.2 for secure connection..." -Level "INFO"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Ensure .NET Framework 4.5 or above is installed
$dotNetVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if ($dotNetVersion -lt 378389) {
    Write-Log "Error: .NET Framework 4.5 or higher is required. Please install the latest version." -Level "ERROR"
    Exit
} else {
    Write-Log ".NET Framework 4.5 or higher detected." -Level "INFO"
}

# Update modules for both x86 and x64 architectures
Update-ModulesForArchitecture -Architecture "x86" -PowerShellPath "$env:SystemRoot\SysWow64\WindowsPowerShell\v1.0"
Update-ModulesForArchitecture -Architecture "x64" -PowerShellPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0"

Write-Log "Please restart your PowerShell session to ensure the new module versions are loaded." -Level "NOTICE"
