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


# Function to save existing modules to a backup location using Save-Module
function Save-ExistingModules {
    param (
        [string]$ModuleName,
        [string]$BackupPath
    )

    Write-Log "Saving all versions of $ModuleName to $BackupPath using Save-Module..." -Level "INFO"
    $modules = Get-Module -ListAvailable -Name $ModuleName
    foreach ($module in $modules) {
        $destination = Join-Path -Path $BackupPath -ChildPath "$($module.Name)_$($module.Version)"
        if (-not (Test-Path -Path $destination)) {
            Write-Log "Saving $($module.Name) version $($module.Version) to $destination" -Level "INFO"
            Save-Module -Name $module.Name -Path $destination -Force
        }
    }
}

# Function to remove existing modules
function Remove-ExistingModules {
    param (
        [string]$ModuleName
    )

    Write-Log "Removing all versions of $ModuleName..." -Level "INFO"
    Get-Module -ListAvailable -Name $ModuleName | ForEach-Object {
        Write-Log "Removing $($_.Name) version $($_.Version) from $($_.ModuleBase)" -Level "INFO"
        Remove-Item -Recurse -Force -Path $_.ModuleBase -ErrorAction SilentlyContinue
    }
}

# Function to reinstall PowerShellGet and PackageManagement
function Reinstall-PowerShellModules {
    param (
        [string]$PowerShellPath,
        [string]$BackupPath
    )

    try {
        Write-Log "Reinstalling PowerShellGet and PackageManagement in $PowerShellPath..." -Level "INFO"

        # Save existing modules before removal
        Save-ExistingModules -ModuleName "PowerShellGet" -BackupPath $BackupPath
        Save-ExistingModules -ModuleName "PackageManagement" -BackupPath $BackupPath

        # Remove existing modules
        Remove-ExistingModules -ModuleName "PowerShellGet"
        Remove-ExistingModules -ModuleName "PackageManagement"

        # Install NuGet provider manually
        Write-Log "Installing NuGet provider..." -Level "INFO"
        & "$PowerShellPath\powershell.exe" -NoProfile -Command {
            Install-PackageProvider -Name NuGet -Force -MinimumVersion 2.8.5.201 -Confirm:$false
        }

        # Install PowerShellGet and PackageManagement modules
        Write-Log "Installing PowerShellGet and PackageManagement..." -Level "INFO"
        & "$PowerShellPath\powershell.exe" -NoProfile -Command {
            Install-Module -Name PowerShellGet -Force -AllowClobber
            Install-Module -Name PackageManagement -Force -AllowClobber
        }

        Write-Log "Reinstallation completed successfully." -Level "INFO"
    }
    catch {
        Write-Log "Error occurred during reinstallation: $_" -Level "ERROR"
        Write-Log "Restoring backup of modules from $BackupPath using Import-Module..." -Level "NOTICE"
        Import-Module -Name "$BackupPath\PowerShellGet_*" -Force
        Import-Module -Name "$BackupPath\PackageManagement_*" -Force
        Write-Log "Backup restored." -Level "INFO"
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
}
else {
    Write-Log ".NET Framework 4.5 or higher detected." -Level "INFO"
}

# Backup path for existing modules
$BackupPath = "C:\Temp\PowerShellModuleBackup"
if (-not (Test-Path -Path $BackupPath)) {
    New-Item -ItemType Directory -Path $BackupPath | Out-Null
}

# Reinstall modules for both x86 and x64 architectures
Reinstall-PowerShellModules -PowerShellPath "$env:SystemRoot\SysWow64\WindowsPowerShell\v1.0" -BackupPath $BackupPath
Reinstall-PowerShellModules -PowerShellPath "$env:SystemRoot\System32\WindowsPowerShell\v1.0" -BackupPath $BackupPath

Write-Log "Please restart your PowerShell session to ensure the new module versions are loaded." -Level "NOTICE"