# Initialize the global steps list
$global:steps = [System.Collections.Generic.List[PSCustomObject]]::new()
$global:currentStep = 0
$processList = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$installationResults = [System.Collections.Generic.List[PSCustomObject]]::new()

# Define the GitHub URLs of the scripts and corresponding software names
$scriptDetails = @(
    @{ Url = "https://raw.githubusercontent.com/aollivierre/setuplab/main/Install-Git.ps1"; SoftwareName = "Git"; MinVersion = [version]"2.41.0.0" },
    @{ Url = "https://raw.githubusercontent.com/aollivierre/setuplab/main/Install-GitHubCLI.ps1"; SoftwareName = "GitHub CLI"; MinVersion = [version]"2.54.0" }

)


function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to add a step
function Add-Step {
    param (
        [string]$description
    )
    $global:steps.Add([PSCustomObject]@{ Description = $description })
}

# Function to log the current step
function Log-Step {
    $global:currentStep++
    $totalSteps = $global:steps.Count
    $stepDescription = $global:steps[$global:currentStep - 1].Description
    Write-Host "Step [$global:currentStep/$totalSteps]: $stepDescription" -ForegroundColor Cyan
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

# Function to validate URL
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

# Function to get PowerShell path
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


# Function to validate software installation via registry with retry mechanism
function Validate-Installation {
    param (
        [string]$SoftwareName,
        [version]$MinVersion = [version]"0.0.0.0",
        [string]$RegistryPath = "",
        [int]$MaxRetries = 3,
        [int]$DelayBetweenRetries = 5  # Delay in seconds
    )


    # if ($SoftwareName -eq "Windows Terminal") {
    #     return @{ IsInstalled = $false }  # Force the Windows Terminal script to always run as it will handle its own validation logic
    # }

    $retryCount = 0
    $validationSucceeded = $false

    while ($retryCount -lt $MaxRetries -and -not $validationSucceeded) {
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"  # Include HKCU for user-installed apps
        )

        if ($RegistryPath) {
            # If a specific registry path is provided, check only that path
            if (Test-Path $RegistryPath) {
                $app = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue
                if ($app -and $app.DisplayName -like "*$SoftwareName*") {
                    $installedVersion = [version]$app.DisplayVersion
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
            # If no specific registry path, check standard locations
            foreach ($path in $registryPaths) {
                $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $app = Get-ItemProperty -Path $item.PsPath -ErrorAction SilentlyContinue
                    if ($app.DisplayName -like "*$SoftwareName*") {
                        $installedVersion = [version]$app.DisplayVersion
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

        $retryCount++
        if (-not $validationSucceeded) {
            Write-Log "Validation attempt $retryCount failed: $SoftwareName not found or version does not meet minimum requirements. Retrying in $DelayBetweenRetries seconds..." -Level "WARNING"
            Start-Sleep -Seconds $DelayBetweenRetries
        }
    }

    return @{IsInstalled = $false }
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
                Write-Log -Message "Git found at: $path" -Level "INFO"
                return $path
            }
        }

        # If not found, check if Git is in the system PATH
        $gitPathInEnv = (Get-Command git -ErrorAction SilentlyContinue).Source
        if ($gitPathInEnv) {
            Write-Log -Message "Git found in system PATH: $gitPathInEnv" -Level "INFO"
            return $gitPathInEnv
        }

        # If Git is still not found, return $null
        Write-Log -Message "Git executable not found." -Level "ERROR"
        return $null
    }
    catch {
        Write-Log -Message "Error occurred while trying to find Git path: $_" -Level "ERROR"
        return $null
    }
}

function Clone-EnhancedRepos {
    <#
    .SYNOPSIS
    Clones all repositories from a GitHub account that start with the word "Enhanced" to a specified directory using GitHub CLI.

    .DESCRIPTION
    This function uses GitHub CLI to list and clone repositories from a GitHub account that start with "Enhanced" into the specified directory.

    .PARAMETER githubUsername
    The GitHub username to retrieve repositories from.

    .PARAMETER targetDirectory
    The directory to clone the repositories into.

    .EXAMPLE
    Clone-EnhancedRepos -githubUsername "aollivierre" -targetDirectory "C:\Code\modules-beta4"
    Clones all repositories starting with "Enhanced" from the specified GitHub account to the target directory.

    .NOTES
    This function requires GitHub CLI (gh) and git to be installed and available in the system's PATH.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$githubUsername,

        [Parameter(Mandatory = $true)]
        [string]$targetDirectory
    )

    begin {
        Write-Log -Message "Starting Clone-EnhancedRepos function" -Level "Notice"

        # Create the target directory if it doesn't exist
        if (-not (Test-Path -Path $targetDirectory)) {
            Write-Log -Message "Creating target directory: $targetDirectory" -Level "INFO"
            New-Item -Path $targetDirectory -ItemType Directory
        }
    }

    process {
     
   
        


        try {
            # Get the Git executable path
            Write-Log -Message "Attempting to find Git executable path..." -Level "INFO"
            $gitPath = Get-GitPath
            if (-not $gitPath) {
                throw "Git executable not found. Please install Git or ensure it is in your PATH."
            }
            Write-Log -Message "Git found at: $gitPath" -Level "INFO"
        
            # Set the GitHub CLI path
            $ghPath = "C:\Program Files\GitHub CLI\gh.exe"
            
            # Define arguments for GitHub CLI as an array
            $ghArguments = @("repo", "list", "aollivierre", "--json", "name,url")
        
            # Execute the GitHub CLI command using the argument array
            Write-Log -Message "Retrieving repositories for user $githubUsername using GitHub CLI..." -Level "INFO"
            $reposJson = & $ghPath $ghArguments
            Write-Log -Message "Raw GitHub CLI output: $reposJson" -Level "DEBUG"
            
            if (-not $reposJson) {
                throw "No repositories found or an error occurred while retrieving repositories."
            }
        
            $repos = $reposJson | ConvertFrom-Json
            Write-Log -Message "Converted JSON output: $repos" -Level "DEBUG"
        
            $filteredRepos = $repos | Where-Object { $_.name -like "Enhanced*" }
            if ($filteredRepos.Count -eq 0) {
                Write-Log -Message "No repositories found that match 'Enhanced*'." -Level "WARNING"
            }
            Write-Log -Message "Filtered repositories count: $($filteredRepos.Count)" -Level "INFO"
            
            # Clone each repository using the full path to Git
            foreach ($repo in $filteredRepos) {
                $repoName = $repo.name
                $repoCloneUrl = $repo.url
                $repoTargetPath = Join-Path -Path $targetDirectory -ChildPath $repoName
        
                # Define arguments for Git as an array
                $gitArguments = @("clone", $repoCloneUrl, $repoTargetPath)
        
                Write-Log -Message "Cloning repository $repoName to $repoTargetPath..." -Level "INFO"
                & $gitPath $gitArguments
                if ($LASTEXITCODE -ne 0) {
                    throw "Failed to clone repository $repoName. Git returned exit code $LASTEXITCODE."
                }
                Write-Log -Message "Successfully cloned repository $repoName." -Level "INFO"
            }
        
            Write-Log -Message "Cloning process completed." -Level "INFO"
        }
        catch {
            Write-Log -Message "Error during cloning process: $_" -Level "ERROR"
            throw $_
        }
        
        
        

    }

    end {
        Write-Log -Message "Clone-EnhancedRepos function execution completed." -Level "Notice"
    }
}



# Add steps for each script
foreach ($detail in $scriptDetails) {
    Add-Step ("Running script from URL: $($detail.Url)")
}

# Main script execution with try-catch for error handling
try {

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
    

    $powerShellPath = Get-PowerShellPath

    foreach ($detail in $scriptDetails) {
        $url = $detail.Url
        $softwareName = $detail.SoftwareName
        $minVersion = $detail.MinVersion
        $registryPath = $detail.RegistryPath  # Directly extract RegistryPath

        # Validate before running the installation script
        Write-Log "Validating existing installation of $softwareName..."

        # Pass RegistryPath if it's available
        $installationCheck = if ($registryPath) {
            Validate-Installation -SoftwareName $softwareName -MinVersion $minVersion -MaxRetries 3 -DelayBetweenRetries 5 -RegistryPath $registryPath
        }
        else {
            Validate-Installation -SoftwareName $softwareName -MinVersion $minVersion -MaxRetries 3 -DelayBetweenRetries 5
        }

        if ($installationCheck.IsInstalled) {
            Write-Log "$softwareName version $($installationCheck.Version) is already installed. Skipping installation." -Level "INFO"
            $installationResults.Add([pscustomobject]@{ SoftwareName = $softwareName; Status = "Already Installed"; VersionFound = $installationCheck.Version })
        }
        else {
            if (Test-Url -url $url) {
                Log-Step
                Write-Log "Running script from URL: $url" -Level "INFO"
                $process = Start-Process -FilePath $powerShellPath -ArgumentList @("-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Invoke-Expression (Invoke-RestMethod -Uri '$url')") -Verb RunAs -PassThru
                $processList.Add($process)

                $installationResults.Add([pscustomobject]@{ SoftwareName = $softwareName; Status = "Installed"; VersionFound = "N/A" })
            }
            else {
                Write-Log "URL $url is not accessible" -Level "ERROR"
                $installationResults.Add([pscustomobject]@{ SoftwareName = $softwareName; Status = "Failed - URL Not Accessible"; VersionFound = "N/A" })
            }
        }
    }

    # Wait for all processes to complete
    foreach ($process in $processList) {
        $process.WaitForExit()
    }

    # Post-installation validation
    foreach ($result in $installationResults) {
        if ($result.Status -eq "Installed") {
            if ($result.SoftwareName -in @("RDP", "Windows Terminal")) {
                Write-Log "Skipping post-installation validation for $($result.SoftwareName)." -Level "INFO"
                $result.Status = "Successfully Installed"
                continue
            }

            Write-Log "Validating installation of $($result.SoftwareName)..."
            $validationResult = Validate-Installation -SoftwareName $result.SoftwareName -MinVersion ($scriptDetails | Where-Object { $_.SoftwareName -eq $result.SoftwareName }).MinVersion

            if ($validationResult.IsInstalled) {
                Write-Log "Validation successful: $($result.SoftwareName) version $($validationResult.Version) is installed." -Level "INFO"
                $result.VersionFound = $validationResult.Version
                $result.Status = "Successfully Installed"
            }
            else {
                Write-Log "Validation failed: $($result.SoftwareName) was not found on the system." -Level "ERROR"
                $result.Status = "Failed - Not Found After Installation"
            }
        }
    }


    # Summary report
    $totalSoftware = $installationResults.Count
    $successfulInstallations = $installationResults | Where-Object { $_.Status -eq "Successfully Installed" }
    $alreadyInstalled = $installationResults | Where-Object { $_.Status -eq "Already Installed" }
    $failedInstallations = $installationResults | Where-Object { $_.Status -like "Failed*" }

    Write-Host "Total Software: $totalSoftware" -ForegroundColor Cyan
    Write-Host "Successful Installations: $($successfulInstallations.Count)" -ForegroundColor Green
    Write-Host "Already Installed: $($alreadyInstalled.Count)" -ForegroundColor Yellow
    Write-Host "Failed Installations: $($failedInstallations.Count)" -ForegroundColor Red

    # Detailed Summary
    Write-Host "`nDetailed Summary:" -ForegroundColor Cyan
    $installationResults | ForEach-Object {
        Write-Host "Software: $($_.SoftwareName)" -ForegroundColor White
        Write-Host "Status: $($_.Status)" -ForegroundColor White
        Write-Host "Version Found: $($_.VersionFound)" -ForegroundColor White
        Write-Host "----------------------------------------" -ForegroundColor Gray
    }

    # Example invocation to clone repositories:
    Clone-EnhancedRepos -githubUsername "aollivierre" -targetDirectory "C:\Code\modulesv2-beta10"

}
catch {
    # Capture the error details
    $errorDetails = $_ | Out-String
    Write-Log "An error occurred: $errorDetails" -Level "ERROR"
    throw
}

# Keep the PowerShell window open to review the logs
Read-Host 'Press Enter to close this window...'