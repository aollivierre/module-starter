function Get-LatestGitHubCLIInstallerUrl {
    <#
    .SYNOPSIS
    Gets the latest GitHub CLI Windows amd64 installer URL.

    .DESCRIPTION
    This function retrieves the URL for the latest GitHub CLI Windows amd64 installer from the GitHub releases page.

    .PARAMETER releasesUrl
    The URL for the GitHub CLI releases page.

    .EXAMPLE
    Get-LatestGitHubCLIInstallerUrl -releasesUrl "https://api.github.com/repos/cli/cli/releases/latest"
    Retrieves the latest GitHub CLI Windows amd64 installer URL.

    .NOTES
    This function requires an internet connection to access the GitHub API.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$releasesUrl
    )

    begin {
        Write-Host -Message "Starting Get-LatestGitHubCLIInstallerUrl function" -Level "Notice"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        try {
            $headers = @{
                "User-Agent" = "Mozilla/5.0"
            }

            $response = Invoke-RestMethod -Uri $releasesUrl -Headers $headers

            foreach ($asset in $response.assets) {
                if ($asset.name -match "windows_amd64.msi") {
                    return $asset.browser_download_url
                }
            }

            throw "Windows amd64 installer not found."
        } catch {
            Write-Host -Message "Error retrieving installer URL: $_" -Level "ERROR"
            # Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        Write-Host -Message "Get-LatestGitHubCLIInstallerUrl function execution completed." -Level "Notice"
    }
}

function Install-GitHubCLI {
    <#
    .SYNOPSIS
    Installs the GitHub CLI on Windows.

    .DESCRIPTION
    This function downloads the latest GitHub CLI Windows amd64 installer and installs it silently. It also verifies the installation in a new PowerShell session.

    .PARAMETER releasesUrl
    The URL for the GitHub CLI releases page.

    .PARAMETER installerPath
    The local path to save the installer.

    .EXAMPLE
    Install-GitHubCLI -releasesUrl "https://api.github.com/repos/cli/cli/releases/latest" -installerPath "$env:TEMP\gh_cli_installer.msi"
    Downloads and installs the latest GitHub CLI.

    .NOTES
    This function requires administrative privileges to run the installer.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$releasesUrl,
        [Parameter(Mandatory = $true)]
        [string]$installerPath
    )

    begin {
        Write-Host -Message "Starting Install-GitHubCLI function" -Level "Notice"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters
    }

    process {
        try {
            # Get the latest installer URL
            $installerUrl = Get-LatestGitHubCLIInstallerUrl -releasesUrl $releasesUrl

            # Download the installer
            Write-Host -Message "Downloading GitHub CLI installer from $installerUrl..." -Level "INFO"
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

            # Install the GitHub CLI
            Write-Host -Message "Running the GitHub CLI installer..." -Level "INFO"
            $msiArgs = @(
                "/i"
                $installerPath
                "/quiet"
                "/norestart"
            )
            Start-Process msiexec.exe -ArgumentList $msiArgs -NoNewWindow -Wait

            # Verify the installation in a new PowerShell session
            Write-Host -Message "Verifying the GitHub CLI installation in a new PowerShell session..." -Level "INFO"
            $verifyScript = {
                try {
                    $version = gh --version
                    if ($version) {
                        $verificationResult = "GitHub CLI installed successfully. Version: $version"
                    } else {
                        $verificationResult = "GitHub CLI installation failed."
                    }
                } catch {
                    $verificationResult = "Error verifying GitHub CLI installation: $_"
                }
                return $verificationResult
            }
            $verificationResult = powershell -Command $verifyScript
            Write-Host -Message $verificationResult -Level "INFO"
        } catch {
            Write-Host -Message "Error during GitHub CLI installation: $_" -Level "ERROR"
            # Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        Write-Host -Message "Install-GitHubCLI function execution completed." -Level "Notice"
    }
}




# Define the URL for the GitHub CLI releases page
$githubCLIReleasesUrl = "https://api.github.com/repos/cli/cli/releases/latest"

# Define the local path to save the installer
$installerPath = "$env:TEMP\gh_cli_installer.msi"

# Example invocation to install GitHub CLI:
Install-GitHubCLI -releasesUrl $githubCLIReleasesUrl -installerPath $installerPath




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
    Clone-EnhancedRepos -githubUsername "aollivierre" -targetDirectory "C:\Code\modules-beta3"
    Clones all repositories starting with "Enhanced" from the specified GitHub account to the target directory.

    .NOTES
    This function requires GitHub CLI (gh) and git to be installed and available in the system's PATH.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$githubUsername,

        [Parameter(Mandatory = $true)]
        [string]$targetDirectory = "C:\Code\modules-beta3"
    )

    begin {
        Write-Host -Message "Starting Clone-EnhancedRepos function" -Level "INFO"
        # Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Create the target directory if it doesn't exist
        if (-not (Test-Path -Path $targetDirectory)) {
            Write-Host -Message "Creating target directory: $targetDirectory" -Level "INFO"
            New-Item -Path $targetDirectory -ItemType Directory
        }
    }

    process {
        try {
            # Get the list of repositories using GitHub CLI
            Write-Host -Message "Retrieving repositories for user $githubUsername using GitHub CLI..." -Level "INFO"
            $reposJson = gh repo list $githubUsername --json name,url --jq '.[] | select(.name | startswith("Enhanced"))'
            $repos = $reposJson | ConvertFrom-Json

            # Clone each repository
            foreach ($repo in $repos) {
                $repoName = $repo.name
                $repoCloneUrl = $repo.url
                $repoTargetPath = Join-Path -Path $targetDirectory -ChildPath $repoName

                Write-Host -Message "Cloning repository $repoName to $repoTargetPath..." -Level "INFO"
                git clone $repoCloneUrl $repoTargetPath
            }

            Write-Host -Message "Cloning process completed." -Level "INFO"
        } catch {
            Write-Host -Message "Error during cloning process: $_" -Level "ERROR"
            # Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        Write-Host -Message "Clone-EnhancedRepos function execution completed." -Level "INFO"
    }
}

# Example invocation to clone repositories:
Clone-EnhancedRepos -githubUsername "aollivierre" -targetDirectory "C:\Code\modules-beta3"