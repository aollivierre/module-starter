function Validate-GitHubCLIInstallation {
    param (
        [version]$MinVersion = [version]"2.54.0",
        [int]$MaxRetries = 3,
        [int]$DelayBetweenRetries = 5  # Delay in seconds
    )

    $retryCount = 0
    $validationSucceeded = $false

    while ($retryCount -lt $MaxRetries -and -not $validationSucceeded) {
        try {
            $registryPaths = @(
                "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"  # Include HKCU for user-installed apps
            )

            foreach ($path in $registryPaths) {
                $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $app = Get-ItemProperty -Path $item.PsPath -ErrorAction SilentlyContinue
                    if ($app.DisplayName -like "*GitHub CLI*") {
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
        } catch {
            Write-Log "Error validating GitHub CLI installation: $_" -Level "ERROR"
        }

        $retryCount++
        if (-not $validationSucceeded) {
            Write-Log "Validation attempt $retryCount failed: GitHub CLI not found or version does not meet minimum requirements. Retrying in $DelayBetweenRetries seconds..." -Level "WARNING"
            Start-Sleep -Seconds $DelayBetweenRetries
        }
    }

    return @{IsInstalled = $false }
}


Validate-GitHubCLIInstallation