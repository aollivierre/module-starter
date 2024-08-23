# Path to check for the PowerShellGet module
$modulePath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules\PowerShellGet"

# Check if the directory exists
if (Test-Path -Path $modulePath) {
    Write-Host "The PowerShellGet module directory exists at $modulePath." -ForegroundColor Green
    
    # Check if the module manifest (.psd1) file exists
    $moduleManifest = Join-Path -Path $modulePath -ChildPath "PowerShellGet.psd1"
    if (Test-Path -Path $moduleManifest) {
        Write-Host "The PowerShellGet module manifest file exists at $moduleManifest." -ForegroundColor Green
    } else {
        Write-Host "The PowerShellGet module manifest file does not exist at $moduleManifest." -ForegroundColor Red
    }
    
    # Check for other expected files (like .psm1)
    $moduleScript = Join-Path -Path $modulePath -ChildPath "PowerShellGet.psm1"
    if (Test-Path -Path $moduleScript) {
        Write-Host "The PowerShellGet module script file exists at $moduleScript." -ForegroundColor Green
    } else {
        Write-Host "The PowerShellGet module script file does not exist at $moduleScript." -ForegroundColor Red
    }
    
} else {
    Write-Host "The PowerShellGet module directory does not exist at $modulePath." -ForegroundColor Red
}
