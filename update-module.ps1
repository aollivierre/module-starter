param (
    [string]$ModuleName,
    [string]$ResultFile  # The result file path is passed from the calling script
)

# Initialize variables for success and failure tracking
$moduleSuccessCount = 0
$moduleFailCount = 0
$successModules = [System.Collections.Generic.List[PSCustomObject]]::new()
$failedModules = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    Update-ModuleIfOldOrMissing -ModuleName $ModuleName
    $moduleInfo = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $moduleDetails = [PSCustomObject]@{
        Name    = $ModuleName
        Version = $moduleInfo.Version
        Path    = $moduleInfo.ModuleBase
    }
    $successModules.Add($moduleDetails)
    Write-EnhancedLog -Message "Successfully installed/updated module: $ModuleName" -Level "INFO"
    $moduleSuccessCount++

    # Write success details to the result file
    "Success: $($moduleInfo.Version)" | Out-File -FilePath $ResultFile -Force
}
catch {
    $moduleDetails = [PSCustomObject]@{
        Name    = $ModuleName
        Version = "N/A"
        Path    = "N/A"
    }
    $failedModules.Add($moduleDetails)
    Write-EnhancedLog -Message "Failed to install/update module: $ModuleName. Error: $_" -Level "ERROR"
    $moduleFailCount++

    # Write failure details to the result file
    "Failure" | Out-File -FilePath $ResultFile -Force
}
