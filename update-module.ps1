param (
    [string]$ModuleName
)

try {
    Update-ModuleIfOldOrMissing -ModuleName $ModuleName
    $moduleInfo = Get-Module -Name $ModuleName -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1
    $moduleDetails = [pscustomobject]@{
        Name    = $ModuleName
        Version = $moduleInfo.Version
        Path    = $moduleInfo.ModuleBase
    }
    Write-Output "Success: $(ConvertTo-Json $moduleDetails)"
}
catch {
    $moduleDetails = [pscustomobject]@{
        Name    = $ModuleName
        Version = "N/A"
        Path    = "N/A"
    }
    Write-Output "Failure: $(ConvertTo-Json $moduleDetails)"
}
