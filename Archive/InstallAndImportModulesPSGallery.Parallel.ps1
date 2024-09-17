function InstallAndImportModulesPSGallery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$modulePsd1Path
    )

    begin {
        Write-EnhancedLog -Message "Starting InstallAndImportModulesPSGallery function" -Level "INFO"
        Log-Params -Params $PSCmdlet.MyInvocation.BoundParameters

        # Initialize counters and lists for summary
        $moduleSuccessCount = 0
        $moduleFailCount = 0
        $successModules = [System.Collections.Generic.List[PSCustomObject]]::new()
        $failedModules = [System.Collections.Generic.List[PSCustomObject]]::new()

        # Validate PSD1 file path
        if (-not (Test-Path -Path $modulePsd1Path)) {
            Write-EnhancedLog -Message "modules.psd1 file not found at path: $modulePsd1Path" -Level "ERROR"
            throw "modules.psd1 file not found."
        }

        Write-EnhancedLog -Message "Found modules.psd1 file at path: $modulePsd1Path" -Level "INFO"
    }

    process {
        try {
            # Read and import PSD1 data
            $moduleData = Import-PowerShellDataFile -Path $modulePsd1Path
            $requiredModules = $moduleData.RequiredModules
            $importedModules = $moduleData.ImportedModules
            $myModules = $moduleData.MyModules

            # Validate, Install, and Import Modules
            if ($requiredModules) {
                Write-EnhancedLog -Message "Installing required modules: $($requiredModules -join ', ')" -Level "INFO"
                # URL of the web script to download
                $webScriptUrl = "https://raw.githubusercontent.com/aollivierre/module-starter/refs/heads/main/update-module.ps1"

                # Create lists for success and failed modules
                # $successModules = [System.Collections.Generic.List[PSCustomObject]]::new()
                # $failedModules = [System.Collections.Generic.List[PSCustomObject]]::new()

                # Array to store the processes that will be run in parallel
                $processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()

                # Base path to powershell.exe for PowerShell 5
                $psExePath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

                # Path for temporary files
                $tempDir = [System.IO.Path]::GetTempPath()

                # Download the script to a temp file
                $tempScriptPath = Join-Path -Path $tempDir -ChildPath "update-module.ps1"
                Invoke-RestMethod -Uri $webScriptUrl -OutFile $tempScriptPath

                # Iterate over each module and start a process for each one
                foreach ($moduleName in $requiredModules) {
                    # Create a unique temp file for storing the result of each process
                    $resultFile = Join-Path -Path $tempDir -ChildPath "$moduleName-result.txt"

                    # Splatting parameters for Start-Process using -File
                    $splatProcess = @{
                        FilePath     = $psExePath
                        ArgumentList = @(
                            "-NoProfile", 
                            "-ExecutionPolicy", "Bypass", 
                            "-File", $tempScriptPath, 
                            "-ModuleName", $moduleName,
                            "-ResultFile", $resultFile  # Pass the result file path to the script
                        )
                        NoNewWindow  = $true
                        PassThru     = $true
                    }

                    # Start the process and add it to the list
                    $process = Start-Process @splatProcess
                    $processes.Add($process)
                }

                # Wait for all processes to complete
                foreach ($process in $processes) {
                    $process.WaitForExit()
                }

                # # Process the results from the temp files
                # foreach ($moduleName in $requiredModules) {
                #     $resultFile = Join-Path -Path $tempDir -ChildPath "$moduleName-result.txt"

                #     if (Test-Path $resultFile) {
                #         $result = Get-Content -Path $resultFile -Raw
                #         if ($result -match 'Success') {
                #             $moduleDetails = [pscustomobject]@{
                #                 Name    = $moduleName
                #                 Version = $result -replace 'Success:', ''
                #                 Path    = "ModulePath"  # You can enhance the script to return the actual path
                #             }
                #             $successModules.Add($moduleDetails)
                #             Write-EnhancedLog -Message "Successfully installed/updated module: $moduleName" -Level "INFO"
                #         }
                #         elseif ($result -match 'Failure') {
                #             $moduleDetails = [pscustomobject]@{
                #                 Name    = $moduleName
                #                 Version = "N/A"
                #                 Path    = "N/A"
                #             }
                #             $failedModules.Add($moduleDetails)
                #             Write-EnhancedLog -Message "Failed to install/update module: $moduleName" -Level "ERROR"
                #         }
                #         # Remove the result file after processing
                #         Remove-Item -Path $resultFile -Force
                #     }
                # }

                # Write-Host "All modules have been processed in parallel."

                # # Cleanup: Remove the temp script
                # Remove-Item -Path $tempScriptPath -Force



                





                Write-EnhancedLog "All module update processes have completed." -Level "NOTICE"
            }

            if ($importedModules) {
                Write-EnhancedLog -Message "Importing modules: $($importedModules -join ', ')" -Level "INFO"
                foreach ($moduleName in $importedModules) {
                    try {
                        Import-Module -Name $moduleName -Force
                        $moduleInfo = Get-Module -Name $moduleName | Select-Object -First 1
                        $moduleDetails = [PSCustomObject]@{
                            Name    = $moduleName
                            Version = $moduleInfo.Version
                            Path    = $moduleInfo.ModuleBase
                        }
                        $successModules.Add($moduleDetails)
                        Write-EnhancedLog -Message "Successfully imported module: $moduleName" -Level "INFO"
                        $moduleSuccessCount++
                    }
                    catch {
                        $moduleDetails = [PSCustomObject]@{
                            Name    = $moduleName
                            Version = "N/A"
                            Path    = "N/A"
                        }
                        $failedModules.Add($moduleDetails)
                        Write-EnhancedLog -Message "Failed to import module: $moduleName. Error: $_" -Level "ERROR"
                        $moduleFailCount++
                    }
                }
            }

            if ($myModules) {
                Write-EnhancedLog -Message "Importing custom modules: $($myModules -join ', ')" -Level "INFO"
                foreach ($moduleName in $myModules) {
                    try {
                        Import-Module -Name $moduleName -Force
                        $moduleInfo = Get-Module -Name $moduleName | Select-Object -First 1
                        $moduleDetails = [PSCustomObject]@{
                            Name    = $moduleName
                            Version = $moduleInfo.Version
                            Path    = $moduleInfo.ModuleBase
                        }
                        $successModules.Add($moduleDetails)
                        Write-EnhancedLog -Message "Successfully imported custom module: $moduleName" -Level "INFO"
                        $moduleSuccessCount++
                    }
                    catch {
                        $moduleDetails = [PSCustomObject]@{
                            Name    = $moduleName
                            Version = "N/A"
                            Path    = "N/A"
                        }
                        $failedModules.Add($moduleDetails)
                        Write-EnhancedLog -Message "Failed to import custom module: $moduleName. Error: $_" -Level "ERROR"
                        $moduleFailCount++
                    }
                }
            }

            Write-EnhancedLog -Message "Modules installation and import process completed." -Level "INFO"
        }
        catch {
            Write-EnhancedLog -Message "Error processing modules.psd1: $_" -Level "ERROR"
            Handle-Error -ErrorRecord $_
            throw $_
        }
    }

    end {
        # Output summary report
        Write-EnhancedLog -Message "InstallAndImportModulesPSGallery function execution completed." -Level "INFO"
    
        Write-Host "---------- Summary Report ----------" -ForegroundColor Cyan
        Write-Host "Total Modules Processed: $($moduleSuccessCount + $moduleFailCount)" -ForegroundColor Cyan
        Write-Host "Modules Successfully Processed: $moduleSuccessCount" -ForegroundColor Green
        Write-Host "Modules Failed: $moduleFailCount" -ForegroundColor Red
    
        if ($successModules.Count -gt 0) {
            Write-Host "Successful Modules:" -ForegroundColor Green
            $successModules | Format-Table -Property Name, Version, Path -AutoSize -Wrap | Out-String | Write-Host
        }
    
        if ($failedModules.Count -gt 0) {
            Write-Host "Failed Modules:" -ForegroundColor Red
            $failedModules | Format-Table -Property Name, Version, Path -AutoSize -Wrap | Out-String | Write-Host
        }
    
        Write-Host "-----------------------------------" -ForegroundColor Cyan
    }
    
}
