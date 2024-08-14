function Download-And-Execute-Script {
    param (
        [string]$scriptUrl = "https://raw.githubusercontent.com/your-repo/example-script.ps1",
        [string]$Mode = "dev"  # Parameter to pass to the web script
    )
    
    try {
        Write-Host "Downloading script from: $scriptUrl"
        
        # Download the script content
        $scriptContent = Invoke-RestMethod -Uri $scriptUrl -UseBasicParsing
        
        # Save the script content to a temporary file
        $tempScriptPath = [System.IO.Path]::Combine($env:TEMP, "example-script.ps1")
        $scriptContent | Out-File -FilePath $tempScriptPath -Encoding UTF8
        
        Write-Host "Executing downloaded script with mode: $Mode"
        
        # Execute the script and pass the Mode parameter
        & $tempScriptPath -Mode $Mode
        
        # Clean up the temporary script file
        Remove-Item -Path $tempScriptPath -Force
    }
    catch {
        Write-Host "Failed to download or execute the script from $scriptUrl"
    }
}

# Example usage:
Download-And-Execute-Script -Mode "prod"