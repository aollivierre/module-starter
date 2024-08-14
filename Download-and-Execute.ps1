# function Download-And-Execute-Script {
#     param (
#         [string]$scriptUrl = "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1",
#         [string]$Mode = "dev"  # Parameter to pass to the web script
#     )
    
#     try {
#         Write-Host "Downloading script from: $scriptUrl"
        
#         # Download the script content
#         $scriptContent = Invoke-RestMethod -Uri $scriptUrl -UseBasicParsing
        
#         # Save the script content to a temporary file
#         $tempScriptPath = [System.IO.Path]::Combine($env:TEMP, "example-script.ps1")
#         $scriptContent | Out-File -FilePath $tempScriptPath -Encoding UTF8
        
#         Write-Host "Executing downloaded script with mode: $Mode"
        
#         # Execute the script and pass the Mode parameter
#         & $tempScriptPath -Mode $Mode
        
#         # Clean up the temporary script file
#         Remove-Item -Path $tempScriptPath -Force
#     }
#     catch {
#         Write-Host "Failed to download or execute the script from $scriptUrl"
#     }
# }

# # Example usage:
# Download-And-Execute-Script -Mode "prod"




# Invoke-RestMethod -Uri "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1" -UseBasicParsing | Invoke-Expression -Args 'dev'


# $script = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1" -UseBasicParsing
# Invoke-Expression "$script -Mode 'dev'"


# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1") -replace 'param \(', "param (`n[string]\`$Mode = 'dev'`n)")

# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1") + "`n`$Mode = 'dev'")

# $mode='dev'; iex "(irm 'https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1')"

# iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/example-script.ps1") -replace '\[string\]\$Mode = "default"', '[string]$Mode = "dev"')


iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1") -replace '\[string\]\$Mode = "dev"', '[string]$Mode = "dev"')