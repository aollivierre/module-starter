iex ((irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1") -replace '\$Mode = "dev"', '$Mode = "prod"')

iex (irm "https://raw.githubusercontent.com/aollivierre/module-starter/main/Module-Starter.ps1")