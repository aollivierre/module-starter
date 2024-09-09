# Initialize the global steps list



# Define the GitHub URLs of the scripts and corresponding software names


# Add steps for each script
foreach ($detail in $scriptDetails) {
    Add-Step ("Running script from URL: $($detail.Url)")
}


# Function to elevate the script to administrator if not already elevated


# Function to process each software detail, validate and run the installation

# Function to wait for all processes to complete and validate installations

# Function to generate the final summary report


# Main function that orchestrates the entire process





# Keep the PowerShell window open to review the logs
Read-Host 'Press Enter to close this window...'