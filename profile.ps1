# profile.ps1
# Runs once when the Function host starts.
# Authenticates to Graph API for both local dev and Azure deployment.

if ($env:MSI_ENDPOINT -or $env:IDENTITY_ENDPOINT) {
    # Running in Azure — Managed Identity handles auth
    Connect-AzAccount -Identity

} else {
    # Running locally — import Graph module from local PowerShell installation
    # Module is at: ~/.local/share/powershell/Modules/Microsoft.Graph.*
    $modulePaths = @(
        "$HOME/.local/share/powershell/Modules",
        "$HOME/Documents/PowerShell/Modules",
        "/usr/local/share/powershell/Modules"
    )

    foreach ($path in $modulePaths) {
        if (Test-Path $path) {
            if ($env:PSModulePath -notlike "*$path*") {
                $env:PSModulePath = "$path$([System.IO.Path]::PathSeparator)$env:PSModulePath"
            }
        }
    }

    $tenantId     = $env:AZURE_TENANT_ID
    $clientId     = $env:AZURE_CLIENT_ID
    $clientSecret = $env:AZURE_CLIENT_SECRET

    if ($tenantId -and $clientId -and $clientSecret) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            Import-Module Microsoft.Graph.Users         -ErrorAction Stop
            Import-Module Microsoft.Graph.Groups        -ErrorAction Stop

            $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
            $credential   = New-Object System.Management.Automation.PSCredential(
                $clientId, $secureSecret
            )

            Connect-MgGraph `
                -TenantId               $tenantId `
                -ClientSecretCredential $credential `
                -NoWelcome

            Write-Host "profile.ps1: Connected to Microsoft Graph successfully."
        }
        catch {
            Write-Warning "profile.ps1: Failed to connect to Graph — $_"
        }
    } else {
        Write-Warning "profile.ps1: AZURE_TENANT_ID, AZURE_CLIENT_ID, or AZURE_CLIENT_SECRET not set."
    }
}