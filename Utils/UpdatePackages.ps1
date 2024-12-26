<#
.SYNOPSIS
    This script updates all of the install packages in the Bin directory.

.DESCRIPTION
    The script checks for internet connectivity and downloads the latest version of the Adobe Reader DC installer from the Microsoft Winget repository.
    It downloads the latest version of the Adoptimum JRE installer from the AdoptOpenJDK repository.
    It downloads the latest version of the ssms installer from the Microsoft Winget repository.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\UpdatePackages.ps1

.NOTES
    Author: John Burriss
    Created: 12/8/2022
    Version: 0.01
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>


#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path
function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $LogObject = [PSCustomObject]@{
        Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
        Hostname  = $env:computername
        Severity  = $Severity
        Message   = $Message
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
}

Write-Host "Checking for Internet Connectivity"

try {
    if (Test-Connection 8.8.8.8 -Count 1 -Quiet) { 
        Write-PSULog -Severity Info -Message "Internet Connection Detected"
        Write-Host "Downloading Adobe Reader"
        # Variables
        $repoUrl = "https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/a/Adobe/Acrobat/Reader/32-bit"
        $headers = @{ "User-Agent" = "PowerShell" }

        # Get the version directories
        $response = Invoke-RestMethod -Uri $repoUrl -Headers $headers
        $versions = $response | Where-Object { $_.type -eq "dir" } | Select-Object -ExpandProperty name

        # Find the latest version
        $latestVersion = $versions | Sort-Object -Descending | Select-Object -First 1

        # Get the manifest file for the latest version
        $manifestUrl = "$repoUrl/$latestVersion"
        $manifestResponse = Invoke-RestMethod -Uri $manifestUrl -Headers $headers
        $yamlFile = $manifestResponse | Where-Object { $_.name -like "*.yaml" -and $_.name -match "installer" } | Select-Object -ExpandProperty download_url

        # Download and parse the YAML
        $yamlContent = Invoke-RestMethod -Uri $yamlFile -Headers $headers
        $installerUrl = ($yamlContent -split "`n" | Where-Object { $_ -like "*InstallerUrl*" }) -replace "InstallerUrl:\s*", ""

        # Output the download URL
        Write-Host "Latest Version: $latestVersion"
        Write-Host "Download URL: $installerUrl"

        $downloadPath = "$RunLocation\bin\Acrobat\AcroRdrInstaller.exe"

        # Download the installer
        (New-Object Net.WebClient).DownloadFile($installerUrl, $downloadPath)

        Write-Host "Downloading Adobe Reader Complete"
    }
    else {
        Write-PSULog -Severity Error -Message "No Internet Connection Detected"
        throw "No Internet Connection Detected"
    }
}
catch {
    Write-PSULog -Severity Error -Message "Failed to download Adobe Reader: $_"
    Write-Host "Failed to download Adobe Reader: $_"
}

try {
    Write-Host "Downloading Java JRE"

    $githubApiUrl = "https://api.github.com/repos/adoptium/temurin11-binaries/releases/latest"

    # Set the User-Agent header to make the request
    $headers = @{ "User-Agent" = "Mozilla/5.0" }

    # Make the API request to get the latest release info
    $response = Invoke-RestMethod -Uri $githubApiUrl -Headers $headers

    # Find the MSI download URL in the assets section
    $msiUrl = $response.assets | Where-Object { $_.name -like "*msi" -and $_.name -match "jre_x64" } | Select-Object -ExpandProperty browser_download_url

    # Validate if a valid URL is found
    if (-not $msiUrl) {
        Write-Host "Could not find MSI download link in the latest release."
        throw "Could not find MSI download link in the latest release."
    }

    Write-Host "Latest OpenJDK MSI found: $msiUrl"

    # Working directory path for download
    $WorkingDirectory = "$RunLocation\bin\java\"

    # Download the latest OpenJDK MSI
    $destination = "$WorkingDirectory\openjdk.msi"
    Write-PSULog -Severity Info -Message "Downloading OpenJDK from $msiUrl"
    $client = New-Object System.Net.WebClient
    $client.DownloadFile($msiUrl, $destination)
    Write-Host "Downloading Java Complete"
}
catch {
    Write-PSULog -Severity Error -Message "Failed to download Java JRE: $_"
    Write-Host "Failed to download Java JRE: $_"
}

try {
    Write-Host "Downloading SSMS"

    $filepath = "$RunLocation\bin\SQL\SSMS-Local\SSMS-Setup-ENU.exe"
    $URL = "https://aka.ms/ssmsfullsetup"

    Write-Host "Latest SSMS installer download URL: $URL"

    $clnt = New-Object System.Net.WebClient
    $clnt.DownloadFile($url, $filepath)
    Write-Host "SSMS installer download complete"
}
catch {
    Write-PSULog -Severity Error -Message "Failed to download SSMS: $_"
    Write-Host "Failed to download SSMS: $_"
}