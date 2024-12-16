<#
.SYNOPSIS
    This script downloads and installs the latest OpenJDK (OpenJRE) silently.

.DESCRIPTION
    The script dynamically fetches the latest OpenJDK version from the Eclipse Adoptium GitHub repository and installs it silently.
    It logs the installation process locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\OpenJDKInstall.ps1
    Runs the script to download and install the latest OpenJDK silently.

.NOTES
    Requires: PowerShell 5.1 or higher, Administrator privileges

#Requires -RunAsAdministrator
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location .. 
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
#----------------------------------------------------------------------------------------------
if ([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True) {

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}
else {
    $null = $RemoteLogLocation
}

function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory = "$RunLocation\Logs\",
        $RemotelogDirectory = $RemoteLogLocation
    )
    $LogObject = [PSCustomObject]@{
        Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
        Hostname  = $env:computername
        Severity  = $Severity
        Message   = $Message
    }

    if (!(Test-Path -Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }

    $logFilePath = Join-Path "$logDirectory" "MachineSetup.json"
    $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $logFilePath -Append
    if ($RemotelogDirectory -ne $null) {
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
}

#-------------------------------------------------------------------------------------------------------------
# Fetch the latest OpenJDK download link dynamically from Adoptium GitHub releases

# GitHub API URL to get the latest release info
$githubApiUrl = "https://api.github.com/repos/adoptium/temurin11-binaries/releases/latest"

# Set the User-Agent header to make the request
$headers = @{ "User-Agent" = "Mozilla/5.0" }

# Make the API request to get the latest release info
$response = Invoke-RestMethod -Uri $githubApiUrl -Headers $headers

# Find the MSI download URL in the assets section
$msiUrl = $response.assets | Where-Object { $_.name -like "*msi" -and $_.name -match "jre_x64" } | Select-Object -ExpandProperty browser_download_url

# Validate if a valid URL is found
if (-not $msiUrl) {
    Write-PSULog -Severity Error -Message "Could not find MSI download link in the latest release."
    exit 1
}

Write-PSULog -Severity Info -Message "Latest OpenJDK MSI found: $msiUrl"

# Working directory path for download
$WorkingDirectory = "$RunLocation\bin\java\"

# Check if working directory exists, create if not
If (!(Test-Path -Path $WorkingDirectory -PathType Container)) { 
    Write-PSULog -Severity Info -Message "Creating working directory at $WorkingDirectory"
    New-Item -Path $WorkingDirectory  -ItemType directory 
}

# Download the latest OpenJDK MSI
$destination = "$WorkingDirectory\openjdk.msi"
Write-PSULog -Severity Info -Message "Downloading OpenJDK from $msiUrl"
$client = New-Object System.Net.WebClient
$client.DownloadFile($msiUrl, $destination)

# Install OpenJDK silently
Write-PSULog -Severity Info -Message "Installing OpenJDK from $destination"
Start-Process -FilePath "$WorkingDirectory\openjdk.msi" -ArgumentList "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome INSTALLDIR=`"c:\Program Files\Temurin\`" /quiet" -Wait

# Clean up
Write-PSULog -Severity Info -Message "Cleaning up OpenJDK Install Folder"
Remove-Item $WorkingDirectory\openjdk.msi -Force
