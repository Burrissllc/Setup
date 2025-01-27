<#
.SYNOPSIS
    This script installs Java based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if Java should be installed.
    It installs Java either from an online source or a local installer based on internet connectivity.
    Logs are created locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallJava.ps1
    Runs the script to install Java if configured to do so.

.NOTES
    Author: John Burriss
    Created: 12/8/2022
    Version: 0.01
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

#$Path = "$RunLocation\Logs\InstallJava.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\InstallJava.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\InstallJava.log" -Force -Append

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
        $RemotelogDirectory = "$RemoteLogLocation"
        #[System.Management.Automation.ErrorRecord]$LastException = $_
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
        if (!(Test-Path -Path $RemotelogDirectory)) {
            New-Item -Path $RemotelogDirectory -ItemType Directory | Out-Null
        }
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}
#-------------------------------------------------------------------------------------------------------------

$INSTALLJAVA = $Settings.General.INSTALLJAVA

Switch ($INSTALLJAVA) {
    Y {
        #Write-Host "Installing 7Zip" -ForegroundColor Yellow
        #Installs 7Zip
        #$RunLocation\bin\7Zip\7z1900-x64.msi /q INSTALLDIR="C:\Program Files\7-Zip"
        #Write-Host "Finished Installing 7Zip" -ForegroundColor Green

        #Installs Java
        if (Test-Connection 8.8.8.8 -Count 1 -Quiet) {
            #Write-Host "Installing Java" -ForegroundColor Yellow
            Write-PSULog -Severity Start -Message "Installing Java"
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

            #Write-Host "Finished Installing Java" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Finished Installing Java"
        }
        else {
            #Write-Host "Installing Java" -ForegroundColor Yellow
            Write-PSULog -Severity Start -Message "Installing Java"
            $WorkingDirectory = "$RunLocation\bin\java\"
            Start-Process -FilePath "$WorkingDirectory\openjdk.msi" -ArgumentList "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome INSTALLDIR=`"c:\Program Files\Temurin\`" /quiet" -Wait
            #Write-Host "Finished Installing Java" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Finished Installing Java"
        }
    }
    N {
        #Write-Host "Skipping Java Install"
        Write-PSULog -Severity Info -Message "Skipping Java Install"
    }
    default {
        #Write-Host "Skipping Java Install"
        Write-PSULog -Severity Info -Message "Skipping Java Install"
    }
}

#Stop-Transcript