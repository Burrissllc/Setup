<#
.SYNOPSIS
    This script installs Adobe Reader DC based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if Adobe Reader DC should be installed.
    It logs the installation process locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallAdobe.ps1
    Runs the script to install Adobe Reader DC if configured to do so.

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

#$Path = "$RunLocation\Logs\InstallAdobe.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\InstallAdobe.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\InstallAdobe.log" -Force -Append

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



$INSTALLADOBE = $Settings.General.INSTALLADOBE

Switch ($INSTALLADOBE) {
    Y {


        if (Test-Connection "8.8.8.8" -Count 1 -Quiet) { 
            Write-PSULog -Severity Info -Message "Internet Connection Detected"
            Write-PSULog -Severity Info -Message "Downloading Adobe Reader"
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
            Write-PSULog -Severity Info -Message "Latest Version: $latestVersion"
            Write-PSULog -Severity Info -Message "Download URL: $installerUrl"

            $downloadPath = "$RunLocation\bin\Acrobat\AcroRdrInstaller.exe"
            $installArgs = "/sAll /msi EULA_ACCEPT=YES"

            # Download the installer
            #Invoke-WebRequest -Uri $installerUrl -OutFile $downloadPath

            (New-Object Net.WebClient).DownloadFile($installerUrl, $downloadPath)

            # Silent install
            Write-PSULog -Severity Info -Message "Installing Adobe Reader"
            Start-Process -FilePath $downloadPath -ArgumentList $installArgs -Wait
            Write-PSULog -Severity Info -Message "Finished Installing Acrobat Reader"

            # Cleanup
            Remove-Item $downloadPath
        
        }

        else {
            #Installs Adobe Reader DC
            #Write-Host "Installing Adobe Reader" -ForegroundColor Yellow
            Write-PSULog -Severity Start -Message "Installing Adobe Reader"
            & $RunLocation\bin\Acrobat\AcroRdrInstaller.exe /sAll | Out-Null
            #Write-Host "Finished Installing Acrobat Reader" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Finished Installing Acrobat Reader"
        }
    }
    
    N {
        #Write-Host "Skipping Adobe Install"
        Write-PSULog -Severity Info -Message "Skipping Adobe Install"
    }
    default {
        #Write-Host "Skipping Adobe Install"
        Write-PSULog -Severity Info -Message "Skipping Adobe Install"
    }
}
#Stop-Transcript