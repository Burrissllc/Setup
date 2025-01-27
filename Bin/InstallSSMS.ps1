<#
.SYNOPSIS
    This script installs SQL Server Management Studio (SSMS) based on the configuration settings.

.DESCRIPTION
    The script checks for internet connectivity and installs SSMS from a local or downloaded package.
    It logs the installation process locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallSSMS.ps1
    Runs the script to install SSMS if configured to do so.

.NOTES
    Author: John Burriss
    Created: 10/17/2022
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>

#Requires -RunAsAdministrator

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path
#$Path = "$RunLocation\Logs\SSMS-Install.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\SSMS-Install.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\SSMS-Install.log" -Force -Append
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


#Write-Host "Checking for Internet connectivity" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Checking for Internet connectivity"
$Internet = PING.EXE 8.8.8.8
if ($internet -contains "Packets: Sent = 4, Received = 4" -or "Packets: Sent = 4, Received = 3") { 
    #Write-Host "Confirmed Internet Connectivity" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Confirmed Internet Connectivity"
    # Set file and folder path for SSMS installer .exe
    $filepath = "$RunLocation\bin\SQL\SSMS-Setup-ENU.exe"
    
    #If SSMS not present, download
    if (!(Test-Path $filepath)) {
        #write-host "Downloading SQL Server SSMS..."
        Write-PSULog -Severity Info -Message "Downloading SQL Server SSMS..."
        $URL = "https://aka.ms/ssmsfullsetup"
        $clnt = New-Object System.Net.WebClient
        $clnt.DownloadFile($url, $filepath)
        #Write-Host "SSMS installer download complete" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "SSMS installer download complete"
    
    }
    else {
    
        #write-host "Located the SQL SSMS Installer binaries, moving on to install..." -ForegroundColor Yellow
        Write-PSULog -Severity Info -Message "Located the SQL SSMS Installer binaries, moving on to install..."

    }
    
    # start the SSMS installer
    #write-host "Beginning SSMS install..." -nonewline -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Beginning SSMS install..."
    $Parms = " /Install /Quiet /Norestart /Logs log.txt"
    $Prms = $Parms.Split(" ")
    & "$filepath" $Prms | Out-Null
    #Write-Host "SSMS installation complete" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "SSMS installation complete"
}
else {
    #Write-Host "Unable to connect to internet, switching to local package" -ForegroundColor Yellow
    Write-PSULog -Severity Warning -Message "Unable to connect to internet, switching to local package"
    #write-host "Beginning SSMS install..." -nonewline -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Beginning SSMS install..."
    $filepath = "$RunLocation\bin\SQL\SSMS-Local\SSMS-Setup-ENU.exe"
    $Parms = " /Install /Quiet /Norestart /Logs log.txt"
    $Prms = $Parms.Split(" ")
    & "$filepath" $Prms | Out-Null
    #Write-Host "SSMS installation complete" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "SSMS installation complete"
}

Write-PSULog -Severity Info -Message "Checking on Active SQL Connections"
& $RunLocation\bin\CheckSQLConnections.ps1 -wait