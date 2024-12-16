<#
.SYNOPSIS
    This script installs the DICOM service based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if the DICOM service should be installed.
    It installs the DICOM service with the specified settings and logs the process.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallDICOM.ps1
    Runs the script to install the DICOM service if configured to do so.

.NOTES
    Author: John Burriss
    Created: 9/26/2023
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


if ([string]::IsNullOrEmpty($Settings.SERVICES.DICOMSERVICESERVER) -or $Settings.SERVICES.DICOMSERVICESERVER -contains $env:COMPUTERNAME) {

    Write-PSULog -Severity Start -Message "Starting DICOM Service Install"

    $DICOMLOCATION = $Settings.SERVICES.DICOMSERVICELOCATION

    if (Test-path $DICOMLOCATION) {

        if ([string]::IsNullOrEmpty($Settings.SERVICES.SCPTITLE)) {
            $SCPTITLE = "RAYSTATION_SSCP"
        }
        else {
            $SCPTITLE = $Settings.SERVICES.SCPTITLE
        }
        if ([string]::IsNullOrEmpty($Settings.SERVICES.SCPPORT)) {
            $SCPPORT = "104"
        }
        else {
            $SCPPORT = $Settings.SERVICES.SCPPORT
        }
        if ([string]::IsNullOrEmpty($Settings.SERVICES.SCPFOLDER)) {
            $SCPFOLDER = "C:\Temp"
        }
        else {
            $SCPFOLDER = $Settings.SERVICES.SCPFOLDER
        }
        if ([string]::IsNullOrEmpty($Settings.SERVICES.SCPDAYS)) {
            $SCPDAYS = "14"
        }
        else {
            $SCPDAYS = $Settings.SERVICES.SCPDAYS
        }

        if (!(Test-path $SCPFOLDER)) {

            Write-PSULog -Severity Info -Message "SCP Folder Missing. Attempting to create folder"

            try {
                New-Item -ItemType Directory -Path $SCPFOLDER
            }
            Catch {
                Write-PSULog -Severity Error -Message  "Failed to create SCP Folder"
            }

        }

        Write-PSULog -Severity Info -Message "Installing Service with AE Title: $SCPTITLE, Port: $SCPPORT, Folder: $SCPFOLDER, Retention Period: $SCPDAYS"

        try {
            start-process msiexec.exe -ArgumentList @("/i $DICOMLOCATION", "/q", "SCPTITLE=$SCPTITLE", "SCPPORT=$SCPPORT", "SCPFOLDER=$SCPFOLDER", "SCPDAYS=$SCPDAYS") -wait
        }
        Catch {
            Write-PSULog -Severity Error -Message "Failed to Install DICOM Service"
        }

    }
    else {
        Write-PSULog -Severity Error -Message "Unable to Locate DICOM Installer Package. Skipping Install" 
    }
}

else {

    Write-PSULog -Severity Info -Message "Skipping DICOM Install, Server is not listed as designated server."

}