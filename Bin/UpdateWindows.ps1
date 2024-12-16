<#
.SYNOPSIS
    This script updates Windows based on the configuration settings.

.DESCRIPTION
    The script checks for internet connectivity and installs Windows updates using the PSWindowsUpdate module.
    It logs the update process locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\UpdateWindows.ps1
    Runs the script to update Windows if configured to do so.

.NOTES
    Author: John Burriss
    Created: 12/2/2019
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>

#Requires -RunAsAdministrator

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
#-------------------------------------------------------------------------------------------------------------


#Write-Host "Checking for Internet connectivity" -ForegroundColor Yellow
Write-PSULog -Severity Start -Message "Starting Windows Updates"
Write-PSULog -Severity Info -Message "Checking for Internet connectivity"


$Internet = PING.EXE 8.8.8.8
if ($internet -contains "Packets: Sent = 4, Received = 4" -or "Packets: Sent = 4, Received = 3") {
    Write-PSULog -Severity Info -Message "Internet Connectivity Confirmed"
    try {
        Write-PSULog -Severity Info -Message "Attempting to Install Modules and Updates"
        Install-PackageProvider -Name NuGet -Force   
        Install-Module PSWindowsUpdate -Force
        Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -confirm:$false
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Confirm:$false
    }
    Catch {
        #Write-Host "Unable to Install Packages for Windows Update. Please Check Internet Connection" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Unable to Install Packages for Windows Update. Please Check Internet Connection"
    }
  
} 
Else {
    Write-PSULog -Severity Error -Message "Unable to connect to Internet to Download Updates."
}