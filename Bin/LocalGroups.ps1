<#
.SYNOPSIS
    This script creates local user groups for RayStation and adds the current user to these groups.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if local groups should be created.
    It creates the specified local groups and adds the current user to these groups.
    Logs are created locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\LocalGroups.ps1
    Runs the script to create local user groups and add the current user to these groups.

.NOTES
    Author: John Burriss
    Created: 10/12/2022
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

#$Path = "$RunLocation\Logs\LocalGroups.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\LocalGroups.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\LocalGroups.log" -Force -Append

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

if ($settings.general.LOCALGROUPS -match "y") {

    $CurrentUser = $env:USERDOMAIN + '\' + $env:USERNAME
    #Write-Host "Creating Local User Groups" -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Creating Local User Groups"
    New-LocalGroup -Name "RayStation-Users"
    New-LocalGroup -Name "RayStation-Administrators"
    New-LocalGroup -Name "RayStation-BeamCommissioning"
    New-LocalGroup -Name "RayStation-PlanApproval"
    #Write-Host "Finished Creating Local Groups" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Finished Creating Local Groups"

    #Write-Host "Adding Current User to RayStation Groups" -ForegroundColor "Yellow"
    Write-PSULog -Severity Info -Message "Adding Current User to RayStation Groups"
    Add-LocalGroupMember -Group "RayStation-Users" -Member "$CurrentUser"
    Add-LocalGroupMember -Group "RayStation-Administrators" -Member "$CurrentUser"
    Add-LocalGroupMember -Group "RayStation-BeamCommissioning" -Member "$CurrentUser"
    Add-LocalGroupMember -Group "RayStation-PlanApproval" -Member "$CurrentUser"
    #Write-Host "Finished Adding Current User to RayStation Groups" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Finished Adding Current User to RayStation Groups"

}

#Stop-Transcript