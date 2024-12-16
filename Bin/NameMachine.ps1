<#
.SYNOPSIS
    This script renames the machine based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine the new machine name.
    It renames the machine if the new name is provided and logs the process.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\NameMachine.ps1
    Runs the script to rename the machine based on the configuration settings.

.NOTES
    Author: John Burriss
    Created: 10/12/2022
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

#$Path = "$RunLocation\Logs\NameMachine.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\NameMachine.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\NameMachine.log" -Force -Append

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


$Readhost = $Settings.general.MACHINENAME
#$ReadHost
if ([string]::IsNullOrEmpty($Settings.general.MACHINENAME) -eq $false) {
    #if ($null -ne $ReadHost) {
        
    if ($ReadHost.count -le 15) {
                
            
        try {
            $ComputerName = $Settings.general.MACHINENAME
            if ($ComputerName -ne $env:computername) {
                Rename-Computer -NewName $ComputerName
                #Write-Host "Machine has been renamed: $ComputerName" -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Machine has been renamed: $ComputerName"
            }
        }
        catch {
            #Write-Host "Failed to name the machine" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "Failed to name the machine"
        }
            
    }
    else {
        #Write-host "$ReadHost has more than 15 characters. Please update name to 15 or less characters" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "$ReadHost has more than 15 characters. Please update name to 15 or less characters"
    }

}

#Write-Host "Machines Name is:$env:computername" -ForegroundColor Green;
Write-PSULog -Severity Info -Message "Machines Name is:$env:computername"

#Stop-Transcript