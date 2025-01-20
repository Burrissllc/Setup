<#
.SYNOPSIS
    This script performs final cleanup by removing all leftover files from setup.

.DESCRIPTION
    The script stops all open processes, removes the setup folder, logs the completion, and reboots the machine.
    Logs are created locally and optionally remotely if specified.

.PARAMETER RunLocation
    The location of the setup files to be cleaned up.

.PARAMETER RemoteLogLocation
    The remote location where logs should be stored, if specified.

.EXAMPLE
    .\FinalCleanup.ps1 -RunLocation "C:\Setup" -RemoteLogLocation "\\Server\Logs"
    Runs the script to perform final cleanup and reboot the machine.

.NOTES
    Author: John Burriss
    Created: 10/7/2019
    Modified: 10/26/2022
    Version: 0.02
    Requires: PowerShell 5.1 or higher, Administrator privileges

#Requires -RunAsAdministrator
#>


#Requires -RunAsAdministrator

param ($RunLocation,
    $RemoteLogLocation)

#----------------------------------------------------------------------------------------------
function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory = "C:\temp",
        [string]$RemotelogDirectory = "$RemoteLogLocation"
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

Set-Location "C:\Temp"

Start-Sleep -Seconds 10

#Restarts Explorer to close all open windows
Stop-Process -ProcessName explorer

#Closes all other open Powershell windows
Get-Process Powershell  | Where-Object { $_.ID -ne $pid } | Stop-Process -Force -Confirm:$false
stop-process -Name explorer -Force

Start-Sleep -Seconds 5

#Removes the Setup Folder
function Get-Tree($Path, $Include = '*') { 
    @(Get-Item $Path -Include $Include -Force) + 
        (Get-ChildItem $Path -Recurse -Include $Include -Force) | sort-object pspath -Descending -unique
} 

function Remove-Tree($Path, $Include = '*') { 
    Get-Tree $Path $Include | Remove-Item -force -recurse
} 

Remove-Tree $RunLocation

Write-PSULog -Severity End -Message "Completed Setup and Cleanup. Reboting machine"

if ($RemoteLogLocation -ne $null) {
    $RemotelogFilePath = Join-Path "$RemoteLogLocation" "CompletedMachines.txt"

    $env:COMPUTERNAME | out-file $RemotelogFilePath -Append

}


Start-Sleep -Seconds 5
#Clears Powershell History
Clear-History

#Removes Currently Running Script
Remove-Item -Path $MyInvocation.MyCommand.Source

Restart-Computer -Force

Exit