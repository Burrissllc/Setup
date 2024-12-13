#------------------------------------------------------
# Name:        Final Cleanup 
# Purpose:     Removes All Leftover files from setup
# Author:      John Burriss
# Created:     10/7/2019  1:00 PM
# Modified:    10/26/2022 11:07 AM
# Version:     0.02 
#------------------------------------------------------
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
Get-Process Powershell  | Where-Object { $_.ID -ne $pid } | Stop-Process
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