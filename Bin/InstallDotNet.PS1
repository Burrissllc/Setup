#------------------------------------------------------
# Name:        InstallDotNet
# Purpose:     Installs .net 4.8
# Author:      John Burriss
# Created:     12/8/2022  5:24 PM 
#Version:      0.01
#------------------------------------------------------
#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json

#----------------------------------------------------------------------------------------------
if([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True){

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}else{
$null = $RemoteLogLocation
}
function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory="$RunLocation\Logs\",
        $RemotelogDirectory="$RemoteLogLocation"
        #[System.Management.Automation.ErrorRecord]$LastException = $_
    )
    $LogObject = [PSCustomObject]@{
        Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
        Hostname  = $env:computername
        Severity  = $Severity
        Message   = $Message
    }

    if(!(Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory | Out-Null
        }

    $logFilePath = Join-Path "$logDirectory" "MachineSetup.json"
    $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $logFilePath -Append
    if($RemotelogDirectory -ne $null){
        if(!(Test-Path -Path $RemotelogDirectory)) {
            New-Item -Path $RemotelogDirectory -ItemType Directory | Out-Null
        }
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}
#-------------------------------------------------------------------------------------------------------------

#$Path = "$RunLocation\Logs\InstallDotNet.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\InstallDotNet.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\InstallDotNet.log" -Force -Append

#Installs .net 4.8
#Write-host "Installing .net4.8" -ForegroundColor Yellow
Write-PSULog -Severity Start -Message "Installing .net4.8"
& $RunLocation\bin\.net\ndp48-x86-x64-allos-enu.exe /passive /norestart | Out-Null
#Write-host "Finished Installing .net4.8" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Finished Installing .net4.8"

if((Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -le 528040){

Write-PSULog -Severity Info -Message "Setting Script to continue after reboot"

$path = "HKLM:\SOFTWARE\MachineSetup"
if (!(Test-Path $path)) {mkdir $path | Out-Null}

Set-ItemProperty $path "dotNet" -Value "1" -Force

$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\Setup.ps1"

Write-PSULog -Severity Info -Message "Machine Needs to Reboot for setup to continue"

$Readhost = $Settings.general.AUTOREBOOT
Switch ($ReadHost) {
    Y { Write-PSULog -Severity End -Message "Rebooting now..."; Start-Sleep -s 2; Restart-Computer -Force }
    N { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds."; Start-Sleep -s 5 }
    Default { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds"; Start-Sleep -s 5 }
}

}

#Stop-Transcript