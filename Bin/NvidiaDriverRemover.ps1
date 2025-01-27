<#
.SYNOPSIS
    This script removes all NVIDIA components and prepares the system for a new driver installation.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if the current NVIDIA driver should be removed.
    It adds a registry key to stop automatic driver installation, runs Display Driver Uninstaller (DDU) to remove all NVIDIA components, and sets the NVIDIA driver to install on the next boot if specified.
    Logs are created locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\NvidiaDriverRemover.ps1
    Runs the script to remove all NVIDIA components and prepare the system for a new driver installation.

.NOTES
    Author: John Burriss
    Created: 12/18/2019
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
#$Path = "$RunLocation\Logs\NvidiaSetup.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType file -Path "$RunLocation\Logs\NvidiaSetup.log" -Force
#}

#Start-Transcript -Path "$RunLocation\Logs\NvidiaSetup.log"

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


$RemoveNvidiaDriver = $Settings.GPU.REMOVECURRENTDRIVER

if ($RemoveNvidiaDriver -match "y") {

    #$ServerType = $Settings.general.SERVERTYPE

    #Adds Reg Key to stop Automatic Driver Install
    if ($Null -eq (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -name "ExcludeWUDriversInQualityUpdate" -errorAction SilentlyContinue)) {
        #Write-Host "Adding Reg Key to stop Automatic Driver Installation" -ForegroundColor Yellow
        Write-PSULog -Severity Info -Message "Adding Reg Key to stop Automatic Driver Installation"
        New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force |  New-ItemProperty -Name "ExcludeWUDriversInQualityUpdate"  -PropertyType dword -Value "1"
        #Write-Host "Added Reg Key to stop Automatic Driver Installation" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Added Reg Key to stop Automatic Driver Installation"
    }

    #Runs the DDU to remove all of the Nvidia Components
    $DDU = "$RunLocation\bin\DDU\Display Driver Uninstaller.exe"
    Write-PSULog -Severity Info -Message "Removing all Nvidia Components"
    #Write-Host "Removing all Nvidia Components" -ForegroundColor Yellow
    Start-Process  $DDU -ArgumentList "-silent -nosafemodemsg -cleannvidia" -Wait
    #Write-Host "Finished Removing all Nvidia Components. Please reboot before re-installing" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Finished Removing all Nvidia Components. Please reboot before re-installing"

    #Sets the Nvidia Driver to install on next boot
    #if ($ServerType -match "app") {
    #    #Write-Host "Setting Nvidia driver to install on next boot" -ForegroundColor Green
    #    Write-PSULog -Severity Info -Message "Setting Nvidia driver to install on next boot"
    #    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    #    Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\InstallNvidiaDriver.ps1"
    #}

    
    #$Readhost = $Settings.general.AUTOREBOOT
    #Switch ($ReadHost) {
    #    Y {Write-host "Rebooting now..."; Start-Sleep -s 2; Restart-Computer -Force}
    #    N {Write-Host "Exiting script in 5 seconds. Please Reboot to continue the Script."; Start-Sleep -s 5}
    #    Default {Write-Host "Exiting script in 5 seconds. Please Reboot to continue the Script."; Start-Sleep -s 5}
    #}
}
#Stop-Transcript