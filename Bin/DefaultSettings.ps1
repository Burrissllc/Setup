#------------------------------------------------------
# Name:        DefaultSettings
# Purpose:     Sets the Default Machine Settings
# Author:      John Burriss
# Created:     10/12/2022  5:24 PM 
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
        [string]$RemotelogDirectory="$RemoteLogLocation"
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

#$Path = "$RunLocation\Logs\DefaultSettings.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\DefaultSettings.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\DefaultSettings.log" -Force -Append

#$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json

# Checking Windows version
if ((Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName -ExpandProperty ProductName) -match "Windows 10" -or  "Windows 11") {
    $windowsVersion = "Desktop"
}
else {
    $windowsVersion = "other"
}

$TimeZone = $Settings.general.TIMEZONE

if ($TimeZone -match "EST") {
    Set-TimeZone -Name "Eastern Standard Time"
}
elseif ($TimeZone -match "CST") {
    Set-TimeZone -Name "Central Standard Time"
}
elseif ($TimeZone -match "MST") {
    Set-TimeZone -Name "Mountain Standard Time"
}
elseif ($TimeZone -match "PST") {
    Set-TimeZone -Name "Pacific Standard Time"
}
elseif ($TimeZone -match "AST") {
    Set-TimeZone -Name "Alaskan Standard Time"
}
elseif ($TimeZone -match "HST") {
    Set-TimeZone -Name "Hawaiian Standard Time"
}
else {
    #Write-Host "Selection was not valid. Please change Timezone Manually" -ForegroundColor red
    Write-PSULog -Severity Warning -Message "Selection was not valid. Please change Timezone Manually"
}


#Set Power Settings
try {
    Powercfg -setacvalueindex scheme_current sub_processor 45bcc044-d885-43e2-8605-ee0ec6e96b59 100
    Powercfg -setactive scheme_current
    Powercfg -setacvalueindex scheme_current sub_processor 893dee8e-2bef-41e0-89c6-b55d0929964c 100
    Powercfg -setactive scheme_current
    Powercfg -setacvalueindex scheme_current sub_processor bc5038f7-23e0-4960-96da-33abaf5935ec 100
    Powercfg -setactive scheme_current
    powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
    Powercfg -setactive scheme_current
    POWERCFG.EXE /S SCHEME_MIN
    Powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
    Powercfg -setactive scheme_current
    Powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
    Powercfg -setactive scheme_current
    Powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2
    Powercfg -setactive scheme_current
    #Write-Host "Power Setthings have been applied." -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Power Setthings have been applied."
}
Catch {
    #Write-Host "Failed to set Power Settings" -ForegroundColor Red 
    Write-PSULog -Severity Error -Message "Failed to set Power Settings"
}

#Disable IE Enhanced Security and UAC
function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    #Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
    Write-PSULog -Severity Info -Message "IE Enhanced Security Configuration (ESC) has been disabled."
}
function Disable-UserAccessControl {
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 00000000 -Force
    #Write-Host "User Access Control (UAC) has been disabled." -ForegroundColor Green
    Write-PSULog -Severity Info -Message "User Access Control (UAC) has been disabled." 
}
try {
    Disable-UserAccessControl
}
Catch {
    #Write-Host "Failed to Disable UAC" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Failed to Disable UAC"
}
if (($windowsVersion) -match "other") {
    try {
        Disable-InternetExplorerESC
    }
    Catch {
        #Write-Host "Failed to disable IE Enhanced Security" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Failed to disable IE Enhanced Security"
    }
}
#Disable Firewall
Try {
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
    #Write-Host "Firewall Disabled" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Firewall Disabled"
}
Catch {
    #Write-Host "Failed to Disable the Firewall" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Failed to Disable the Firewall"
}
#Enable RDP
Try {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    #Write-Host "Remote Desktop has been enabled" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Remote Desktop has been enabled"
}
Catch {
    #Write-Host "Failed to enable RDP"
    Write-PSULog -Severity Error -Message "Failed to enable RDP"
}
#Enables .net 3.5
#Write-Host "Enabling .net 3.5" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Enabling .net 3.5"
Add-WindowsCapability -Online -Name NetFx3~~~~ -Source $RunLocation\bin\.net
#Write-Host "Enabled .net 3.5" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Enabled .net 3.5"

#Stop-Transcript