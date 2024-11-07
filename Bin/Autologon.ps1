#------------------------------------------------------
# Name:        AutoLogon
# Purpose:     Enables Auto Logon
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
if([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True){

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}else{
$null = $RemoteLogLocation
}
#----------------------------------------------------------------------------------------------
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

#$Path = "$RunLocation\Logs\AutoLogon.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\AutoLogon.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\AutoLogon.log" -Force -Append

#$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json

$AutoLoginChoice = $Settings.general.ENABLEAUTOLOGON
if ($AutoLoginChoice -match "y") {
    #Write-Host "Enabling Auto Logon" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Enabling Auto Logon"
    $Autologon = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $Username = Read-Host "Enter the Remote Username"
    $Password = Read-Host "Please enter the Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $TempPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $Domain = $username.split("\")[0]
    $username = $username.split("\")[1]

    if($CleanDomain -match '`.' -or $CleanDomain -match 'localhost'){
        $CleanDomain = "$env:COMPUTERNAME"
   }


    $autologonexe = "$RunLocation\bin\Autologon.exe"
    $username = "$username"
    $domain = "$CleanDomain"
    
    Start-Process $autologonexe -ArgumentList "/accepteula", $username, $domain, $Temppassword -PassThru
    Clear-Variable -name TempPassword
    #Write-host "Enabling machine to Auto Logon 2 times" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Enabling machine to Auto Logon 2 times"
    Set-ItemProperty $Autologon "AutoLogonCount" -Value "2" -type dword
    #Write-Host "Machine is set to Auto Login 2 times." -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Machine is set to Auto Login 2 times."
}

#Stop-Transcript