#------------------------------------------------------
# Name:        InstallAdobe
# Purpose:     Installs Adobe
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

#$Path = "$RunLocation\Logs\InstallAdobe.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\InstallAdobe.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\InstallAdobe.log" -Force -Append

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



$INSTALLADOBE = $Settings.General.INSTALLADOBE

Switch ($INSTALLADOBE) {
    Y{
#Installs Adobe Reader DC
#Write-Host "Installing Adobe Reader" -ForegroundColor Yellow
Write-PSULog -Severity Start -Message "Installing Adobe Reader"
& $RunLocation\bin\Acrobat\AcroRdrDC1502320070_en_US.exe /sAll | Out-Null
#Write-Host "Finished Installing Acrobat Reader" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Finished Installing Acrobat Reader"
    }
    
    N {
        #Write-Host "Skipping Adobe Install"
        Write-PSULog -Severity Info -Message "Skipping Adobe Install"
    }
    default{
        #Write-Host "Skipping Adobe Install"
        Write-PSULog -Severity Info -Message "Skipping Adobe Install"
    }
}
#Stop-Transcript