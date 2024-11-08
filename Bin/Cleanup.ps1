#------------------------------------------------------
# Name:        Cleanup
# Purpose:     Removes All Leftover files from setup
# Author:      John Burriss
# Created:     8/26/2019  5:24 PM 
#------------------------------------------------------
#Requires -RunAsAdministrator

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

    if((get-process | Where-Object {$_.ProcessName -match "XenDesktopVdaSetup"})){

        #Write-host "Waiting for Citrix  Setup to Complete" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Waiting for Citrix  Setup to Complete"

    }


    while((get-process | Where-Object {$_.ProcessName -match "XenDesktopVdaSetup"})){

        start-sleep -Seconds 5

    }

$Readhost1 = $Settings.general.UPDATEWINDOWS
Switch ($ReadHost1) { 
    Y {
        Write-PSULog -Severity Info -Message "Starting Windows Updates"
        & $RunLocation\bin\UpdateWindows.ps1
    }
    N {
        #Write-Host "Skipping Windows Updates" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Windows Updates"
    } 
    Default {
        #Write-Host "Skipping Windows Updates" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Windows Updates"
    } 
}

#Runs Machine Info Script before Final Cleanup
& $RunLocation\bin\MachineInfo.ps1

#Removes Leftover Reg keys of they exist
#Write-Host "Removing Leftover Reg Keys" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Removing Leftover Reg Keys"
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$RegistryRunOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
$MachineSetupKeyPath = "HKLM:\SOFTWARE\MachineSetup"

if(Get-ItemProperty -Path $RegistryRunOncePath -Name "NextRun" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $RegistryRunOncePath -Name "NextRun"}
if(Get-ItemProperty -Path $RegistryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $RegistryPath -Name "AutoAdminLogon"}
if(Get-ItemProperty -Path $RegistryPath -Name "DefaultUsername" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $RegistryPath -Name "DefaultUsername"}
if(Get-ItemProperty -Path $RegistryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $RegistryPath -Name "DefaultPassword"}
if(Get-ItemProperty -Path $RegistryPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $RegistryPath -Name "DefaultDomainName"}
if(Get-ItemProperty -Path $MachineSetupKeyPath -Name "Password" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $MachineSetupKeyPath -Name "Password"}
if(Get-ItemProperty -Path $MachineSetupKeyPath -Name "UserName" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $MachineSetupKeyPath -Name "UserName"}
if(Get-ItemProperty -Path $MachineSetupKeyPath -Name "Domain" -ErrorAction SilentlyContinue){Remove-ItemProperty -Path $MachineSetupKeyPath -Name "Domain"}
Remove-Item -Path $MachineSetupKeyPath -Force -ErrorAction SilentlyContinue

Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\ -Name 'LastLoggedOnUser' -Value '' -ErrorAction SilentlyContinue
Set-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\ -Name 'LastLoggedOnUserSID' -Value '' -ErrorAction SilentlyContinue

Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\ -Name 'LastLoggedOnUser'
Get-ItemProperty -path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\ -Name 'LastLoggedOnUserSID'

#Write-Host "Keys Removed" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Keys Removed"

#Write-Host "Creating C:\Temp and Moving Logs and setting up final cleanup" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Creating C:\Temp and Moving Logs and setting up final cleanup"
$Path = "C:\Temp"
if(!(Test-Path $Path)) { 
mkdir "C:\Temp"
}
Copy-Item "$RunLocation\Logs\*.json" "C:\Temp" -ErrorAction SilentlyContinue
Copy-Item "$RunLocation\Logs\*.txt" "C:\Temp" -ErrorAction SilentlyContinue
Copy-Item "$RunLocation\Logs\*.log" "C:\Temp" -ErrorAction SilentlyContinue
Copy-Item "$RunLocation\VDALOGS\" "C:\Temp\" -Recurse -ErrorAction SilentlyContinue
Copy-Item "$RunLocation\bin\FinalCleanup.ps1" "C:\Temp\"

$Run = "C:\Temp\FinalCleanup.ps1 -RunLocation $RunLocation -remoteloglocation $RemoteLogLocation"

start-process powershell  -argument "-noexit -nologo -noprofile -file $Run"
