#------------------------------------------------------
# Name:        SQLDriveSetup
# Purpose:     Sets up Drives for SQL server setup and passes info to the SQL install script
# Author:      John Burriss
# Created:     10/10/2022  2:24 PM 
#------------------------------------------------------

#Requires -RunAsAdministrator

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

#$Path = "$RunLocation\Logs\SQLDriveSetup.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\SQLDriveSetup.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\SQLDriveSetup.log" -Force -Append

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

$newdisk = @(get-disk | Where-Object partitionstyle -eq 'raw')

$newdiskcount = $newdisk.number.count

$uniquedisknumber = $Settings.DRIVES.DriveNumber | Get-Unique

if($uniquedisknumber.count -ne $Settings.DRIVES.DriveNumber.count){
    
    #Write-host "JSON DriveNumber contains non unique Numbers. Please ensure that all drive numbers are unique and sequntial." -ForegroundColor Red
    Write-PSULog -Severity Error -Message "JSON DriveNumber contains non unique Numbers. Please ensure that all drive numbers are unique and sequntial."
    #Write-Host "Exiting Script" -ForegroundColor Red
    Write-PSULog -Severity Warning -Message "Exiting Script"
    start-sleep 10
    exit
}

$uniqueDriveLetter = $Settings.DRIVES.DriveLetter | Get-Unique

if ($uniqueDriveLetter.count -ne $settings.DRIVES.DriveLetter.count){
    
    #Write-Host "JSON DriveLetter contains non unique Letters. Please ensure that all drive letters are unique." -ForegroundColor Red
    Write-PSULog -Severity Error -Message "JSON DriveLetter contains non unique Letters. Please ensure that all drive letters are unique."
    #Write-Host "Exiting Script" -ForegroundColor Red
    Write-PSULog -Severity Warning -Message "Exiting Script"
    start-sleep 10
    exit
}

$uniqueDriveLabel = $Settings.DRIVES.DriveLabel | Get-Unique

if ($uniqueDriveLabel.count -ne $settings.DRIVES.DriveLabel.count){
    
    #Write-Host "JSON DriveLabel contains non unique Lables. Please ensure that all drive Lables are unique." -ForegroundColor Red
    Write-PSULog -Severity Error -Message "JSON DriveLabel contains non unique Lables. Please ensure that all drive Lables are unique."
    #Write-Host "Exiting Script" -ForegroundColor Red
    Write-PSULog -Severity Warning -Message "Exiting Script"
    start-sleep 10
    exit
}


if ($newdiskcount -ne $Settings.DRIVES.DriveNumber.count){

    #Write-host "New Disk Count does not match count in JSON file. Please fix count to match $newdiskcount Disks." -ForegroundColor Red
    Write-PSULog -Severity Error -Message "New Disk Count does not match count in JSON file. Please fix count to match $newdiskcount Disks."
    #Write-Host "Exiting Script" -ForegroundColor Red
    Write-PSULog -Severity Warning -Message "Exiting Script"
    start-sleep 10
    exit

}

$driveLetters = (Get-PSDrive).Name -match '^[a-z]$'

foreach ($driveLetterJSON in $settings.Drives.DriveLetter){

    foreach ($driveLetter in $driveLetters){

    if($driveLetter -match $driveLetterJSON){

            #Write-host "One of the DriveLetters $driveLetter already exists on the system. Please update the JSON file to fix this conflict." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "One of the DriveLetters $driveLetter already exists on the system. Please update the JSON file to fix this conflict."
            #Write-Host "Exiting Script" -ForegroundColor Red
            Write-PSULog -Severity Warning -Message "Exiting Script"
            start-sleep 10
          

        }

    }

}

$SettingsDrives = $Settings.DRIVES
foreach ($disk in $newdisk){
    $diskNumber = $disk.number
    
    foreach($drive in $SettingsDrives){
       $DriveINT = $drive.DriveNumber
        if($diskNumber -match $DriveINT){

          get-disk -number $driveINT | Initialize-Disk -PartitionStyle GPT -PassThru | New-Partition -DriveLetter $drive.DriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel $drive.DriveLabel -AllocationUnitSize 65536 -Confirm:$false
        }
     }
 }
 #Write-Host "Restarting Explorer to clear screen." -ForegroundColor Green
 Write-PSULog -Severity Info -Message "Restarting Explorer to clear screen."
 Stop-Process -name explorer -force

 #Stop-Transcript