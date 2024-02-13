#------------------------------------------------------
# Name:        CitrixInstall
# Purpose:     Installs Citrix VDA
# Author:      John Burriss
# Created:     1/6/2020  9:49 PM 
#------------------------------------------------------

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
cd ..
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


#$Path = "$RunLocation\Logs\CitrixSetup.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\CitrixSetup.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\CitrixSetup.log" -Force


if($Settings.CITRIX.OMITTEDSERVERS -notcontains $env:COMPUTERNAME ){

$CitrixLocation = $Settings.CITRIX.CITRIXISOLOCATION

if(Test-Path -Path $CitrixLocation){

    # Extracts the Citrix ISO to the $RunLocation\Bin\Citrix Folder
    #Write-Host "Mounting disk image file '$ImageFile'..."
    Write-PSULog -Severity Info -Message "Mounting disk image file '$ImageFile'..."
    $DiskImage = Mount-DiskImage $CitrixLocation -PassThru
    $DriveLetter = (Get-Volume -DiskImage $DiskImage).DriveLetter
    $DriveLetter = $DriveLetter + ":\"
    #Write-Host "Copying contents of Citrix ISO to $RunLocation\bin\Citrix" -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Copying contents of Citrix ISO to $RunLocation\bin\Citrix"
    robocopy $DriveLetter "$RunLocation\bin\Citrix\" /E /NFL /NDL /NJH /NJS /nc /ns /np
    #Write-host "Copied contents of Citrix iso to $RunLocation\bin\Citrix" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Copied contents of Citrix iso to $RunLocation\bin\Citrix"
    Dismount-DiskImage -InputObject $DiskImage
}

# Pauses Install if the ISO path is incorrect
else{
    Write-Host "Path to Citrix ISO incorrect. Please Unzip Citrix iso into $RunLocation\bin\Citrix" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Path to Citrix ISO incorrect. Please Unzip Citrix iso into $RunLocation\bin\Citrix"
    Write-PSULog -Severity Warning -Message 'Press any key to continue when the ISO is unzipped'
    Write-Host -NoNewLine 'Press any key to continue when the ISO is unzipped';
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
}

#Sets up the installer and runs the Installation
$DeliveryControllers = $Settings.CITRIX.DELIVERYCONTROLLERS

#Write-Host "Installing Citrix VDA" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Installing Citrix VDA"

Start-process "$RunLocation\bin\Citrix\x64\XenDesktop Setup\XenDesktopVDASetup.exe" -ArgumentList "/components VDA /controllers `"$DeliveryControllers`" /disableexperiencemetrics /enable_framehawk_port /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /exclude `"Personal vDisk, Citrix Personalization for App-V - VDA`" /optimize /logpath $RunLocation\VDAInstallLogs /noreboot /quiet" -wait

    if((get-process | Where-Object {$_.ProcessName -match "XenDesktopVdaSetup"})){

        #Write-host "Waiting for Citrix  Setup to Complete" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Waiting for Citrix  Setup to Complete"

    }


    while((get-process | Where-Object {$_.ProcessName -match "XenDesktopVdaSetup"})){

        start-sleep -Seconds 5

    }

#Write-Host "Finished Citrix VDA, A Reboot is required to complete the Install" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Finished Citrix VDA, A Reboot is required to complete the Install"

#Stop-Transcript
}
Else{

    Write-PSULog -Severity Info -Message "Machine $env:COMPUTERNAME is listed in Omitted Servers. Skipping Citrix VDA Install"
    
}