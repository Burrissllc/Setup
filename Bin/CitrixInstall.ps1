<#
.SYNOPSIS
    This script installs Citrix VDA based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if Citrix VDA should be installed.
    It mounts the Citrix ISO or extracts the Citrix EXE and runs the installation.
    Logs are created locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\CitrixInstall.ps1
    Runs the script to install Citrix VDA if configured to do so.

.NOTES
    Author: John Burriss
    Created: 1/6/2020
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>

#requires -RunAsAdministrator

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
if ([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True) {

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}
else {
    $null = $RemoteLogLocation
}
#----------------------------------------------------------------------------------------------
function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory = "$RunLocation\Logs\",
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


#$Path = "$RunLocation\Logs\CitrixSetup.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\CitrixSetup.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\CitrixSetup.log" -Force


if ($Settings.CITRIX.OMITTEDSERVERS -notcontains $env:COMPUTERNAME ) {

    $CitrixLocation = $Settings.CITRIX.CITRIXISOLOCATION

    if (Test-Path -Path $CitrixLocation) {

        If ($CitrixLocation -like "*.iso") {

            #Write-Host "Citrix ISO Found" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Citrix ISO Found"
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
            $CitrixEXE = "$RunLocation\bin\Citrix\x64\XenDesktop Setup\XenDesktopVDASetup.exe"
        }   
        elseif ($CitrixLocation -like "*.exe") {

            #Write-Host "Citrix EXE Found" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Citrix EXE Found"
            # Extracts the Citrix EXE to the $RunLocation\Bin\Citrix Folder
            #Write-Host "Extracting Citrix EXE to $RunLocation\bin\Citrix" -ForegroundColor Yellow
            $CitrixEXE = $CitrixLocation

        }
        else {

            #Write-Host "Citrix ISO/EXE Not Found" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "Citrix ISO/EXE Not Found"
            break
        }

        #Sets up the installer and runs the Installation
        $DeliveryControllers = $Settings.CITRIX.DELIVERYCONTROLLERS

        #Corrects delimiter
        $DeliveryControllers = $DeliveryControllers -replace ",", " "

        $DeliveryControllers = $DeliveryControllers -replace ";", " "

        #Write-Host "Installing Citrix VDA" -ForegroundColor Yellow
        Write-PSULog -Severity Info -Message "Installing Citrix VDA"

        #$InstallNvidiaDriver = $Settings.GENERAL.INSTALLGPUDRIVER
        #$Cleanup = $Settings.GENERAL.CLEANUP
        #if ($InstallNvidiaDriver -match "y" -or $Cleanup -match "y") {
        #    Start-process $CitrixEXE -ArgumentList "/components VDA /controllers `"$DeliveryControllers`" /disableexperiencemetrics /enable_framehawk_port /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /exclude `"Personal vDisk, Citrix Personalization for App-V - VDA`" /optimize /logpath $RunLocation\VDAInstallLogs /noreboot /NORESUME /quiet" -wait
        #}
        #else {
        Start-process $CitrixEXE -ArgumentList "/components VDA /controllers `"$DeliveryControllers`" /disableexperiencemetrics /enable_framehawk_port /enable_hdx_ports /enable_hdx_udp_ports /enable_real_time_transport /enable_remote_assistance /exclude `"Personal vDisk, Citrix Personalization for App-V - VDA`" /optimize /logpath $RunLocation\VDAInstallLogs /noreboot /quiet" -wait    
        #}
        if ((get-process | Where-Object { $_.ProcessName -match "XenDesktopVdaSetup" })) {

            #Write-host "Waiting for Citrix  Setup to Complete" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Waiting for Citrix  Setup to Complete"

        }


        while ((get-process | Where-Object { $_.ProcessName -match "XenDesktopVdaSetup" })) {

            start-sleep -Seconds 5

        }

        #Write-Host "Finished Citrix VDA, A Reboot is required to complete the Install" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Finished Citrix VDA, A Reboot is required to complete the Install"

        $SeamlessFlags = "HKLM:\System\CurrentControlSet\Control\Citrix\wfshell\TWI"
        if (!(Test-Path $SeamlessFlags)) {
            Write-PSULog -Severity Info -Message "Setting the Seamless Flag for Citrix"
            New-Item $SeamlessFlags -Force -ErrorAction SilentlyContinue | New-ItemProperty -Name "SeamlessFlags" -Value "0x20" -Type DWord
        }
        else {
            Write-PSULog -Severity Info -Message "Setting the Seamless Flag for Citrix"
            New-ItemProperty -Name "SeamlessFlags" -Value "0x20" -Type DWord -Path $SeamlessFlags -Force
        }

        #Stop-Transcript
    }
}
Else {

    Write-PSULog -Severity Info -Message "Machine $env:COMPUTERNAME is listed in Omitted Servers. Skipping Citrix VDA Install"
    
}