#$RunLocation\bin\Licensing\LMXServer\lmx-enduser-tools_v4.8.12_win64_x64.msi INSTALLSERVER=1 VENDORDLLPATH=$RunLocation\bin\Licensing\LMXServer\liblmxvendor.dll INSTALLSERVICE=1
#------------------------------------------------------
# Name:        Licensing Install
# Purpose:     Removes Old Versions of LMX and Installs the LMX Utility and moves the license file into the proper folder and starts the service
# Author:      John Burriss
# Created:     12/11/2019  8:45 PM 
# Modified:    10/13/2019 1:33 PM
#------------------------------------------------------
#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
cd ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

#$Path = "$RunLocation\Logs\LicenseInstall.log"

#if (!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\LicenseInstall.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\LicenseInstall.log"

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

if($Settings.LICENSING.DESIGNATEDSERVER -contains $env:computername -or $null -eq $Settings.LICENSING.DESIGNATEDSERVER){
if($settings.GENERAL.INSTALLLMX -match "y"){

Try{
    Write-PSULog -Severity Info -Message "Checking for Previous Versions of LMX Service"
    $LMXServices = get-service | Where-Object {$_.DisplayName -match "LM-X license server*"}

    if($Null -ne $LMXServices){
        Write-PSULog -Severity Info -Message "Found Other Versions of LMX Service Installed"
        Try{
            Write-PSULog -Severity Info -Message "Trying to Stop and Disable old LMX Services."
            foreach($LMXService in $LMXServices){
                $LMXService | Stop-Service
                $LMXService | Set-Service -Status Disable
            }
            Write-PSULog -Severity Info -Message " Old LMX Services Stopped and Disabled."
        }
        Catch{
            Write-PSULog -Severity Error -Message "Failed to Stop and Disable Old LMX Services." 
        }
        Write-PSULog -Severity Info -Message "Trying to Uninstall Previous Versions of LMX"
        $LMXAPPs = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -match "LM-X*"}
        try{
            Foreach($LMXAPP in $LMXAPPs){
                $LMXAPP.Uninstall() | out-null
            }
            Write-PSULog -Severity Info -Message "Sucesfully Uninstalled Old LMX Versions"
        }
        Catch{
            Write-PSULog -Severity Error -Message "Failed to Uninstall Old LMX Versions. Please remove manually."
        }

    }

}
Catch{

}

Try{
    #Write-Host "Installing the LMX Utility" -ForegroundColor Yellow
    Write-PSULog -Severity Start -Message "Installing the LMX Utility"
    Start-Process "$RunLocation\Bin\Licensing\LMXServer\lmx-enduser-tools_win64_x64.msi" -ArgumentList "INSTALLSERVER=1 VENDORDLLPATH=$RunLocation\bin\Licensing\LMXServer\liblmxvendor.dll INSTALLSERVICE=1 /qr" -Wait
    #Write-Host "Finished Installing LMX Utility" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Finished Installing LMX Utility"

#Write-Host "Moving License and Dll Files" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Moving License and Dll Files"

if(Test-Path -Path "C:\Program Files\X-Formation\LM-X End-user Tools 5.4.1 x64"){
Copy-Item -path "$RunLocation\bin\Licensing\matrix64.dll" -Destination "C:\Program Files\X-Formation\LM-X End-user Tools 5.4.1 x64" -Force
#Write-Host "Copied the Matrix64.dll file to the LMX folder" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Copied the Matrix64.dll file to the LMX folder"
}
Else{
    #Write-Host "Failed to Move the Matrix64.dll to LMX folder" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Failed to Move the Matrix64.dll to LMX folder"
}
#if(!(Test-Path -Path "C:\Windows\System32\config\systemprofile\AppData\Local\x-formation")){
#   New-Item -ItemType Directory -Path "C:\Windows\System32\config\systemprofile\AppData\Local\x-formation"
#}

if(test-Path -Path $Settings.LICENSING.LICENSELOCATION){
    Copy-Item -path $Settings.LICENSING.LICENSELOCATION -Destination "C:\Program Files\X-Formation\LM-X End-user Tools 5.4.1 x64\"
    #Write-Host "Moved the License File to the Correct Location." -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Moved the License File to the Correct Location."
}
Else{
    #Write-Host "No License found in Setup.json. Please Manually Add the license file and restart the LMX service" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "No License found in Setup.json. Please Manually Add the license file and restart the LMX service"
}

if($Settings.LICENSING.CONFIGUREHAL -match "Y"){
    Write-PSULog -Severity Info -Message "Configuring LMX HAL."
    $HALSERVER1 = $Settings.LICENSING.HALSERVER1
    $HALSERVER2 = $Settings.LICENSING.HALSERVER2
    $HALSERVER3 = $Settings.LICENSING.HALSERVER3

    if([string]::IsNullOrEmpty($HALSERVER1) -or [string]::IsNullOrEmpty($HALSERVER2) -or [string]::IsNullOrEmpty($HALSERVER3)){
        Write-PSULog -Severity Error -Message "Missing HAL Server in Setup.json. Please correct and try again."
        break
    }

    $LMXConfigFile = "C:\Program Files\X-Formation\LM-X End-user Tools 5.4.1 x64\lmx-serv.cfg"

    if(Test-path -path $LMXConfigFile){
        Add-Content $LMXConfigFile "HAL_SERVER1 = 6200@$HALServer1"
        Add-Content $LMXConfigFile "HAL_SERVER1 = 6200@$HALServer2"
        Add-Content $LMXConfigFile "HAL_SERVER1 = 6200@$HALServer3"

    }
    else{
        Write-PSULog -Severity Error -Message "Unable to find LMX Configuration File."
    }

}

#Write-Host "Restarting the LMX Service" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Restarting the LMX Service"
$Service = Get-service | Where-Object { $_ -match "LMX"}
if($Null -ne $Service){
    Try{
    Restart-Service -Name $Service.Name
    Get-Service -Name $service.Name
    #Write-Host "Restarted the LMX Service" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Restarted the LMX Service"
    }
    Catch{
        #Write-Host "Unable to restart the LMX service, Please Manually restart the service" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Unable to restart the LMX service, Please Manually restart the service"
    }
}
Else{
    #Write-Host "Unable to Locate the LMX Service. Please make sure that it is installed correctly." -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Unable to Locate the LMX Service. Please make sure that it is installed correctly."
}

}

Catch{
    #Write-Host "Errors Installing the LMX utility. Please Install Manually" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Errors Installing the LMX utility. Please Install Manually"
}

}

if($settings.LICENSING.LOCALLICENSE -match "y"){
    #Write-Host "Installing the License Locally" -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Installing the License Locally"
    Try{
        #Write-Host "Attempting to Copy License File to C:\Program Files\RaySearch Laboratories\LicenseFile"
        Write-PSULog -Severity Info -Message "Attempting to Copy License File to C:\Program Files\RaySearch Laboratories\LicenseFile"
        if(!(Test-Path -Path "C:\Program Files\RaySearch Laboratories\LicenseFile")){
            New-Item -ItemType Directory -Path "C:\Program Files\RaySearch Laboratories\LicenseFile"
        }
        if((test-Path -Path $Settings.LICENSING.LICENSELOCATION) -eq $true){
            Copy-Item -path $Settings.LICENSING.LICENSELOCATION -Destination "C:\Program Files\RaySearch Laboratories\LicenseFile"
            #Write-Host "Moved the License File to the Correct Location."
            Write-PSULog -Severity Info -Message "Moved the License File to the Correct Location."
        }
        Else{
            #Write-Host "No License found in Setup.json. Please Manually Add the license file and restart the LMX service" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "No License found in Setup.json. Please Manually Add the license file and restart the LMX service"
        }

}
Catch{
    #Write-Host "Unable to Move License File to C:\Program Files\RaySearch Laboratories\LicenseFile" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Unable to Move License File to C:\Program Files\RaySearch Laboratories\LicenseFile"
}
}
}
else{
    Write-PSULog -Severity Info -Message "Skipping LMX Install because Machine was not listed as a designated server."
}
#Stop-Transcript