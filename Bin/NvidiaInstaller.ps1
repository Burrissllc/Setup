<#
.SYNOPSIS
    Installs Nvidia GPU drivers and configures settings based on a JSON configuration file.

.DESCRIPTION
    This script installs Nvidia GPU drivers, configures Nvidia Control Panel settings, and handles licensing for virtual GPUs.
    It reads settings from a JSON configuration file and logs the process locally and optionally to a remote location.

.PARAMETER None
    This script does not take any parameters.

.NOTES
    Author: John Burriss
    Created: 12/16/2019 2:07 PM
    Requires: Run as Administrator

.EXAMPLE
    .\NvidiaInstaller.ps1
    Runs the script to install and configure Nvidia GPU drivers based on the settings in Setup.json.

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

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
#----------------------------------------------------------------------------------------------
if ($Settings.GENERAL.REMOTELOGGINGLOCATION -ne $null) {

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}

function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory = "$RunLocation\Logs\",
        $RemotelogDirectory = $RemoteLogLocation
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


#Start-Transcript -Path "$RunLocation\Logs\NvidiaSetup.log"

if ($Settings.GPU.OMITTEDSERVERS -notcontains $env:COMPUTERNAME ) {


    if (Test-Path -Path $Settings.GPU.DRIVERLOCATION) {

        if (Test-path -Path "$RunLocation\bin\nvidia\Install") {
            Remove-Item "$RunLocation\bin\nvidia\Install\*" -Recurse -Force
        }

        #Extracts the setup files from the exe
        $fileToExtract = $settings.GPU.DRIVERLOCATION
        $extractFolder = "$RunLocation\bin\Nvidia\Install"
        $filesToExtract = "Display.Driver NVI2 EULA.txt ListDevices.txt setup.cfg setup.exe"
        $7z = "$RunLocation\bin\7-ZipPortable\App\7-Zip64\7z.exe"

        #Write-Host "Extracting the Driver" -ForegroundColor Yellow
        Write-PSULog -Severity Start -Message "Extracting the Nvidia Driver"
        Start-Process -FilePath $7z -ArgumentList "x $fileToExtract $filesToExtract -o""$extractFolder""" -wait
        #Write-Host "Finished Extracting the Driver" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Finished Extracting the Driver"
        #Removes the dependencies in the config file 
        #Write-Host "Editing the Driver Config File" -ForegroundColor Yellow
        Write-PSULog -Severity Info -Message "Editing the Driver Config File"
(Get-Content "$extractFolder\setup.cfg") | Where-Object { $_ -notmatch 'name="\${{(EulaHtmlFile|FunctionalConsentFile|PrivacyPolicyFile)}}' } | Set-Content "$extractFolder\setup.cfg" -Encoding UTF8 -Force
        #Write-Host "Finished editing the Driver config file" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Finished editing the Driver config file"

        #Installs the GPU Driver with Args
        $install_args = "-s -noreboot -noeula"

        if ($settings.GPU.CLEANINSTALL -match "y") {
            $install_args = $install_args + " -clean"
        }
        #Write-Host "Starting the Driver Install" -ForegroundColor Yellow
        Write-PSULog -Severity Start -Message "Starting the Nvidia Driver Install"
        Start-Process -FilePath "$extractFolder\setup.exe" -ArgumentList $install_args -wait
        #Write-Host "Finished Installing the Display Driver" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Finished Installing the Display Driver"



        if (Test-Path "$RunLocation\bin\NvidiaPerformance.ps1") {
            $RunOnceKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\NvidiaPerformance.ps1"
            #Write-Host "Cards will be optimized on next boot." -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Cards will be optimized on next boot."
        }


        $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Get-ItemProperty -Path $RegistryPath -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue) {
            #Write-Host "Removing Auto Driver Update Reg Key" -ForegroundColor Yellow
            Write-PSULog -Severity Info -Message "Removing Auto Driver Update Reg Key"
            Remove-ItemProperty -Path $RegistryPath -Name "ExcludeWUDriversInQualityUpdate"
            #Write-Host "Removed Auto Driver Update Reg Key" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Removed Auto Driver Update Reg Key"
        }
    }

    Else {
        #Write-Host "Unable to locate GPU driver specified in the setup.json file. Please Install the Driver Manually" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Unable to locate GPU driver specified in the setup.json file. Please Install the Driver Manually"
        #Write-Host "Please correct location in the config and run $RunLocation\bin\NvidiaInstaller.ps1 again." -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Please correct location in the config and run $RunLocation\bin\NvidiaInstaller.ps1 again."
    }

    #$Readhost = $Settings.general.AUTOREBOOT
    #Switch ($ReadHost) {
    #    Y {Write-host "Rebooting now..."; Start-Sleep -s 2; Restart-Computer -Force}
    #    N {Write-Host "Exiting script in 5 seconds."; Start-Sleep -s 5}
    #    Default {Write-Host "Exiting script in 5 seconds"; Start-Sleep -s 5}
    #}

    #Checks and sets the Nvidia-SMI location based on Driver version
    if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
        $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
    }
    elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
        $NVSMILocation = "C:\Windows\System32"
    }
    elseif (Test-Path ((gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent)) {
        $NVSMILocation = (gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent
    }

    if ($null -ne $NVSMILocation) {

        $NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q
        if ($NvidiaQuery -match "NVIDIA-SMI has failed") {
            $NoGPU = $true
        }
        else {
            $NoGPU = $false
        }
        if ($NoGPU) {
            #Write-Host "No Nvidia GPU Detected" -ForegroundColor Red
            Write-PSULog -Severity Warn -Message "No Nvidia GPU Detected"
        }
        else {
            #Write-Host "Nvidia GPU Detected" -ForegroundColor Green
            Write-PSULog -Severity Info -Message "Nvidia GPU Detected"
            $GPUType = $NvidiaQuery | Where-Object { $_ -match 'Virtualization Mode\s*:' } | % { $_.Split(":")[1] }
            $GPUType = $GPUType.replace(' ', '')

            if ($GPUType -notmatch "None") {

                if ($GPUType -match "VGPU") {

                    if (Test-Path -Path $Settings.GPU.NVIDIALICENSETOKENLOCATION) {
                        #Write-Host "Copying Nvidia License Token" -ForegroundColor Green
                        Write-PSULog -Severity Info -Message "Copying Nvidia License Token"
                        $token = $Settings.GPU.NVIDIALICENSETOKENLOCATION
                        $TokenDir = $token | split-path
                        $tokenName = $token | Split-Path -Leaf
                        try {
                            #Copy-Item -Path $token -Destination "C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\" -Force
                            robocopy $TokenDir "C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken" $tokenName
                        }
                        catch {
                            Write-PSULog -Severity Error -Message "Failed to copy License token to C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\"
                        }
                        $TokenName = split-path $token -Leaf -Resolve
                        $licensePath = "C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\$tokenName"
                        if (!(Test-path -Path $licensePath)) {
                            Write-PSULog -Severity Error -Message "Token File not in correct License Directory. Atempting to copy again"
                            try {
                                Copy-Item -Path $token -Destination "C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\" -Force
                                if (!(Test-path -Path $licensePath)) {
                                    Write-PSULog -Severity Error -Message "Failed to Copy Token Again. Please move it manually."
                                }
                            }
                            catch {
                                Write-PSULog -Severity Error -Message "Failed to copy License token to C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\"
                            }
                        }
                        $ServiceName = 'NVDisplay.ContainerLocalSystem'
                        $arrService = Get-Service -Name $ServiceName
                        #Write-Host "Restarting Nvidia Display Container Service" -ForegroundColor Green
                        Write-PSULog -Severity Info -Message "Restarting Nvidia Display Container Service" 
                        Restart-Service -Name $ServiceName -Force
                        while ($arrService.Status -ne 'Running') {
                            Start-Service $ServiceName
                            #write-host $ServiceName $arrService.status -ForegroundColor Yellow
                            Write-PSULog -Severity Info -Message $ServiceName $arrService.status
                            #write-host 'Service starting' -ForegroundColor Yellow
                            Write-PSULog -Severity Info -Message 'Service starting'
                            Start-Sleep -seconds 5
                            $arrService.Refresh()
                        } 
                    }
                }

                elseif ($GPUType -match "Pass-Through") {
                    $RegistryPath = "HKLM:\SOFTWARE\NVIDIA Corporation\Global\GridLicensing"
                    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\GridLicensing"
                    if (!(Test-path -Path $RegistryPath)) {
                        mkdir $RegistryPath | Out-Null
                    }
                    Set-ItemProperty -Path $RegistryPath -Name "FeatureType" -Value "2"
                    Set-ItemProperty -Path $RegistryPath2 -Name "FeatureType" -Value "2"
                    #New-Item RegistryKey -Path $RegistryPath -Name "FeatureType" -Value "2"
                    $ServiceName = 'NVDisplay.ContainerLocalSystem'
                    $arrService = Get-Service -Name $ServiceName
                    Write-Host "Restarting Nvidia Display Container Service" -ForegroundColor Green
                    Restart-Service -Name $ServiceName -Force
                    while ($arrService.Status -ne 'Running') {
                        Start-Service $ServiceName
                        #write-host $ServiceName $arrService.status -ForegroundColor Yellow
                        Write-PSULog -Severity Info -Message $ServiceName $arrService.status
                        #write-host 'Service starting' -ForegroundColor Yellow
                        Write-PSULog -Severity Info -Message 'Service starting'
                        Start-Sleep -seconds 5
                        $arrService.Refresh()
                    } 
                }
                [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x

                $LicenseStatus = $NvidiaQuery.nvidia_smi_log.gpu.vgpu_software_licensed_product.license_status | % { $_.Split(" ")[0] }

                if ($LicenseStatus -match "Unlicensed") {

                    #Write-Host "Nvidia License Status: $LicenseStatus" -ForegroundColor Red
                    Write-PSULog -Severity Warn -Message "Nvidia License Status: $LicenseStatus"
                    #Write-Host "Querying License Status Every 5 Seconds" -ForegroundColor Yellow
                    Write-PSULog -Severity Info -Message "Querying License Status Every 5 Seconds"

                }


                $BreakoutTimer = 0
                While ($LicenseStatus -match "Unlicensed" -or $BreakoutTimer -ge 12) {

                    [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x

                    $LicenseStatus = $NvidiaQuery.nvidia_smi_log.gpu.vgpu_software_licensed_product.license_status | ForEach-Object { $_.Split(" ")[0] }

                    if ($LicenseStatus -eq "Licensed") {

                        #Write-Host "Acquired Nvidia License" -ForegroundColor Green
                        Write-PSULog -Severity Info -Message "Acquired Nvidia License"

                    }

                    Start-sleep -Seconds 5

                    $BreakoutTimer++

                    if ($BreakoutTimer -eq 12) {

                        #Write-Host "Unable to obtain Nvidia License, operation timed out. Please check connection to server." -ForegroundColor Red
                        Write-PSULog -Severity Error -Message "Unable to obtain Nvidia License, operation timed out. Please check connection to server."
                        break

                    }

                }
    
                $UseHWRender = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                New-ItemProperty -path $UseHWRender -name "bEnumerateHWBeforeSW" -value "1" -PropertyType DWORD -force
                #Write-Host "Setting Windows to use Hardware to render remote sessions." -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Setting Windows to use Hardware to render remote sessions."
                #Write-host "Please note that the machine will need to be rebooted for this to take effect" -ForegroundColor Yellow
                Write-PSULog -Severity Info -Message "Please note that the machine will need to be rebooted for this to take effect"
                try {
                    Write-PSULog -Severity Info -Message "Disabling Microsoft Basic Display Adapter"
                    $Null = Disable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "Microsoft Basic Display Adapter" -Class Display -Status Ok).InstanceId -Confirm:$false
                    $Null = Disable-PnpDevice -InstanceId (Get-PnpDevice -FriendlyName "Microsoft Basic Display Adapter" -Class Display -Status Error).InstanceId -Confirm:$false
                }
                catch {

                }
                #Write-host "Disabling Microsoft Basic Display Adapter" -ForegroundColor Green
        

            }

        }

        Write-PSULog -Severity Info -Message "Configuring Nvidia Control Panel Settings"
        & $RunLocation\bin\GPUSetup.ps1 -wait
    }
    Write-PSULog -Severity End -Message "Nvidia Driver Install Complete"
}
else {

    Write-PSULog -Severity Info -Message "Machine $env:COMPUTERNAME is listed in Omitted Servers. Skipping Nvidia Driver Install"

}

#Stop-Transcript