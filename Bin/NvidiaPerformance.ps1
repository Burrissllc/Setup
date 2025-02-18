<#
.SYNOPSIS
    Set Nvidia Cards to Max Power and Clock.

.DESCRIPTION
    This script sets Nvidia cards in an application server to maximum power and clock settings. It also handles various Nvidia-specific configurations.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\NvidiaPerformance.ps1
    Runs the Nvidia performance optimization script.

.NOTES
    Author: John Burriss
    Created: 8/22/2019
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

Start-Transcript -Path "$RunLocation\Logs\setup.log" -NoClobber -Confirm:$false

#$Path = "$RunLocation\Logs\NvidiaPerformance.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType file -Path "$RunLocation\Logs\NvidiaPerformance.log"
#}
$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
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

#Start-Transcript -Path "$RunLocation\Logs\NvidiaPerformance.log"

if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
    $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
}
elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
    $NVSMILocation = "C:\Windows\System32"
}
elseif (Test-Path ((gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent)) {
    $NVSMILocation = (gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent
}

if ($NvidiaQuery -match "NVIDIA-SMI has failed") {
    $NoGPU = $true
}
if ($NoGPU -ne $true) {

    #Sets Mode to Unrestricted and Sets to Persistent Mode
    try {
        $Mode = (& "$NVSMILocation\nvidia-smi.exe" -acp UNRESTRICTED)
    }
    catch {
        Write-PSULog -Severity Error -Message "Unsupported SMI Command"
    }
    if ($Mode -match "Unsupported") {
        #Write-Host "Unable to set mode to Unrestricted, Unsupported" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Unable to set mode to Unrestricted, Unsupported"
    }
    else {
    (& "$NVSMILocation\nvidia-smi.exe" -acp UNRESTRICTED)  
    }
    try {
        $Persist = & "$NVSMILocation\nvidia-smi.exe" -pm 1
    }
    catch {
        Write-PSULog -Severity Error -Message "Unsupported SMI Command"
    }
    if ($Persist -match "Unsupported") {
        #Write-Host = "Unable to set mode to persistent, unsupported" -ForegroundColor Red
        Write-PSULog -Severity Error -Message "Unable to set mode to Unrestricted, Unsupported"

    }
    else {
        & "$NVSMILocation\nvidia-smi.exe" -pm 1  
    }

    #Gets Card Count for Loop
    $CardCount = & "$NVSMILocation\nvidia-smi.exe" -L
    $i = 0

    $CardType = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Card in $CardCount) {
        $CardName = ($Card.Split(" ")[2])
        $CardType.Add($CardName)
    }

    if (($CardType | Select-Object -Unique).Count -eq 1) {

        $AllTesla = $true
    }
    else {
        $AllTesla = $false
    }

    ForEach ($Card in $CardCount) {
        #Sets ECC on and TCC Mode on if Tesla
        $ecc = & "$NVSMILocation\nvidia-smi.exe" -i $i --ecc-config=1
        Write-PSULog -Severity Info -Message "Enabled ECC on Card $1"

        if ($ecc -match "unsupported") {
            #Write-Host "Unable to change ECC Setting, Unsupported" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "Unable to change ECC Setting, Unsupported for card $i"
        }

        if ($AllTesla -eq $True) {
            if ($i -eq 1) {
                & "$NVSMILocation\nvidia-smi.exe" -i $i -dm 0
            }
        }
        else {
            if ($Card -match "Tesla") {

                & "$NVSMILocation\nvidia-smi.exe" -i $i -dm 1
            }
        }
        #Gathers Clock Speeds and Cleans data to select Top Graphics and Memory Speeds
        try {
            $Clocks = (& "$NVSMILocation\nvidia-smi.exe" -i $i -q -d SUPPORTED_CLOCKS)
        }
        catch {
            Write-PSULog -Severity Error -Message "Unsupported SMI Command"
        }
        if ($Clocks -match 'N/A') {
            #Write-Host "Setting Clocks is not supported on this card: $Card" -ForegroundColor Red
            Write-PSULog -Severity Warn -Message "Setting Clocks is not supported on this card: $Card"
        }
        Else {
            $Clocks1 = $Clocks | Where-Object { $_ -match 'Graphics' }
            $Graphics = $Clocks1[0] -replace "\D", ""
            $Clocks1 = $Clocks | Where-Object { $_ -match 'Memory' }
            $Memory = $Clocks1[0] -replace "\D", ""
            #Sets Card to Max Clock Speed
            try {
                & "$NVSMILocation\nvidia-smi.exe" -ac $Memory, $Graphics -i $i
            }
            catch {
                Write-PSULog -Severity Error -Message "Unsupported SMI Command"
            }
        }
        #Queries if cards power is adjustable and then set it to Max
        $Power = (& "$NVSMILocation\nvidia-smi.exe" -i $i --format=csv --query-gpu=power.limit)

        if ($Power -notmatch "[Not Supported]") {

            $Power = $Power[1].split('.')

            try {
 (& "$NVSMILocation\nvidia-smi.exe" -i $i -pl $Power[0])
            }
            catch {
                Write-PSULog -Severity Error -Message "Unsupported SMI Command"
            }
        }
    }
}
else {
    Write-PSULog -Severity Warn -Message "No Nvidia Cards Found"
}
if ($Settings.GENERAL.CLEANUP -match "y") {
    #Write-Host "Setting Machine to Cleanup on Next Boot" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Setting Machine to Cleanup on Next Boot"
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\Cleanup.ps1"

}

while ((get-process | Where-Object { $_.ProcessName -match "XenDesktopVdaSetup" })) {

    start-sleep -Seconds 5

}

#Disabled the Nvidia Tray Icon
#$TrayIcon = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\NvTray"
$TrayIcon = "HKLM:\SOFTWARE\NVIDIA Corporation\NvTray"
if ($null -eq (Test-Path $Trayicon)) {
    Write-PSULog -Severity Info -Message "Disabling the Nvidia Tray Icon in Citrix"
    New-Item $TrayIcon -Force | New-ItemProperty -Name "StartOnLogin" -Value "00000000" -type dword
}



#Runs Machine Info Script and updates the Machine Info with GPU Information
& $RunLocation\bin\MachineInfo.ps1


# Monitor VDA install logs and processes
$logPath = "$RunLocation\VDAInstallLogs"
$timeout = 90
$sleepInterval = 60

function Get-RecentlyModifiedFiles {
    Get-ChildItem -Path $logPath -Recurse -File | 
    Where-Object { (New-TimeSpan -Start $_.LastWriteTime -End (Get-Date)).TotalSeconds -le $timeout }
}

function Get-InstallerProcesses {
    Get-Process | Where-Object { 
        $_.Name -match "msiexec|install|setup|XenDesktopVdaSetup" 
    }
}

# Monitor file modifications
do {
    $recentFiles = Get-RecentlyModifiedFiles
    if ($recentFiles) {
        Write-PSULog -Severity Info -Message "Files still being modified. Waiting $sleepInterval seconds..."
        Start-Sleep -Seconds $sleepInterval
    }
} while ($recentFiles)

Write-PSULog -Severity Info -Message "No recent file modifications detected in Citrix Logs."

# Monitor installer processes
do {
    $installers = Get-InstallerProcesses
    if ($installers) {
        Write-PSULog -Severity Info -Message "Installer processes still running. Waiting $sleepInterval seconds..."
        Write-PSULog -Severity Info -Message "Running processes: $($installers.Name -join ', ')"
        Start-Sleep -Seconds $sleepInterval
    }
} while ($installers)

Write-PSULog -Severity Info -Message "All installer processes completed."

Write-PSULog -Severity Info -Message "Configuring Nvidia Control Panel Settings"
& $RunLocation\bin\GPUSetup.ps1 -wait

Write-PSULog -Severity Info -Message "Nvidia Performance Script Completed"
#Stop-Transcript
$Readhost = $Settings.general.AUTOREBOOT
Switch ($ReadHost) {
    Y { Write-PSULog -Severity Info -Message "Rebooting now..."; Start-Sleep -s 2; Restart-Computer -force }
    N { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds."; Start-Sleep -s 5 }
    Default { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds"; Start-Sleep -s 5 }
}
