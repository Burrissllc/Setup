<#
.SYNOPSIS
    This script sets up the scheduled task to update the GPUUUIDUpdate.ps1 script.

.DESCRIPTION
    The script checks for the presence of NVIDIA Driver and GPU UUID and sets up the scheduled task to update the GPUUUIDUpdate.ps1 script.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\AutoUpdateGPUUUID.ps1

.NOTES
    Author: John Burriss
    Created: 12/24/2024
    Requires: PowerShell 5.1 or higher, Administrator privileges
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json

#----------------------------------------------------------------------------------------------
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
}
#-------------------------------------------------------------------------------------------------------------


if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
    $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
}
elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
    $NVSMILocation = "C:\Windows\System32"
}
elseif (Test-Path ((Get-WmiObject Win32_SystemDriver | Select-Object DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent)) {
    $NVSMILocation = (Get-WmiObject Win32_SystemDriver | select-object DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent
}

if (-not ($null -eq $NVSMILocation)) {

    if (-not (Test-Path -Path "C:\ProgramData\RaySearch\GpuSettings\")) {
        Write-PSULog -Severity Info -Message "Creating directory C:\ProgramData\RaySearch\GpuSettings\"
        New-Item -Path "C:\ProgramData\RaySearch\GpuSettings\" -ItemType Directory
    }
    try {
        Copy-Item -Path "$RunLocation\bin\GPUUUIDUpdate.ps1" -Destination "C:\ProgramData\RaySearch\GpuSettings\GPUUUIDUpdate.ps1" -Force
        Write-PSULog -Severity Info -Message "GPUUUIDUpdate.ps1 copied successfully"
    }
    Catch {
        Write-PSULog -Severity Error -Message "Error copying GPUUUIDUpdate.ps1"
        exit 1 
    }

    try {
        $Action = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\ProgramData\RaySearch\GpuSettings\GPUUUIDUpdate.ps1"
        $Trigger = New-ScheduledTaskTrigger -AtStartup
        $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "UpdateGPUUUID" -Description "Updates the GPU UUID, driver version, and RAM in the RayStation GPU settings files."
        Register-ScheduledTask -TaskName "UpdateGPUUUID" -InputObject $Task -Force
        Write-PSULog -Severity Info -Message "Scheduled task created successfully"
    }
    Catch {
        Write-PSULog -Severity Error -Message "Error creating scheduled task"
        exit 1
    }

}
else {
    Write-PSULog -Severity Error -Message "NVIDIA Driver not found. Skipping scheduled task creation for Auto-Update GPU UUID."
}