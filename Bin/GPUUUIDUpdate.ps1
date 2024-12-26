<#
.SYNOPSIS
    This script updates the GPU UUID, driver version, and RAM in the RayStation GPU settings files.

.DESCRIPTION
    The script updates the GPU UUID, driver version, and RAM in the RayStation GPU settings files.

.EXAMPLE
    .\GPUUUIDUpdate.ps1
    
.NOTES
    Author: Derek Nelson
    Refactored: John Burriss
    Created: 12/24/2024
    Version: 0.03
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>

#Requires -RunAsAdministrator

# Determine the location of nvidia-smi.exe
if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
    $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
}
elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
    $NVSMILocation = "C:\Windows\System32"
}
elseif (Test-Path ((Get-WmiObject Win32_SystemDriver | Select-Object DisplayName, @{n = "Path"; e = { (get-item $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent)) {
    $NVSMILocation = (Get-WmiObject Win32_SystemDriver | select-object DisplayName, @{n = "Path"; e = { (get-item $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent
}

# Path to the RayStation GPU settings files
$ConfigPath = "C:\ProgramData\RaySearch\GpuSettings\"
$FILES = Get-ChildItem "$configpath\*.config"

# Loop through each config file
foreach ($file in $files) {
    # Get the current GPU driver version
    $DRIVER = (& $NVSMILocation\nvidia-smi.exe --query-gpu=driver_version --format=csv, noheader)
    $DRIVERVERSION = -join ('GPU driver ', $DRIVER)
    
    # Get the current GPU UUID
    $NVIDIAGUID = (& $NVSMILocation\nvidia-smi.exe --query-gpu=gpu_uuid --format=csv, noheader)
    
    # Get the current GPU RAM in GB
    $NVIDIARAM = (& $NVSMILocation\nvidia-smi.exe --query-gpu=memory.total --format=csv, noheader, nounits)
    $NVIDIARAM = [math]::ceiling($NVIDIARAM / 1024)
    $RAMINGB = -join ($NVIDIARAM, ' GB')
    
    # Update the driver version in the config file
    (Get-content -path $file.FullName -Raw) | ForEach-Object { $_ -replace 'GPU driver [0-9]{3}.[0-9]{2}', $DRIVERVERSION } | out-file $file.FullName -Force
    
    # Update the GPU UUID in the config file
    (Get-Content -Path $file.FullName -Raw) | ForEach-Object { $_ -replace 'GPU-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', $NVIDIAGUID } | out-file $file.FullName -Force
    
    # Update the GPU RAM in the config file
    (get-content -path $file.FullName -Raw) | ForEach-object { $_ -replace '(0?[1-9]|[1-9][0-9]) GB', $RAMINGB } | out-file $file.FullName -Force

    # Ensure the file is saved with UTF-8 encoding without BOM
    $updatedFile = get-content -path $file.FullName
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($file.FullName, $updatedFile, $Utf8NoBomEncoding)
}