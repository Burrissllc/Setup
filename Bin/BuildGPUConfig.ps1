<#
.SYNOPSIS
    This script builds GPU configuration files for RayStation based on the system's GPU setup.

.DESCRIPTION
    The script checks for the presence of NVIDIA GPUs and gathers information about them.
    It then creates GPU configuration files for different versions of RayStation based on the gathered information.
    Logs are created locally and optionally remotely if specified in the Setup.json file.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\BuildGPUConfig.ps1
    Runs the script to build GPU configuration files for RayStation.

.NOTES
    Author: John Burriss
    Created: 09/21/2023
    Requires: PowerShell 5.1 or higher, Administrator privileges

#Requires -RunAsAdministrator
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

#$Path = "$RunLocation\Logs\RayStationSetup.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType file -Path "$RunLocation\Logs\RayStation.log" -Force
#}

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


Function Format-XMLText {
    Param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [xml[]]
        $xmlText
    )
    Process {
        # Use a StringWriter, an XMLWriter and an XMLWriterSettings to format XML
        $stringWriter = New-Object System.IO.StringWriter
        $stringWriterSettings = New-Object System.Xml.XmlWriterSettings
 
        # Turn on indentation
        $stringWriterSettings.Indent = $true
 
        # Turn off XML declaration
        #$stringWriterSettings.OmitXmlDeclaration = $true
 
        # Create the XMLWriter from the StringWriter
        $xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter, $stringWriterSettings)
 
        # Write the XML using the XMLWriter
        $xmlText.WriteContentTo($xmlWriter)
 
        # Don't forget to flush!
        $xmlWriter.Flush()
        $stringWriter.Flush()
 
        # Output the text
        $stringWriter.ToString()
        # This works in a remote session, when [Console]::Out doesn't
    }
}


function AddmaxConcurrentDevices {
    param(
        [Parameter(Mandatory = $true)] $xml,
        [Parameter(Mandatory = $true)] $value
    )

    
    $xml.configuration.gpuConfiguration.SetAttribute('maxConcurrentDevices', $value)

    #return $xml

}

function AddpostReleaseApprovedSelfTestOutputs {
    param(
        [Parameter(Mandatory = $true)] $xml,
        [Parameter(Mandatory = $true)] $value
    )

    $xml.configuration.gpuConfiguration.SetAttribute('postReleaseApprovedSelfTestOutputs', $value)

    #return $xml
}

$GPUInstalled = ((Get-WmiObject Win32_VideoController) | where-object { $_.Name -match "NVIDIA" }).Name
    
if ($Null -ne $GPUInstalled) {
    Write-PSULog -Severity Info -Message "GPU: $GPUInstalled is installed. Building Config files."

    if (!(Test-Path "C:\ProgramData\RaySearch\GpuSettings\")) {

        New-Item -ItemType Directory -Path "C:\ProgramData\RaySearch\GpuSettings\"

    }

    $RSversions = Get-WmiObject -Class Win32_Product | where vendor -eq 'RaySearch Laboratories' | select Name, Version
    $cleanRSVersions = @()
    foreach ($RSVersion in $RSVersions) {

        if ($RSVersion.name -match "RayStation \d+" -or $RSVersion.name -match "RayStation \w+-R" -or $RSVersion.name -match "MicroRayStation .+") {

            $RSVersion = $RSVersion.Version

            if ($RSVersion.Split('.', 4)[3] -ne $null) {

                $RSVersion = $RSVersion.Substring(0, $RSVersion.lastIndexOf('.'))

            }
        
            if ($cleanRSVersions -notcontains $RSVersion) {

                [version]$RSVersionUpdate = [String]$RSVersion

                $CleanRSVersions += $RSVersionUpdate

            }

        }

    }

    $OSBuild = [System.Environment]::OSVersion.Version | select-object Major, Build

    [string]$formattedOSBuild = $OSBuild.major, $OSBuild.Build -join "."

    if (((Get-CimInstance Win32_OperatingSystem).caption) -match "Server") {

        $formattedOSBuild = $formattedOSBuild + "s"
    }
    else {

        $formattedOSBuild = $formattedOSBuild + "w"

    }


    if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
        $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
    }
    elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
        $NVSMILocation = "C:\Windows\System32"
    }
    elseif (Test-Path ((gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent)) {
        $NVSMILocation = (gwmi Win32_SystemDriver | select DisplayName, @{n = "Path"; e = { (gi $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | split-path -Parent
    }


    [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x

    $GPUs = $NvidiaQuery.SelectNodes("/nvidia_smi_log/gpu")
    $Driver_Version = $NvidiaQuery.nvidia_smi_log.driver_version
    $AttachedGPUs = $NvidiaQuery.nvidia_smi_log.attached_gpus
    $GPUCount = 0

    $FinalIndex = $GPUs.Count - 1
    $Rotated_GPUs = foreach ($Index in 0..$FinalIndex) {
        $NewIndex = $Index + 1
        if ($NewIndex -gt $FinalIndex) {
            $NewIndex = 0
        }
        $GPUs[$NewIndex]
    }

    $GPUs = $Rotated_GPUs

    $GPUObjects = foreach ($GPU in $GPUs) {

        $GPUName = $GPU.product_name
        if ($GPUName.Split(' ').count -le 2) { $GPUNameShort = $GPUName.Split(' ')[-1] }
        if ($GPUName.Split(' ').count -eq 3) { $GPUNameShort = [string]::Join('', $GPUName.Split(' ')[1], $GPUName.Split(' ')[2]) }
        $DriverModel = $GPU.driver_model.current_dm
        $uuid_machine = $GPU.uuid
        $pci_machine = $GPU.pci.pci_bus_id
        $pci_machine = $pci_machine -replace '\s', ''
        $pci_machine = $pci_machine -replace '0+', '0'
        if ($pci_machine.Substring(4) -match 0) { $pci_machine = -join $pci_machine[0..3 + 5..($pci_machine.Length)] }
        $memory_machine = $GPU.fb_memory_usage.total -replace "\D", ""
        $memory_machine = [math]::ceiling($memory_machine / 1024)
        $ECCCheck = $GPU.ecc_mode.current_ecc
        if ($ECCCheck -match "N/A") { $ECCCheck = " (no ECC)" } else { $ECCCheck = $null }

        [PSCustomObject]@{
            GPU          = "GPU$GPUCount"
            GPUName      = $GPUName
            GPUNameShort = $GPUNameShort
            DriverModel  = $DriverModel
            UUID         = $uuid_machine
            PCI          = $pci_machine
            Memory       = $memory_machine
            ECC          = $ECCCheck
        }

        $GPUCount++
    }


    $ComputeCards = $GPUObjects | where-object { $_.ECC -EQ $null }

    $maxConcurrentDevices = 0
    if ($ComputeCards.count -eq 1) {

        $maxConcurrentDevices = 1

    }

    if ($ComputeCards.count -gt 1 -and ($ComputeCards.GPUName | Get-Unique).Count -eq 1) {

        $maxConcurrentDevices = $ComputeCards - 1

    }
    else {

        $maxConcurrentDevices = ($ComputeCards.Memory | Measure-Object -Maximum).count

    }

    $postReleaseApprovedSelfTestOutputs = ""

    # Given XML content
    $BaseConfig = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <configSections>
        <section name="gpuConfiguration" type="RaySearch.CoreUtilities.GPUConfigurationSection, RaySearch.CoreUtilities.NET" />
    </configSections>
    <gpuConfiguration deviceIndices="0" systemInfo="" />
</configuration>
"@

    $delimiter = "`n"


    foreach ($version in $cleanRSVersions) {

        Write-PSULog -Severity Info -Message "Building Config for RayStation Version: $version"

        if ($Version -lt [System.Version]"8.99.10") {

            Write-host "Version $version is too old" -ForegroundColor Red

        }#--------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"8.99.10" -and $Version -le [System.Version]"10.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUName
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUPci"

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }
            $newSystemInfo = "$Windows formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            # Convert the modified XML back to a string
            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"10.1.0" -and $Version -lt [System.Version]"11.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUName
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUPci" 

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }

            $newSystemInfo = "Windows $formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            AddmaxConcurrentDevices -xml $xml -value $maxConcurrentDevices 
            # Convert the modified XML back to a string
            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"11.0.0" -and $Version -le [System.Version]"12.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUName
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI
                $GPUuuid = $GPUObject.uuid

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUuuid, $GPUPci"

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }

            $newSystemInfo = "Windows $formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            AddmaxConcurrentDevices -xml $xml -value $maxConcurrentDevices
            AddpostReleaseApprovedSelfTestOutputs -xml $xml -value $postReleaseApprovedSelfTestOutputs 

            # Convert the modified XML back to a string


            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"13.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUNameshort
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI
                $GPUuuid = $GPUObject.uuid

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUuuid"

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }

            $newSystemInfo = "Windows $formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            AddmaxConcurrentDevices -xml $xml -value $maxConcurrentDevices
            AddpostReleaseApprovedSelfTestOutputs -xml $xml -value $postReleaseApprovedSelfTestOutputs 

            # Convert the modified XML back to a string


            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"14.0.0" -and $Version -lt [System.Version]"15.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUNameDash
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI
                $GPUuuid = $GPUObject.uuid

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUuuid"

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }

            $newSystemInfo = "Windows $formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            AddmaxConcurrentDevices -xml $xml -value $maxConcurrentDevices
            AddpostReleaseApprovedSelfTestOutputs -xml $xml -value $postReleaseApprovedSelfTestOutputs 

            # Convert the modified XML back to a string


            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------

        if ($Version -ge [System.Version]"15.0.0") {
            $xml = [xml]$BaseConfig
            $xml.PreserveWhitespace = $true
            $GPUStringCombined = @()
            foreach ($GPUObject in $GPUObjects) {

                $GPU = $GPUObject.gpu
                $GPUName = $GPUObject.GPUNameShort
                $GPUMemory = $GPUObject.Memory
                $GPUEcc = $GPUObject.ECC
                $GPUDriverModel = $GPUObject.DriverModel
                $GPUPci = $GPUObject.PCI
                $GPUuuid = $GPUObject.uuid

                $GPUString = $delimiter + "$GPU" + ": $GPUName, $GPUMemory GB$GPUEcc, $GPUDriverModel, $GPUuuid"

                $GPUStringCombined += $GPUString
            }
            if ($GPUStringCombined.count -gt 1) {
                $GPUStringFinal = $GPUStringCombined -join ""
            }
            else {
                $GPUStringFinal = $GPUStringCombined
            }

            $newSystemInfo = "Windows $formattedOSBuild, GPU driver $Driver_Version$GPUStringFinal"
            # Update the systemInfo attribute value
            $xml.configuration.gpuConfiguration.systemInfo = $newSystemInfo
            AddmaxConcurrentDevices -xml $xml -value $maxConcurrentDevices
            AddpostReleaseApprovedSelfTestOutputs -xml $xml -value $postReleaseApprovedSelfTestOutputs 

            # Convert the modified XML back to a string


            $updatedXmlContent = $xml.OuterXml
            # Display the updated XML content
            $updatedXmlContent = $updatedXmlContent | Format-XMLText
            $MyPath = "C:\ProgramData\RaySearch\GpuSettings\GpuSettings-v$Version.config"
            $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
            [System.IO.File]::WriteAllLines($MyPath, $updatedXmlContent, $Utf8NoBomEncoding)

        }#----------------------------------------------------------------------------------------------------------------------------
    }

}
else {
    Write-PSULog -Severity Warn -Message "Nvidia GPU not detected. Skipping writing RayStation GPU Config Files."
}
