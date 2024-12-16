#------------------------------------------------------
# Name:        RemoteInventory
# Purpose:     Collects Inventory Information from Remote Servers
# Author:      Derek Nelson, Refactored by John Burriss
# Created:     11/26/2024  2:24 PM 
# Version:     0.01
#------------------------------------------------------
#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

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
    if ($null -ne $RemotelogDirectory) {
        if (!(Test-Path -Path $RemotelogDirectory)) {
            New-Item -Path $RemotelogDirectory -ItemType Directory | Out-Null
        }
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}
#----------------------------------------------------------------------------------------------
$outfile = $RunLocation + "\Logs\ServerInfo.csv"
$servers = Get-Content "$RunLocation\RemoteMachines.txt"

# Maximum number of concurrent jobs
$MaxConcurrentJobs = 10

# Create the complete script block that will run in each job
$jobScriptBlock = {
    param($ComputerName)
    
    $cimParams = @{
        ErrorAction = 'Stop'
    }

    function Get-ServerDetails {
        param (
            [string]$ComputerName
        )
        
        try {
            # Test connection first
            if (-not (Test-Connection -ComputerName $ComputerName -Count 1 -Quiet)) {
                return [PSCustomObject]@{
                    ServerName = $ComputerName
                    Status     = 'Not Responding'
                }
            }

            Get-DetailedServerInfo -ComputerName $ComputerName
        }
        catch {
            Write-Warning "Error processing $ComputerName : $_"
            [PSCustomObject]@{
                ServerName = $ComputerName
                Status     = "Error: $_"
            }
        }
    }

    function Get-DetailedServerInfo {
        param (
            [string]$ComputerName
        )
        
        # Get common system Information
        $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName @cimParams
        $ram = (Get-CimInstance Win32_PhysicalMemory -ComputerName $ComputerName @cimParams | 
            Measure-Object -Property Capacity -Sum).Sum / 1GB
        $cpuInfo = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Get-ItemProperty -Path "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0" |
            Select-Object -ExpandProperty ProcessorNameString
        }

        # Determine if physical or virtual
        $isVirtual = $systemInfo.Manufacturer -in ('VMware, Inc.', 'Nutanix')
        
        # Initialize the base server object
        $serverDetails = [ordered]@{
            ServerName   = $ComputerName
            Type         = if ($isVirtual) { 'Virtual' } else { 'Physical' }
            Manufacturer = $systemInfo.Manufacturer
            Model        = $systemInfo.Model
            CPU          = $cpuInfo
            Processors   = "$($systemInfo.NumberOfProcessors)x$($systemInfo.NumberOfLogicalProcessors)"
            RAM          = "$($ram)GB"
        }
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName @cimParams -Filter 'DriveType = "3"' |
        ForEach-Object {
            "$($_.DeviceID) $([math]::Round($_.Size /1GB))GB"
        }
        $serverDetails['Disks'] = $disks -join '; '
        # Add virtual-specific Information
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName @cimParams
            
        # Get GPU and driver Info
        $gpuInfo = Get-CimInstance -ClassName Win32_VideoController -ComputerName $ComputerName @cimParams |
        Where-Object { $_.Name -like "NVIDIA*" } |
        Select-Object -First 1
            
        $driverVersion = if ($gpuInfo) {
            $version = $gpuInfo.DriverVersion.Replace('.', '')
            $version.Substring($version.Length - 5).Insert(3, '.')
        }
        else { "N/A" }
            
        # Get service status
        $services = @{
            LMX          = 'lmx*'
            DICOM        = 'dicom*'
            LicenseAgent = 'RayStationLicenseAgent'
            IndexService = 'RaystationIndexService*'
        }
            
        $runningServices = foreach ($service in $services.GetEnumerator()) {
            $running = Get-Service -ComputerName $ComputerName |
            Where-Object { $_.Name -like $service.Value -and $_.Status -eq 'Running' }
            if ($running) { $service.Key }
        }
            
        # Check for specific applications
        $appPaths = @{
            'App Server' = 'Raystation.exe'
            'RayGateway' = 'RaySearch.RayGateway.RayGatewayService.exe'
        }
            
        $installedApps = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($paths)
            $found = @()
            foreach ($app in $paths.GetEnumerator()) {
                if (Get-ChildItem "$Env:ProgramFiles\Raysearch Laboratories" -Recurse |
                    Where-Object { $_.Name -eq $app.Value }) {
                    $found += $app.Key
                }
            }
            $found
        } -ArgumentList $appPaths

        # Add virtual-specific properties
        $serverDetails['OS'] = $osInfo.Caption
        $ipAddress = (Resolve-DnsName $ComputerName).IPAddress
        $serverDetails['IPAddress'] = $ipAddress
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName @cimParams
        $serverDetails['SerialNumber'] = $biosInfo.SerialNumber.Trim()
        $serverDetails['GPU'] = if ($gpuInfo) { $gpuInfo.Name } else { "N/A" }
        $serverDetails['DriverVersion'] = $driverVersion
        $serverDetails['Roles'] = ($runningServices + $installedApps | Where-Object { $_ }) -join '; '


        # Convert to PSCustomObject and return
        [PSCustomObject]$serverDetails
    }

    # Execute the main function for this server
    Get-ServerDetails -ComputerName $ComputerName
}

# Initialize results collection
$results = @()

Write-PSULog  -Severity "Start" -Message "Starting parallel server Information collection..."

# Create jobs in batches
$jobs = @()
foreach ($server in $servers) {
    # Start new job
    $jobs += Start-Job -ScriptBlock $jobScriptBlock -ArgumentList $server
    
    # If we've hit the max concurrent jobs, wait for some to complete
    while ($jobs.Count -ge $MaxConcurrentJobs) {
        $completed = $jobs | Wait-Job -Any
        foreach ($job in $completed) {
            $result = Receive-Job -Job $job -ErrorAction Continue
            if ($result) {
                $results += $result | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            }
            Remove-Job -Job $job
        }
        $jobs = @($jobs | Where-Object { $_.State -eq 'Running' })
    }
}

# Wait for remaining jobs to complete
while ($jobs) {
    $completed = $jobs | Wait-Job -Any
    foreach ($job in $completed) {
        $result = Receive-Job -Job $job -ErrorAction Continue
        if ($result) {
            $results += $result | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        }
        Remove-Job -Job $job
    }
    $jobs = @($jobs | Where-Object { $_.State -eq 'Running' })
}

Write-PSULog  -Severity "Info" -Message  "Collection complete. Processing results..."

# Export results
$results | Export-Csv -Path $outfile -NoTypeInformation

Write-PSULog  -Severity "Info" -Message "Results exported to $outfile"