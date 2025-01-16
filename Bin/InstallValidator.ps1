<#
.SYNOPSIS
    This script Validates the install and configuration.

.DESCRIPTION
    The script checks if the install and configuration ran properly and generates a report and saves it locally and remote if the location exists.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallValidator.ps1

.NOTES
    Author: John Burriss
    Created: 1/15/2025
    Requires: PowerShell 5.1 or higher, Administrator privileges
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$ConfigPath = "$RunLocation\Setup.json"
$OutputPath = "$RunLocation\Logs\Reports\$env:ComputerName-SystemConfigurationReport.html"

    
# Import and validate configuration
$Settings = Get-Content $ConfigPath -Raw | ConvertFrom-Json

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


# Function to validate and prepare output path
function Test-OutputPath {
    param(
        [string]$Path
    )
    
    try {
        $directory = Split-Path -Parent $Path
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        # Test write access
        $testFile = Join-Path $directory "test.tmp"
        [System.IO.File]::Create($testFile).Close()
        Remove-Item $testFile -Force
        
        return $true
    }
    catch {
        Write-PSULog -Severity "Warn" -Message  "Output path validation failed`: $_"
        return $false
    }
}

# Function to safely encode HTML
function ConvertTo-HtmlEncoded {
    param(
        [string]$text
    )
    if ([string]::IsNullOrEmpty($text)) { return "" }
    return $text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

# Function to write colored HTML row
function Write-HTMLTableRow {
    param(
        [string]$CheckName,
        [bool]$Status,
        [string]$Details = ""
    )
    
    try {
        $color = if ($Status) { "#90EE90" } else { "#FFB6C1" }
        $statusText = if ($Status) { "Passed" } else { "Failed" }
        
        return @"
        <tr style="background-color: $color">
            <td>$(ConvertTo-HtmlEncoded $CheckName)</td>
            <td>$statusText</td>
            <td>$(ConvertTo-HtmlEncoded $Details)</td>
        </tr>
"@
    }
    catch {
        Write-PSULog -Severity "Warn" -Message  "Failed to generate HTML row for $CheckName`: $_"
        return "<tr><td>Error</td><td>Failed</td><td>Failed to generate row</td></tr>"
    }
}

# Function to add section header
function Add-SectionHeader {
    param(
        [string]$Title,
        [System.Collections.ArrayList]$Rows
    )
    
    try {
        $null = $Rows.Add(@"
        <tr>
            <td colspan="3" style="background-color: #f0f0f0; font-weight: bold; padding: 10px;">$(ConvertTo-HtmlEncoded $Title)</td>
        </tr>
"@)
    }
    catch {
        Write-PSULog -Severity "Warn" -Message  "Failed to add section header for $Title`: $_"
    }
}

# Function to check if server is in omitted list
function Test-ServerOmitted {
    param(
        [string]$CheckType,
        [PSCustomObject]$Settings
    )
    
    try {
        $serverName = $env:COMPUTERNAME
        if ($CheckType -eq "SQL") {
            if ($null -ne $Settings.DESIGNATEDSQLSERVER.DESIGNATEDSQLSERVER) {
                return (-not ($Settings.DESIGNATEDSQLSERVER.DESIGNATEDSQLSERVER -contains $serverName))
            }
            return $false
        }
        if ($null -ne $Settings.$CheckType.OMITTEDSERVERS) {
            return ($Settings.$CheckType.OMITTEDSERVERS -contains $serverName)
        }
        return $false
    }
    catch {
        Write-PSULog -Severity "Warn" -Message  "Error checking server omission for $CheckType`: $_"
        return $false
    }
}

# Function to safely execute WMI queries
function Invoke-WMIQuery {
    param(
        [string]$Query,
        [string]$Namespace = "root\cimv2",
        [int]$Timeout = 30
    )
    
    try {
        $options = New-Object System.Management.ConnectionOptions
        $options.Timeout = [TimeSpan]::FromSeconds($Timeout)
        
        $scope = New-Object System.Management.ManagementScope("\\.\$Namespace", $options)
        $scope.Connect()
        
        $searcher = New-Object System.Management.ManagementObjectSearcher($scope, $Query)
        return $searcher.Get()
    }
    catch {
        Write-PSULog -Severity "Warn" -Message  "WMI query failed`: $_"
        return $null
    }
    finally {
        if ($null -ne $searcher) {
            $searcher.Dispose()
        }
    }
}

# Main script execution
try {
    # Add System.Web assembly for HTML encoding
    Add-Type -AssemblyName System.Web
    
    # Initialize variables
    $htmlRows = [System.Collections.ArrayList]@()
    $errorOccurred = $false
    $errorMessages = [System.Collections.ArrayList]@()
    $global:checkCount = 0
    $global:passedChecks = 0
    
    # Validate configuration file
    if (-not (Test-Path $ConfigPath)) {
        throw "Setup.json file not found at: $ConfigPath"
    }
    
    # Validate output path
    if (-not (Test-OutputPath -Path $OutputPath)) {
        $OutputPath = Join-Path $env:TEMP "SystemConfigurationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        Write-PSULog -Severity "Warn" -Message "Using alternate output path: $OutputPath"
    }
    
    # Create HTML header
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Configuration Check Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: left; border: 1px solid #ddd; }
        th { background-color: #4CAF50; color: white; }
        h1, h2 { color: #333; }
        .section-header { background-color: #f0f0f0; font-weight: bold; }
        .pass { background-color: #90EE90; }
        .fail { background-color: #FFB6C1; }
        .summary { margin-top: 20px; padding: 10px; background-color: #f8f8f8; }
    </style>
</head>
<body>
    <h1>System Configuration Check Report</h1>
    <h2>Server Name: $env:COMPUTERNAME</h2>
    <h2>Check Time: $(Get-Date)</h2>
    <table>
        <tr>
            <th>Check</th>
            <th>Status</th>
            <th>Details</th>
        </tr>
"@

    # Basic System Checks
    try {
        Add-SectionHeader -Title "Basic System Configuration" -Rows $htmlRows
        
        # Power Plan Check
        try {
            $powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -ErrorAction Stop | 
            Where-Object { $_.IsActive -eq $true } |
            Select-Object -ExpandProperty ElementName
            $global:checkCount++
            $isPassed = $powerPlan -eq "High performance"
            if ($isPassed) { $global:passedChecks++ }
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Power Plan" -Status $isPassed -Details "Current: $powerPlan"))
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("Power Plan check failed`: $_")
        }

        # IE Security Check
        try {
            $adminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
            $userKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
            if ((Test-Path $adminKey) -and (Test-Path $userKey)) {
                $adminKeyValue = (Get-ItemProperty -Path $adminKey -Name "IsInstalled").IsInstalled
                $userKeyValue = (Get-ItemProperty -Path $userKey -Name "IsInstalled").IsInstalled
                $ieSecStatus = ($adminKeyValue -eq 0) -and ($userKeyValue -eq 0)
                $global:checkCount++
                if ($ieSecStatus) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "IE Security Disabled" -Status $ieSecStatus))
            }
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("IE Security check failed`: $_")
        }

        # UAC Check
        try {
            $uacStatus = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA -eq 0
            $global:checkCount++
            if ($uacStatus) { $global:passedChecks++ }
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "UAC Disabled" -Status $uacStatus))
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("UAC check failed`: $_")
        }

        # Firewall Check
        try {
            $firewallStatus = $true
            $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
            foreach ($profile in $firewallProfiles) {
                if ($profile.Enabled) {
                    $firewallStatus = $false
                    break
                }
            }
            $global:checkCount++
            if ($firewallStatus) { $global:passedChecks++ }
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Firewall Disabled" -Status $firewallStatus))
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("Firewall check failed`: $_")
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Basic System Checks section failed`: $_")
    }

    # .NET Framework Checks
    try {
        if ($Settings.GENERAL.INSTALLDOTNET -eq "Y") {
            Add-SectionHeader -Title ".NET Framework" -Rows $htmlRows

            # .NET 3.5
            try {
                $net35Feature = Get-WindowsOptionalFeature -Online -FeatureName "NetFx3" -ErrorAction Stop
                $net35Status = $net35Feature.State -eq "Enabled"
                $global:checkCount++
                if ($net35Status) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName ".NET 3.5" -Status $net35Status))
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add(".NET 3.5 check failed`: $_")
            }

            # .NET 4.8
            try {
                $net48Path = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"
                if (Test-Path $net48Path) {
                    $net48Version = (Get-ItemProperty $net48Path).Release -ge 528040
                    $global:checkCount++
                    if ($net48Version) { $global:passedChecks++ }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName ".NET 4.8" -Status $net48Version))
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add(".NET 4.8 check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add(".NET Framework Checks section failed`: $_")
    }

    # Application Checks
    try {
        Add-SectionHeader -Title "Application Installation" -Rows $htmlRows

        $InstalledSoftware = @()
        try {
            $InstalledSoftware += Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            $InstalledSoftware += Get-ChildItem "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("Failed to get installed software list`: $_")
        }

        # Java Check
        if ($Settings.GENERAL.INSTALLJAVA -eq "Y") {
            try {
                $javaInstalled = $false
                if ($InstalledSoftware | Where-Object { $_.GetValue('DisplayName') -match "JRE" }) {
                    $javaInstalled = $true
                }
                $global:checkCount++
                if ($javaInstalled) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Java Installation" -Status $javaInstalled))
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("Java check failed`: $_")
            }
        }

        # Adobe Check
        if ($Settings.GENERAL.INSTALLADOBE -eq "Y") {
            try {
                $adobeInstalled = $false
                if ($InstalledSoftware | Where-Object { $_.GetValue('DisplayName') -match "Adobe Acrobat Reader" }) {
                    $adobeInstalled = $true
                }
                $global:checkCount++
                if ($adobeInstalled) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Adobe Reader" -Status $adobeInstalled))
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("Adobe Reader check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Application Checks section failed`: $_")
    }

    # Local Groups Check
    try {
        if ($Settings.GENERAL.LOCALGROUPS -eq "Y") {
            Add-SectionHeader -Title "Local Groups" -Rows $htmlRows
            $requiredGroups = @(
                "RayStation-Users",
                "RayStation-Administrators",
                "RayStation-BeamCommissioning",
                "RayStation-PlanApproval"
            )
            foreach ($group in $requiredGroups) {
                try {
                    $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
                    $global:checkCount++
                    $exists = $null -ne $groupExists
                    if ($exists) { $global:passedChecks++ }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Local Group: $group" -Status $exists))
                }
                catch {
                    $errorOccurred = $true
                    $null = $errorMessages.Add("Local group check failed for $group`: $_")
                }
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Local Groups Check section failed`: $_")
    }

    # Drive Configuration
    try {
        if ($Settings.GENERAL.FORMATDRIVES -eq "Y") {
            Add-SectionHeader -Title "Drive Configuration" -Rows $htmlRows
            foreach ($drive in $Settings.DRIVES) {
                try {
                    $driveLetter = $drive.DriveLetter
                    $driveExists = Test-Path "${driveLetter}:"
                    $global:checkCount++
                    
                    if ($driveExists) {
                        $driveInfo = Get-PSDrive -Name $driveLetter -ErrorAction Stop
                        $freeSpaceGB = [math]::Round($driveInfo.Free / 1GB, 2)
                        $totalSpaceGB = [math]::Round(($driveInfo.Free + $driveInfo.Used) / 1GB, 2)
                        $details = "Label: $($drive.DriveLabel), Free: $freeSpaceGB GB / $totalSpaceGB GB"
                        if ($driveExists) { $global:passedChecks++ }
                    }
                    else {
                        $details = "Drive not found"
                    }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Drive ${driveLetter}:" -Status $driveExists -Details $details))
                }
                catch {
                    $errorOccurred = $true
                    $null = $errorMessages.Add("Drive check failed for $driveLetter``: $_")
                }
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Drive Configuration section failed`: $_")
    }

    # SQL Server Checks
    try {
        if ($Settings.GENERAL.INSTALLSQL -eq "Y") {
            $isOmitted = Test-ServerOmitted -CheckType "SQL" -Config $Settings
            if (-not $isOmitted) {
                Add-SectionHeader -Title "SQL Server Configuration" -Rows $htmlRows
                
                try {
                    $instanceName = $Settings.SQL.INSTANCENAME
                    $sqlService = Get-Service "MSSQL`$$instanceName" -ErrorAction SilentlyContinue
                    $sqlInstalled = $null -ne $sqlService
                    $global:checkCount++
                    if ($sqlInstalled) { $global:passedChecks++ }
                    
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "SQL Installation" -Status $sqlInstalled))
                    
                    if ($sqlInstalled) {
                        # Port Configuration
                        try {
                            $sqlRegistryPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceName\MSSQLServer\SuperSocketNetLib\Tcp"
                            if (Test-Path $sqlRegistryPath) {
                                $sqlPort = Get-ItemProperty $sqlRegistryPath -Name TcpPort -ErrorAction Stop
                                $portMatch = $sqlPort.TcpPort -eq "1433"
                                $global:checkCount++
                                if ($portMatch) { $global:passedChecks++ }
                                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "SQL Port" -Status $portMatch -Details "Port: $($sqlPort.TcpPort)"))
                            }
                        }
                        catch {
                            $errorOccurred = $true
                            $null = $errorMessages.Add("SQL Port check failed`: $_")
                        }
                        
                        # Service Status
                        try {
                            $serviceRunning = $sqlService.Status -eq "Running"
                            $global:checkCount++
                            if ($serviceRunning) { $global:passedChecks++ }
                            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "SQL Service Status" -Status $serviceRunning -Details "Status: $($sqlService.Status)"))
                        }
                        catch {
                            $errorOccurred = $true
                            $null = $errorMessages.Add("SQL Service status check failed`: $_")
                        }
                    }
                }
                catch {
                    $errorOccurred = $true
                    $null = $errorMessages.Add("SQL Server checks failed`: $_")
                }
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("SQL Server Checks section failed`: $_")
    }

    # NVIDIA GPU Checks
    try {
        if ($Settings.GENERAL.INSTALLGPUDRIVER -eq "Y") {
            $isOmitted = Test-ServerOmitted -CheckType "GPU" -Config $Settings
            if (-not $isOmitted) {
                Add-SectionHeader -Title "NVIDIA GPU Configuration" -Rows $htmlRows
                
                try {
                    # Driver Check
                    $nvidiaDriver = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -like "*NVIDIA*" }
                    $driverInstalled = $null -ne $nvidiaDriver
                    $driverDetails = if ($driverInstalled) { $nvidiaDriver.Name } else { "Not Installed" }
                    $global:checkCount++
                    if ($driverInstalled) { $global:passedChecks++ }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "NVIDIA Driver" -Status $driverInstalled -Details $driverDetails))
                }
                catch {
                    $errorOccurred = $true
                    $null = $errorMessages.Add("NVIDIA driver check failed`: $_")
                }
                if ($driverInstalled) {
                    try {
                        if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
                            $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
                        }
                        elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
                            $NVSMILocation = "C:\Windows\System32"
                        }
                        elseif (Test-Path ((Get-WmiObject Win32_SystemDriver | Select-Object DisplayName, @{n = "Path"; e = { (Get-Item $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | Split-Path -Parent)) {
                            $NVSMILocation = (Get-WmiObject Win32_SystemDriver | Select-Object DisplayName, @{n = "Path"; e = { (Get-Item $_.pathname) } } | Where-Object { $_.DisplayName -match "nvlddmkm" }).path | Split-Path -Parent
                        }
                        else {
                            $NVSMILocation = $null
                        }

                        if ($null -ne $NVSMILocation) {
                            [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x
                            $GPUType = $NvidiaQuery.nvidia_smi_log.gpu.gpu_virtualization_mode.virtualization_mode

                            if ($GPUType -match "VGPU") {
                                # Token Check
                                $tokenExists = (Get-ChildItem "C:\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken").Name -match ".tok"
                                $global:checkCount++
                                if ($tokenExists) { $global:passedChecks++ }
                                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "NVIDIA License Token" -Status $tokenExists))

                                [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x
                                $LicenseStatus = $NvidiaQuery.nvidia_smi_log.gpu.vgpu_software_licensed_product.license_status | ForEach-Object { $_.Split(" ")[0] }
                                $Licensed = $LicenseStatus -eq "Licensed"
                                $global:checkCount++
                                if ($Licensed) { $global:passedChecks++ }
                                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "NVIDIA License Status" -Status $Licensed))
                            }
                        }
                    }
                    catch {
                        $errorOccurred = $true
                        $null = $errorMessages.Add("NVIDIA GPU configuration check failed`: $_")
                    }
                }
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("NVIDIA GPU Checks section failed`: $_")
    }

    # RayStation Checks
    try {
        if ($Settings.GENERAL.INSTALLRAYSTATION -eq "Y") {
            $isOmitted = Test-ServerOmitted -CheckType "RAYSTATION" -Config $Settings
            if (-not $isOmitted) {
                Add-SectionHeader -Title "RayStation Configuration" -Rows $htmlRows
                
                try {
                    # Installation Check
                    $RayStationPackage = if (Test-Path $Settings.RAYSTATION.RAYSTATIONLOCATION) {
                        $Settings.RAYSTATION.RAYSTATIONLOCATION
                    }
                    
                    if ($RayStationPackage) {
                        $PackageVersion = (Get-Item $Settings.RAYSTATION.RAYSTATIONLOCATION).VersionInfo.ProductVersion
                        $rayStationVersionsInstalled = $InstalledSoftware | Where-Object { $_.GetValue('DisplayName') -match "RayStation" }
                        $rayStationInstalled = if ($PackageVersion -match $rayStationVersionsInstalled.DisplayVersion) { $true }
                        $global:checkCount++
                        if ($rayStationInstalled) { $global:passedChecks++ }
                        $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "RayStation Installation" -Status $rayStationInstalled -Details "Version: $PackageVersion"))
                        
                        if ($rayStationInstalled) {
                            # Service Checks
                            try {
                                $indexService = Get-Service "RayStationIndexService" -ErrorAction SilentlyContinue
                                if ($null -ne $indexService) {
                                    $indexStatus = $indexService.Status -eq "Running"
                                    $global:checkCount++
                                    if ($indexStatus) { $global:passedChecks++ }
                                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Index Service" -Status $indexStatus -Details "Status: $($indexService.Status)"))
                                }
                            }
                            catch {
                                $errorOccurred = $true
                                $null = $errorMessages.Add("Index Service check failed`: $_")
                            }
                            
                            try {
                                $transferService = Get-Service "RayStationTransferService" -ErrorAction SilentlyContinue
                                if ($null -ne $transferService) {
                                    $transferStatus = $transferService.Status -eq "Running"
                                    $global:checkCount++
                                    if ($transferStatus) { $global:passedChecks++ }
                                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Transfer Service" -Status $transferStatus -Details "Status: $($transferService.Status)"))
                                }
                            }
                            catch {
                                $errorOccurred = $true
                                $null = $errorMessages.Add("Transfer Service check failed`: $_")
                            }

                            $RSVersion = $PackageVersion
                            if ($RSVersion.Split('.', 4)[3] -ne $null) {
                                $RSVersion = $RSVersion.Substring(0, $RSVersion.LastIndexOf('.'))
                            }
                            [version]$RSVersionUpdate = [String]$RSVersion

                            # GPU Config Check
                            try {
                                $gpuConfigPath = "$env:ProgramData\RaySearch\GpuSettings\GpuSettings-v$RSVersionUpdate.config"
                                $gpuConfigExists = Test-Path $gpuConfigPath
                                if ($gpuConfigExists) {
                                    [xml]$gpuConfig = Get-Content $gpuConfigPath
                                    $selectedGPU = $gpuConfig.configuration.gpuConfiguration.systemInfo
                                    $selectedGPU = ($selectedGPU -split "`n")[1]
                                    $global:checkCount++
                                    if ($gpuConfigExists) { $global:passedChecks++ }
                                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "GPU Configuration" -Status $gpuConfigExists -Details $selectedGPU))
                                }
                                else {
                                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "GPU Configuration" -Status $gpuConfigExists))
                                }
                            }
                            catch {
                                $errorOccurred = $true
                                $null = $errorMessages.Add("GPU Configuration check failed`: $_")
                            }
                        }
                    }
                }
                catch {
                    $errorOccurred = $true
                    $null = $errorMessages.Add("RayStation installation check failed`: $_")
                }
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("RayStation Checks section failed`: $_")
    }


    #GPU UUID Check
    try {
        if ($Settings.GENERAL.AUTOUPDATEGPUUUID -eq "Y") {
            try {
                # Driver Check
                $nvidiaDriver = Get-WmiObject Win32_VideoController | Where-Object { $_.Name -like "*NVIDIA*" }
                $driverInstalled = $null -ne $nvidiaDriver
                $driverDetails = if ($driverInstalled) { $nvidiaDriver.Name } else { "Not Installed" }
                $global:checkCount++
                if ($driverInstalled) { $global:passedChecks++ }
                Add-SectionHeader -Title "GPU UUID Auto Update Configuration" -Rows $htmlRows

                $updateScriptExists = Test-Path "C:\ProgramData\RaySearch\GpuSettings\GPUUUIDUpdate.ps1" 

                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Update Script Exists" -Status $updateScriptExists))

                $taskName = "UpdateGPUUUID"
                $task = Get-ScheduledTask | Where-Object { $_.TaskName -like $taskName }
                if ($null -ne $task) { $taskExists = $True }
                else { $taskExists = $False }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Auto Update Scheduled Task Exists" -Status $taskExists))
                $global:checkCount++
                            

            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("NVIDIA driver check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("GPU UUID Checks section failed`: $_")
    }


    # License Configuration
    try {
        if ($Settings.GENERAL.INSTALLLMX -eq "Y" -and $Settings.LICENSING.DESIGNATEDSERVER -match $env:COMPUTERNAME) {
            Add-SectionHeader -Title "License Configuration" -Rows $htmlRows
            
            try {
                # License File Check
                $LicensePath = "C:\Windows\System32\config\systemprofile\AppData\Local\x-formation"
                $LicensePathGCI = Get-ChildItem $LicensePath -ErrorAction Stop
                $licensePath = Join-Path $LicensePath -ChildPath ($LicensePathGCI | Where-Object { $_.Name -match ".lic" }).Name
                $licenseExists = Test-Path $licensePath
                $global:checkCount++
                if ($licenseExists) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "License File" -Status $licenseExists))
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("License file check failed`: $_")
            }

            try {
                $path = "$env:ProgramFiles\X-Formation"
                $NameArray = @()
                $names = (Get-ChildItem -Directory $path | Where-Object { $_.Name -match "^LM-X End-user Tools \d+\.\d+\.\d+ x64$" }).Name
                foreach ($name in $names) {
                    $NameSplit = $name -split " "
                    $NameArray += $NameSplit[3]
                }
                $sortedVersions = $NameArray | Sort-Object -Descending
                $greatestVersion = $sortedVersions[0]
                $greatestVersion = $names | Where-Object { $_ -match $greatestVersion }
                $LMXPath = Join-Path $path $greatestVersion

                $LMXService = Get-Service | Where-Object { $_.DisplayName -match "LM-X license server $($sortedVersions[0])" }
                if ($null -ne $LMXService) {
                    $LMXStatus = $LMXService.Status -eq "Running"
                    $global:checkCount++
                    if ($LMXStatus) { $global:passedChecks++ }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "LMX Service" -Status $LMXStatus -Details "Status: $($LMXService.Status)"))
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("LMX service check failed`: $_")
            }

            # HAL Configuration
            try {
                if ($Settings.LICENSING.CONFIGUREHAL -eq "Y") {
                    $halServers = @($Settings.LICENSING.HALSERVER1, $Settings.LICENSING.HALSERVER2, $Settings.LICENSING.HALSERVER3) | Where-Object { $_ }
                    foreach ($server in $halServers) {
                        $pingable = Test-Connection -ComputerName $server -Count 1 -Quiet
                        $global:checkCount++
                        if ($pingable) { $global:passedChecks++ }
                        $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "HAL Server $server" -Status $pingable))
                    }
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("HAL Configuration check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("License Configuration section failed`: $_")
    }

    # DICOM Service
    try {
        if ($Settings.GENERAL.INSTALLDICOM -eq "Y" -and $Settings.SERVICES.DICOMSERVICESERVER -match $env:COMPUTERNAME) {
            Add-SectionHeader -Title "DICOM Service Configuration" -Rows $htmlRows
            
            try {
                # Service Installation Check
                $dicomService = Get-Service "DicomStorageService" -ErrorAction SilentlyContinue
                $serviceInstalled = $null -ne $dicomService
                $serviceStatus = if ($serviceInstalled) { $dicomService.Status } else { "Not Installed" }
                $global:checkCount++
                if ($serviceInstalled) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "DICOM Service" -Status $serviceInstalled -Details "Status: $serviceStatus"))
                
                if ($serviceInstalled) {
                    # Configuration Check
                    $configPath = "$env:ProgramFiles\RaySearch Laboratories\RayStation Dicom Storage SCP\DicomStorageService.exe.config"
                    if (Test-Path $configPath) {
                        [xml]$dicomConfig = Get-Content $configPath
                        
                        # Port Check
                        $portMatch = ($dicomConfig.configuration.appSettings.add | Where-Object { $_.Key -eq 'Port' }).Value -eq $Settings.SERVICES.SCPPORT
                        $global:checkCount++
                        if ($portMatch) { $global:passedChecks++ }
                        $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "DICOM Port Configuration" -Status $portMatch -Details "Config Port: $(($dicomConfig.configuration.appSettings.add | Where-Object { $_.Key -eq 'Port' }).Value), Expected: $($Settings.SERVICES.SCPPORT)"))
                        
                        # Title Check
                        $titleMatch = ($dicomConfig.configuration.appSettings.add | Where-Object { $_.Key -eq 'AETitle' }).Value -eq $Settings.SERVICES.SCPTITLE
                        $global:checkCount++
                        if ($titleMatch) { $global:passedChecks++ }
                        $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "DICOM Title Configuration" -Status $titleMatch -Details "Config Title: $(($dicomConfig.configuration.appSettings.add | Where-Object { $_.Key -eq 'AETitle' }).Value)"))
                        
                        # Folder Check
                        $folderExists = Test-Path ($dicomConfig.configuration.appSettings.add | Where-Object { $_.Key -eq 'StorageLocation' }).Value
                        $global:checkCount++
                        if ($folderExists) { $global:passedChecks++ }
                        $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Storage Folder" -Status $folderExists -Details $Settings.SERVICES.SCPFOLDER))
                    }
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("DICOM Service configuration check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("DICOM Service section failed`: $_")
    }

    # License Agent Check
    try {
        if ($Settings.GENERAL.INSTALLLICENSEAGENT -eq "Y" -and $Settings.SERVICES.LICENSEAGENTSERVER -match $env:COMPUTERNAME) {
            Add-SectionHeader -Title "License Agent Configuration" -Rows $htmlRows
            
            try {
                # Service Check
                $licenseService = Get-Service "RayStationLicenseAgent" -ErrorAction SilentlyContinue
                $serviceInstalled = $null -ne $licenseService
                $serviceStatus = if ($serviceInstalled) { $licenseService.Status } else { "Not Installed" }
                $global:checkCount++
                if ($serviceInstalled) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "License Agent Service" -Status $serviceInstalled -Details "Status: $serviceStatus"))
                
                if ($serviceInstalled) {
                    # Endpoint Check
                    $endpointUri = $Settings.SERVICES.LICENSESERVICEENDPOINT
                    if ($endpointUri) {
                        try {
                            $testConnection = Test-NetConnection -ComputerName ([System.Uri]$endpointUri).Host -Port 443 -WarningAction SilentlyContinue -ErrorAction Stop
                            $global:checkCount++
                            if ($testConnection.TcpTestSucceeded) { $global:passedChecks++ }
                            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "License Service Endpoint" -Status $testConnection.TcpTestSucceeded -Details $endpointUri))
                        }
                        catch {
                            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "License Service Endpoint" -Status $false -Details "Failed to test connection to $endpointUri"))
                        }
                    }
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("License Agent check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("License Agent section failed`: $_")
    }

    # System Performance Checks
    try {
        Add-SectionHeader -Title "System Performance" -Rows $htmlRows

        # CPU Load
        try {
            $cpuLoad = [Math]::Round((Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 2)
            $global:checkCount++
            $cpuLoadOK = $cpuLoad -lt 80
            if ($cpuLoadOK) { $global:passedChecks++ }
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "CPU Load" -Status $cpuLoadOK -Details "Current Load: $cpuLoad%"))
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("CPU Load check failed`: $_")
        }

        # Memory Usage
        try {
            $computerSystem = Get-WmiObject Win32_ComputerSystem
            $osMemory = Get-WmiObject Win32_OperatingSystem
            $totalRamGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
            $freeRamGB = [math]::Round($osMemory.FreePhysicalMemory / 1MB, 2)
            $usedRamGB = $totalRamGB - $freeRamGB
            $ramPercentage = [math]::Round(($usedRamGB / $totalRamGB) * 100, 2)
            $ramOK = $ramPercentage -lt 90
            $global:checkCount++
            if ($ramOK) { $global:passedChecks++ }
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Memory Usage" `
                        -Status $ramOK `
                        -Details "Used: $usedRamGB GB of $totalRamGB GB ($ramPercentage%)"))
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("Memory Usage check failed`: $_")
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("System Performance section failed`: $_")
    }

    # Network Configuration
    try {
        Add-SectionHeader -Title "Network Configuration" -Rows $htmlRows
        
        try {
            $adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
            foreach ($adapter in $adapters) {
                $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction Stop
                $speed = [math]::Round($adapter.LinkSpeed.Split(' ')[0] / 1000, 2)
                $details = "Speed: $speed Gbps, IP: $($ipConfig.IPv4Address.IPAddress)"
                $global:checkCount++
                $adapterOK = $adapter.Status -eq 'Up'
                if ($adapterOK) { $global:passedChecks++ }
                $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Network Adapter: $($adapter.Name)" -Status $adapterOK -Details $details))
            }
        }
        catch {
            $errorOccurred = $true
            $null = $errorMessages.Add("Network adapter check failed`: $_")
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Network Configuration section failed`: $_")
    }

    # Certificate Checks
    try {
        if ($Settings.SERVICES.SECUREHOSTING -eq "Y") {
            Add-SectionHeader -Title "Certificate Configuration" -Rows $htmlRows
            
            try {
                if ($Settings.SERVICES.GenerateSelfSignedCert -eq "Y") {
                    $certSubject = if ($Settings.SERVICES.CERTSUBJECT) { $Settings.SERVICES.CERTSUBJECT } else { $env:COMPUTERNAME }
                    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$certSubject*" }
                    $certFound = $null -ne $cert
                    $certDetails = if ($certFound) {
                        "Subject: $($cert.Subject), Expires: $($cert.NotAfter)"
                    }
                    else {
                        "Certificate not found"
                    }
                    $global:checkCount++
                    if ($certFound) { $global:passedChecks++ }
                    $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "SSL Certificate" -Status $certFound -Details $certDetails))
                }
            }
            catch {
                $errorOccurred = $true
                $null = $errorMessages.Add("Certificate check failed`: $_")
            }
        }
    }
    catch {
        $errorOccurred = $true
        $null = $errorMessages.Add("Certificate Checks section failed`: $_")
    }

    # Add error section if needed
    if ($errorOccurred) {
        Add-SectionHeader -Title "Execution Errors" -Rows $htmlRows
        foreach ($error in $errorMessages) {
            $null = $htmlRows.Add((Write-HTMLTableRow -CheckName "Error" -Status $false -Details $error))
        }
    }

    # Add summary section
    $summaryHtml = @"
    <div class="summary">
        <h3>Execution Summary</h3>
        <p>Total Checks: $global:checkCount</p>
        <p>Passed Checks: $global:passedChecks</p>
        <p>Failed Checks: $($global:checkCount - $global:passedChecks)</p>
        <p>Status: $(if ($errorOccurred) { "Completed with errors" } else { "Completed successfully" })</p>
        <p>Pass Rate: $([math]::Round(($global:passedChecks / $global:checkCount) * 100, 2))%</p>
    </div>
"@

    # Generate final report
    $htmlContent = $htmlHeader + ($htmlRows -join "`n") + @"
    </table>
    $summaryHtml
    <p>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
</body>
</html>
"@

    # Save the report with error handling
    try {
        # Ensure output directory exists
        $outputDir = Split-Path -Parent $OutputPath
        if (-not (Test-Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }

        # Save report
        $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        Write-PSULog -Severity "Info" -Message  "Report generated successfully at: $OutputPath"
       
    }
    catch {
        Write-PSULog -Severity "Error" -Message "Failed to save report at primary location`: $_"
        # Try alternate location
        $fallbackPath = Join-Path $env:TEMP "SystemConfigurationReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlContent | Out-File -FilePath $fallbackPath -Encoding UTF8 -Force
        Write-PSULog -Severity "Warn" -Message  "Report saved to alternate location: $fallbackPath"
    }

    try {
        # Ensure Remote output directory exists
        if ($RemoteLogLocation -ne $Null) {
            $outputDir = Join-Path $RemoteLogLocation -ChildPath "Reports"

            if (-not (Test-Path $outputDir)) {
                New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
            }

            # Save report
            #$htmlContent | Out-File -FilePath $outputDir -Encoding UTF8 -Force
            Copy-Item -Path $OutputPath -Destination $outputDir
            Write-PSULog -Severity "Info" -Message  "Report generated successfully at: $OutputDir"
        }
    }
    Catch {

        Write-PSULog -Severity "Error" -Message "Failed to save report at remote location`: $_"

    }

    # Return success with warnings if errors occurred
    if ($errorOccurred) {
        Write-PSULog -Severity "Warn" -Message  "Script completed with errors. Check the report for details."
        exit 2
    }
}
catch {
    # Critical error handling
    $criticalError = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Configuration Check - Critical Error</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .error { color: red; }
    </style>
</head>
<body>
    <h1>System Configuration Check - Critical Error</h1>
    <p class="Error">Error: $(ConvertTo-HtmlEncoded $_.Exception.Message)</p>
    <p>Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Server: $env:COMPUTERNAME</p>
    <p>Line Number: $($_.InvocationInfo.ScriptLineNumber)</p>
    <p>Stack Trace:</p>
    <pre>$(ConvertTo-HtmlEncoded $_.Exception.StackTrace)</pre>
</body>
</html>
"@

    # Try to save error report
    try {
        $errorPath = Join-Path $env:TEMP "SystemConfigurationError_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $criticalError | Out-File -FilePath $errorPath -Encoding UTF8 -Force
        Write-PSULog -Severity "Error" -Message "Critical error`: $_. Error report saved to: $errorPath"
    }
    catch {
        Write-PSULog -Severity "Error" -Message "Critical error occurred and failed to save error report`: $_"
    }
}