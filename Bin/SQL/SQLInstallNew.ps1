<#
.SYNOPSIS
    Installs SQL Server with specified features and configurations.

.DESCRIPTION
    This script installs SQL Server using the provided parameters for features, directories, and configurations.
    It supports downloading the SQL Server ISO, mounting it, and running the installation in silent mode.
    Additionally, it can configure SQL Server protocols, set memory limits, and more.

.PARAMETER IsoPath
    Path to the SQL Server ISO file. If not specified, the script will use the default path or download the ISO.

.PARAMETER Features
    SQL Server features to install. See the documentation for a list of valid features.

.PARAMETER InstallDir
    Specifies a non-default installation directory.

.PARAMETER DataDir
    Data directory for SQL Server.

.PARAMETER BackupDir
    Backup directory for SQL Server.

.PARAMETER TempDBDDir
    Temporary Database Directory.

.PARAMETER TempLogDir
    Temporary Log Directory.

.PARAMETER FileStreamDrive
    Drive for FileStream.

.PARAMETER FilestreamShareName
    Share name for FileStream.

.PARAMETER Port
    Default SQL TCP and Dynamic TCP Port. Default is 1433.

.PARAMETER InstanceName
    Service name. Default is MSSQLSERVER.

.PARAMETER SaPassword
    Password for the 'sa' user. If empty, SQL security mode (mixed mode) is disabled.

.PARAMETER ServiceAccountName
    Username for the service account.

.PARAMETER ServiceAccountPassword
    Password for the service account.

.PARAMETER SystemAdminAccounts
    List of system administrative accounts.

.PARAMETER ProductKey
    Product key for SQL Server. If omitted, evaluation is used unless VL edition which is already activated.

.PARAMETER UseBitsTransfer
    Use BITS transfer to get files from the Internet.

.PARAMETER EnableProtocols
    Enable SQL Server protocols: TCP/IP, Named Pipes.

.EXAMPLE
    .\SQLInstallNew.ps1 -IsoPath "C:\SQLServer2019.iso" -Features "SQLEngine" -InstanceName "RAYSTATION" -SaPassword "Zxcvb12345"
    This command installs SQL Server with the specified ISO path, features, instance name, and sa password.

.NOTES
    Requires: Run as Administrator

#>
#Requires -RunAsAdministrator



param(
    # Path to ISO file, if empty and current directory contains single ISO file, it will be used.
    [string] $IsoPath = $ENV:SQLSERVER_ISOPATH,

    # Sql Server features, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Feature
    [ValidateSet('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')]
    [string[]] $Features = @('SQLEngine'),

    # Specifies a nondefault installation directory
    [string] $InstallDir,

    # Data directory, by default "$Env:ProgramFiles\Microsoft SQL Server"
    [string] $DataDir,

    # Backup directory, by default "$Env:ProgramFiles\Microsoft SQL Server"
    [string] $BackupDir,

    # Temporary Database Directory
    [string] $TempDBDDir,

    # Temporary Log Directory
    [string] $TempLogDir,

    # FileStream Drive
    [string] $FileStreamDrive,

    # FileStream Share Name
    [string] $FilestreamShareName,

    # Sets the default SQL TCP and Dynamic TCP Port, by default its 1433
    [string] $Port = '1433',

    # Service name. Mandatory, by default MSSQLSERVER
    [ValidateNotNullOrEmpty()]
    [string] $InstanceName = 'RAYSTATION',

    # sa user password. If empty, SQL security mode (mixed mode) is disabled
    [string] $SaPassword = "Zxcvb12345",

    # Username for the service account, see https://docs.microsoft.com/en-us/sql/database-engine/install-windows/install-sql-server-2016-from-the-command-prompt#Accounts
    # Optional, by default 'NT Service\MSSQLSERVER'
    [string] $ServiceAccountName, # = "$Env:USERDOMAIN\$Env:USERNAME"

    # Password for the service account, should be used for domain accounts only
    # Mandatory with ServiceAccountName
    [string] $ServiceAccountPassword,

    # List of system administrative accounts in the form <domain>\<user>
    # Mandatory, by default current user will be added as system administrator
    [string[]] $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),

    # Product key, if omitted, evaluation is used unless VL edition which is already activated
    [string] $ProductKey = "22222-00000-00000-00000-00000",

    # Use bits transfer to get files from the Internet
    [switch] $UseBitsTransfer,

    # Enable SQL Server protocols: TCP/IP, Named Pipes
    [switch] $EnableProtocols
)

$ErrorActionPreference = 'STOP'
$scriptName = (Split-Path -Leaf $PSCommandPath).Replace('.ps1', '')



$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..\..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$start = Get-Date
Start-Transcript "$RunLocation\Logs\$scriptName-$($start.ToString('s').Replace(':','-')).log"

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

Write-PSULog -Severity Start -Message "Starting SQL Install"

if (!$IsoPath) {
    #Write-Host "SQLSERVER_ISOPATH environment variable not specified, using defaults"
    Write-PSULog -Severity Info -Message "SQLSERVER_ISOPATH environment variable not specified, using defaults"
    $IsoPath = "https://download.microsoft.com/download/7/c/1/7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLServer2019-x64-ENU-Dev.iso"

    $saveDir = Join-Path $Env:TEMP $scriptName
    New-item $saveDir -ItemType Directory -ErrorAction 0 | Out-Null

    $isoName = $isoPath -split '/' | Select-Object -Last 1
    $savePath = Join-Path $saveDir $isoName

    if (Test-Path $savePath) {
        #Write-Host "ISO already downloaded, checking hashsum..."
        Write-PSULog -Severity Info -Message "ISO already downloaded, checking hashsum..."
        $hash = Get-FileHash -Algorithm MD5 $savePath | % Hash
        $oldHash = Get-Content "$savePath.md5" -ErrorAction 0
    }

    if ($hash -and $hash -eq $oldHash) { Write-Host "Hash is OK"; Write-PSULog -Severity Info -Message "Hash is OK" } else {
        if ($hash) { Write-Host "Hash is NOT OK"; Write-PSULog -Severity Warning -Message "Hash is NOT OK" }
        #Write-Host "Downloading: $isoPath"
        Write-PSULog -Severity Info -Message "Downloading: $isoPath"

        if ($UseBitsTransfer) {
            #Write-Host "Using bits transfer"
            Write-PSULog -Severity Info -Message "Using bits transfer"
            $proxy = if ($ENV:HTTP_PROXY) { @{ ProxyList = $ENV:HTTP_PROXY -replace 'http?://'; ProxyUsage = 'Override' } } else { @{} }
            Start-BitsTransfer -Source $isoPath -Destination $saveDir @proxy
        }
        else {
            Invoke-WebRequest $IsoPath -OutFile $savePath -UseBasicParsing -Proxy $ENV:HTTP_PROXY
        }

        Get-FileHash -Algorithm MD5 $savePath | % Hash | Out-File "$savePath.md5"
    }

    $IsoPath = $savePath
}

#Write-Host "`IsoPath: " $IsoPath
Write-PSULog -Severity Info -Message "`IsoPath: $IsoPath"

$volume = Mount-DiskImage $IsoPath -StorageType ISO -PassThru | Get-Volume
$sql_drive = $volume.DriveLetter + ':'
Get-ChildItem $sql_drive | ft -auto | Out-String

Get-CimInstance win32_process | ? { $_.commandLine -like '*setup.exe*/ACTION=install*' } | % {
    #Write-Host "Sql Server installer is already running, killing it:" $_.Path  "pid: " $_.processId
    Write-PSULog -Severity Warning -Message "Sql Server installer is already running, killing it:" $_.Path  "pid: " $_.processId
    Stop-Process $_.processId -Force
}

$cmd = @(
    "${sql_drive}setup.exe"
    '/Q'                                # Silent install
    '/INDICATEPROGRESS'                 # Specifies that the verbose Setup log file is piped to the console
    '/IACCEPTSQLSERVERLICENSETERMS'     # Must be included in unattended installations
    '/ACTION=install'                   # Required to indicate the installation workflow
    '/UPDATEENABLED=false'              # Should it discover and include product updates.
    '/TCPENABLED=1'                     # Enables TCP
    '/NPENABLED=1'                      # Enables Namepipes

    '/FILESTREAMLEVEL=3'                # Enables FileStream
    "/FILESTREAMSHARENAME=""$FilestreamShareName""" # Sets FileStream share name

    "/INSTANCEDIR=""$InstallDir"""
    "/INSTALLSQLDATADIR=""$DataDir"""
    "/SQLBACKUPDIR=""$BackupDir"""
    "/SQLTEMPDBDIR=""$TempDBDDir"""
    "/SQLTEMPDBLOGDIR=""$TempLogDir"""

    "/FEATURES=" + ($Features -join ',')

    #Security
    "/SQLSYSADMINACCOUNTS=""$SystemAdminAccounts"""
    '/SECURITYMODE=SQL'                 # Specifies the security mode for SQL Server. By default, Windows-only authentication mode is supported.
    "/SAPWD=""$SaPassword"""            # Sa user password

    "/INSTANCENAME=$InstanceName"       # Server instance name

    "/SQLSVCACCOUNT=""$ServiceAccountName"""
    "/SQLSVCPASSWORD=""$ServiceAccountPassword"""

    # Service startup types
    "/SQLSVCSTARTUPTYPE=automatic"
    "/AGTSVCSTARTUPTYPE=automatic"
    "/ASSVCSTARTUPTYPE=automatic"

    "/PID=$ProductKey"
)

# remove empty arguments
$cmd_out = $cmd = $cmd -notmatch '/.+?=("")?$'

# show all parameters but remove password details
Write-Host "Install parameters:`n"
'SAPWD', 'SQLSVCPASSWORD' | % { $cmd_out = $cmd_out -replace "(/$_=).+", '$1"****"' }
$cmd_out[1..100] | % { $a = $_ -split '='; Write-Host '   ' $a[0].PadRight(40).Substring(1), $a[1] }
Write-Host

"$cmd_out"
Invoke-Expression "$cmd"
if ($LastExitCode) {
    if ($LastExitCode -ne 3010) { throw "SqlServer installation failed, exit code: $LastExitCode"; Write-PSULog -Severity Error -Message "SqlServer installation failed, exit code: $LastExitCode" }
    #Write-Warning "SYSTEM REBOOT IS REQUIRED"
    Write-PSULog -Severity Warning -Message "SYSTEM REBOOT IS REQUIRED"
}

if ($EnableProtocols) {
    function Enable-Protocol ($ProtocolName) { $sqlNP | ? ProtocolDisplayName -eq $ProtocolName | Invoke-CimMethod -Name SetEnable }

    #Write-Host "Enable SQL Server protocols: TCP/IP, Named Pipes"
    Write-PSULog -Severity Info -Message "Enable SQL Server protocols: TCP/IP, Named Pipes"

    $sqlCM = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -ClassName "__NAMESPACE"  | ? name -match 'ComputerManagement' | Select-Object -Expand name
    $sqlNP = Get-CimInstance -Namespace "root\Microsoft\SqlServer\$sqlCM" -ClassName ServerNetworkProtocol

    Enable-Protocol 'TCP/IP'
    Enable-Protocol 'Named Pipes'

    #Get-Service | where {$_.DisplayName -like "*$instanceName*"} | restart-service -force
}

function SetPort($InstanceName, $port) {
    # fetch the WMI object that contains TCP settings; filter for the 'IPAll' setting only
    # note that the 'ComputerManagement13' corresponds to SQL Server 2017

    $inst = (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server').InstalledInstances
    $i = ($inst | Where-Object { $_ -match $InstanceName })

    $p = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL').$i
    $Version = ((Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$p\Setup").Version).split('.')[0]

    $WMISettings = Get-WmiObject `
        -Namespace root/Microsoft/SqlServer/ComputerManagement$Version `
        -Class ServerNetworkProtocolProperty `
        -Filter "InstanceName=`'$InstanceName`' and IPAddressName='IPAll' and PropertyType=1 and ProtocolName='Tcp'"

    # there are two settings in a list: TcpPort and TcpDynamicPorts
    foreach ($setting in $WMIsettings) {
        if ($null -ne $setting ) {
            # set the static TCP port and at the same time clear any dynamic ports
            if ($setting.PropertyName -eq "TcpPort") {
                $setting.SetStringValue($port)
            }
            elseif ($setting.PropertyName -eq "TcpDynamicPorts") {
                $setting.SetStringValue("")
            }
        }
    }
    #Write-Host "Restarting SQL Services" -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Restarting SQL Services"
    Get-service | Where-Object { $_.Name -eq "MSSQL`$$InstanceName" } | Restart-Service -Force

    (Get-Service | Where-Object { $_.Name -eq "MSSQL`$$InstanceName" }).WaitForStatus('Running')

}
#Write-Host "Attempting to Set SQL port to $port" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Attempting to Set SQL port to $port"
SetPort "$InstanceName" "$port"
#Write-Host "Set SQL Port to $port" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Set SQL Port to $port"

Function Get-SQLMaxMemory { 
    $memtotal = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1mb
    $min_os_mem = 2048 ;
    if ($memtotal -le $min_os_mem) {
        Return $null;
    }
    if ($memtotal -le 8192) {
        $sql_mem = $memtotal - 2048
    }
    else {
        $sql_mem = $memtotal * 0.8 ;
    }
    return [int]$sql_mem ;  
}
Function Set-SQLInstanceMemory {
    param (
        [string]$SQLInstanceName = ".", 
        [int]$maxMem = $null, 
        [int]$minMem = 0
    )
 
    if ($minMem -eq 0) {
        $minMem = $maxMem
    }
    [reflection.assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    $srv = New-Object Microsoft.SQLServer.Management.Smo.Server($SQLInstanceName)
    if ($srv.status) {
        #Write-Host "[Running] Setting Maximum Memory to: $($srv.Configuration.MaxServerMemory.RunValue)"
        Write-PSULog -Severity Info -Message "[Running] Setting Maximum Memory to: $($srv.Configuration.MaxServerMemory.RunValue)"
        #Write-Host "[Running] Setting Minimum Memory to: $($srv.Configuration.MinServerMemory.RunValue)"
        Write-PSULog -Severity Info -Message "[Running] Setting Minimum Memory to: $($srv.Configuration.MinServerMemory.RunValue)"
 
        #Write-Host "[New] Setting Maximum Memory to: $maxmem"
        Write-PSULog -Severity Info -Message "[New] Setting Maximum Memory to: $maxmem"
        #Write-Host "[New] Setting Minimum Memory to: $minmem"
        Write-PSULog -Severity Info -Message "[New] Setting Minimum Memory to: $minmem"
        $srv.Configuration.MaxServerMemory.ConfigValue = $maxMem
        $srv.Configuration.MinServerMemory.ConfigValue = $minMem   
        $srv.Configuration.Alter()
    }
}

#Write-Host "Setting SQL Memory Config" -ForegroundColor Yellow
Write-PSULog -Severity Info -Message "Setting SQL Memory Config"
$SQLMem = Get-SQLMaxMemory
Set-SQLInstanceMemory InstanceName ($SQLMem)

#Write-Host "Set SQL Max memory to $SQLMem" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Set SQL Max memory to $SQLMem"

"`nInstallation length: {0:f1} minutes" -f ((Get-Date) - $start).TotalMinutes

Dismount-DiskImage $IsoPath
Stop-Transcript
trap { Stop-Transcript; if ($IsoPath) { Dismount-DiskImage $IsoPath -ErrorAction 0 } }
Write-PSULog -Severity End -Message "Finished SQL Install"