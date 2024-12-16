<#
.SYNOPSIS
    Base Install for App or SQL Server.

.DESCRIPTION
    This script performs the base installation for an application or SQL server. It reads settings from a JSON file and performs various setup tasks based on those settings.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\Setup.ps1
    Runs the setup script with the settings defined in Setup.json.

.NOTES
    Author: John Burriss
    Created: 8/26/2019
    Modified: 10/12/2022
    Version: 0.07
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition

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
#-------------------------------------------------------------------------------------------------------------



#$Path = "$RunLocation\Logs\"

Get-Process Powershell  | Where-Object { $_.ID -ne $pid } | Stop-Process

#if (!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\setup.log"
#}
4
if (Test-Connection 8.8.8.8 -Count 1 -Quiet) { 
    Install-PackageProvider -Name NuGet -Force | Out-Null
}
Else {

    $RepositoryName = "Temp"
    $Path = "C:\Users\$env:UserName\Documents\WindowsPowerShell\Modules"

    $exists = Test-Path "filesystem::$path"
    if (!($exists)) {
        Write-PSULog -Severity Warn -Message "Repository $path is offline"
    }

    $Existing = Get-PSRepository -Name $RepositoryName -ErrorAction Ignore

    if ($null -eq $Existing) {
        try {
            Register-PSRepository -Name $RepositoryName -SourceLocation $Path -ScriptSourceLocation $Path -InstallationPolicy Trusted -Confirm:$false
        }
        Catch {
            Write-PSULog -Severity Warn -Message "Unable to register Repository: $RepositoryName from path: $Path"
        }

    }
    
    $error.clear()
    Try {
        Install-PackageProvider -Name NuGet -ErrorAction SilentlyContinue -Force -Confirm:$false
    }
    Catch {
        Write-PSULog -Severity Warn -Message "Failed to Install NuGet"
    }
}


#Start-Transcript -Path "$RunLocation\Logs\setup.log"

if (!(Test-path "$RunLocation\Bin\Key")) {
    New-Item -ItemType Directory -Path "$RunLocation\Bin\Key" -out $null
}
  
If (!(Test-path "$RunLocation\Bin\Key\key.key")) {
  
    $AESKey = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    $AESKey | out-file "$RunLocation\Bin\Key\key.key"
        
}
else {
  
    $AESKey = Get-Content "$RunLocation\Bin\Key\key.key"
  
}


$SQLUser = $Settings.SQL.SERVICEACCOUNTNAME
$IndexUser = $Settings.RAYSTATION.IndexServiceUser
$TransferUser = $Settings.RAYSTATION.TransferServiceUser
$LicenseUser = $Settings.SERVICES.SERVICEUSER

if (($Settings.GENERAL.INSTALLSQL -match "Y") -and !([string]::IsNullOrEmpty($SQLUser)) -and $SQLUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

    Write-PSULog -Severity Error -Message "SQL Service User is in incorrect Format, please use Username@Domain.Suffix format"
    Break

}
if (($Settings.GENERAL.INSTALLRAYSTATION -match "Y") -and !([string]::IsNullOrEmpty($IndexUser)) -and $IndexUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

    Write-PSULog -Severity Error -Message "Index Service User is in incorrect Format, please use Username@Domain.Suffix format"
    Break

}
if (($Settings.GENERAL.INSTALLRAYSTATION -match "Y") -and !([string]::IsNullOrEmpty($TransferUser)) -and $TransferUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

    Write-PSULog -Severity Error -Message "Transfer Service User is in incorrect Format, please use Username@Domain.Suffix format"
    Break

}
if (($Settings.GENERAL.INSTALLLICENSEAGENT -match "Y") -and !([string]::IsNullOrEmpty($LicenseUser)) -and $LicenseUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

    Write-PSULog -Severity Error -Message "License Agent Service User is in incorrect Format, please use Username@Domain.Suffix format"
    Break

}

$SQLSAPassword = $Settings.SQL.SAPASSWORD
$SERVICEACCOUNTPASSWORD = $Settings.SQL.SERVICEACCOUNTPASSWORD
$IndexServicePwd = $settings.RAYSTATION.IndexServicePwd
$TransferServicePwd = $settings.RAYSTATION.TransferServicePwd
$LicenseAgentPWD = $settings.SERVICES.SERVICEPWD


if (!([string]::IsNullOrEmpty($SQLSAPassword)) -and $SQLSAPassword.Length -le "64") {

    $secureSQLSAPassword = convertto-securestring $SQLSAPassword -asplaintext -force
    $secureSQLSAPassword = ConvertFrom-SecureString -SecureString $secureSQLSAPassword -Key $AESkey
    $Settings.SQL.SAPASSWORD = $secureSQLSAPassword
    $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}
if (!([string]::IsNullOrEmpty($SERVICEACCOUNTPASSWORD)) -and $SERVICEACCOUNTPASSWORD.Length -le "64") {

    $secureSERVICEACCOUNTPASSWORD = convertto-securestring $SERVICEACCOUNTPASSWORD -asplaintext -force
    $secureSERVICEACCOUNTPASSWORD = ConvertFrom-SecureString -SecureString $secureSERVICEACCOUNTPASSWORD -Key $AESkey
    $Settings.SQL.SERVICEACCOUNTPASSWORD = $secureSERVICEACCOUNTPASSWORD
    $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}
if (!([string]::IsNullOrEmpty($IndexServicePwd)) -and $IndexServicePwd.Length -le "64") {

    $secureIndexServicePwd = convertto-securestring $IndexServicePwd -asplaintext -force
    $secureIndexServicePwd = ConvertFrom-SecureString -SecureString $secureIndexServicePwd -Key $AESkey
    $settings.RAYSTATION.IndexServicePwd = $secureIndexServicePwd
    $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}
if (!([string]::IsNullOrEmpty($TransferServicePwd)) -and $TransferServicePwd.Length -le "64") {

    $secureTransferServicePwd = convertto-securestring $TransferServicePwd -asplaintext -force
    $secureTransferServicePwd = ConvertFrom-SecureString -SecureString $secureTransferServicePwd -Key $AESkey
    $settings.RAYSTATION.TransferServicePwd = $secureTransferServicePwd
    $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}
if (!([string]::IsNullOrEmpty($LicenseAgentPWD)) -and $LicenseAgentPWD.Length -le "64") {

    $secureLicenseAgentPWD = convertto-securestring $LicenseAgentPWD -asplaintext -force
    $secureLicenseAgentPWD = ConvertFrom-SecureString -SecureString $secureLicenseAgentPWD -Key $AESkey
    $settings.SERVICES.SERVICEPWD = $secureLicenseAgentPWD
    $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}

Write-host "Checking Packages" -ForegroundColor Green

if (($Settings.GENERAL.INSTALLSQL -match "Y") -and !([string]::IsNullOrEmpty($settings.SQL.ISOPATH))) {
    if (!(Test-path $settings.SQL.ISOPATH)) {
        write-host "SQL ISO Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLGPUDRIVER -match "Y") -and !([string]::IsNullOrEmpty($Settings.GPU.DRIVERLOCATION))) {
    if (!(Test-path $Settings.GPU.DRIVERLOCATION)) {
        write-host "GPU Driver Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLGPUDRIVER -match "Y") -and !([string]::IsNullOrEmpty($Settings.GPU.NVIDIALICENSETOKENLOCATION))) {
    if (!(Test-path $Settings.GPU.NVIDIALICENSETOKENLOCATION)) {
        write-host "Nvidia License Token Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLLMX -match "Y") -and !([string]::IsNullOrEmpty($Settings.LICENSING.LICENSELOCATION))) {
    if (!(Test-path $Settings.LICENSING.LICENSELOCATION)) {
        write-host "RayStation License Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLCITRIX -match "Y") -and !([string]::IsNullOrEmpty($Settings.CITRIX.CITRIXISOLOCATION))) {
    if (!(Test-path $Settings.CITRIX.CITRIXISOLOCATION)) {
        write-host "Citrix ISO Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLRAYSTATION -match "Y") -and !([string]::IsNullOrEmpty($Settings.RAYSTATION.RAYSTATIONLOCATION))) {
    if (!(Test-path $Settings.RAYSTATION.RAYSTATIONLOCATION)) {
        write-host "RayStation Installer Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLDICOM -match "Y") -and !([string]::IsNullOrEmpty($Settings.SERVICES.DICOMSERVICELOCATION))) {
    if (!(Test-path $Settings.SERVICES.DICOMSERVICELOCATION)) {
        write-host "DICOM Installer Path Incorrect. Please correct and rerun"
        Break
    }
}
if (($Settings.GENERAL.INSTALLLICENSEAGENT -match "Y") -and !([string]::IsNullOrEmpty($Settings.SERVICES.LICENSESETUPEXE))) {
    if (!(Test-path $Settings.SERVICES.LICENSESETUPEXE)) {
        write-host "RRayStation License Agent Installer EXE Path Incorrect. Please correct and rerun"
        Break
    }
}
    
try {

    $Dotnet = (Get-ItemPropertyValue -LiteralPath "HKLM:\SOFTWARE\MachineSetup" -Name dotNet -ErrorAction SilentlyContinue) -eq "1"

}
catch {
    $Dotnet = $false
}


if ($Dotnet -eq $false) {

    #Enables Autologon for the machine
    $ENABLEAUTOLOGON = $settings.GENERAL.ENABLEAUTOLOGON
    if ($ENABLEAUTOLOGON -match "y") {
        #Write-Host "Enabeling Autologon" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Enabeling Autologon"
        & $RunLocation\bin\Autologon.ps1 -wait
    }

    #Write-host "Running through Default Settings" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Running through Default Settings"
    & $RunLocation\bin\DefaultSettings.ps1

    if ($null -ne $settings.GENERAL.MACHINENAME) {
        #write-host "Renaming machine" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Renaming machine"
        & $RunLocation\bin\NameMachine.ps1
    }


    #Installs Java, Adobe Reader, .Net 4.8
    $INSTALLJAVA = $settings.GENERAL.INSTALLJAVA
    if ($INSTALLJAVA -match "y") {
        #Write-Host "Installing Java" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Installing Java"
        & $RunLocation\bin\InstallJava.ps1 -wait
    }

    #Installs Java, Adobe Reader, .Net 4.8
    $INSTALLADOBE = $settings.GENERAL.INSTALLADOBE
    if ($INSTALLADOBE -match "y") {
        #Write-Host "Installing Adobe Reader" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Installing Adobe Reader"
        & $RunLocation\bin\InstallAdobe.ps1 -wait
    }

    #Installs Java, Adobe Reader, .Net 4.8
    $INSTALLDOTNET = $settings.GENERAL.INSTALLDOTNET
    if ($INSTALLDOTNET -match "y") {
        #Write-Host "Installing .Net 4.8" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Installing .Net 4.8"
        & $RunLocation\bin\InstallDotNet.ps1 -wait
    }
}
elseif ($dotnet -eq $true) {

    Write-PSULog -Severity Info -Message "Continuing Setup after .net4.8 Install"

    if (Get-ItemProperty -Path "HKLM:\SOFTWARE\MachineSetup" -Name dotNet) { Remove-ItemProperty -Path "HKLM:\SOFTWARE\MachineSetup" -Name dotNet }

}

$Make = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer -ExpandProperty Manufacturer

#Checks if its a dell and installs dell open manage.
if ($Make -match "Dell Inc.") {
    #Write-Host "Installing Dell Open Manage" -ForegroundColor Yellow
    Write-PSULog -Severity Info -Message "Installing Dell Open Manage" 
    & $RunLocation\bin\OpenManage\SYSMGMT\srvadmin\windows\SystemsManagementx64\SysMgmtx64.msi ADDLOCAL=ALL /qb
    #$RunLocation\bin\OpenManage\SYSMGMT\ManagementStation\windows\iDRACToolsx64\iDRACTools_x64.msi ADDLOCAL=ALL /qb
    #$RunLocation\bin\OpenManage\SYSMGMT\ManagementStation\windows\ADSnapInx64\ADSnapIn_x64.msi ADDLOCAL=ALL /qb
    #$RunLocation\bin\OpenManage\SYSMGMT\iSM\windows\iDRACSvcMod.msi ADDLOCAL=ALL /qb
    #Write-Host "Finished Installing Dell Open Manage" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Finished Installing Dell Open Manage"
}



#Creates Local Groups for RayStation
$LOCALGROUPS = $settings.GENERAL.LOCALGROUPS
if ($LOCALGROUPS -match "y") {
    #Write-Host "Creating Local Groups" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Creating Local Groups"
    & $RunLocation\bin\LocalGroups.ps1 -wait
}

#Calls script to setup SQL Drives
if ($settings.DESIGNATEDSQLSERVER -contains $env:computername -or $null -eq $settings.DESIGNATEDSQLSERVER) {
    if ($settings.GENERAL.FORMATDRIVES -match "y") {
        #Write-Host "Configuring Drives" -ForegroundColor Green
        Write-PSULog -Severity Start -Message "Configuring Drives"
        $SQLDriveSetup = "$RunLocation\bin\DriveSetup.ps1"
        & $SQLDriveSetup -Wait
    }
  
    if ($settings.GENERAL.INSTALLSQL -match "y") {
        $ISOPATH = $settings.SQL.ISOPATH
        $FEATURES = $settings.SQL.FEATURES
        $DATADIR = $settings.SQL.DATADIR
        $BACKUPDIR = $settings.SQL.BACKUPDIR
        $TEMPDBDIR = $settings.SQL.TEMPDBDIR
        $TEMPLOGDIR = $settings.SQL.TEMPLOGDIR
        $FILESTREAMDRIVE = $settings.SQL.FILESTREAMDRIVE
        $FILESTREAMSHARENAME = $settings.SQL.FILESTREAMSHARENAME
        $PORT = $settings.SQL.PORT
        $INSTANCENAME = $settings.SQL.INSTANCENAME
        $SAPASSWORD = $settings.SQL.SAPASSWORD
        $SERVICEACCOUNTNAME = $settings.SQL.SERVICEACCOUNTNAME
        $SERVICEACCOUNTPASSWORD = $settings.SQL.SERVICEACCOUNTPASSWORD
        $PRODUCTKEY = $settings.SQL.PRODUCTKEY
        $USETRANSFERBITS = $settings.SQL.USETRANSFERBITS
        $ENABLEPROTOCOLS = $settings.SQL.ENABLEPROTOCOLS

        $SERVICEACCOUNTPASSWORD = ConvertTo-SecureString -String $SERVICEACCOUNTPASSWORD -Key $AESKey
        $SERVICEACCOUNTPASSWORD = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SERVICEACCOUNTPASSWORD)
        $SERVICEACCOUNTPASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SERVICEACCOUNTPASSWORD)

        $SAPASSWORD = ConvertTo-SecureString -String $SAPASSWORD -Key $AESKey
        $SAPASSWORD = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SAPASSWORD)
        $SAPASSWORD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SAPASSWORD)

        #Write-Host "Checking prerequisites for SQL Installation." -ForegroundColor Yellow 
        Write-PSULog -Severity Info -Message "Checking prerequisites for SQL Installation."
        if ($null -eq $ISOPATH) {
            #Write-Host "The default ISO of Server 2019 will be downloaded and installed" -ForegroundColor Yellow
            Write-PSULog -Severity Info -Message "The default ISO of Server 2019 will be downloaded and installed"
        }
        if (!(Test-Path $ISOPATH)) {
            #Write-Host "The SQL ISO Path does not exist or cannot be reached." -ForegroundColor Red
            Write-PSULog -Severity Warn -Message "The SQL ISO Path does not exist or cannot be reached."
            #Write-Host "Switching to default ISO Download."
            Write-PSULog -Severity Warn -Message "Switching to default ISO Download."
            $null = $ISOPATH
        }
        if ($null -eq $features) {
            #Write-Host "There are no selected features. The default SQLEngine feature will be installed." -ForegroundColor Yellow
            Write-PSULog -Severity Warn -Message "There are no selected features. The default SQLEngine feature will be installed."
        }
        $DATADIRLETTER = $DATADIR.substring(0, 1)
        if ($null -eq (Get-PSDrive | Where-Object { $_.Name -match "$DATADIRLETTER" } | Select-Object name)) {
            #Write-Host "The Data Drive Does not exist. Please select a drive that exists and rerun." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "The Data Drive Does not exist. Please select a drive that exists and rerun."
            #Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            Exit
        }
        else {
            if (!(Test-Path $DATADIR)) { 
                #Write-Host "Creating Data Directory: $DATADIR" -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Creating Data Directory: $DATADIR"
                New-Item -ItemType "directory" -Path "$DATADIR"
            }
            else {
                #Write-Host "Data Directory $DATADIR already exists." -ForegroundColor Yellow
                Write-PSULog -Severity Warn -Message "Data Directory $DATADIR already exists."
            }
        }
        $BACKUPDIRLETTER = $BACKUPDIR.substring(0, 1)
        if ($null -eq (Get-PSDrive | Where-Object { $_.Name -match "$BACKUPDIRLETTER" } | Select-Object name)) {
            #Write-Host "The Backup Drive Does not exist. Please select a drive that exists and rerun." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "The Backup Drive Does not exist. Please select a drive that exists and rerun."
            #Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            Exit
        }
        else {
            if (!(Test-Path $BACKUPDIR)) { 
                #Write-Host "Creating backup directory: $BACKUPDIR" -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Creating backup directory: $BACKUPDIR"
                New-Item -ItemType "directory" -Path "$BACKUPDIR"
            }
            else {
                #Write-Host "Backup Directory $BACKUPDIR already exists." -ForegroundColor Yellow
                Write-PSULog -Severity Warn -Message "Backup Directory $BACKUPDIR already exists."
            }
        }
        $TEMPDBDIRLETTER = $TEMPDBDIR.substring(0, 1)
        if ($null -eq (Get-PSDrive | Where-Object { $_.Name -match "$TEMPDBDIRLETTER" } | Select-Object name)) {
            #Write-Host "The Temp Drive Does not exist. Please select a drive that exists and rerun." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "The Temp Drive Does not exist. Please select a drive that exists and rerun."
            Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            Exit
        }
        else {
            if (!(Test-Path $TEMPDBDIR)) { 
                #Write-Host "Creating Temp directory: $TEMPDBDIR" -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Creating Temp directory: $TEMPDBDIR"
                New-Item -ItemType "directory" -Path "$TEMPDBDIR"
            }
            else {
                Write-Host "Temp Directory $TEMPDBDIR already exists." -ForegroundColor Yellow
            }
        }
        $TEMPLOGDIRLETTER = $TEMPLOGDIR.substring(0, 1)
        if ($null -eq (Get-PSDrive | Where-Object { $_.Name -match "$TEMPLOGDIRLETTER" } | Select-Object name)) {
            #Write-Host "The Temp Log Drive Does not exist. Please select a drive that exists and rerun." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "The Temp Log Drive Does not exist. Please select a drive that exists and rerun."
            #Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            Exit
        }
        else {
            if (!(Test-Path $TEMPLOGDIR)) { 
                #Write-Host "Creating Temp Log directory: $TEMPLOGDIR" -ForegroundColor Green
                Write-PSULog -Severity Info -Message "Creating Temp Log directory: $TEMPLOGDIR"
                New-Item -ItemType "directory" -Path "$TEMPLOGDIR"
            }
            else {
                #Write-Host "Temp Log Directory $TEMPLOGDIR already exists." -ForegroundColor Yellow
                Write-PSULog -Severity Warning -Message "Temp Log Directory $TEMPLOGDIR already exists."
            }
        }
        $FILESTREAMDRIVELETTER = $FILESTREAMDRIVE.substring(0, 1)
        if ($null -eq (Get-PSDrive | Where-Object { $_.Name -match "$FILESTREAMDRIVELETTER" } | Select-Object name)) {
            #Write-Host "The FileStream Drive Does not exist. Please select a drive that exists and rerun." -ForegroundColor Red
            Write-PSULog -Severity Error -Message "The FileStream Drive Does not exist. Please select a drive that exists and rerun."
            #Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            #Exit
            else {
                if (!(Test-Path $FILESTREAMDRIVELETTER":\SQLServer\FileStream")) {
                    #Write-Host "Creating FileStream Directory $FILESTREAMDRIVELETTER`':\SQLServer\FileStream`'" -ForegroundColor Green
                    Write-PSULog -Severity Info -Message "Creating FileStream Directory $FILESTREAMDRIVELETTER`':\SQLServer\FileStream`'"
                    New-Item -ItemType "Directory" -Path $FILESTREAMDRIVELETTER":\SQLServer\FileStream"
                }

            }
        }
        if ($PORT -notmatch "^\d+$") {

            #Write-host "PORT contains Illegal characters, Please ensure that an integer is used. The Default SQL port is 1433" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "PORT contains Illegal characters, Please ensure that an integer is used. The Default SQL port is 1433"
            #Write-Host "Exiting script in 5 seconds." -ForegroundColor Yellow; Start-Sleep -s 5
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            Exit
            
        }
        if ($USETRANSFERBITS -match "n") {
            $null = $USETRANSFERBITS
        }
        if ($ENABLEPROTOCOLS -match "n") {
            $null = $ENABLEPROTOCOLS
        }

        Write-PSULog -Severity Start -Message "Starting SQL Install"
        $InstallSQL = "$RunLocation\bin\SQL\SQLInstallNew.ps1"
        #$args = "-IsoPath `"$ISOPATH`" -Features `"$Features`" -InstallDir `"$InstallDir`" -DataDir `"$DataDir`" -BackupDir `"$BackupDir`" -TempDBDDir `"$TEMPDBDIR`" -TempLogDir `"$TempLogDir`" -FilestreamShareName `"$FILESTREAMSHARENAME`" -Port `"$Port`" -InstanceName `"$InstanceName`" -SaPassword `"$SaPassword`" -ServiceAccountName `"$ServiceAccountName`" -ServiceAccountPassword `"$ServiceAccountPassword`" -SystemAdminAccounts `"$Env:USERDOMAIN\$Env:USERNAME`" -ProductKey `"$ProductKey`" -UseBitsTransfer `"$USETRANSFERBITS`" -EnableProtocols `"$EnableProtocols`""
        & $installSQL -IsoPath $ISOPATH -Features $Features -InstallDir $InstallDir -DataDir $DataDir -BackupDir $BackupDir -TempDBDDir $TEMPDBDIR -TempLogDir $TempLogDir -FilestreamShareName $FILESTREAMSHARENAME -Port $Port -InstanceName $InstanceName -SaPassword $SaPassword -ServiceAccountName $ServiceAccountName -ServiceAccountPassword $ServiceAccountPassword -SystemAdminAccounts $Env:USERDOMAIN\$Env:USERNAME -ProductKey $ProductKey -UseBitsTransfer $USETRANSFERBITS -EnableProtocols $EnableProtocols

        $FILESTREAMDRIVE = $FILESTREAMDRIVE.substring(0, 1)

        if ($FILESTREAMDRIVE -match "[a-zA-Z]") {

            #Write-Host "Fixing FileStream Directory" -ForegroundColor Green
            Write-PSULog -Severity Start -Message "Fixing FileStream Directory"
            & $RunLocation\bin\sql\FileStreamPerformance.ps1 -FileStreamDirectory "$FILESTREAMDRIVE':\'" -FixProblems "fix"

        }

        Else {

            Write-Host "Please enter a valid Drive letter for FileStream" -ForegroundColor Red
            Write-PSULog -Severity Error -Message "Please enter a valid Drive letter for FileStream"
            #Write-Host "Exiting Script in 5 Seconds" -ForegroundColor Red
            Write-PSULog -Severity Warning -Message "Exiting script in 5 seconds."; Start-Sleep -s 5
            exit

        }

        #Write-Host "Installing SSMS" -ForegroundColor Green
        Write-PSULog -Severity Start -Message "Installing SSMS"
        & $RunLocation\bin\SSMSInstall.ps1

    }
}
$SkipGPUInstall = $settings.GPU.OMITTEDSERVERS
if ($Settings.general.CLEANUP -match "y" -and $Settings.GENERAL.INSTALLGPUDRIVER -match "n") {
    #Write-Host "Setting Machine to Cleanup on Next Boot" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Setting Machine to Cleanup on Next Boot"
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\Cleanup.ps1"
}
if ( $settings.general.Cleanup -match "y" -and $settings.GENERAL.INSTALLGPUDRIVER -match "y") {
    #Write-Host "Skipping Setting Machine Cleanup until GPU optimizes" -ForegroundColor Yellow
    Write-PSULog -Severity Warn -Message "Skipping Setting Machine Cleanup until GPU optimizes"
}
if ($Settings.general.CLEANUP -match "y" -and $Settings.GENERAL.INSTALLGPUDRIVER -match "y" -and $SkipGPUInstall -contains $env:COMPUTERNAME) {
    #Write-Host "Setting Machine to Cleanup on Next Boot" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Setting Machine to Cleanup on Next Boot"
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\Cleanup.ps1"
}


#Sets Script to continue to Remove Nvidia Driver
$RemoveNvidiaDriver = $Settings.GPU.REMOVECURRENTDRIVER
if ($RemoveNvidiaDriver -match "y") {
    #Write-Host "Attempting to remove the current GPU Driver" -ForegroundColor Green
    Write-PSULog -Severity Start -Message "Attempting to remove the current GPU Driver"
    & $RunLocation\bin\NvidiaDriverRemover.ps1
}

#Sets script to install the GPU Driver.
$InstallNvidiaDriver = $Settings.GENERAL.INSTALLGPUDRIVER
if ($InstallNvidiaDriver -match "y") {
    #Write-Host "Attempting to Install GPU Driver" -ForegroundColor Green
    Write-PSULog -Severity Start -Message "Attempting to Install GPU Driver"
    & $RunLocation\bin\NvidiaInstaller.ps1
}



#Sets up the Switch to Install the Citrix VDA
$CitrixInstall = $Settings.GENERAL.INSTALLCITRIX
Switch ($CitrixInstall) { 
    Y {
        #Write-Host "Attempting to Install Citrix." -ForegroundColor Green
        Write-PSULog -Severity Start -Message "Attempting to Install Citrix."
        & $RunLocation\bin\CitrixInstall.ps1
    }
    N {
        #Write-Host "Skipping Citrix VDA Install" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Citrix VDA Install"
    }
    Default {
        #Write-Host "Skipping Citrix VDA Install" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Citrix VDA Install"
    }
}


if ($Settings.GENERAL.INSTALLLMX -match "y") {
    #Write-Host "Attempting to Install RayStation Licensing"
    Write-PSULog -Severity Start -Message "Attempting to Install RayStation Licensing"
    & $RunLocation\bin\LicensingInstall.ps1
}
#Runs the Machine Info Script

& $RunLocation\bin\MachineInfo.ps1 -PWD $TempPassword -RemoteLogDirectory $RemoteLogLocation -RunLocation "$RunLocation\bin"

if ($settings.GENERAL.INSTALLRAYSTATION -match "y") {
    #Write-Host "Attempting to Install RayStation" -ForegroundColor Green
    Write-PSULog -Severity Start -Message "Attempting to Install RayStation"
    & $RunLocation\bin\RayStationInstall.ps1 -wait
}

if ($settings.GENERAL.BUILDRAYSTATIONGPUCONFIGS -match "y") {
    #Write-Host "Writing RayStation GPU Configs" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Writing RayStation GPU Configs"
    & $RunLocation\bin\BuildGPUConfig.ps1 -wait
}

if ($settings.GENERAL.INSTALLDICOM -match "y") {
    #Write-Host "Writing RayStation GPU Configs" -ForegroundColor Green
    #Write-PSULog -Severity Info -Message "Installing DICOM Service"
    & $RunLocation\bin\InstallDICOM.ps1 -wait
}

if ($settings.GENERAL.INSTALLLICENSEAGENT -match "y") {
    #Write-Host "Writing RayStation GPU Configs" -ForegroundColor Green
    #Write-PSULog -Severity Info -Message "Installing License Agent"
    & $RunLocation\bin\InstallLicenseAgent.ps1 -wait
}




#Stop-Transcript

$Readhost1 = $Settings.general.UPDATEWINDOWS
Switch ($ReadHost1) { 
    Y {
        #Write-Host "Installing Windows Updates" -ForegroundColor Green
        Write-PSULog -Severity Start -Message "Installing Windows Updates"
        & $RunLocation\bin\UpdateWindows.ps1
    }
    N {
        #Write-Host "Skipping Windows Updates" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Windows Updates"
    } 
    Default {
        #Write-Host "Skipping Windows Updates" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Skipping Windows Updates"
    } 
}

if ($settings.DESIGNATEDSQLSERVER -contains $env:computername -or $null -eq $settings.DESIGNATEDSQLSERVER) {
    Write-PSULog -Severity Info -Message "Checking on Active SQL Connections"
    & $RunLocation\bin\CheckSQLConnections.ps1 -wait
}


$Readhost = $Settings.general.AUTOREBOOT
Switch ($ReadHost) {
    Y { Write-PSULog -Severity End -Message "Rebooting now..."; Start-Sleep -s 2; Restart-Computer -Force }
    N { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds."; Start-Sleep -s 5 }
    Default { Write-PSULog -Severity Info -Message "Exiting script in 5 seconds"; Start-Sleep -s 5 }
}
