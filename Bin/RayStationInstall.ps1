<#
.SYNOPSIS
    RayStation Installer.

.DESCRIPTION
    This script installs RayStation as defined in the setup JSON file. It handles various installation tasks and configurations based on the settings provided.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\RayStationInstall.ps1
    Runs the RayStation installation script with the settings defined in Setup.json.

.NOTES
    Author: John Burriss
    Created: 07/20/2022
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
$AESKey = Get-Content "$RunLocation\Bin\Key\key.key"
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

function New-SelfSignedCertificateRS {
  [CmdletBinding()]
  param (
    [string]$SubjectName,
    [string]$SubjectAlternativeName,
    [string]$FriendlyName = "New Certificate",
    [object]$Issuer,
    [bool]$IsCA = $false,
    [int]$KeyStrength = 2048,
    [int]$ValidYears = 2,
    [hashtable]$EKU = @{}
  )

  # Needed generators
  $random = New-SecureRandom
  $certificateGenerator = New-CertificateGenerator

  if ($Issuer -ne $null -and $Issuer.HasPrivateKey -eq $true) {
    $IssuerName = $Issuer.IssuerName.Name
    $IssuerPrivateKey = $Issuer.PrivateKey
  }
  # Create and set a random certificate serial number
  $serial = New-SerialNumber -Random $random
  $certificateGenerator.SetSerialNumber($serial)

  # The signature algorithm
  $certificateGenerator.SetSignatureAlgorithm('SHA256WithRSA')

  # Basic Constraints - certificate is allowed to be used as intermediate.
  # Powershell requires either a $null or reassignment or it will return this from the function
  $certificateGenerator = Add-BasicConstraints -isCertificateAuthority $IsCA -certificateGenerator $certificateGenerator

  # Key Usage
  if ($EKU.Count -gt 0) {
    $certificateGenerator = $certificateGenerator | Add-ExtendedKeyUsage @EKU
  }
  # Create and set the Issuer and Subject name
  $subjectDN = New-X509Name -Name ($SubjectName)
  if ($Issuer -ne $null) {
    $IssuerDN = New-X509Name -Name ($IssuerName)
  }
  else {
    $IssuerDN = New-X509Name -Name ($SubjectName)
  }  
  $certificateGenerator.SetSubjectDN($subjectDN)
  $certificateGenerator.SetIssuerDN($IssuerDN)

  # Authority Key and Subject Identifier
  if ($Issuer -ne $null) {
    $IssuerKeyPair = ConvertTo-BouncyCastleKeyPair -PrivateKey $IssuerPrivateKey
    $IssuerSerial = [Org.BouncyCastle.Math.BigInteger]$Issuer.GetSerialNumber()
    $authorityKeyIdentifier = New-AuthorityKeyIdentifier -name $Issuer.IssuerName.Name -publicKey $IssuerKeyPair.Public -serialNumber $IssuerSerial
    $certificateGenerator = Add-AuthorityKeyIdentifier -certificateGenerator $certificateGenerator -authorityKeyIdentifier $authorityKeyIdentifier
  }

  if ($Null -ne $SubjectAlternativeName) {
    $certificateGenerator = Add-SubjectAlternativeName -certificateGenerator $certificateGenerator -DnsName $SubjectAlternativeName


  }

  # Validity range of the certificate
  [DateTime]$notBefore = (Get-Date).AddDays(-1)
  if ($ValidYears -gt 0) {
    [DateTime]$notAfter = $notBefore.AddYears($ValidYears)
  }
  $certificateGenerator.SetNotBefore($notBefore)
  $certificateGenerator.SetNotAfter($notAfter)


  # Subject public key ~and private
  $subjectKeyPair = New-KeyPair -Strength $keyStrength -Random $random
  if ($IssuerPrivateKey -ne $null) {
    $IssuerKeyPair = [Org.BouncyCastle.Security.DotNetUtilities]::GetKeyPair($IssuerPrivateKey)
  }
  else {
    $IssuerKeyPair = $subjectKeyPair
  }
  $certificateGenerator.SetPublicKey($subjectKeyPair.Public)

  # Create the Certificate
  $IssuerKeyPair = $subjectKeyPair
  $certificate = $certificateGenerator.Generate($IssuerKeyPair.Private, $random)
  # At this point you have the certificate and need to convert it and export, I return the private key for signing the next cert
  $pfxCertificate = ConvertFrom-BouncyCastleCertificate -certificate $certificate -subjectKeyPair $subjectKeyPair -friendlyName $FriendlyName
  return $pfxCertificate
}
#-------------------------------------------------------------------------------------------------------------




#Start-Transcript -Path "$RunLocation\Logs\RayStation.log"

if ($Settings.RAYSTATION.OMITTEDSERVERS -notcontains $env:COMPUTERNAME ) {

  if (Test-Path -Path $Settings.RAYSTATION.RAYSTATIONLOCATION) {
        
    $RayStationEXE = $Settings.RAYSTATION.RAYSTATIONLOCATION
    $Features = $Settings.RAYSTATION.FEATURES
    $DATABASEADDRESS = $Settings.RAYSTATION.DATABASEADDRESS
    $DATABASEPORT = $Settings.RAYSTATION.DATABASEPORT
    $DATABASEINSTANCE = $Settings.RAYSTATION.DATABASEINSTANCE
    $DATABASESUFFIX = $Settings.RAYSTATION.DATABASESUFFIX
    $GenerateSelfSignedCert = $Settings.RAYSTATION.GenerateSelfSignedCert
    $IndexServiceUser = $Settings.RAYSTATION.INDEXSERVICEUSER
    $IndexServicePwd = $Settings.RAYSTATION.IndexServicePwd
    $INDEXSERVICECERT = $Settings.RAYSTATION.INDEXSERVICECERT
    $TransferServiceUser = $Settings.RAYSTATION.TransferServiceUser
    $TransferServicePwd = $Settings.RAYSTATION.TransferServicePwd
    #$LicenseAgentUser = $Settings.RAYSTATION.LicenseAgentUser
    #$LicenseAgentPwd = $Settings.RAYSTATION.LicenseAgentPwd
    $IndexServicePort = $Settings.RAYSTATION.IndexServicePort
    $RayStationLocation = $Settings.RAYSTATION.RAYSTATIONLOCATION
    $WaitForSQLConnection = $Settings.RAYSTATION.WAITFORSQLCONNECTION

    if (-not ([string]::IsNullOrEmpty($IndexServicePwd))) {
      $IndexServicePwd = ConvertTo-SecureString -String $IndexServicePwd -Key $AESKey
      $IndexServicePwd = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($IndexServicePwd)
      $IndexServicePwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($IndexServicePwd)
    }
    if (-not ([string]::IsNullOrEmpty($TransferServicePwd))) {
      $TransferServicePwd = ConvertTo-SecureString -String $TransferServicePwd -Key $AESKey
      $TransferServicePwd = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($TransferServicePwd)
      $TransferServicePwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($TransferServicePwd)
    }
    #$LicenseAgentPwd = ConvertTo-SecureString -String $LicenseAgentPwd -Key $AESKey
    #$LicenseAgentPwd = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($LicenseAgentPwd)
    #$LicenseAgentPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($LicenseAgentPwd)

    $IndexServiceServer = $settings.RAYSTATION.INDEXSERVICESERVER
    $TransferServiceServer = $Settings.RAYSTATION.TRANSFERSERVICESERVER
    #$LicenseServiceServer = $Settings.RAYSTATION.LICENSESERVICESERVER

    $AdditionalFeatures = @()

    if ($IndexServiceServer -match $env:COMPUTERNAME) {
      Write-PSULog -Severity Info -Message "Adding Index Service"
      $AdditionalFeatures += ",IndexService"
            
      if ([string]::IsNullOrEmpty($IndexServicePort)) {
        $IndexServicePort = "5001"
      }

    }
    if ($TransferServiceServer -match $env:COMPUTERNAME) {
      Write-PSULog -Severity Info -Message "Adding TransferService Service"
      $AdditionalFeatures += ",TransferService"

    }

    #if(!([string]::IsNullOrEmpty($IndexServiceUser))){
    #$Indexserviceuserclean = $IndexServiceUser.split('@')[0]
    #$DomainClean = $IndexServiceUser.split('@')[1].split('.')[0]
    #$IndexServiceUser = "$DomainClean\$IndexServiceUserClean"
    #}
    #if(!([string]::IsNullOrEmpty($TransferServiceUser))){
    #$Transferserviceuserclean = $TransferServiceUser.split('@')[0]
    #$DomainClean = $TransferServiceUser.split('@')[1].split('.')[0]
    #$TransferServiceUser = "$DomainClean\$TransferServiceUserClean"
    #}

    #if($LicenseServiceServer -match $env:COMPUTERNAME){
    #    Write-PSULog -Severity Info -Message "Adding LicenseService Service"
    #    $AdditionalFeatures += ",LicenseService"
    #
    #}
        
    $AdditionalFeatures = [string]$AdditionalFeatures

    $AdditionalFeatures = $AdditionalFeatures -replace ' ', ''
        
    $Features = $Features + $AdditionalFeatures

    if ($features -eq $null) {
      #write-host "No Features Specified" -ForegroundColor Red
      Write-PSULog -Severity Error -Message "No Features Specified"
      exit 1
    }
    if ([string]::IsNullOrEmpty($DATABASEADDRESS)) {
      #write-host "No Database Address Specified" -ForegroundColor Red
      Write-PSULog -Severity Error -Message "No Database Address Specified"
      exit 1
    }
    if ([string]::IsNullOrEmpty($DATABASEPORT)) {
      #write-host "No Database Port Specified" -ForegroundColor Red
      $DATABASEPORT = "1433"
    }
    if ([string]::IsNullOrEmpty($DATABASESUFFIX)) {
      #write-host "No Database Suffix Specified" -ForegroundColor Red
      Write-PSULog -Severity Error -Message "No Database Suffix Specified"
      exit 1
    }

    if ($GenerateSelfSignedCert -match "y" -and $IndexServiceServer -match $env:COMPUTERNAME -or [string]::IsNullOrEmpty($IndexServiceServer) -and $GenerateSelfSignedCert -match "y") {


      Import-Module "$runlocation\Bin\PSBouncyCastle.New\PSBouncyCastle.psm1"


      $SubjectAlternitaveName = [System.Net.Dns]::GetHostByName($env:computerName).HostName

      $Hex = (1..10 | % { '{0:X}' -f (Get-Random -Max 16) }) -join ''

      $CommonName = "RayStationIndexService_$hex"

      Write-PSULog -Severity Info -Message "Attempting to generate a self signed certificate."

      try {
        $TestRootCA = New-SelfSignedCertificateRS -SubjectName "CN=$CommonName" -SubjectAlternativeName $SubjectAlternitaveName -FriendlyName $CommonName
        Export-Certificate -Certificate $TestRootCA -OutputFile "$Runlocation\Bin\Certs\RayStationIndexService.pfx" -X509ContentType Pfx
        Write-PSULog -Severity Info -Message "Finished Generating Certificate"
      }
      Catch {
        Write-PSULog -Severity Error -Message "Failed to Generate Certificate. Falling Back to Unsecure."
      }

      if (Test-Path -Path "$Runlocation\Bin\Certs\RayStationIndexService.pfx") {
        Write-PSULog -Severity Info -Message "Attempting to Import Generated Certificate"
        Try {

          Import-PfxCertificate -FilePath "$Runlocation\Bin\Certs\RayStationIndexService.pfx" -CertStoreLocation Cert:\LocalMachine\Root | out-null
          Import-PfxCertificate -FilePath "$Runlocation\Bin\Certs\RayStationIndexService.pfx" -CertStoreLocation Cert:\LocalMachine\My | out-null
          $INDEXSERVICECERT = $commonName
          Write-PSULog -Severity Info -Message "Finished Importing Certificate"

        }
        Catch {
          Write-PSULog -Severity Error -Message "Failed to Import Certificate. Falling Back to Unsecure."
          $INDEXSERVICECERT = ""
        }
      }

      Function GrantLoginAsService {
        param([string] $username)
        $computerName = $env:COMPUTERNAME
        $tempPath = [System.IO.Path]::GetTempPath()
        $import = Join-Path -Path $tempPath -ChildPath "import.inf"
        if (Test-Path $import) { Remove-Item -Path $import -Force }
        $export = Join-Path -Path $tempPath -ChildPath "export.inf"
        if (Test-Path $export) { Remove-Item -Path $export -Force }
        $secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
        if (Test-Path $secedt) { Remove-Item -Path $secedt -Force }
        try {
          Write-PSULog -Severity Info -Message ("Granting SeServiceLogonRight to user account: {0} on host: {1}." -f $username, $computerName)
          $sid = ((New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier])).Value
          secedit /export /cfg $export
          $sids = (Select-String $export -Pattern "SeServiceLogonRight").Line
          foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=GrantLogOnAsAService security template", "[Privilege Rights]", "$sids,*$sid")) {
            Add-Content $import $line
          }
          secedit /import /db $secedt /cfg $import
          secedit /configure /db $secedt
          gpupdate /force
          Remove-Item -Path $import -Force
          Remove-Item -Path $export -Force
          Remove-Item -Path $secedt -Force
        }
        catch {
          Write-PSULog -Severity Error -Message ("Failed to grant SeServiceLogonRight to user account: {0} on host: {1}." -f $username, $computerName)
          $error[0]
        }
      }

      if (!([string]::IsNullOrEmpty($IndexServiceUser))) {

        Write-PSULog -Severity Info -Message "Trying to Grant Logon as a service to User $IndexServiceUser"
        try {
          GrantLoginAsService -username $IndexServiceUser
        }
        catch {
          Write-PSULog -Severity Error -Message "Failed to grant Logon as a service permission to $IndexServiceUser"
        }

      }

      if (!([string]::IsNullOrEmpty($TransferServiceUser)) -and $IndexServiceUser -notmatch $TransferServiceUser) {
        Write-PSULog -Severity Info -Message "Trying to Grant Logon as a service to User $TransferServiceUser"
        try {
          GrantLoginAsService -username $TransferServiceUser
        }
        catch {
          Write-PSULog -Severity Error -Message "Failed to grant Logon as a service permission to $TransferServiceUser"
        }


      }
    }

    if ($WaitForSQLConnection -match "y") {
      Write-PSULog -Severity Info -Message "Waiting for Stable SQL Connection"
      if (!([string]::IsNullOrEmpty($DATABASEINSTANCE))) {
        $Instance = $DATABASEADDRESS + '\' + $DATABASEINSTANCE
      }
      else {
        $Instance = $DATABASEADDRESS
      }

      $inst = $Instance + "," + $DATABASEPORT
      $SQLConnection = $false
      $timeout = new-timespan -Minutes 20
      $StableTime = new-timespan -Minutes 2
      $endTime = (Get-Date).Add($timeout)
      $StableCounter = new-object system.diagnostics.stopwatch
      $StableCounter.Start()
      $CheckInPeriod = [diagnostics.stopwatch]::StartNew()
      Write-PSULog -Severity Info -Message "Waiting for stable SQL Connection."
      $i = 0
      Do {
        try {
          $conn = New-Object system.Data.SqlClient.SqlConnection
          $conn.connectionstring = [string]::format("Server={0};Integrated Security=true;", $inst)
          $conn.open()
          $conn.Close()
          $countdown = ($StableTime - $StableCounter.elapsed).TotalSeconds
          $countdown = [math]::Round($countdown)
          Write-PSULog -Severity Info -Message "Connection to SQL $Instance was Sucessfull. Waiting $Countdown Seconds to make sure connection is stable."
          if ($StableCounter.elapsed -ge $StableTime) {
            Write-PSULog -Severity Info -Message "Connection to SQL $Instance was Sucessfull. Moving on."
            $SQLConnection = $True
          }
        
        
        }
        catch {
          $SQLConnection = $false
          Write-Host "Connection Failed $i Times"
          $I++
          $StableCounter.restart()
        }
        start-sleep -Seconds 10
      }Until($SQLConnection -eq $True -or ((Get-Date) -gt $endTime))
      $StableCounter.stop()
      if ($CheckInPeriod.elapsed -ge $timeout) {
        $CheckInPeriod.stop()
        Write-PSULog -Severity Error -Message "Connection timed out for SQL Connection, Exiting Installer."
        exit
      }
      $CheckInPeriod.stop()
      Write-PSULog -Severity Info -Message "Stable SQL Connection Established"
    }

    #Write-host "Installing Features: $features" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Installing RayStation Features: $features"

    $RayStationEXEParent = Split-Path $RayStationEXE -Parent

    $SetupMSI = Join-path $RayStationEXEParent "SetupContent.msi"

    $Prams = @(
      '/i',
      "$SetupMSI",
      '/q',
      "/L*V `"$runlocation\Logs\RSInstall.log`"",
      "ARPSYSTEMCOMPONENT=`"1`"",
      "MSIFASTINSTALL=`"7`"",
      "WIXUI_INSTALLDIR=`"C:\Program Files (x86)\RaySearch Laboratories`"",
      "ADDLOCAL=`"$features`"",
      "ARPNOREPAIR=`"1`"",
      "ARPNOMODIFY=`"1`"",
      "DATABASEADDRESS=`"$DATABASEADDRESS`"",
      "DATABASEINSTANCE=`"$DATABASEINSTANCE`"",
      "DATABASESUFFIX=`"$DATABASESUFFIX`"",
      "DATABASEPORT=`"$DATABASEPORT`"",
      "INDEXSERVICEUSER=`"$IndexServiceUser`"",
      "INDEXSERVICEPWD=`"$IndexServicePwd`"",
      "TRANSFERSERVICEUSER=`"$TransferServiceUser`"",
      "TRANSFERSERVICEPWD=`"$TransferServicePwd`"",
      "LICENSEAGENTUSER=`"`"",
      "LICENSEAGENTPWD=`"`"",
      "INDEXSERVICEPORT=`"$IndexServicePort`"",
      "INDEXSERVICECERT=`"$INDEXSERVICECERT`""
    )

    # Create the Write-PSULog function as scriptblock to pass to runspaces
    $WriteLogScriptBlock = {
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


    # Create scriptblock for database configuration monitoring
    $DatabaseConfigMonitor = {
      param($WriteLogScriptBlock, $RunLocation, $RemoteLogLocation)

      $processStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      $processFound = $false
    
      while ($true) {
        try {
          $dbConfigProcess = Get-Process | Where-Object { $_.ProcessName -match "RaySearch.RayStation.SetUp.DatabaseConfiguration" }
            
          if ($dbConfigProcess) {
            if (-not $processFound) {
              $processFound = $true
              $processStopwatch.Restart()
              & $WriteLogScriptBlock -Severity "Info" -Message "Database configuration process started" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
            }

            if ($processStopwatch.Elapsed.TotalMinutes -gt 5) {
              & $WriteLogScriptBlock -Severity "Error" -Message "Database configuration process exceeded 5 minute timeout. Terminating installation." -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
                    
              # Terminate all related processes
              $processesToKill = @(
                "RaySearch.RayStation.SetUp.DatabaseConfiguration",
                "msiexec",
                "RayStationSetup"
              )

              foreach ($procName in $processesToKill) {
                Get-Process | Where-Object { $_.ProcessName -match $procName } | ForEach-Object {
                  try {
                    $_ | Stop-Process -Force -ErrorAction Stop
                    & $WriteLogScriptBlock -Severity "Info" -Message "Successfully terminated process: $($_.ProcessName)" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
                  }
                  catch {
                    & $WriteLogScriptBlock -Severity "Error" -Message "Failed to terminate process $($_.ProcessName): $_" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
                    # Try using taskkill as a fallback
                    try {
                      Start-Process "taskkill.exe" -ArgumentList "/F /PID $($_.Id)" -Wait -NoNewWindow
                      & $WriteLogScriptBlock -Severity "Info" -Message "Terminated process $($_.ProcessName) using taskkill" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
                    }
                    catch {
                      & $WriteLogScriptBlock -Severity "Error" -Message "Failed to terminate process $($_.ProcessName) using taskkill: $_" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
                    }
                  }
                }
              }
                    
              return $false
            }
          }
          elseif ($processFound) {
            & $WriteLogScriptBlock -Severity "Info" -Message "Database configuration process completed normally after $([Math]::Floor($processStopwatch.Elapsed.TotalMinutes)) minutes" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
            return $true
          }
        }
        catch {
          & $WriteLogScriptBlock -Severity "Error" -Message "Error in database configuration monitor: $_" -logDirectory "$RunLocation\Logs\" -RemotelogDirectory $RemoteLogLocation
        }
        Start-Sleep -Seconds 10
      }
    }

    try {
      # Create runspaces
      $runspacePool = [runspacefactory]::CreateRunspacePool(1, 2)
      $runspacePool.Open()

      # Create monitoring powershell instances
      $dbMonitorPS = [powershell]::Create().AddScript($DatabaseConfigMonitor)
      $dbMonitorPS.AddArgument($WriteLogScriptBlock)
      $dbMonitorPS.AddArgument($RunLocation)
      $dbMonitorPS.AddArgument($RemoteLogLocation)
      $dbMonitorPS.RunspacePool = $runspacePool

      # Start MSI installation
      Write-PSULog -Severity Info -Message "Starting RayStation MSI installation"
      $msiProcess = Start-Process msiexec.exe -ArgumentList $Prams -PassThru

      # Start monitoring
      Write-PSULog -Severity Info -Message "Starting monitoring processes"
      $dbMonitorHandle = $dbMonitorPS.BeginInvoke()

      # Set timeout
      $timeoutMinutes = 15
      $timeout = [DateTime]::Now.AddMinutes($timeoutMinutes)
      $installationComplete = $false
      $success = $true
    
      Write-PSULog -Severity Info -Message "Waiting for installation to complete (timeout: $timeoutMinutes minutes)"

      $progressStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      $lastProgressUpdate = 0

      while ([DateTime]::Now -lt $timeout -and -not $installationComplete) {
        # Check monitor results first
        if ($dbMonitorHandle.IsCompleted) {
          $dbResult = $dbMonitorPS.EndInvoke($dbMonitorHandle)
          if ($dbResult -eq $false) {
            Write-PSULog -Severity Error -Message "Database configuration monitor reported failure, terminating installation"
            $success = $false
            break
          }
        }

        # Check if MSI process is still running
        if ($msiProcess.HasExited) {
          Write-PSULog -Severity Info -Message "MSI process completed with exit code: $($msiProcess.ExitCode)"
          if ($msiProcess.ExitCode -ne 0) {
            Write-PSULog -Severity Error -Message "MSI installation failed with exit code: $($msiProcess.ExitCode)"
            $success = $false
            break
          }

          # Check for RayStationSetup process
          $setupRunning = Get-Process | Where-Object { $_.ProcessName -match "RayStationSetup" }
          if (-not $setupRunning) {
            $installationComplete = $true
            break
          }
        }

        # Show progress every 5 minutes
        $currentMinutes = [Math]::Floor($progressStopwatch.Elapsed.TotalMinutes)
        if ($currentMinutes -ge ($lastProgressUpdate + 5)) {
          $remainingMinutes = [Math]::Round(($timeout - [DateTime]::Now).TotalMinutes)
          Write-PSULog -Severity Info -Message "Installation in progress... ($remainingMinutes minutes remaining)"
          $lastProgressUpdate = $currentMinutes
        }

        Start-Sleep -Seconds 30
      }

      $progressStopwatch.Stop()

      # Clean up runspaces
      if ($dbMonitorPS -ne $null) {
        try {
          $dbMonitorPS.Dispose()
        }
        catch {
          Write-PSULog -Severity Error -Message "Error disposing database monitor: $_"
        }
      }

      if ($runspacePool -ne $null) {
        try {
          $runspacePool.Close()
          $runspacePool.Dispose()
        }
        catch {
          Write-PSULog -Severity Error -Message "Error cleaning up runspace pool: $_"
        }
      }

      # Final status check
      if (-not $success) {
        Write-PSULog -Severity Error -Message "RayStation installation failed - Skipping final setup step"
        # Ensure all processes are terminated
        @("RaySearch.RayStation.SetUp.DatabaseConfiguration", "msiexec", "RayStationSetup") | ForEach-Object {
          Get-Process | Where-Object { $_.ProcessName -match $_ } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        exit 1
      }
      elseif ($installationComplete) {
        Write-PSULog -Severity Info -Message "MSI installation completed successfully, proceeding with RayStation setup"
        & $RayStationLocation /quiet -wait
        Write-PSULog -Severity Info -Message "RayStation installation completed successfully"
      }
      else {
        Write-PSULog -Severity Error -Message "Installation timed out after $timeoutMinutes minutes"
        # Ensure all processes are terminated
        @("RaySearch.RayStation.SetUp.DatabaseConfiguration", "msiexec", "RayStationSetup") | ForEach-Object {
          Get-Process | Where-Object { $_.ProcessName -match $_ } | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        exit 1
      }
    }
    catch {
      Write-PSULog -Severity Error -Message "Error in installation process: $_"
      # Ensure processes are cleaned up
      @("RaySearch.RayStation.SetUp.DatabaseConfiguration", "msiexec", "RayStationSetup") | ForEach-Object {
        Get-Process | Where-Object { $_.ProcessName -match $_ } | Stop-Process -Force -ErrorAction SilentlyContinue
      }
      exit 1
    }

  }
  else {
    #Write-Host "RayStation Location not found" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "RayStation Location not found"
    exit 1
  }
  if ($Features.split(',') -contains "IndexService") {
    Try {
      Write-PSULog -Severity Info -Message "Attempting to start Index Service"
      $ServiceName = Get-Service | Where-Object { $_.Name -match "RayStationIndexService" }
      $timeoutService = new-timespan -Seconds 30
      $CheckInPeriodService = [diagnostics.stopwatch]::StartNew()
      Start-Service $ServiceName
      Write-PSULog -Severity Info -Message 'Service starting'
      while ($ServiceName.Status -notmatch "Running" -and $CheckInPeriodService.elapsed -le $timeoutService) {
        #write-host $ServiceName $arrService.status -ForegroundColor Yellow
                
        $Name = $servicename.DisplayName
        $Status = $ServiceName.status
        Write-PSULog -Severity Info -Message "$Name $Status"
        #write-host 'Service starting' -ForegroundColor Yellow
        Start-Sleep -seconds 5
        $ServiceName.Refresh()
      }
      if ($ServiceName.Status -notmatch 'Running' -and $CheckInPeriodService.elapsed -ge $timeoutService) {

        Write-PSULog -Severity Error -Message "Failed to Start Index Service. Service Timed Out"  

      }

    }
    Catch {
      Write-PSULog -Severity Error -Message "Failed to Start Index Service"   
    }
  }
  if ($Features.split(',') -contains "TransferService") {
    Try {
      Write-PSULog -Severity Info -Message "Attempting to start Transfer Service"
      $ServiceName = Get-Service | Where-Object { $_.Name -match "RayStationTransferService" }
      $timeoutService = new-timespan -Seconds 30
      $CheckInPeriodService = [diagnostics.stopwatch]::StartNew()
      Start-Service $ServiceName
      Write-PSULog -Severity Info -Message 'Service starting'
      while ($ServiceName.Status -notmatch "Running" -and $CheckInPeriodService.elapsed -le $timeoutService) {
        #write-host $ServiceName $arrService.status -ForegroundColor Yellow
                
        $Name = $servicename.DisplayName
        $Status = $ServiceName.status
        Write-PSULog -Severity Info -Message "$Name $Status"
        #write-host 'Service starting' -ForegroundColor Yellow
        Start-Sleep -seconds 5
        $ServiceName.Refresh()
      }
      if ($ServiceName.Status -notmatch 'Running' -and $CheckInPeriodService.elapsed -ge $timeoutService) {

        Write-PSULog -Severity Error -Message "Failed to Start Transfer Service. Service Timed Out"  

      }

    }
    Catch {
      Write-PSULog -Severity Error -Message "Failed to Start Transfer Service"   
    }
  }

}
else {

  Write-PSULog -Severity Info -Message "Machine $env:COMPUTERNAME is listed in Omitted Servers. Skipping RayStation Install"

}