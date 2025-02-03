<#
.SYNOPSIS
    This script installs the RayStation License Agent based on the configuration settings.

.DESCRIPTION
    The script reads the configuration from Setup.json to determine if the License Agent should be installed.
    It installs the License Agent with the specified settings, generates and imports a self-signed certificate if required, and logs the process.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\InstallLicenseAgent.ps1
    Runs the script to install the RayStation License Agent if configured to do so.

.NOTES
    Author: John Burriss
    Created: 9/29/2023
    Version: 0.01
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


if ([string]::IsNullOrEmpty($Settings.SERVICES.LICENSEAGENTSERVER) -or $Settings.SERVICES.LICENSEAGENTSERVER -contains $env:COMPUTERNAME) {

  $SetupEXE = $Settings.SERVICES.LICENSESETUPEXE
  $SERVICEUSER = $Settings.SERVICES.SERVICEUSER
  $SERVICEPWD = $Settings.SERVICES.SERVICEPWD
  $SERVICEPORT = $Settings.SERVICES.SERVICEPORT
  $SECUREHOSTING = $Settings.SERVICES.SECUREHOSTING
  $OFFLINEMODE = $Settings.SERVICES.OFFLINEMODE
  $LICENSESERVICEENDPOINT = $Settings.SERVICES.LICENSESERVICEENDPOINT
  $GenerateSelfSignedCert = $Settings.SERVICES.GenerateSelfSignedCert
  $CERTSUBJECT = $Settings.SERVICES.CERTSUBJECT
  $CERTSTORE = $Settings.SERVICES.CERTSTORE
  $CERTLOCATION = $Settings.SERVICES.CERTLOCATION
  $DATABASEADDRESS = $Settings.SERVICES.DATABASEADDRESS 
  $DATABASEINSTANCE = $Settings.SERVICES.DATABASEINSTANCE 
  $DATABASEPORT = $Settings.SERVICES.DATABASEPORT
  $INSTALLDIR = $Settings.SERVICES.INSTALLDIR

  $SERVICEPWD = ConvertTo-SecureString -String $SERVICEPWD -Key $AESKey
  $SERVICEPWD = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SERVICEPWD)
  $SERVICEPWD = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($SERVICEPWD)

  $RayStationEXEParent = Split-Path $SetupEXE -Parent

  $SetupMSI = Join-path $RayStationEXEParent "SetupContent.msi"


  If (!(Test-Path $SetupMSI)) {
    Write-PSULog -Severity Error -Message "Path to License Agent MSI in Incorrect."
    break
  }
  If (!(Test-Path $SetupMSI)) {
    Write-PSULog -Severity Error -Message "Path to License Agent MSI in Incorrect."
    break
  }
  if ([string]::IsNullOrEmpty($SERVICEPORT)) {
    $SERVICEPORT = "5021"
  }
  if ([string]::IsNullOrEmpty($LICENSESERVICEENDPOINT)) {
    $LICENSESERVICEENDPOINT = "https://rslicense.raysearchlabs.com"
  }
  if ([string]::IsNullOrEmpty($DATABASEADDRESS)) {
    Write-PSULog -Severity Error -Message "No Database Server Selected."
    break 
  }
  if ([string]::IsNullOrEmpty($INSTALLDIR)) {
    $INSTALLDIR = "C:\Program Files\RaySearch Laboratories\"
  }
  if ([string]::IsNullOrEmpty($DATABASEPORT)) {
    $DATABASEPORT = "1433"
  }
  $IsInstalled = Get-WmiObject -Class Win32_Product | where vendor -eq 'RaySearch Laboratories' | select Name

  if ($IsInstalled.Name -contains 'RayStation License Agent') {
    Write-PSULog -Severity Info -Message "License Agent Already Installed on this system."

    $UninstallPrams = @(
      '/x',
      "$SetupMSI",
      '/qn/'

    )
    try {
      Write-PSULog -Severity Info -Message "Attempting to Uninstall Previous Version"
      Start-Process msiexec -ArgumentList $UninstallPrams -wait
      & $SetupEXE /quiet -wait
      Write-PSULog -Severity Info -Message "Uninstall Complete"
    }
    Catch {
      Write-PSULog -Severity Info -Message "Failed to Uninstall Previous Version. Please Manually remove and retry."
      Break
    }

  }

  $PreviousCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "RayStationLicenseAgent" }

  if ($null -ne $PreviousCert) {
    Write-PSULog -Severity Info -Message "Removing Previous License Agent Cert."
    try {
      Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "RayStationLicenseAgent" } | Remove-Item
    }
    catch {
      Write-PSULog -Severity Error -Message "Failed to remove old License Agent Cert."
    }
  }

  if ($GenerateSelfSignedCert -match "y" -and $SECUREHOSTING -match "y") {

    Import-Module "$runlocation\Bin\PSBouncyCastle.New\PSBouncyCastle.psm1"


    $SubjectAlternitaveName = [System.Net.Dns]::GetHostByName($env:computerName).HostName

    $Hex = (1..10 | % { '{0:X}' -f (Get-Random -Max 16) }) -join ''

    $CommonName = "RayStationLicenseAgentHTTPS_$hex"

    Write-PSULog -Severity Info -Message "Attempting to generate a self signed certificate."

    try {
      $TestRootCA = New-SelfSignedCertificateRS -subjectName "CN=$CommonName" -SubjectAlternativeName $SubjectAlternitaveName -FriendlyName $CommonName
      Export-Certificate -Certificate $TestRootCA -OutputFile "$Runlocation\Bin\Certs\RayStationLicenseAgent.pfx" -X509ContentType Pfx
      Write-PSULog -Severity Info -Message "Finished Creating Certificate."
    }
    Catch {
      Write-PSULog -Severity Error -Message "Failed to Generate Certificate. Falling Back to Unsecure."
      $SECUREHOSTING = ""
    }

    if (Test-Path -Path "$Runlocation\Bin\Certs\RayStationLicenseAgent.pfx") {
      Write-PSULog -Severity Info -Message "Attempting to Import Generated Certificate"
      Try {

        Import-PfxCertificate -FilePath "$Runlocation\Bin\Certs\RayStationLicenseAgent.pfx" -CertStoreLocation Cert:\LocalMachine\Root | out-null
        Import-PfxCertificate -FilePath "$Runlocation\Bin\Certs\RayStationLicenseAgent.pfx" -CertStoreLocation Cert:\LocalMachine\My | out-null

        $SECUREHOSTING = "True"
        $CERTSUBJECT = $commonName
        $CERTSTORE = "My"
        $CERTLOCATION = "LocalMachine"
        Write-PSULog -Severity Info -Message "Finished Importing Certificate."

      }
      Catch {
        Write-PSULog -Severity Error -Message "Failed to Import Certificate. Falling Back to Unsecure."
        $SECUREHOSTING = ""
        $CERTSUBJECT = ""
        $CERTSTORE = ""
        $CERTLOCATION = ""
      }

    }

  }

  if ($GenerateSelfSignedCert -match "n" -and $SECUREHOSTING -match "y" -and [string]::IsNullOrEmpty($CERTSUBJECT) -or [string]::IsNullOrEmpty($CERTSTORE) -or [string]::IsNullOrEmpty($CERTLOCATION)) {

    Write-PSULog -Severity Warn -Message "Missing Certificate Details. Falling back to Unsecure."

    $CERTSUBJECT = ""
    $CERTSTORE = ""
    $CERTLOCATION = ""

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

  if (!([string]::IsNullOrEmpty($SERVICEUSER))) {

    Write-PSULog -Severity Info -Message "Trying to Grant Logon as a service to User $SERVICEUSER"
    try {
      GrantLoginAsService -username $SERVICEUSER
    }
    catch {
      Write-PSULog -Severity Error -Message "Failed to grant Logon as a service permission to $SERVICEUSER"
    }

  }

  if ($OFFLINEMODE -match "y") {
    $OFFLINEMODE = "True"
  }

  Write-PSULog -Severity Start -Message "Starting License Agent Install"

  try {
    $Prams = @(
      '/i',
      "$SetupMSI",
      '/q',
      "/L*V `"$runlocation\Logs\RSLicenseAgentInstall.log`""
      "ARPSYSTEMCOMPONENT=`"1`"",
      "MSIFASTINSTALL=`"7`"",
      "ARPNOREPAIR=`"1`"",
      "ADDLOCAL=`"LicenseAgent`"",
      "SERVICEUSER=`"$SERVICEUSER`"",
      "SERVICEPWD=`"$SERVICEPWD`"",
      "SERVICEPORT=`"$SERVICEPORT`"",
      "SERVICEPORT=`"$SERVICEPORT`"",
      "SECUREHOSTING=`"$SECUREHOSTING`"",
      "OFFLINEMODE=`"$OFFLINEMODE`"",
      "LICENSESERVICEENDPOINT=`"$LICENSESERVICEENDPOINT`"",
      "CERTSUBJECT=`"$CERTSUBJECT`"",
      "CERTSTORE=`"$CERTSTORE`"",
      "CERTLOCATION=`"$CERTLOCATION`"",
      "DATABASEADDRESS=`"$DATABASEADDRESS`"",
      "DATABASEINSTANCE=`"$DATABASEINSTANCE`"",
      "DATABASEPORT=`"$DATABASEPORT`"",
      "INSTALLDIR=`"$INSTALLDIR`"",
      "WIXBUNDLEORIGINALSOURCE=`"$SetupEXE`""
    )

    start-process msiexec.exe -ArgumentList $Prams -wait
    & $SetupEXE /quiet -wait
  }
  Catch {
    Write-PSULog -Severity Error -Message "Failed to Install the License Agent Service"
  }

  Try {
    Write-PSULog -Severity Info -Message "Attempting to start License Agent Service"
    $ServiceName = Get-Service -Name "RayStationLicenseAgent"
    $timeoutService = new-timespan -Minutes 1
    $CheckInPeriodService = [diagnostics.stopwatch]::StartNew()
    while ($ServiceName.Status -ne 'Running' -and $CheckInPeriodService.elapsed -le $timeoutService) {
      Start-Service $ServiceName
      #write-host $ServiceName $arrService.status -ForegroundColor Yellow
      Write-PSULog -Severity Info -Message 'Service starting'
      $Name = $servicename.DisplayName
      $Status = $ServiceName.status
      Write-PSULog -Severity Info -Message "$Name $Status"
      #write-host 'Service starting' -ForegroundColor Yellow
      Start-Sleep -seconds 5
      $ServiceName.Refresh()
    }
    if ($ServiceName.Status -ne 'Running' -and $CheckInPeriodService.elapsed -ge $timeoutService) {

      Write-PSULog -Severity Error -Message "Failed to Start License Agent Service. Service Timed Out"  

    }

  }
  Catch {
    Write-PSULog -Severity Error -Message "Failed to Start License Agent Service"   
  }

  if ($ServiceName.Status -eq 'Running') {
    $NewLicenseAgentCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "RayStationLicenseAgent__" }
    if ($Null -ne $NewLicenseAgentCert) {
      $Thumbprint = $NewLicenseAgentCert.Thumbprint

      Write-PSULog -Severity Info -Message "License Agent Cert Thumbprint: $Thumbprint"

      Write-PSULog -Severity Info -Message "Writing Thumbprint to $RunLocation\Logs\LicenseAgentCert.txt"
      $Thumbprint | out-file "$RunLocation\Logs\LicenseAgentCert.txt" -Append

      if ($RemoteLogLocation -ne $null) {
        Write-PSULog -Severity Info -Message "Writing Thumbprint to remote Log Location"
        $Thumbprint | out-file "$RemotelogDirectory\LicenseAgentCert.txt" -Append
      }
    }

    $timeout = new-timespan -Minutes 1
    $CheckInPeriod = [diagnostics.stopwatch]::StartNew()

    while ($Null -eq $NewLicenseAgentCert -or $CheckInPeriod.elapsed -ge $timeout) {

      if ($Null -ne $NewLicenseAgentCert) {
        $Thumbprint = $NewLicenseAgentCert.Thumbprint

        Write-PSULog -Severity Info -Message "License Agent Cert Thumbprint: $Thumbprint"

        Write-PSULog -Severity Info -Message "Writing Thumbprint to $RunLocation\Logs\LicenseAgentCert.txt"
        $Thumbprint | out-file "$RunLocation\Logs\LicenseAgentCert.txt" -Append

        if ($RemotelogDirectory -ne $null) {
          Write-PSULog -Severity Info -Message "Writing Thumbprint to remote Log Location"
          $Thumbprint | out-file "$RemotelogDirectory\LicenseAgentCert.txt" -Append
        }
      }
      $NewLicenseAgentCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "RayStationLicenseAgent" }
    }
  }
  if ($Null -eq $NewLicenseAgentCert) {
    Write-PSULog -Severity Warn -Message "License Agent Cert was not generated within Timeout window."
  }

  try {
    $groups = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | % {
        $_.Translate([System.Security.Principal.NTAccount])
      } | Sort) -join "`r`n"
  }
  catch { "Groups could not be retrieved." }

  foreach ($Group in $Groups) {

    if ($group -match "Domain Admins") {
      $DomainAdmin = $true
    }
    else {
      $DomainAdmin = $false
    }

    $serviceuserclean = $ServiceUser.split('@')[0]
    $DomainClean = $ServiceUser.split('@')[1].split('.')[0]
    $Domain = $ServiceUser.split('@')[1]
    $UPN = "$DomainClean\$ServiceUserClean"

    Write-PSULog -Severity Info -Message "Checking SPNs"

    $SPN1 = "http/$env:computername"
    $SPN2 = "http/$env:computername.$Domain"
    $SPNs = setspn -L $UPN
    $SPNS = $SPNs -replace '\s', ''
    $SPNs = $SPNs.split('`n')

    $NeededSPNs = @()
    if ($SPNs -contains $SPN1) {
      Write-PSULog -Severity Info -Message "SPN for $SPN1 Exists"
    }
    Else {
      Write-PSULog -Severity Warn -Message "SPN for $SPN1 Does not Exist"
      $NeededSPNs += $SPN1
    }
    if ($SPNs -contains $SPN2) {
      Write-PSULog -Severity Info -Message "SPN for $SPN2 Exists"
    }
    Else {
      Write-PSULog -Severity Warn -Message "SPN for $SPN2 Does not Exist"
      $NeededSPNs += $SPN2
    }



    if ($DomainAdmin -eq $True) {

      $Domain = Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain -ExpandProperty Domain
      if (!([string]::IsNullOrEmpty($NeededSPNs))) {
        Write-PSULog -Severity Info -Message "User has proper Permissions to set SPNs."

        Try {
          Write-PSULog -Severity Info -Message "Trying to set SPNs"
          foreach ($SPN in $NeededSPNs) {
            setspn -U -S $SPN $UPN
          }
          Write-PSULog -Severity Info -Message "Finished Setting SPNs"
        }
        Catch {
          Write-PSULog -Severity Error -Message "SPNs could not be set."
        }
      }
      Start-sleep -Seconds 5
    }
    elseif ($DomainAdmin -eq $false) {

      Write-PSULog -Severity Info -Message "User does not have proper permissions to set SPN Records."
      Write-PSULog -Severity Info -Message "Writing SPN Commands to $RunLocation\Logs\SPNs.txt"
      Add-Content "$RunLocation\Logs\SPNs.txt" "setspn -U -S http/$env:computername $UPN"
      Add-Content "$RunLocation\Logs\SPNs.txt" "setspn -U -S http/$env:computername.$Domain $UPN"

      if ($RemoteLogLocation -ne $null) {
        Write-PSULog -Severity Info -Message "Writing SPN Commands to Remote Log Location"
        Add-Content "$RemoteLogLocation\SPNs.txt" "setspn -U -S http/$env:computername $UPN"
        Add-Content "$RemoteLogLocation\SPNs.txt" "setspn -U -S http/$env:computername.$Domain $UPN"
      }
      Write-PSULog -Severity Info -Message "Have a Domain Admin Run the following Command on $env:computername: setspn -U -S http/$env:computername $UPN"
      Write-PSULog -Severity Info -Message "Have a Domain Admin Run the following Command on $env:computername: setspn -U -S http/$env:computername.$Domain $UPN"
    }

  }

  $sleepInterval = 60
  function Get-InstallerProcesses {
    Get-Process | Where-Object { 
      $_.Name -match "msiexec|install|setup|XenDesktopVdaSetup|Python" 
    }
  }

  do {
    $installers = Get-InstallerProcesses
    if ($installers) {
      Write-PSULog -Severity Info -Message "Installer processes still running. Waiting $sleepInterval seconds..."
      Write-PSULog -Severity Info -Message "Running processes: $($installers.Name -join ', ')"
      Start-Sleep -Seconds $sleepInterval
    }
  } while ($installers)

  Write-PSULog -Severity Info -Message "All installer processes completed."

  if ($settings.GENERAL.INSTALLGPUDRIVER -eq "y") {
    if (Test-Path "$RunLocation\bin\NvidiaPerformance.ps1") {
      write-PSULog -Severity Info -Message "Setting up Nvidia Performance Script to run on next boot."
      $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
      Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $RunLocation\bin\NvidiaPerformance.ps1" -force
    }
  }
  Write-PSULog -Severity End -Message "Finished License Agent Install"
}
else {

  Write-PSULog -Severity Info -Message "Skipping License Agent Install, Server is not listed as designated server."

}

