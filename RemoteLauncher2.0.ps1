<#
.SYNOPSIS
Automates monitoring and managing machine setup status through JSON log files.

.DESCRIPTION
This script monitors a specified directory for `*MachineSetup.json` log files. 
It identifies new machines checking in, starts monitoring jobs for each machine, 
and ensures all machines complete their setup processes. Machines that do not 
check in within a specified timeout are logged as warnings. Once all machines 
have completed, a remote inventory collection process is initiated.

.PARAMETER logDirectory
Specifies the directory where machine setup log files are stored.

.PARAMETER timeout
Defines the timeout period for machine check-ins.

.PARAMETER CheckInPeriod
A stopwatch to track intervals for machine monitoring cycles.

.NOTES
Version: 1.0.0
Author: John Burriss
Date: 10/24/2022
License: MIT

.EXAMPLE
# Example to run the script with a specified log directory
$logDirectory = "C:\\Setup\\Logs"
.
Run the script to monitor the directory for new machine setup log files.
#>
#Requires -RunAsAdministrator


set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition

$remoteRunLocation = $RunLocation -replace ":", "$"
$remoteRunLocation = Join-Path "\\$env:computername" "$remoteRunLocation"

#$remoteRunLocation = $remoteRunLocation.Replace("\", "\\")

Get-ChildItem -Path "$RunLocation\" -Recurse | Unblock-File

Get-Job | Stop-Job
Get-Job | Remove-Job

if (!(Test-Path "$RunLocation\Logs")) {
  New-Item -ItemType Directory -Path "$RunLocation\Logs" | out-null
}
if (!(Test-Path "$RunLocation\Logs\Reports")) {
  New-Item -ItemType Directory -Path "$RunLocation\Logs\Reports" | out-null
}

if ((Get-ChildItem "$RunLocation\Logs\" | ? ( $_.Name -notMatch "Reports" )).count -ge "1" -or (Get-ChildItem "$RunLocation\Logs\Reports").count -ge "1") {
  $ClearLogs = read-Host "Would you like to purge old Log Files and Reports?(Y/n)"
  Switch ($ClearLogs) {
    Y {
      Remove-Item -Path "$RunLocation\Logs\*.*" -Recurse -Force
      Remove-Item -Path "$RunLocation\Logs\Reports\*.*" -Recurse -Force   
    }
    N {  }
    Default { 
      Remove-Item -Path "$RunLocation\Logs\*.*" -Recurse -Force
      Remove-Item -Path "$RunLocation\Logs\Reports\*.*" -Recurse -Force 
     }

  }
}
function Test-Cred {
           
  [CmdletBinding()]
  [OutputType([String])] 
       
  Param ( 
    [Parameter( 
      Mandatory = $false, 
      ValueFromPipeLine = $true, 
      ValueFromPipelineByPropertyName = $true
    )] 
    [Alias( 
      'PSCredential'
    )] 
    [ValidateNotNull()] 
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()] 
    $Credentials
  )
  $Domain = $null
  $Root = $null
  $Username = $null
  $Password = $null
      
  If ($null -eq $Credentials) {
    Try {
      $Credentials = Get-Credential "domain\$env:username" -ErrorAction Stop
    }
    Catch {
      $ErrorMsg = $_.Exception.Message
      Write-Warning "Failed to validate credentials: $ErrorMsg "
      Pause
      Break
    }
  }
      
  # Checking module
  Try {
    # Split username and password
    $Username = $credentials.username
    $Password = $credentials.GetNetworkCredential().password
  
    # Get Domain
    $Root = "LDAP://" + ([ADSI]'').distinguishedName
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root, $UserName, $Password)
  }
  Catch {
    $_.Exception.Message
    Continue
  }
  
  If (!$domain) {
    Write-Warning "Something went wrong"
  }
  Else {
    If ($null -ne $domain.name) {
      return "Authenticated"
    }
    Else {
      return "Not authenticated"
    }
  }
}

$MachineList = Get-Content "$RunLocation\RemoteMachines.txt"

if ($MachineList -contains $env:computername) {

  Write-Host "RemoteMachines.txt cannot contain Current Host $env:computername. Please remove hostname from the file and rerun." -ForegroundColor Red
  break

}

write-host "Checking Connection to Machines" -ForegroundColor Green

$Connection = Get-Content -path "$RunLocation\RemoteMachines.txt"  | ForEach-Object { Test-Connection -ComputerName $_ -Count 1 -AsJob } | Get-Job | Receive-Job -Wait | Select-Object @{Name = 'ComputerName'; Expression = { $_.Address } }, @{Name = 'Reachable'; Expression = { if ($_.StatusCode -eq 0) { $true } else { $false } } }

$Unreachable = $Connection | Where-Object { $_.Reachable -Match "False" }

if ($null -ne $Unreachable) {

  $unreachable = $Unreachable | Format-Table -AutoSize | Out-String

  Write-host "Unable to reach the following hosts.`n $unreachable `nPlease fix Connection or remove before continuing."
  Break

}

Get-Job | Remove-Job

Try {

  $Settings = Get-Content "$RunLocation\setup.json" | ConvertFrom-Json -ErrorAction Stop

}
catch {

  Write-Host "Error Importing JSON File. Please Check Syntax and try again." -ForegroundColor Red
  Break

}

$Settings = Get-Content "$RunLocation\setup.json" | ConvertFrom-Json

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
    write-host "RayStation License Agent Installer EXE Path Incorrect. Please correct and rerun"
    Break
  }
}


if ("" -eq $Settings.GENERAL.REMOTELOGGINGLOCATION) {

  $Settings.GENERAL.REMOTELOGGINGLOCATION = "$remoteRunLocation\Logs"
  $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}

$AutoLoginChoice = $Settings.general.ENABLEAUTOLOGON
if ($AutoLoginChoice -match "y") {

  $Settings.general.ENABLEAUTOLOGON = "N"
  $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"

}

Write-Host "Checking Username Format in Setup.Json" -ForegroundColor Green

$SQLUser = $Settings.SQL.SERVICEACCOUNTNAME
$IndexUser = $Settings.RAYSTATION.IndexServiceUser
$TransferUser = $Settings.RAYSTATION.TransferServiceUser
$LicenseUser = $Settings.SERVICES.SERVICEUSER

if (($Settings.GENERAL.INSTALLSQL -match "Y") -and !([string]::IsNullOrEmpty($SQLUser)) -and $SQLUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

  Write-Host "SQL Service User is in incorrect Format, please use Username@Domain.Suffix format" -ForegroundColor Red
  Break

}
if (($Settings.GENERAL.INSTALLRAYSTATION -match "Y") -and !([string]::IsNullOrEmpty($IndexUser)) -and $IndexUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

  Write-Host "Index Service User is in incorrect Format, please use Username@Domain.Suffix format" -ForegroundColor Red
  Break

}
if (($Settings.GENERAL.INSTALLRAYSTATION -match "Y") -and !([string]::IsNullOrEmpty($TransferUser)) -and $TransferUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

  Write-Host "Transfer Service User is in incorrect Format, please use Username@Domain.Suffix format" -ForegroundColor Red
  Break

}
if (($Settings.GENERAL.INSTALLLICENSEAGENT -match "Y") -and !([string]::IsNullOrEmpty($LicenseUser)) -and $LicenseUser -notmatch "[A-Za-z0-9]+@[A-Za-z0-9]+\.[A-Za-z0-9]+") {

  Write-Host "License Agent Service User is in incorrect Format, please use Username@Domain.Suffix format" -ForegroundColor Red
  Break

}


$DistributeAccount = Read-Host "Is the package distributution account different than installation account?(y/N)"

Switch ($DistributeAccount) {
  Y {
    $DistributeUsername = Read-Host "Enter the package Distribution Account Username(domain\username)"
    $DistributionPassword = Read-Host "Enter the package Distribution Account Password" -AsSecureString 
    $DistributionCreds = New-Object System.Management.Automation.PSCredential ($DistributeUsername, $DistributionPassword)
    $Domain = $DistributeUsername.split("\")[0]
    if ($Domain -notmatch '`.' -or $Domain -notmatch 'localhost') {
      $CredCheck = $DistributionCreds  | Test-Cred
      If ($CredCheck -ne "Authenticated") {
        Write-Warning "Credential validation failed"
        pause
        Break
      }
    }
  }
  N {  }
  Default {  }
}

$validUsername = $false
while (-not $validUsername) {
  try {
    $Username = Read-Host "Enter the Remote Username(domain\username)"
    if ($Username -match '^[^\\]+\\[^\\]+$') {
      $domain, $user = $Username -split '\\'
      $validUsername = $true
    }
    else {
      Write-Host "Invalid format. Please use domain\username format" -ForegroundColor Red
    }
  }
  catch {
    Write-Host "Error validating username: $_" -ForegroundColor Red
  }
}

$Password = Read-Host "Enter the Remote Password" -AsSecureString

$Remotecreds = New-Object System.Management.Automation.PSCredential ($Username, $Password)

$UsernameFQDN = $Username
$Domain = $username.split("\")[0]
$username = $username.split("\")[1]

if ($Domain -notmatch '`.' -or $Domain -notmatch 'localhost') {
  $CredCheck = $Remotecreds  | Test-Cred
  If ($CredCheck -ne "Authenticated") {
    Write-Warning "Credential validation failed"
    pause
    Break
  }
}



if (!(Test-path "$RunLocation\Bin\Key")) {
  New-Item -ItemType Directory -Path "$RunLocation\Bin\Key" -out $null
}

If (!(Test-path "$RunLocation\Bin\Key\key.key")) {

  $AESKey = New-Object Byte[] 32
  [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)

  $encrypted = ConvertFrom-SecureString -SecureString $Password -Key $AESkey
  $AESKey | out-file "$RunLocation\Bin\Key\key.key"

}
else {

  $AESKey = Get-Content "$RunLocation\Bin\Key\key.key"
  $encrypted = ConvertFrom-SecureString -SecureString $Password -Key $AESkey

}

function Get-ValidatedDestinationDirectory {
    param(
        [string]$DefaultPath = "C:\"
    )
    
    do {
        $IsValidInput = $true
        $ErrorMessage = ""
        
        # Get user input
        $UserInput = Read-Host "Enter the remote Directory (Standard is $DefaultPath)"
        
        # Use default if input is empty
        if ([string]::IsNullOrWhiteSpace($UserInput)) {
            $UserInput = $DefaultPath
        }
        
        # Trim whitespace
        $UserInput = $UserInput.Trim()
        
        # Validation checks
        if ($UserInput.Length -eq 0) {
            $IsValidInput = $false
            $ErrorMessage = "Path cannot be empty"
        }
        elseif ($UserInput.Length -gt 248) {
            # Windows path limit is typically 260, leaving room for filename
            $IsValidInput = $false
            $ErrorMessage = "Path is too long (maximum 248 characters)"
        }
        elseif ($UserInput -notmatch '^[A-Za-z]:') {
            $IsValidInput = $false
            $ErrorMessage = "Path must start with a drive letter (e.g., C:, D:)"
        }
        elseif ($UserInput -match '[<>"|?*]') {
            $IsValidInput = $false
            $ErrorMessage = 'Path contains invalid characters: < > ` " | ? *'
        }
        elseif ($UserInput -match '[\x00-\x1F]') {
            $IsValidInput = $false
            $ErrorMessage = "Path contains control characters"
        }
        elseif ($UserInput -match '\\{2,}') {
            $IsValidInput = $false
            $ErrorMessage = "Path contains consecutive backslashes"
        }
        elseif ($UserInput -match '\\\s+\\') {
            $IsValidInput = $false
            $ErrorMessage = "Path contains whitespace between backslashes"
        }
        elseif ($UserInput -match '\\\.+\\') {
            $IsValidInput = $false
            $ErrorMessage = "Path contains invalid directory names (dots only)"
        }
        
        # Check for reserved Windows names
        $ReservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
        $PathParts = $UserInput.Split('\') | Where-Object { $_ -ne '' }
        
        foreach ($Part in $PathParts) {
            $PartName = $Part.Split('.')[0] # Remove extension if present
            if ($ReservedNames -contains $PartName.ToUpper()) {
                $IsValidInput = $false
                $ErrorMessage = "Path contains reserved Windows name: $Part"
                break
            }
        }
        
        if (-not $IsValidInput) {
            Write-Host "Error: $ErrorMessage" -ForegroundColor Red
            Write-Host "Please enter a valid Windows path." -ForegroundColor Yellow
            Write-Host ""
        }
        
    } while (-not $IsValidInput)
    
    # Clean and process the validated input
    $DestinationDirOriginal = $UserInput.TrimEnd('\')
    $DestinationDir = $UserInput.Insert(1, '$')
    $DestinationDir = $DestinationDir -replace ':', ''
    
    # Return both original and processed paths
    return @{
        Original = $DestinationDirOriginal
        Processed = $DestinationDir
        Raw = $UserInput
    }
}

# Example usage:
$Result = Get-ValidatedDestinationDirectory

$DestinationDirOriginal = $Result.Original
$DestinationDir = $Result.Processed

#$DestinationDir = Read-host "Enter the remote Directory (Standard is C:\)"
#$DestinationDirOriginal = $DestinationDir.TrimEnd('\')
#$DestinationDir = $DestinationDir.Insert(1, '$')
#$DestinationDir = $DestinationDir -replace ':', ''


Write-Host "Encrypting Passwords in Setup.json" -ForegroundColor Green

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


$UpdatedMachineList = @()

function WriteJobProgress {
  param($Job,
    $Completed = $false)
 
  if ($null -ne $Job.ChildJobs[0].Progress) {
    $jobProgressHistory = $Job.ChildJobs[0].Progress
    if ($jobProgressHistory.Count -gt 0) {
      $latestProgress = $jobProgressHistory[$jobProgressHistory.Count - 1]
      if ($null -ne $latestProgress) {
        $latestPercentComplete = $latestProgress.PercentComplete
        $latestActivity = $latestProgress.Activity
        $latestStatus = $latestProgress.StatusDescription
        $CurrentOperation = $latestProgress.CurrentOperation
        
        if ($Completed -eq $false -and $null -ne $latestActivity) {
          Write-Progress -Id $Job.id -Activity $latestActivity -Status $latestStatus -PercentComplete $latestPercentComplete -CurrentOperation $CurrentOperation -ErrorAction SilentlyContinue
        }
        elseif ($Completed -eq $true -and $null -ne $latestActivity) {
          Write-Progress -Id $Job.id -Activity $latestActivity -Completed -ErrorAction SilentlyContinue
        }
        else {
          Write-Progress -Id $Job.id -Completed -ErrorAction SilentlyContinue
        }
      }
    }
  }
}
#_______________________________________________________________________________________________________________________
$computers = @(Get-Content -Path "$RunLocation\RemoteMachines.txt")

Write-Host "Checking remote connection and if Logon Banner is Enabled on remote Machines" -ForegroundColor Green

# Maximum number of concurrent jobs
$maxConcurrentJobs = 50

# Enhanced connectivity check script block
$checkScript = {
  param($computer)
  
  $resultObj = [PSCustomObject]@{
    ComputerName   = $computer
    Status         = "Failed"
    BannerEnabled  = $false
    Error          = $null
    ErrorCategory  = $null
    TestConnection = $false
    TestWSMan      = $false
    TestPSRemoting = $false
  }
  
  try {
    # Test basic connectivity
    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
      $resultObj.Error = "Host unreachable"
      $resultObj.ErrorCategory = "Network"
      return $resultObj
    }
    $resultObj.TestConnection = $true
    
    # Test WSMan
    if (-not [bool](Test-WSMan -ComputerName $computer -ErrorAction SilentlyContinue)) {
      $resultObj.Error = "WinRM not available"
      $resultObj.ErrorCategory = "WinRM"
      return $resultObj
    }
    $resultObj.TestWSMan = $true
    
    # Test PowerShell remoting and get banner info
    try {
      $result = Invoke-Command -ComputerName $computer -ScriptBlock {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        try {
          $regValues = Get-ItemProperty -Path $regPath -Name legalnoticetext, legalnoticecaption -ErrorAction SilentlyContinue
          return @{
            Success       = $true
            BannerText    = $regValues.legalnoticetext
            BannerCaption = $regValues.legalnoticecaption
          }
        }
        catch {
          return @{ Success = $false; Error = $_.Exception.Message }
        }
      } -ErrorAction Stop
      
      $resultObj.TestPSRemoting = $true
      $resultObj.Status = "Success"
      $resultObj.BannerEnabled = ($null -ne $result.BannerText -and $result.BannerText -ne "") -or 
                                ($null -ne $result.BannerCaption -and $result.BannerCaption -ne "")
    }
    catch {
      # Fallback to WMI
      try {
        $regProv = Get-WmiObject -List "StdRegProv" -ComputerName $computer -Namespace root\default -ErrorAction Stop
        $HKLM = 2147483650
        $key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        
        $bannerText = $regProv.GetStringValue($HKLM, $key, "legalnoticetext").sValue
        $bannerCaption = $regProv.GetStringValue($HKLM, $key, "legalnoticecaption").sValue
        
        $resultObj.Status = "Success"
        $resultObj.TestPSRemoting = $false  # Mark as false since PS remoting failed, used WMI instead
        $resultObj.Error = "PSRemoting Disabled"
        $resultObj.ErrorCategory = "Access"
        $resultObj.BannerEnabled = ($null -ne $bannerText -and $bannerText -ne "") -or 
                                  ($null -ne $bannerCaption -and $bannerCaption -ne "")
      }
      catch {
        $resultObj.Error = "Access denied"
        $resultObj.ErrorCategory = "Access"
      }
    }
  }
  catch {
    $resultObj.Error = $_.Exception.Message
    $resultObj.ErrorCategory = "Unknown"
  }
  
  return $resultObj
}

# Initialize and run parallel checks
$results = @()
$computerQueue = [System.Collections.Queue]::new()
$runningJobs = @{}

foreach ($computer in $computers) {
  $computerQueue.Enqueue($computer)
}

$totalComputers = $computers.Count
$processedComputers = 0

# Process all computers
while ($computerQueue.Count -gt 0 -or $runningJobs.Count -gt 0) {
  # Start new jobs
  while ($computerQueue.Count -gt 0 -and $runningJobs.Count -lt $maxConcurrentJobs) {
    $computer = $computerQueue.Dequeue()
    $job = Start-Job -ScriptBlock $checkScript -ArgumentList $computer
    $runningJobs[$job.Id] = @{
      Job      = $job
      Computer = $computer
    }
  }
  
  # Check completed jobs
  $completedJobIds = @($runningJobs.Keys | Where-Object { $runningJobs[$_].Job.State -ne 'Running' })
  
  foreach ($jobId in $completedJobIds) {
    $jobInfo = $runningJobs[$jobId]
    $job = $jobInfo.Job
    
    try {
      $result = Receive-Job -Job $job -ErrorAction Stop
      if ($result) {
        $results += $result
      }
    }
    catch {
      $results += [PSCustomObject]@{
        ComputerName   = $jobInfo.Computer
        Status         = "Failed"
        Error          = "Job execution failed"
        ErrorCategory  = "JobFailure"
        TestConnection = $false
        TestWSMan      = $false
        TestPSRemoting = $false
        BannerEnabled  = $false
      }
    }
    
    Remove-Job -Job $job
    $runningJobs.Remove($jobId)
    $processedComputers++
  }
  
  Start-Sleep -Milliseconds 50
}

# Process results
$FailedObjects = @()
$successCount = ($results | Where-Object { $_.Status -eq 'Success' }).Count
$failed = ($results | Where-Object { $_.Status -eq 'Failed' -or $_.TestConnection -eq $false -or $_.TestWSMan -eq $false -or $_.TestPSRemoting -eq $false})
$FailedObjects += $failed
$failedcount = ($FailedObjects | Measure-Object).Count
$bannersEnabled = ($results | Where-Object { $_.BannerEnabled -eq $true }).Count

# Connectivity statistics
$pingSuccess = ($results | Where-Object { $_.TestConnection -eq $true }).Count
$wsmanSuccess = ($results | Where-Object { $_.TestWSMan -eq $true }).Count
$psRemotingSuccess = (($results | Where-Object { $_.TestPSRemoting -eq $true }) | Measure-Object).count

Write-Host "Connectivity Tests: Ping=$pingSuccess/$totalComputers, WSMan=$wsmanSuccess/$totalComputers, PSRemoting=$psRemotingSuccess/$totalComputers" -ForegroundColor Cyan
Write-Host "Banner Check Complete: $successCount/$totalComputers successful, $bannersEnabled have banners enabled" -ForegroundColor $(if ($bannersEnabled -gt 0) { 'Yellow' }else { 'Green' })

# Handle results based on findings
if ($bannersEnabled -gt 0) {
  $banneredMachines = ($results | Where-Object { $_.BannerEnabled -eq $true }).ComputerName -join ', '
  Write-Host "WARNING: Logon banners detected on: $banneredMachines" -ForegroundColor Yellow
  Write-Host "This may cause issues with the Remote Setup Process." -ForegroundColor Yellow
}
elseif ($failedcount -gt 0) {
  Write-Host "WARNING: $failedcount machine(s) failed connectivity checks:" -ForegroundColor Yellow
  
  # Display detailed failure information for each machine
  foreach ($failedMachine in $FailedObjects) {
    $failedTests = @()
    
    if ($failedMachine.TestConnection -eq $false) { $failedTests += "Ping" }
    if ($failedMachine.TestWSMan -eq $false) { $failedTests += "WSMan" }
    if ($failedMachine.TestPSRemoting -eq $false) { $failedTests += "PSRemoting" }
    
    $failedTestsString = $failedTests -join ', '
    $errorInfo = if ($failedMachine.Error) { " ($($failedMachine.Error))" } else { "" }
    
    Write-Host "  - $($failedMachine.ComputerName): Failed [$failedTestsString]$errorInfo" -ForegroundColor Red
  }
  Write-Host "Please See the section in the read me file on resolving connectivity problems." -ForegroundColor Red
}
else {
  Write-Host "No logon banners detected on any remote machines." -ForegroundColor Green
}

try{
  Write-Host "Do you wish to continue?" -ForegroundColor Yellow
  $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
  }
  Catch{
  $cont = read-host "(Y/n)"
  Switch($Cont){
  Y{}
  N{exit}
  default{}
  }
  }
#_______________________________________________________________________________________________________________________
  
$SkipRename = Read-Host "Would you like to rename any machines(y/N)"

ForEach ($machine in $MachineList) {
  if ($SkipRename -match "Y") {
    $NameMachine = Read-Host "Would you like to name $machine"

    if ($NameMachine -match "Y") {
      $MachineName = Read-Host "What would you like to name the machine?"

      $Settings = Get-Content "$RunLocation\setup.json" | ConvertFrom-Json

      $settings.GENERAL.MACHINENAME = $MachineName

      $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"

      $MachineHash = @{
        OldName = "$machine";
        NewName = "$MachineName"
      }

      $UpdatedMachineList += $MachineHash;
    }
  }

  $DeploymentTime = [diagnostics.stopwatch]::StartNew()

  Try {

    Write-Host "Attempting to copy Package to Remote Host $machine" -ForegroundColor Green

    $Source = $RunLocation
    $Dest = "\\$machine\$DestinationDir"

    $source_path = $source
    $destination_path = $Dest

    $job = Start-Job -ScriptBlock { param($source_path, $destination_path, $machine) Robocopy.exe $source_path $destination_path\setup /MIR /NDL /NJH /NJS /XD $source_path\Utils $source_path\.git $source_path\.vscode | % { $data = $_.Split([char]9); if ("$($data[4])" -ne "") { $file = "$($data[4])" }; $Percent = ($($data[0]).Replace('%', "").Replace(' ', "")); Write-Progress "Percentage $($data[0])" -PercentComplete $Percent -Activity "$machine Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; } }  -name "Start $machine Transfer" -ArgumentList $source_path, $destination_path, $machine
    #WriteJobProgress($job);
  }
  Catch {

    Write-Host "Failed to copy packages to remote Location" -ForegroundColor Red

  }
  $Dest = $Dest.Substring(0, $Dest.Length - 1)

}

$NewMachineList = @()

ForEach ($machine in $MachineList) {

  if ($UpdatedMachineList.oldName -contains $machine) {
    
    $NewMachineList += $UpdatedMachineList.NewName

  }
  else {
    $NewMachineList += $Machine
  }
}

if ($null -ne $NewMachineList -and $NewMachineList -notmatch $MachineList) {

  Move-Item -Path "$RunLocation\RemoteMachines.txt" -destination "$RunLocation\OriginalRemoteMachines.txt" -Force

  $NewMachineList | Out-File "$RunLocation\RemoteMachines.txt"

} 



while ((Get-Job | Where-Object { $_.State -ne "Completed" }).Count -gt 0) {   

  $jobs = (Get-Job | Where-Object { $_.State -ne "Completed" })
  foreach ($Job in $jobs) {
    WriteJobProgress($job);
  }
  $completedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })
  foreach ($CompletedJob in $CompletedJobs) {
    WriteJobProgress -Job $CompletedJob -Completed $true
  }
}
$completedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })
foreach ($CompletedJob in $CompletedJobs) {
  WriteJobProgress -Job $CompletedJob -Completed $true
}
$AllJobs = Get-Job
foreach ($job in $AllJobs) {
  try {
    WriteJobProgress -Job $job -Completed $true
  }
  catch {}
}

get-job | stop-job -ErrorAction SilentlyContinue
get-job | remove-job -ErrorAction SilentlyContinue


#New Multi-Threaded Code
$JobResults = @()

# Launch parallel jobs
foreach ($Machine in $MachineList) {
  $JobResults += Start-Job -Name "Setup_$Machine" -ScriptBlock {
    param($Machine, $Domain, $Username, $Encrypted, $DestinationDirOriginal, $RunLocation, $UsernameFQDN, $DistributionCreds, $Password)

    # Define all script blocks within the job
    $configBlock = {
      param($DestinationDirOriginal, $RunLocation)
      Write-Host "Copy to Machine Completed" -ForegroundColor Green
      Write-Host "Adjusting Configuration Files" -ForegroundColor Green
      @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\Launcher.ps1") | Set-Content "$RunLocation\Launcher.ps1"
      @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\Setup.ps1") | Set-Content "$RunLocation\Setup.ps1"
      @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\bin\cleanup.ps1") | Set-Content "$RunLocation\bin\cleanup.ps1"
      @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\bin\NvidiaPerformance.ps1") | Set-Content "$RunLocation\bin\NvidiaPerformance.ps1"
    }

    $adminBlock = {
      param($Username, $UsernameFQDN)
      $AdminGroupMembership = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -Match $Username }
      if ($Null -eq $AdminGroupMembership) {
        Add-LocalGroupMember -Group "Administrators" -Member $UsernameFQDN
      }
    }

    $credsBlock = {
      param($Domain, $Machine, $Encrypted, $Username)
      $path = "HKLM:\SOFTWARE\MachineSetup"
      $CleanDomain = $Domain
      if ($CleanDomain -match '\.' -or $CleanDomain -match 'localhost') {
        $CleanDomain = $Machine
      }
      if (!(Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
      Set-ItemProperty $path "Password" -Value $Encrypted -Force
      Set-ItemProperty $path "UserName" -Value $Username -Force
      Set-ItemProperty $path "Domain" -Value $CleanDomain -Force
    }

    $logonBlock = {
      param($DestinationDirOriginal)
      & powershell.exe -file "$DestinationDirOriginal\setup\bin\AutologinReg.ps1"
    }

    $encryptedLoginBlock = {
      param($Machine, $DestinationDirOriginal)
      $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
      Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $DestinationDirOriginal\setup\Setup.ps1"
      Write-Host "Finished setting Remote Machine: $Machine for Install." -ForegroundColor Green
    }

    $clearLoginBlock = {
      param($Machine, $Domain, $Username, $TempPassword, $DestinationDirOriginal)
      $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
      Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $DestinationDirOriginal\setup\Setup.ps1"
      $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
      Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String
      Set-ItemProperty $RegPath "DefaultUsername" -Value $Username -type String
      Set-ItemProperty $RegPath "DefaultPassword" -Value $TempPassword -type String
      Set-ItemProperty $RegPath "DefaultDomainName" -Value $Domain -type String
      Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type String
      Invoke-WmiMethod -Class win32_process -ComputerName $Machine -Name create -ArgumentList "c:\windows\system32\msg.exe * This Machine is going to restart!" | Out-Null
      Write-Host "Finished setting Remote Machine: $Machine for Install." -ForegroundColor Green
    }

    # Execute initial setup
    if ($null -ne $DistributionCreds) {
      Invoke-Command -ComputerName $Machine -ScriptBlock $configBlock -Credential $DistributionCreds -ArgumentList $DestinationDirOriginal, $RunLocation
      Invoke-Command -ComputerName $Machine -ScriptBlock $adminBlock -Credential $DistributionCreds -ArgumentList $Username, $UsernameFQDN
    }
    else {
      Invoke-Command -ComputerName $Machine -ScriptBlock $configBlock -ArgumentList $DestinationDirOriginal, $RunLocation
    }

    # Check for PSRemoting
    $PSRemoting = Test-WSMan -ComputerName $Machine -ErrorAction SilentlyContinue

    if ($PSRemoting -ne $null) {
      Write-Host "Securely enabling Auto Logon Remotely" -ForegroundColor Green

      # Set credentials
      if ($null -ne $DistributionCreds) {
        Invoke-Command -ComputerName $Machine -ScriptBlock $credsBlock -Credential $DistributionCreds -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }
      else {
        Invoke-Command -ComputerName $Machine -ScriptBlock $credsBlock -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }

      # Create remote session
      if ($null -ne $DistributionCreds) {
        $RemoteSession = New-PSSession -ComputerName $Machine -Credential $DistributionCreds
      }
      else {
        $RemoteSession = New-PSSession -ComputerName $Machine
      }

      try {
        # Enable auto logon
        Invoke-Command -Session $RemoteSession -ScriptBlock $logonBlock -ArgumentList $DestinationDirOriginal
        Start-Sleep -Seconds 1

        # Check login status
        $checkLogin = Invoke-Command -ComputerName $Machine {
          try {
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -ErrorAction Stop | 
            Select-Object AutoAdminLogon
          }
          catch {
            return @{AutoAdminLogon = "0" }
          }
        }

        if ($checkLogin.AutoAdminLogon -eq "0") {
          Write-Host "Failed to enable Auto Logon on $Machine, trying again" -ForegroundColor Yellow
          Invoke-Command -Session $RemoteSession -ScriptBlock $logonBlock -ArgumentList $DestinationDirOriginal
          
          $checkLogin = Invoke-Command -ComputerName $Machine {
            try {
              Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon -ErrorAction Stop |
              Select-Object AutoAdminLogon
            }
            catch {
              return @{AutoAdminLogon = "0" }
            }
          }

          if ($checkLogin.AutoAdminLogon -eq "0") {
            Write-Host "Failed to enable Auto Logon on $Machine. Please Login Manually to start script" -ForegroundColor Red
          }
        }

        # Set encrypted login
        Invoke-Command -Session $RemoteSession -ScriptBlock $encryptedLoginBlock -ArgumentList $Machine, $DestinationDirOriginal
      }
      finally {
        if ($RemoteSession) {
          Remove-PSSession $RemoteSession
        }
      }
    }
    else {
      Write-Host "Falling back on Clear Text Login and restarting" -ForegroundColor Yellow
      
      # Convert SecureString to plain text for clear login
      $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
      $TempPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

      if ($Domain -match '\.' -or $Domain -match 'localhost') {
        $Domain = $Machine
      }

      if ($null -ne $DistributionCreds) {
        Invoke-Command -ComputerName $Machine -ScriptBlock $clearLoginBlock -Credential $DistributionCreds -ArgumentList $Machine, $Domain, $Username, $TempPassword, $DestinationDirOriginal
      }
      else {
        Invoke-Command -ComputerName $Machine -ScriptBlock $clearLoginBlock -ArgumentList $Machine, $Domain, $Username, $TempPassword, $DestinationDirOriginal
      }
    }
  } -ArgumentList $Machine, $Domain, $Username, $Encrypted, $DestinationDirOriginal, $RunLocation, $UsernameFQDN, $DistributionCreds, $Password
}

# Monitor jobs
while ((Get-Job | Where-Object { $_.State -ne "Completed" }).Count -gt 0) {   

  $jobs = (Get-Job | Where-Object { $_.State -ne "Completed" })
  foreach ($Job in $jobs) {
    WriteJobProgress($job);
  }
  $completedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })
  foreach ($CompletedJob in $CompletedJobs) {
    WriteJobProgress -Job $CompletedJob -Completed $true
  }
}
$completedJobs = (Get-Job | Where-Object { $_.State -eq "Completed" })
foreach ($CompletedJob in $CompletedJobs) {
  WriteJobProgress -Job $CompletedJob -Completed $true
}

# Retrieve results
Get-Job | ForEach-Object {
  $_ | Receive-Job
  Remove-Job -Job $_
}

#_______________________________________________________________________________________________________________________________


Write-Host "Restarting Machines" -ForegroundColor Green
foreach ($Machine in $MachineList) {
  Write-Host "Restarting $Machine" -ForegroundColor Green
  restart-computer -ComputerName $Machine -Force -AsJob | out-null

}

get-job | Wait-Job | out-null
Get-job | Remove-Job -ErrorAction SilentlyContinue

Write-Host "Starting Log Reader" -ForegroundColor Green

function Register-Watcher {
  param(
    [string]$folder,
    [string]$FileName
  )
    
  $logFile = Join-Path -Path $folder -ChildPath $FileName
  $processedLines = @{}

  while ($true) {
    if (Test-Path $logFile) {
      try {
        $content = Get-Content $logFile -Raw
        if ($content) {
          $lines = $content -split '\r?\n' | Where-Object { $_ -and ($_ -match '\{.*\}') }
                    
          foreach ($line in $lines) {
            $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($line))
            $hashString = [System.Convert]::ToBase64String($hash)
                        
            if (-not $processedLines.ContainsKey($hashString)) {
              try {
                $logEntry = $line | ConvertFrom-Json
                $color = switch ($logEntry.Severity) {
                  "Info" { "White" }
                  "Warn" { "Yellow" }
                  "Error" { "Red" }
                  "Start" { "Green" }
                  "End" { "Blue" }
                  default { "White" }
                }
                                
                Write-Host "$($logEntry.Timestamp) $($logEntry.Hostname) Severity=$($logEntry.Severity) Message=$($logEntry.Message)" -ForegroundColor $color
                                
                if ($logEntry.Severity -in @("Error", "Warning")) {
                  $line | Out-File -FilePath (Join-Path $folder "ErrorLog.json") -Append
                }
                                
                $processedLines[$hashString] = $true
              }
              catch {
                Write-Error "Error parsing log entry: $_"
              }
            }
          }
        }
      }
      catch {
        Write-Error "Error reading log file: $_"
      }
    }
    Start-Sleep -Milliseconds 500
  }
}

$logDirectory = Join-Path $remoteRunLocation "Logs"
$LogArray = @()
$CheckIn = @()

Start-Process powershell -ArgumentList "-noexit", "-noprofile", "-file $RunLocation\bin\ErrorLogReader.ps1"

try {
  $timeout = New-TimeSpan -Minutes 3
  $CheckInPeriod = [Diagnostics.Stopwatch]::StartNew()

  while ($true) {
    $Logfiles = Get-ChildItem -Path $logDirectory -Filter "*MachineSetup.json"

    foreach ($LogFile in $Logfiles) {
      $FileName = $LogFile.Name
      $ShortName = ($FileName -split "-MachineSetup.json")[0]
        
      if ($CheckIn -notcontains $ShortName) {
        $CheckIn += $ShortName
        Write-Host "New machine check-in detected: $ShortName" -ForegroundColor Green
            
        # Start watcher job with timeout
        $Job = Start-Job -ScriptBlock ${function:Register-Watcher} -ArgumentList $logDirectory, $FileName
        Receive-Job -Job $Job | Write-Host -ForegroundColor Cyan
            
        $LogArray += $LogFile.FullName
      }
    }

    if ($CheckInPeriod.Elapsed -ge $timeout) {
      $NotCheckedInMachines = Compare-Object -ReferenceObject $NewMachineList -DifferenceObject $CheckIn -PassThru
      foreach ($NotCheckedInMachine in $NotCheckedInMachines) {
        if ($NotCheckedInMachine -ne "") {
          $ErrorObject = [PSCustomObject]@{
            Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
            Hostname  = $env:computername
            Severity  = "Warning"
            Message   = "Host: $NotCheckedInMachine has not checked in"
          }
          $ErrorObject | ConvertTo-Json -Compress | 
          Out-File -FilePath "$logDirectory\ErrorLog.json" -Append
                
          Write-Host "$($ErrorObject.Timestamp) $($ErrorObject.Hostname) Severity=$($ErrorObject.Severity) Message=$($ErrorObject.Message)" -ForegroundColor Yellow
        }
      }

      # Inside the main loop:
      $FinishedMachinesFile = Join-Path $RunLocation "Logs\CompletedMachines.txt"
      if (Test-Path $FinishedMachinesFile) {
        $FinishedMachines = Get-Content $FinishedMachinesFile -ErrorAction Stop
        $ReferenceList = if ($null -eq $NewMachineList) { $MachineList } else { $NewMachineList }

        # Normalize data to prevent case or whitespace issues
        $FinishedMachines = ($FinishedMachines | ForEach-Object { $_.Trim() }).ToUpper()
        $ReferenceList = ($ReferenceList | ForEach-Object { $_.Trim() }).ToUpper()

        #Write-Host "Finished Machines: $($FinishedMachines -join ', ')" -ForegroundColor Yellow
        #Write-Host "Reference List: $($ReferenceList -join ', ')" -ForegroundColor Yellow

        # Get machines that haven't completed yet
        $RemainingMachines = Compare-Object -ReferenceObject $ReferenceList -DifferenceObject $FinishedMachines -PassThru | Where-Object { $_ }

        # If no remaining machines (empty array), all are complete
        if (-not $RemainingMachines) {
          Write-Host "All Machines have checked in" -ForegroundColor Green
          Write-Host "Starting Inventory Collection" -ForegroundColor Green
          & $RunLocation\bin\RemoteInventory.ps1

          $DeploymentTimeMin = $DeploymentTime.Elapsed.Minutes
          $DeploymentTimeSec = $DeploymentTime.Elapsed.Seconds
          $message = "Setup Has Completed on All Machines. Time to complete: $DeploymentTimeMin Minutes $DeploymentTimeSec Seconds."

          # Generate consolidated report
          $reportDirectory = "$RunLocation\Logs\Reports"
          $outputFile = "$RunLocation\Logs\ConsolidatedReport.html"

          # HTML template with tabs functionality
          $htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <title>Consolidated System Configuration Reports</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .tab-container { margin-top: 20px; }
        .tab-buttons { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
        .tab-buttons button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
        }
        .tab-buttons button:hover { background-color: #ddd; }
        .tab-buttons button.active { background-color: #ccc; }
        .tab-content {
            display: none;
            padding: 6px 12px;
            border: 1px solid #ccc;
            border-top: none;
        }
        iframe {
            width: 100%;
            height: 800px;
            border: none;
        }
    </style>
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tab-content");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tab-button");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        window.onload = function() {
            // Open first tab by default
            document.getElementsByClassName("tab-button")[0].click();
        }
    </script>
</head>
<body>
    <h1>Consolidated System Configuration Reports</h1>
    <div class="tab-container">
        <div class="tab-buttons">
            {{TAB_BUTTONS}}
        </div>
        {{TAB_CONTENT}}
    </div>
</body>
</html>
"@

          # Create reports directory if it doesn't exist
          if (-not (Test-Path $reportDirectory)) {
            New-Item -ItemType Directory -Path $reportDirectory
          }

          # Get all HTML files in the directory
          $reports = Get-ChildItem -Path $reportDirectory -Filter "*.html"

          $tabButtons = ""
          $tabContent = ""
          $firstTab = $true

          foreach ($report in $reports) {
            # Read the report content
            $content = Get-Content -Path $report.FullName -Raw
    
            # Extract server name using regex
            if ($content -match '<h2>Server Name:\s*(.+?)</h2>') {
              $serverName = $matches[1].Trim()
            }
            else {
              $serverName = $report.BaseName
            }
    
            # Create safe ID for the tab (remove special characters)
            $tabId = "tab_" + ($serverName -replace '[^a-zA-Z0-9]', '_')
    
            # Add tab button
            $activeClass = if ($firstTab) { ' active' } else { '' }
            $tabButtons += "<button class=`"tab-button$activeClass`" onclick=`"openTab(event, '$tabId')`">$serverName</button>`n"
    
            # Add tab content
            $displayStyle = if ($firstTab) { 'block' } else { 'none' }
            $tabContent += @"
    <div id="$tabId" class="tab-content" style="display: $displayStyle;">
        $content
    </div>
"@
    
            $firstTab = $false
          }

          # Replace placeholders in template
          $finalHtml = $htmlTemplate -replace '{{TAB_BUTTONS}}', $tabButtons
          $finalHtml = $finalHtml -replace '{{TAB_CONTENT}}', $tabContent

          # Write the consolidated report
          $finalHtml | Out-File -FilePath $outputFile -Encoding UTF8

          Write-Host "Consolidated report has been generated at: $outputFile"


          Write-Host $message -ForegroundColor Green
          Invoke-WmiMethod -Class win32_process -Name create -ArgumentList "c:\windows\system32\msg.exe * $message" | Out-Null

          # Stop all monitoring jobs
          Get-Job | Stop-Job
          Get-Job | Remove-Job
          Break
        }
      }

            
      $CheckInPeriod.Restart()
    }
        
    # Display job output
    Get-Job | Where-Object { $_.HasMoreData } | ForEach-Object {
      Receive-Job -Job $_ | Write-Host -ForegroundColor Cyan
      #Remove-Job -Job $_
    }

    Start-Sleep -Seconds 1
  }
}
catch {
  Write-Error "Error in main monitoring loop: $_"
}
finally {
  Get-Job | Stop-Job
  Get-Job | Remove-Job
  $DeploymentTime.Stop()
  $DeploymentTimeMin = $DeploymentTime.Elapsed.Minutes
  $DeploymentTimeSec = $DeploymentTime.Elapsed.Seconds
  Write-Host "Deployment ran for: $DeploymentTimeMin Minutes $DeploymentTimeSec Seconds" -ForegroundColor Yellow
}
