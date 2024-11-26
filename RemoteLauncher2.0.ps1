#------------------------------------------------------
# Name:        RemoteLauncher2.0
# Purpose:     Kicks off Machine setup on remote machines
# Author:      John Burriss
# Created:     10/24/2022  2:22 PM 
# Modified:    09/13/2023  11:08 AM
#Version:      0.15
#------------------------------------------------------
#Requires -RunAsAdministrator


set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition

$remoteRunLocation = $RunLocation -replace ":", "$"
$remoteRunLocation = Join-Path "\\$env:computername" "$remoteRunLocation"

#$remoteRunLocation = $remoteRunLocation.Replace("\", "\\")

Get-ChildItem -Path "$RunLocation\" -Recurse | Unblock-File

Get-Job | Stop-Job
Get-Job | Remove-Job

if ((Get-ChildItem "$RunLocation\Logs").count -ge "1") {
  $ClearLogs = read-Host "Would you like to purge old Log Files?(y/n)"
  Switch ($ClearLogs) {
    Y { Remove-Item -Path "$RunLocation\Logs\*.*" -Recurse -Force }
    N {  }
    Default {  }

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
      
  If ($Credentials -eq $null) {
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
    If ($domain.name -ne $null) {
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

if ($Unreachable -ne $null) {

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
    write-host "RRayStation License Agent Installer EXE Path Incorrect. Please correct and rerun"
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


$DistributeAccount = Read-Host "Is the distributution account diffrent than installation account?(y/n)"

Switch ($DistributeAccount) {
  Y {
    $DistributeUsername = Read-Host "Enter the Distribution Account Username(domain\username)"
    $DistributionPassword = Read-Host "Enter the Distribution Account Password" -AsSecureString 
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

$Username = Read-Host "Enter the Remote Username(domain\username)"

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

$DestinationDir = Read-host "Enter the remote Directory (Standard is C:\)"
$DestinationDirOriginal = $DestinationDir.TrimEnd('\')
$DestinationDir = $DestinationDir.Insert(1, '$')
$DestinationDir = $DestinationDir -replace ':', ''


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
 
  #Make sure the first child job exists
  if ($null -ne $Job.ChildJobs[0].Progress) {
    #Extracts the latest progress of the job and writes the progress
    $jobProgressHistory = $Job.ChildJobs[0].Progress;
    $latestProgress = $jobProgressHistory[$jobProgressHistory.Count - 1];
    $latestPercentComplete = $latestProgress | Select-object -expand PercentComplete;
    $latestActivity = $latestProgress | Select-object -expand Activity;
    $latestStatus = $latestProgress | Select-object -expand StatusDescription;
    $CurrentOperation = $latestProgress | Select-object -expand CurrentOperation
    
    #When adding multiple progress bars, a unique ID must be provided. Here I am providing the JobID as this
    if ($Completed -eq $false) {
      try {
        Write-Progress -Id $Job.id -Activity $latestActivity -Status $latestStatus -PercentComplete $latestPercentComplete -CurrentOperation $CurrentOperation;
      }
      catch {
        $_
      }
    }
    elseif ($Completed -eq $true) {
      Write-Progress -Id $Job.id -Activity $latestActivity -Completed
    }
  }
}
$SkipRename = Read-Host "Would you like to rename any machines(Y/N)"

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

    $job = Start-Job -ScriptBlock { param($source_path, $destination_path, $machine) Robocopy.exe $source_path $destination_path\setup /MIR /NDL /NJH /NJS | % { $data = $_.Split([char]9); if ("$($data[4])" -ne "") { $file = "$($data[4])" }; $Percent = ($($data[0]).Replace('%', "").Replace(' ', "")); Write-Progress "Percentage $($data[0])" -PercentComplete $Percent -Activity "$machine Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; } }  -name "Start $machine Transfer" -ArgumentList $source_path, $destination_path, $machine
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

if ($NewMachineList -ne $null -and $NewMachineList -notmatch $MachineList) {

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

#Get-Job | Wait-Job | out-null



<#
OLD SINGLE THREAD CODE
foreach ($Machine in $MachineList) {

  $CredsToReg = {
    $path = "HKLM:\SOFTWARE\MachineSetup"
    $CleanDomain = $Using:Domain
    if ($CleanDomain -match '`.' -or $CleanDomain -match 'localhost') {
      $CleanDomain = "$Using:Machine"
    }
    if (!(Test-Path $path)) { mkdir $path | Out-Null }
    Set-ItemProperty $path "Password" -Value $Using:encrypted -Force
    Set-ItemProperty $path "UserName" -Value $Using:Username -Force
    Set-ItemProperty $path "Domain" -Value $CleanDomain -Force
  }

  $AdjustConfigFile = {
    Write-Host "Copy to Machine $Using:machine Completed" -ForegroundColor Green
    Write-Host "Adjusting Configuration Files on $Using:machine" -ForegroundColor Green
    @("Set-Location `"$Using:DestinationDirOriginal\setup`"") + (Get-Content "$Using:RunLocation\Launcher.ps1") | Set-Content "$Using:RunLocation\Launcher.ps1"
    @("Set-Location `"$Using:DestinationDirOriginal\setup`"") + (Get-Content "$Using:RunLocation\Setup.ps1") | Set-Content "$Using:RunLocation\Setup.ps1"
    @("Set-Location `"$Using:DestinationDirOriginal\setup`"") + (Get-Content "$Using:RunLocation\bin\cleanup.ps1") | Set-Content "$Using:RunLocation\bin\cleanup.ps1"
    @("Set-Location `"$Using:DestinationDirOriginal\setup`"") + (Get-Content "$Using:RunLocation\bin\NvidiaPerformance.ps1") | Set-Content "$Using:RunLocation\bin\NvidiaPerformance.ps1"
  }

  $AddInstallAccounttoAdmin = {
    $AdminGroupMembership = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -Match "$Using:username" }
    if ($Null -eq $AdminGroupMembership) {
      Add-LocalGroupMember -Group "Administrators" -Member $Using:UsernameFQDN
    }
  }

  if ($null -ne $DistributionCreds) {
    Invoke-Command -ComputerName $machine -ScriptBlock $AdjustConfigFile -Credential $DistributionCreds
    Invoke-Command -ComputerName $machine -ScriptBlock $AddInstallAccounttoAdmin -Credential $DistributionCreds
  }
  else {
    Invoke-Command -ComputerName $machine -ScriptBlock $AdjustConfigFile
  }

  $EnableAutoLogon = {
    #write-host "Start-Process Powershell -ArgumentList -file $Using:DestinationDirOriginal\setup\bin\AutologinReg.ps1"
    & powershell.exe -file "$Using:DestinationDirOriginal\setup\bin\AutologinReg.ps1"
  } 
      
  $EncryptedLogin = {
    $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $Using:DestinationDirOriginal\setup\Setup.ps1"
    Write-Host "Finished setting Remote Machine: $Using:machine for Install." -ForegroundColor Green
    #Write-Host "Restarting Machine" -ForegroundColor Green
    #Restart-Computer -ComputerName $Using:machine -Force
  }

  $PSRemoting = Test-WSMan -ComputerName $machine -ErrorAction SilentlyContinue

  if ($PSRemoting -ne $null) {

    Write-Host "Securely enabling Auto Logon Remotely" -ForegroundColor Green

    if ($null -ne $DistributionCreds) {
      Invoke-command -ComputerName $Machine -ScriptBlock $CredsToReg -Credential $DistributionCreds
    }
    else {
      Invoke-command -ComputerName $Machine -ScriptBlock $CredsToReg
    }

    if ($null -ne $DistributionCreds) {
      $RemoteSession = New-PSSession -ComputerName $Machine -Credential $DistributionCreds
    }
    else {
      $RemoteSession = New-PSSession -ComputerName $Machine
    }

    if ($null -ne $DistributionCreds) {
      Invoke-command -session $RemoteSession -ScriptBlock $EnableAutoLogon #-credential $DistributionCreds
      #start-sleep -Seconds 3
      $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select AutoAdminLogon }
      if ($checkLogin.AutoAdminLogon -eq "0") {
        write-host "Failed to enable Auto Logon on $machine, trying again" -ForegroundColor Yellow
        Invoke-command -session $RemoteSession -ScriptBlock $EnableAutoLogon # -Credential $DistributionCreds
        #start-sleep -Seconds 2
        $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select AutoAdminLogon }
        if ($checkLogin.AutoAdminLogon -eq "0") {
          Write-Host "Failed to enable Auto Logon on $machine. Please Login Manually to start script" -ForegroundColor Red  
        }
      }
      Invoke-Command -session $RemoteSession -ScriptBlock $EncryptedLogin # -Credential $DistributionCreds
    }
    else {
      Invoke-command -session $RemoteSession -ScriptBlock $EnableAutoLogon
      start-sleep -Seconds 1
      $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select AutoAdminLogon }
      if ($checkLogin.AutoAdminLogon -eq "0") {
        write-host "Failed to enable Auto Logon on $machine, trying again" -ForegroundColor Yellow
        Invoke-command -session $RemoteSession -ScriptBlock $EnableAutoLogon
        #start-sleep -Seconds 1
        $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select AutoAdminLogon }
        if ($checkLogin.AutoAdminLogon -eq "0") {
          Write-Host "Failed to enable Auto Logon on $machine. Please Login Manually to start script" -ForegroundColor Red  
        }
      }
      Invoke-Command -session $RemoteSession -ScriptBlock $EncryptedLogin
    }
    Remove-PSSession $RemoteSession
  }
  else {
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $TempPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    if ($Domain -match '`.' -or $Domain -match 'localhost') {
      $Domain = $Machine
    }
    $ClearLogin = {
      $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
      Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $Using:DestinationDirOriginal\setup\Setup.ps1"
      $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
      Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String 
      Set-ItemProperty $RegPath "DefaultUsername" -Value "$Using:Username" -type String 
      Set-ItemProperty $RegPath "DefaultPassword" -Value "$Using:TempPassword" -type String
      Set-ItemProperty $RegPath "DefaultDomainName" -Value "$Using:Domain" -type String  
      Set-ItemProperty $RegPath "AutoLogonCount" -Value "1" -type String
      $message = "This Machine is going to restart!"
      Invoke-WmiMethod -Class win32_process -ComputerName $Using:Machine -Name create -ArgumentList  "c:\windows\system32\msg.exe * $message" | Out-Null

      Write-Host "Finished setting Remote Machine: $Using:machine for Install." -ForegroundColor Green
      #Write-Host "Restarting Machine" -ForegroundColor Green

      #Restart-Computer -ComputerName $Using:machine -Force
    }
    write-host "Falling back on Clear Text Login and restarting" -ForegroundColor Yellow
      
    if ($null -ne $DistributionCreds) {
      Invoke-Command -ComputerName $machine -ScriptBlock $ClearLogin -Credential $DistributionCreds
    }
    else {
      Invoke-Command -ComputerName $machine -ScriptBlock $ClearLogin
    }
  }


}
#>
#_______________________________________________________________________________________________________________________________

#New Multi-Threaded Code
$JobResults = @()
$ScriptBlocks = @{}

# Define reusable script blocks
$ScriptBlocks['CredsToReg'] = {
  param($Domain, $Machine, $Encrypted, $Username)
  $path = "HKLM:\SOFTWARE\MachineSetup"
  $CleanDomain = $Domain
  if ($CleanDomain -match '\.' -or $CleanDomain -match 'localhost') {
    $CleanDomain = $Machine
  }
  if (!(Test-Path $path)) { mkdir $path | Out-Null }
  Set-ItemProperty $path "Password" -Value $Encrypted -Force
  Set-ItemProperty $path "UserName" -Value $Username -Force
  Set-ItemProperty $path "Domain" -Value $CleanDomain -Force
}

$ScriptBlocks['AdjustConfigFile'] = {
  param($DestinationDirOriginal, $RunLocation)
  Write-Host "Copy to Machine $Using:Machine Completed" -ForegroundColor Green
  Write-Host "Adjusting Configuration Files on $Using:Machine" -ForegroundColor Green
  @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\Launcher.ps1") | Set-Content "$RunLocation\Launcher.ps1"
  @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\Setup.ps1") | Set-Content "$RunLocation\Setup.ps1"
  @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\bin\cleanup.ps1") | Set-Content "$RunLocation\bin\cleanup.ps1"
  @("Set-Location `"$DestinationDirOriginal\setup`"") + (Get-Content "$RunLocation\bin\NvidiaPerformance.ps1") | Set-Content "$RunLocation\bin\NvidiaPerformance.ps1"
}

$ScriptBlocks['AddInstallAccountToAdmin'] = {
  param($Username, $UsernameFQDN)
  $AdminGroupMembership = Get-LocalGroupMember -Group "Administrators" | Where-Object { $_.Name -Match $Username }
  if ($Null -eq $AdminGroupMembership) {
    Add-LocalGroupMember -Group "Administrators" -Member $UsernameFQDN
  }
}

$ScriptBlocks['EnableAutoLogon'] = {
  param($DestinationDirOriginal)
  & powershell.exe -file "$DestinationDirOriginal\setup\bin\AutologinReg.ps1"
}

$ScriptBlocks['EncryptedLogin'] = {
  param($Machine, $DestinationDirOriginal)
  $RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  Set-ItemProperty $RunOnceKey "NextRun" "C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -ExecutionPolicy Unrestricted -File $DestinationDirOriginal\setup\Setup.ps1"
  Write-Host "Finished setting Remote Machine: $Machine for Install." -ForegroundColor Green
}

$ScriptBlocks['ClearLogin'] = {
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
}

# Launch parallel jobs
foreach ($Machine in $MachineList) {
  $JobResults += Start-Job -Name "Setup_$Machine" -ScriptBlock {
    param($Machine, $ScriptBlocks, $Domain, $Username, $Encrypted, $DestinationDirOriginal, $RunLocation, $UsernameFQDN, $DistributionCreds)

    # Reuse script blocks inside the job
    if ($null -ne $DistributionCreds) {
      Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['AdjustConfigFile'] -Credential $DistributionCreds -ArgumentList $DestinationDirOriginal, $RunLocation
      Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['AddInstallAccountToAdmin'] -Credential $DistributionCreds -ArgumentList $Username, $UsernameFQDN
    }
    else {
      Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['AdjustConfigFile'] -ArgumentList $DestinationDirOriginal, $RunLocation
    }

    $PSRemoting = Test-WSMan -ComputerName $Machine -ErrorAction SilentlyContinue
    if ($PSRemoting -ne $null) {
      Write-Host "Securely enabling Auto Logon Remotely" -ForegroundColor Green
      if ($null -ne $DistributionCreds) {
        Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['CredsToReg'] -Credential $DistributionCreds -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }
      else {
        Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['CredsToReg'] -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }
      Write-Host "Securely enabling Auto Logon Remotely" -ForegroundColor Green

      if ($null -ne $DistributionCreds) {
        Invoke-command -ComputerName $Machine -ScriptBlock $ScriptBlocks['CredsToReg'] -Credential $DistributionCreds -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }
      else {
        Invoke-command -ComputerName $Machine -ScriptBlock $ScriptBlocks['CredsToReg'] -ArgumentList $Domain, $Machine, $Encrypted, $Username
      }

      if ($null -ne $DistributionCreds) {
        $RemoteSession = New-PSSession -ComputerName $Machine -Credential $DistributionCreds
      }
      else {
        $RemoteSession = New-PSSession -ComputerName $Machine
      }

      if ($null -ne $DistributionCreds) {
        Invoke-command -session $RemoteSession -ScriptBlock $ScriptBlocks['EnableAutoLogon'] -ArgumentList $DestinationDirOriginal  #-credential $DistributionCreds
        #start-sleep -Seconds 3
        $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select-object AutoAdminLogon }
        if ($checkLogin.AutoAdminLogon -eq "0") {
          write-host "Failed to enable Auto Logon on $machine, trying again" -ForegroundColor Yellow
          Invoke-command -session $RemoteSession -ScriptBlock $ScriptBlocks['EnableAutoLogon'] -ArgumentList $DestinationDirOriginal # -Credential $DistributionCreds
          #start-sleep -Seconds 2
          $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select-object AutoAdminLogon }
          if ($checkLogin.AutoAdminLogon -eq "0") {
            Write-Host "Failed to enable Auto Logon on $machine. Please Login Manually to start script" -ForegroundColor Red  
          }
        }
        Invoke-Command -session $RemoteSession -ScriptBlock $ScriptBlocks['EncryptedLogin'] -ArgumentList $Machine, $DestinationDirOriginal # -Credential $DistributionCreds
      }
      else {
        Invoke-command -session $RemoteSession -ScriptBlock $ScriptBlocks['EnableAutoLogon'] -ArgumentList $DestinationDirOriginal
        start-sleep -Seconds 1
        $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select-object AutoAdminLogon }
        if ($checkLogin.AutoAdminLogon -eq "0") {
          write-host "Failed to enable Auto Logon on $machine, trying again" -ForegroundColor Yellow
          Invoke-command -session $RemoteSession -ScriptBlock $ScriptBlocks['EnableAutoLogon'] -ArgumentList $DestinationDirOriginal
          #start-sleep -Seconds 1
          $checkLogin = Invoke-Command -ComputerName $machine { Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name AutoAdminLogon | select-object AutoAdminLogon }
          if ($checkLogin.AutoAdminLogon -eq "0") {
            Write-Host "Failed to enable Auto Logon on $machine. Please Login Manually to start script" -ForegroundColor Red  
          }
        }
        Invoke-Command -session $RemoteSession -ScriptBlock $ScriptBlocks['EncryptedLogin'] -ArgumentList $Machine, $DestinationDirOriginal
      }
      Remove-PSSession $RemoteSession
            
    }
    else {
      Write-Host "Falling back on Clear Text Login and restarting" -ForegroundColor Yellow
      # Call ClearLogin with necessary parameters
      $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
      $TempPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

      if ($Domain -match '`.' -or $Domain -match 'localhost') {
        $Domain = $Machine
      }
      if ($null -ne $DistributionCreds) {
        Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['ClearLogin'] -Credential $DistributionCreds -ArgumentList $Machine, $Domain, $Username, $TempPassword, $DestinationDirOriginal
      }
      else {
        Invoke-Command -ComputerName $Machine -ScriptBlock $ScriptBlocks['ClearLogin'] -ArgumentList $Machine, $Domain, $Username, $TempPassword, $DestinationDirOriginal
      }
    }
  } -ArgumentList $Machine, $ScriptBlocks, $Domain, $Username, $Encrypted, $DestinationDirOriginal, $RunLocation, $UsernameFQDN, $DistributionCreds
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

<#
Function Register-Watcher {
  param ($folder,
    $FileName
  )

  $filter = "$FileName" #all files
  $watcher = New-Object IO.FileSystemWatcher $folder, $filter -Property @{ 
    IncludeSubdirectories = $false
    EnableRaisingEvents   = $true
  }

  $changeAction = [scriptblock]::Create('
      # This is the code which will be executed every time a file change is detected
      $path = $Event.SourceEventArgs.FullPath
      $ParentPath = split-path -path $path -parent

      $content = Get-Content -Path $path -Tail 1 | ConvertFrom-Json

      $LogObject = [PSCustomObject]@{
      Timestamp = $content.Timestamp
      Hostname  = $content.Hostname
      Severity  = $content.Severity
      Message   = $content.message
      }
        if($LogObject.Severity -match "Info"){
          $Color = "White"
        }
        elseif ($LogObject.Severity -match "Warn") {
          $Color = "Yellow"
        }
        elseif ($LogObject.Severity -match "Error") {
          $Color = "Red"
        }
        elseif ($LogObject.Severity -match "Start") {
          $Color = "Green"
        }
        elseif ($LogObject.Severity -match "End") {
          $Color = "Blue"
        }
      $WarningsErrors = $logObject | Where-Object { $_.Severity -like "Error" -or $_.Severity -like "Warning"} | ConvertTo-Json -Compress | Out-File -FilePath $ParentPath\ErrorLog.json -Append -ErrorAction SilentlyContinue
      Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)" -ForegroundColor $Color
  ')

  Register-ObjectEvent $Watcher -EventName "Changed" -Action $changeAction | out-null
}
#>
function Register-Watcher {
  param ($folder,
    $FileName
  )
  try {
    # Create log directory if it doesn't exist
    $logDir = $folder
    if (-not (Test-Path $logDir)) {
      New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $logFile = Join-Path -Path $logDir -ChildPath $FileName
    # Initialize the last position to the current file size if the file exists
    if (Test-Path $logFile) {
      $lastLogPosition = (Get-Item $logFile).Length
    }
    else {
      $lastLogPosition = 0
    }

    # Create a dispatcher timer
    $logCheckTimer = New-Object System.Windows.Threading.DispatcherTimer
    $logCheckTimer.Interval = [TimeSpan]::FromMilliseconds(500)
        
    $logCheckTimer.Add_Tick({
        try {
          if (Test-Path $logFile) {
            $currentFileSize = (Get-Item $logFile).Length
                    
            # Only read if there's new content
            if ($currentFileSize -gt $lastLogPosition) {
              $fileStream = [System.IO.File]::Open($logFile, 'Open', 'Read', 'ReadWrite')
              $streamReader = New-Object System.IO.StreamReader($fileStream)
                        
              # Skip to last position
              if ($lastLogPosition -gt 0) {
                $streamReader.BaseStream.Position = $lastLogPosition
              }
                        
              # Read only new content
              $newContent = $streamReader.ReadToEnd()
                        
              # Update position
              $lastLogPosition = $fileStream.Position
                        
              # Close readers
              $streamReader.Close()
              $fileStream.Close()
                        
              # Update UI if we have new content
              if ($newContent) {
                $LogObject = [PSCustomObject]@{
                  Timestamp = $newContent.Timestamp
                  Hostname  = $newContent.Hostname
                  Severity  = $newContent.Severity
                  Message   = $newContent.message
                }
                if ($LogObject.Severity -match "Info") {
                  $Color = "White"
                }
                elseif ($LogObject.Severity -match "Warn") {
                  $Color = "Yellow"
                }
                elseif ($LogObject.Severity -match "Error") {
                  $Color = "Red"
                }
                elseif ($LogObject.Severity -match "Start") {
                  $Color = "Green"
                }
                elseif ($LogObject.Severity -match "End") {
                  $Color = "Blue"
                }
                $WarningsErrors = $logObject | Where-Object { $_.Severity -like "Error" -or $_.Severity -like "Warning" } | ConvertTo-Json -Compress | Out-File -FilePath $ParentPath\ErrorLog.json -Append -ErrorAction SilentlyContinue
                Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)" -ForegroundColor $Color
              }
            }
          }
        }
        catch {
          $errorMsg = "Error reading log file: $_"
          Write-Host $errorMsg
          Add-Content -Path "$logDir\error.log" -Value "$(Get-Date): $errorMsg"
        }
      })
        
    # Start the timer
    $logCheckTimer.Start()
    Write-Host "Log monitoring initialized for: $logFile"
  }
  catch {
    $errorMsg = "Error initializing log monitoring: $_"
    Write-Host $errorMsg
    Add-Content -Path "$logDir\error.log" -Value "$(Get-Date): $errorMsg"
  }
}

$logDirectory = "$remoteRunLocation\Logs"
$LogArray = @()
$CheckIn = @()

Start-Process powershell -ArgumentList "-noexit", "-noprofile", "-file $RunLocation\bin\ErrorLogReader.ps1"

try {
  $timeout = new-timespan -Minutes 3
  $CheckInPeriod = [diagnostics.stopwatch]::StartNew()
  While ($True) {

    $Logfiles = Get-ChildItem -Path $logDirectory -Filter "*MachineSetup.json"

    ForEach ($LogFile in $Logfiles) {

      $FileName = $LogFile.Name
      $ShortName = $FileName -split "-"
      if ($checkin -notcontains $ShortName[0]) {
        $CheckIn += $ShortName[0]
      }

      $LogName = Join-Path "$logDirectory" "$FileName"

      if ($LogArray -notcontains $Logname) {

        Register-Watcher -folder $logDirectory -filename "$FileName" | out-null

        $logArray += $LogName

      }
    }

    if ($CheckInPeriod.elapsed -ge $timeout) {
      $NotCheckedInMachines = Compare-Object -ReferenceObject ($NewMachineList) -DifferenceObject ($CheckIn) -PassThru
      forEach ($NotCheckedInMachine in $NotCheckedInMachines) {
        if ($NotCheckedInMachine -ne "") {
          $ErrorObject = [PSCustomObject]@{
            Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
            Hostname  = $env:computername
            Severity  = "Warning"
            Message   = "Host: $NotCheckedInMachine has not checked in"
          }

          $Color = "Yellow"

          $ErrorObject | ConvertTo-Json -Compress | Out-File -FilePath "$logDirectory\ErrorLog.json" -Append
          Write-Host "$($ErrorObject.Timestamp) $($ErrorObject.Hostname) Severity=$($ErrorObject.Severity) Message=$($ErrorObject.Message)" -ForegroundColor $Color
        }
      }
      $FinishedMachinesFile = "$RunLocation\Logs\CompletedMachines.txt"
      if (Test-path $FinishedMachinesFile) {
        
        $FinishedMachines = Get-Content $FinishedMachinesFile
        $CompletedMachines = Compare-Object -ReferenceObject ($NewMachineList) -DifferenceObject ($FinishedMachines) -PassThru
        if ($Null -eq $CompletedMachines) {
          Write-Host "All Machines have checked in" -ForegroundColor Green
          Write-Host "Starting Inventory Collection" -ForegroundColor Green
          & $RunLocation\bin\RemoteInventory.ps1 -wait
          $DeploymentTimeMin = $DeploymentTime.Elapsed.Minutes
          $DeploymentTimeSec = $DeploymentTime.Elapsed.Seconds
          $message = "Setup Has Completed on All Machines. Time to complete: $DeploymentTimeMin Minutes $DeploymentTimeSec Seconds."
          Invoke-WmiMethod -Class win32_process -Name create -ArgumentList  "c:\windows\system32\msg.exe * $message" | Out-Null
          Break
        }

        
      } 
      $CheckInPeriod.Restart() 
    }
  }
}
finally {
  # release the watcher and free its memory:
  $DeploymentTime.Stop()
  $DeploymentTimeMin = $DeploymentTime.Elapsed.Minutes
  $DeploymentTimeSec = $DeploymentTime.Elapsed.Seconds
  Write-Host "Deployment ran for: $DeploymentTimeMin Minutes $DeploymentTimeSec Seconds" -ForegroundColor Yellow
  Get-EventSubscriber | Unregister-Event
  Write-Warning 'FileSystemWatcher for log file removed.'
}
