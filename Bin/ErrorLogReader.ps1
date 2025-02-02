<#
.SYNOPSIS
    This script reads and monitors the error log for changes.

.DESCRIPTION
    The script sets up a file system watcher to monitor the error log file for changes.
    It reads the latest log entry and displays it with appropriate color coding based on severity.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\ErrorLogReader.ps1
    Runs the script to monitor and display changes in the error log file.

.NOTES
    Author: John Burriss
    Created: 8/26/2023
    Modified: 8/26/2023
    Version: 0.01
    Requires: PowerShell 5.1 or higher, Administrator privileges

#Requires -RunAsAdministrator
#>

#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

Clear-Host

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
Set-Location ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path
$remoteRunLocation = $RunLocation -replace ":", "$"
$remoteRunLocation = Join-Path "\\$env:computername" "$remoteRunLocation"
$Settings = Get-Content "$RunLocation\setup.json" | ConvertFrom-Json -ErrorAction Stop
Write-Host "Error Log Read Out" -ForegroundColor Green
if ("" -eq $Settings.GENERAL.REMOTELOGGINGLOCATION) {

  $Settings.GENERAL.REMOTELOGGINGLOCATION = "$remoteRunLocation\Logs"
  $settings | ConvertTo-Json | out-file "$RunLocation\Setup.json"
}

$ErrorLogPath = $Settings.GENERAL.REMOTELOGGINGLOCATION
$ErrorLogFile = "ErrorLog.json"
#$Path = Join-Path -Path $ErrorLogPath -ChildPath $ErrorLogFile
#New-Item -ItemType File -Path $Path

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
      #$WarningsErrors = $logObject | Where-Object { $_.Severity -like "Error" -or $_.Severity -like "Warning"} | ConvertTo-Json -Compress | Out-File -FilePath $ParentPath\ErrorLog.json -Append -ErrorAction SilentlyContinue
      Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)" -ForegroundColor $Color
  ')
  Register-ObjectEvent $Watcher -EventName "Changed" -Action $changeAction
}

try {
  Register-Watcher -folder $ErrorLogPath -filename $ErrorLogFile | out-null
  while ($true) {}
}
finally {
  Get-EventSubscriber | Unregister-Event
  Write-Warning 'FileSystemWatcher removed.'
}