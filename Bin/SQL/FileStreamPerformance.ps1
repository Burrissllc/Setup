#------------------------------------------------------
# Name:        FileStreamPerformance
# Purpose:     Checks FileStream Settings for best performance and runs Fixes
# Author:      John Burriss
# Created:     11/14/2019  11:24 AM 
#------------------------------------------------------
#Requires -RunAsAdministrator



Param(
[Parameter()]
$FileStreamDirectory,
[ValidateSet("fix")]
[String]
$FixProblems
)

function Invoke-ConsoleCommand
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The target of the action.
        $Target,

        [Parameter(Mandatory=$true)]
        [string]
        # The action/command being performed.
        $Action,

        [Parameter(Mandatory=$true)]
        [scriptblock]
        # The command to run.
        $ScriptBlock
    )

    Set-StrictMode -Version 'Latest'

    Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

    if( -not $PSCmdlet.ShouldProcess( $Target, $Action ) )
    {
        return
    }

    $output = Invoke-Command -ScriptBlock $ScriptBlock
    if( $LASTEXITCODE )
    {
        $output = $output -join [Environment]::NewLine
        Write-Error ('Failed action ''{0}'' on target ''{1}'' (exit code {2}): {3}' -f $Action,$Target,$LASTEXITCODE,$output)
    }
    else
    {
        $output | Where-Object { $_ -ne $null } | Write-Verbose
    }
}
function Disable-NtfsCompression
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string[]]
        [Alias('FullName')]
        # The path where compression should be disabled.
        $Path,

        [Switch]
        # Disables compression on all sub-directories.
        $Recurse
    )

    begin
    {
        Set-StrictMode -Version 'Latest'

        Use-CallerPreference -Cmdlet $PSCmdlet -Session $ExecutionContext.SessionState

        $compactPath = Join-Path $env:SystemRoot 'system32\compact.exe'
        if( -not (Test-Path -Path $compactPath -PathType Leaf) )
        {
            if( (Get-Command -Name 'compact.exe' -ErrorAction SilentlyContinue) )
            {
                $compactPath = 'compact.exe'
            }
            else
            {
                Write-Error ("Compact command '{0}' not found." -f $compactPath)
                return
            }
        }
    }

    process
    {
        foreach( $item in $Path )
        {
            if( -not (Test-Path -Path $item) )
            {
                Write-Error -Message ('Path {0} not found.' -f $item) -Category ObjectNotFound
                return
            }

            $recurseArg = ''
            $pathArg = $item
            if( (Test-Path -Path $item -PathType Container) )
            {
                if( $Recurse )
                {
                    $recurseArg = ('/S:{0}' -f $item)
                    $pathArg = ''
                }
            }

            Invoke-ConsoleCommand -Target $item -Action 'disable NTFS compression' -ScriptBlock {
                & $compactPath /U $recurseArg $pathArg
            }
        }
    }
}

$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
#----------------------------------------------------------------------------------------------
if($Settings.GENERAL.REMOTELOGGINGLOCATION -ne $null){

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}

function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory="$RunLocation\Logs\",
        $RemotelogDirectory="$RemoteLogLocation"
        #[System.Management.Automation.ErrorRecord]$LastException = $_
    )
    $LogObject = [PSCustomObject]@{
        Timestamp = Get-Date -Format "dd-MM-yyyy HH:mm:ss"
        Hostname  = $env:computername
        Severity  = $Severity
        Message   = $Message
    }

    if(!(Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory | Out-Null
        }

    $logFilePath = Join-Path "$logDirectory" "MachineSetup.json"
    $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $logFilePath -Append
    if($RemotelogDirectory -ne $null){
        if(!(Test-Path -Path $RemotelogDirectory)) {
            New-Item -Path $RemotelogDirectory -ItemType Directory | Out-Null
        }
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}
#-------------------------------------------------------------------------------------------------------------

#$Path = "$RunLocation\FileStreamPerformance.log"

#if(!(Test-Path $Path)) { 
#    New-Item -ItemType File -Path "$RunLocation\Logs\FileStreamPerformance.log"
#}

#Start-Transcript -Path "$RunLocation\Logs\FileStreamPerformance.log" -Force

Write-PSULog -Severity Start -Message "Starting to Optimize FileStream"


$Null = $FixLastAccess
$Null = $Fix83naming
$Null = $FixDefender
$Null = $FixCompression
$Null = $FixEncryption
$FixStripeSize = 1

#Write-Host "Checking FileStream Performance" -ForegroundColor Green
Write-PSULog -Severity Info -Message "Checking FileStream Performance"
if($Null -eq $FileStreamDirectory){
$FileStreamDirectory = Read-Host "Enter the FileStream Directory"
}

$DefragDir = $FileStreamDirectory.Substring(0, $FileStreamDirectory.IndexOf('\'))

$Fltmc = C:\Windows\system32\fltMC.exe

$Fltmc 

#Write-Host "`n"


$NtfsDisableLastAccessUpdate = Get-ItemProperty -Path hklm:SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsDisableLastAccessUpdate" -ErrorAction SilentlyContinue
if($NtfsDisableLastAccessUpdate.NtfsDisableLastAccessUpdate -eq 1){
    #Write-host "last access time is Disabled" -ForegroundColor Green  
    Write-PSULog -Severity Info -Message "last access time is Disabled"
}
else{
    #Write-Host "last access time is enabled. Please Update Registry Key" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "last access time is enabled. Please Update Registry Key"
    $FixLastAccess = 1
}
$NtfsDisable8dot3NameCreation = Get-ItemProperty -Path hklm:SYSTEM\CurrentControlSet\Control\FileSystem -Name "NtfsDisable8dot3NameCreation" -ErrorAction SilentlyContinue
if($NtfsDisable8dot3NameCreation.NtfsDisable8dot3NameCreation -eq 1){
    #Write-host "8.3 naming is Disabled" -ForegroundColor Green 
    Write-PSULog -Severity Info -Message "8.3 naming is Disabled"
}
else {
    #Write-Host "8.3 naming is enabled. Please Update Registry Key" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "8.3 naming is enabled. Please Update Registry Key"
    $Fix83naming = 1
}

$IsEncrypted = Get-Item "$FileStreamDirectory" -Force -ErrorAction SilentlyContinue | Where-Object {$_.Attributes -ge "Encrypted"} | format-list fullname, attributes

if($Null -eq $IsEncrypted){
#Write-Host "FileStream directory is not encrypted" -ForegroundColor Green
Write-PSULog -Severity Info -Message "FileStream directory is not encrypted"
}
else{
    #Write-Host "FileStream Directory is encrypted $IsEncrypted" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "FileStream Directory is encrypted $IsEncrypted"
    $FixEncryption = 1
}

$Compressed = Get-WmiObject Win32_Volume -ComputerName "$env:COMPUTERNAME" | Select-Object name,label,filesystem,compressed
$Compressed = $Compressed | Where-Object {$_.name -eq "$DefragDir\"}
if($Compressed.compressed -match "False"){
    #Write-Host "Compression on FileStream Drive is Disabled" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "Compression on FileStream Drive is Disabled"
}
else{
    #Write-Host "Compression on FileStream Drive is Enabled" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "Compression on FileStream Drive is Enabled"
    $FixCompression = 1
}

$WDAVprefs = Get-MpPreference

if($WDAVprefs.ExclusionPath -contains "$FileStreamDirectory"){
    #Write-Host "FileStream is excluded from Windows Defender Scans" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "FileStream is excluded from Windows Defender Scans"
}
Else{
    #Write-Host "FileStream Directory is not excluded from Windows Defender Scans" -ForegroundColor Red
    Write-PSULog -Severity Error -Message "FileStream Directory is not excluded from Windows Defender Scans"
    $FixDefender = 1
}

$FileCountDirs =Get-Childitem -Recurse $FileStreamDirectory | Group-Object name | Select-Object count
$FileCount = 0
foreach($FileCountDir in $FileCountDirs){
$FileCount = $FileCountDir.count + $FileCount
}

if($Null -eq $FileCount){
    #Write-Host "FileStream Directory has 0 files" -ForegroundColor Green
    Write-PSULog -Severity Info -Message "FileStream Directory has 0 files"
}
elseif($FileCount -le 300000){
    #Write-Host "FileStream Directory has $FileCount files" -ForegroundColor Green 
    Write-PSULog -Severity Info -Message "FileStream Directory has $FileCount files"  
}
else{
    #Write-Host "FileStream Directory has $FileCount files. Please look into splitting into multiple directory's" -ForegroundColor Red
    Write-PSULog -Severity Warn -Message "FileStream Directory has $FileCount files. Please look into splitting into multiple directory's"
}

$wql = "SELECT Label, Blocksize, Name FROM Win32_Volume WHERE FileSystem='NTFS'"
Get-WmiObject -Query $wql -ComputerName '.' | Select-Object Label, Blocksize, Name | where-object Name -eq "$DefragDir"


$Defrag = defrag /A /V $DefragDir

$Defrag
if($Defrag  -match "Neither Slab Consolidation nor Slab Analysis will run if slabs are less than 8 MB"){
    $Null = $FixStripeSize
}
#Write-Host "`n"

$mftZone = fsutil behavior query mftZone

#Write-Host "MFTZone should = 2" -ForegroundColor Yellow
#$mftZone
Write-PSULog -Severity Info -Message "$mftZone"

$NumbefOfFixes = $FixLastAccess + $Fix83naming + $FixDefender + $FixCompression + $FixEncryption


if($NumbefOfFixes -ge 1){
    if($FixProblems -match "fix"){
        $FixFilestream = "y"
    }
    else{
        $FixFilestream = Read-Host "Would you like to automatically fix some errors (y/n)"
    }
if($FixFilestream -match "y"){

    Write-PSULog -Severity Info -Message "Starting FileStream Fixes"

    if($FixLastAccess -eq 1){
        fsutil behavior set disablelastaccess 1 | Out-Null
        #Write-Host "Disabled Last Access Time" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Disabled Last Access Time"
    }
    if($Fix83naming -eq 1){
        fsutil behavior set disable8dot3 1 | Out-Null
        #Write-Host "Disabled 8.3 Naming" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Disabled 8.3 Naming"
    }
    if($FixCompression -eq 1){
        Disable-NtfsCompression -Path $DefragDir\ -Recurse
        #Write-Host "Disabled Compression on FileStream Directory" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Disabled Compression on FileStream Directory"
    }
    if($FixEncryption -eq 1){
        cipher /d /s:$FileStreamDirectory
        #Write-Host "Disabled Encryption on FileStream Directory" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Disabled Encryption on FileStream Directory"
    }
    if($FixDefender -eq 1){
        Add-MpPreference -ExclusionPath $FileStreamDirectory
        #Write-Host "Added Windows Defender Exclusion to $FileStreamDirectory" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Added Windows Defender Exclusion to $FileStreamDirectory"
    }
    if($FixStripeSize -eq 1){
        $pattern = '[^a-zA-Z]'
        $DefragDir = $DefragDir -replace $pattern, ''
        Optimize-Volume -DriveLetter $DefragDir -Defrag -Verbose
        #Write-Host "Volume is now Defragged" -ForegroundColor Green
        Write-PSULog -Severity Info -Message "Volume is now Defragged"
    }

    #Write-Host "All Fixes have been applied. Please reboot the machine for them to take effect" -ForegroundColor Green
    Write-PSULog -Severity End -Message "All Fixes have been applied. Please reboot the machine for them to take effect"

    }
}

#Stop-Transcript



