#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
cd ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
#----------------------------------------------------------------------------------------------
if([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True){

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}else{
$null = $RemoteLogLocation
}

function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory="$RunLocation\Logs\",
        $RemotelogDirectory=$RemoteLogLocation
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
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}
#-------------------------------------------------------------------------------------------------------------


# Download and silent install Java Runtime Environnement

# working directory path
$WorkingDirectory = "$RunLocation\bin\java\"

# Check if work directory exists if not create it
If (!(Test-Path -Path $WorkingDirectory -PathType Container))
{ 
    Write-PSULog -Severity Info -Message "Creating working directory at $WorkingDirectory"
    New-Item -Path $WorkingDirectory  -ItemType directory 
}

#create config file for silent install
$text = '
INSTALL_SILENT=Enable
AUTO_UPDATE=Enable
SPONSORS=Disable
REMOVEOUTOFDATEJRES=1
'
$text | Set-Content "$WorkingDirectory\jreinstall.cfg"
    
#download executable, this is the small online installer
[Net.ServicePointManager]::SecurityProtocol = "tls12"
$source = "http://javadl.oracle.com/webapps/download/AutoDL?BundleId=230511_2f38c3b165be4555a1fa6e98c45e0808"
$destination = "$WorkingDirectory\jreInstall.exe"
Write-PSULog -Severity Info -Message "Downloading JRE"
$client = New-Object System.Net.WebClient
$client.DownloadFile($source, $destination)

#install silently
Write-PSULog -Severity Info -Message "Installing JRE from $WorkingDirectory\jreInstall.exe"
Start-Process -FilePath "$WorkingDirectory\jreInstall.exe" -ArgumentList INSTALLCFG="$WorkingDirectory\jreinstall.cfg" -Wait

# Remove the installer
Write-PSULog -Severity Info -Message "Cleaning up JRE Install Folder"
Remove-Item $WorkingDirectory\jre* -Force