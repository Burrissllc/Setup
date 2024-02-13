#------------------------------------------------------
# Name:        CitrixInstall
# Purpose:     Installs Citrix VDA
# Author:      John Burriss
# Created:     1/6/2020  9:49 PM 
#------------------------------------------------------

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition
set-location $RunLocation
cd ..
$RunLocation = get-location
$RunLocation = $RunLocation.Path

$Settings = Get-Content "$RunLocation\Setup.json" | ConvertFrom-Json
if([string]::IsNullOrEmpty($Settings.GENERAL.REMOTELOGGINGLOCATION) -ne $True){

    $RemoteLogLocation = $Settings.GENERAL.REMOTELOGGINGLOCATION 
}else{
$null = $RemoteLogLocation
}
#----------------------------------------------------------------------------------------------
function Write-PSULog {
    param(
        [ValidateSet('Info', 'Warn', 'Error', 'Start', 'End', IgnoreCase = $false)]
        [string]$Severity = "Info",
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$logDirectory="$RunLocation\Logs\",
        [string]$RemotelogDirectory="$RemoteLogLocation"
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

try{
Import-Module sqlps

$INSTANCENAME= $settings.SQL.INSTANCENAME

if(!([string]::IsNullOrEmpty($INSTANCENAME))){
$Server = "$env:COMPUTERNAME\$INSTANCENAME"
}
else{
$Server = "$env:COMPUTERNAME"
}

$SMOServer = New-Object Microsoft.SQLServer.Management.SMO.Server $Server
$HostsConnected = $True
While($HostsConnected -eq $True){

# connection and query stuff        
	$ConnectionStr = "Server=$Server;Database=Master;Integrated Security=True"
	$Query = "EXEC sp_who2"
 
	$Connection = new-object system.Data.SQLClient.SQLConnection
	$Table = new-object "System.Data.DataTable"
 
	$Connection.connectionstring = $ConnectionStr
	try{
		$Connection.open()
		$Command = $Connection.CreateCommand()
		$Command.commandtext = $Query
 
		$result = $Command.ExecuteReader()
 
		$Table.Load($result)
	}
	catch{
# Show error
		Write-PSULog -Severity Error -Message $error[0]
	}
#$Title = "Data access processes (" + $Table.Rows.Count + ")"
#$Table | Out-GridView -Title $Title
$Hosts = $Table.hostname


$MachineList = Get-Content "$RunLocation\RemoteMachines.txt"
$HostsConnected = $False
foreach($Machine in $MachineList){

if($hosts -contains $Machine | Where-Object {$_ -ne $env:COMPUTERNAME} -eq "True"){
$HostsConnected = $True
}
else{
$HostsConnected = $False
}

}
start-sleep -Seconds 2
}
$Connection.close()
return $true
}
Catch{

Write-PSULog -Severity Error -Message "$_"

}