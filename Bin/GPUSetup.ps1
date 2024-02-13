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
        if(!(Test-Path -Path $RemotelogDirectory)) {
            New-Item -Path $RemotelogDirectory -ItemType Directory | Out-Null
        }
        $RemotelogFilePath = Join-Path "$RemotelogDirectory" "$($LogObject.Hostname)-MachineSetup.json"
        $LogObject | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append
    }
    
    Write-Host "$($LogObject.Timestamp) $($LogObject.Hostname) Severity=$($LogObject.Severity) Message=$($LogObject.Message)"
    #if ($Severity -eq "Error") {throw $LastException}
}

function Set-WindowState {
param(
    [Parameter()]
    [ValidateSet('FORCEMINIMIZE', 'HIDE', 'MAXIMIZE', 'MINIMIZE', 'RESTORE', 
                 'SHOW', 'SHOWDEFAULT', 'SHOWMAXIMIZED', 'SHOWMINIMIZED', 
                 'SHOWMINNOACTIVE', 'SHOWNA', 'SHOWNOACTIVATE', 'SHOWNORMAL')]
    [Alias('Style')]
    [String] $State = 'SHOW',
    
    [Parameter(ValueFromPipelineByPropertyname='True')]
    [System.IntPtr] $MainWindowHandle = (Get-Process –id $pid).MainWindowHandle,

    [Parameter()]
    [switch] $PassThru

)
BEGIN
{

$WindowStates = @{
    'FORCEMINIMIZE'   = 11
    'HIDE'            = 0
    'MAXIMIZE'        = 3
    'MINIMIZE'        = 6
    'RESTORE'         = 9
    'SHOW'            = 5
    'SHOWDEFAULT'     = 10
    'SHOWMAXIMIZED'   = 3
    'SHOWMINIMIZED'   = 2
    'SHOWMINNOACTIVE' = 7
    'SHOWNA'          = 8
    'SHOWNOACTIVATE'  = 4
    'SHOWNORMAL'      = 1
}
    
$Win32ShowWindowAsync = Add-Type –memberDefinition @” 
[DllImport("user32.dll")] 
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow); 
“@ -name “Win32ShowWindowAsync” -namespace Win32Functions –passThru

}
PROCESS
{
    $Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates[$State]) | Out-Null
    Write-Verbose ("Set Window State on '{0}' to '{1}' " -f $MainWindowHandle, $State)

    if ($PassThru)
    {
        Write-Output $MainWindowHandle
    }

}
END
{
}

}

Set-Alias -Name 'Set-WindowStyle' -Value 'Set-WindowState'

Function Format-XMLText {
    Param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [xml[]]
        $xmlText
    )
    Process {
        # Use a StringWriter, an XMLWriter and an XMLWriterSettings to format XML
        $stringWriter = New-Object System.IO.StringWriter
        $stringWriterSettings = New-Object System.Xml.XmlWriterSettings
 
        # Turn on indentation
        $stringWriterSettings.Indent = $true
 
        # Turn off XML declaration
        #$stringWriterSettings.OmitXmlDeclaration = $true
 
        # Create the XMLWriter from the StringWriter
        $xmlWriter = [System.Xml.XmlWriter]::Create($stringWriter,$stringWriterSettings)
 
        # Write the XML using the XMLWriter
        $xmlText.WriteContentTo($xmlWriter)
 
        # Don't forget to flush!
        $xmlWriter.Flush()
        $stringWriter.Flush()
 
        # Output the text
        $stringWriter.ToString()
        # This works in a remote session, when [Console]::Out doesn't
        }
    }

    $GPUInstalled = ((Get-WmiObject Win32_VideoController) | where-object {$_.Name -match "NVIDIA"}).Name
    
    if($Null -ne $GPUInstalled){

    if((Get-ItemPropertyValue -LiteralPath 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release) -ge 528040){

    if(Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"){
        $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
    }
    elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
        $NVSMILocation = "C:\Windows\System32"
    }

    [xml]$NvidiaQuery = & "$NVSMILocation\nvidia-smi.exe" -q -x

    $AllGPUs = $NvidiaQuery.SelectNodes("/nvidia_smi_log/gpu")


    $WorkingDir = "C:\Temp"
    if(!(Test-Path -Path $WorkingDir)) {
            New-Item -Path $WorkingDir -ItemType Directory | Out-Null
        }

    $OpenGLFile = "C:\Temp\GPUConfig.nip"
    if(Test-Path -Path $OpenGLFile) {
        Remove-Item $OpenGLFile
    }
    $OpenGLOptions = "C:\TEMP\OpenGL.txt"
    if(Test-Path -Path $OpenGLOptions) {
        Remove-Item $OpenGLOptions
    }

    Start-Process "$RunLocation\Bin\nvidia\nvidiaProfileInspector.exe"

    start-sleep -seconds 3

    get-process -name "nvidiaProfileInspector" | Set-WindowState -State HIDE

    While (!(Test-Path $OpenGLOptions -ErrorAction SilentlyContinue))
{
  # endless loop, when the file will be there, it will continue
}

start-sleep -Seconds 5

Get-Process -Name nvidiaProfileInspector | Stop-process



$Content = Get-Content $OpenGLOptions
$GPUs = $Content | Where-Object {$_ -match 'id,2.0:\w*,\w*,\w\w\W-\W\W\d*,\d,\d*,\d*\W\W*\d\W'} | Sort-Object | Get-Unique

$GPUObjects=@()

foreach($GPU in $GPUs){

$GPUmemory = $GPU -split ','
$GPUmemory = $GPUmemory[-1]
$GPUmemory = $GPUmemory -replace '\D'
#$GPUmemory = $GPUmemory[0]

$GPUmemory = $GPUmemory.Substring(0, $GPUmemory.Length - 1)
#$GPUmemory

$GPUObjects += [PSCustomObject]@{
    Memory = $GPUmemory
    String = $GPU
    }

#$GPUObjects =+ $GPUObject

}

$RenderGPU = $GPUObjects | Sort-Object -Property Memory -Descending | Select-Object -First 1

$RenderGPU = $RenderGPU.string

$GPUConfig = @"
<?xml version="1.0" encoding="utf-16"?>
<ArrayOfProfile>
  <Profile>
    <ProfileName>Base Profile</ProfileName>
    <Executeables />
    <Settings>
      <ProfileSetting>
        <SettingNameInfo>Power management mode</SettingNameInfo>
        <SettingID>274197361</SettingID>
        <SettingValue>1</SettingValue>
        <ValueType>Dword</ValueType>
      </ProfileSetting>
      <ProfileSetting>
        <SettingNameInfo>Preferred OpenGL GPU</SettingNameInfo>
        <SettingID>550564838</SettingID>
        <SettingValue>$RenderGPU</SettingValue>
        <ValueType>String</ValueType>
      </ProfileSetting>
    </Settings>
  </Profile>
</ArrayOfProfile>
"@

$xml = [xml]$GPUConfig

$xml = $xml.OuterXml
$xml = $xml | Format-XMLText

$MyPath = "C:\temp\GPUConfig.nip"
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $True
[System.IO.File]::WriteAllLines($MyPath, $xml, $Utf8NoBomEncoding)

$RenderGPUid = $RenderGPU.split(',')[2]

    Foreach($GPU in $AllGPUs){
        $GUID = $GPU.id
        $GUID = ($GUID.Split('.')[0] -replace '\D').substring(4)
            if($GUID -eq $RenderGPUid){
            $GPUName = $GPU.product_name
            Write-PSULog -Severity Info -Message "Setting OpenGL Render card to $GPUName"
            }

        }



    if(Test-Path -Path $OpenGLOptions) {
        Remove-Item $OpenGLOptions
    }

Write-PSULog -Severity Info -Message "Setting Nvidia Power Managment Mode to Prefer Maximum Performance"
Start-Process "$RunLocation\Bin\nvidia\nvidiaProfileInspector.exe" -ArgumentList "-silentImport $MyPath" -wait


Remove-Item $OpenGLFile -ErrorAction SilentlyContinue
Remove-Item $MyPath -ErrorAction SilentlyContinue

}
else{
Write-PSULog -Severity Warn -Message ".net 4.8 not detected Machine may need a reboot"
}
}
else{
Write-PSULog -Severity Warn -Message "Nvidia GPU not detected. Skipping card optimization."
}