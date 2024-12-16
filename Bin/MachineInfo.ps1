<#
.SYNOPSIS
    This script gathers machine information and makes an API request to Dell to get support information for the service tag.

.DESCRIPTION
    The script retrieves the machine's serial number, model, OS, GPU information, and Dell warranty information if applicable.
    It logs the machine information to a text file on the desktop and optionally to a remote location.

.PARAMETER PWD
    The password for the local admin account, if provided.

.PARAMETER RemoteLogDirectory
    The remote location where logs should be stored, if specified.

.PARAMETER RunLocation
    The location of the setup files.

.EXAMPLE
    .\MachineInfo.ps1 -PWD "password" -RemoteLogDirectory "\\Server\Logs" -RunLocation "C:\Setup"
    Runs the script to gather machine information and log it.

.NOTES
    Author: John Burriss
    Created: 10/7/2019
    Requires: PowerShell 5.1 or higher, Administrator privileges

#>

[CmdletBinding()]

Param(
    [Parameter()]
    $PWD,
    $RemoteLogDirectory,
    $RunLocation
)

$SN = (get-ciminstance win32_bios | Select-object SerialNumber).SerialNumber # -ExpandProperty SerialNumber
#Start of the API request to dell
$Make = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer).Manufacturer # -ExpandProperty Manufacturer

if (Test-Connection 8.8.8.8 -Count 1 -Quiet) {
    if ($Make -match "Dell") {
        $AESkey = (2, 3, 1, 4, 54, 32, 144, 23, 5, 3, 1, 41, 36, 31, 18, 175, 6, 17, 1, 9, 5, 1, 76, 23)
        $key = "C:\setup\Bin\Key\Dell.key"

        if (Test-Path $Key) {

            $key = get-content "C:\setup\Bin\Key\Dell.key"

            $APIKey = ConvertTo-SecureString -String $key -Key $AESKey
    
            $decryptedKey = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIKey)
            $DellClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($decryptedKey)

            $DellClientID = 'l75f2ee0a146e843bfabce0b0572f59f57'
            $SourceDevice = "H0RDNW3"
            function get-DellWarranty([Parameter(Mandatory = $true)]$SourceDevice) {
                $today = Get-Date -Format yyyy-MM-dd
                $AuthURI = "https://apigtwb2c.us.dell.com/auth/oauth/v2/token"
                if ($Global:TokenAge -lt (get-date).AddMinutes(-55)) { $global:Token = $null }
                If ($null -eq $global:Token) {
                    $OAuth = "$global:DellClientID`:$global:DellClientSecret"
                    $Bytes = [System.Text.Encoding]::ASCII.GetBytes($OAuth)
                    $EncodedOAuth = [Convert]::ToBase64String($Bytes)
                    $headersAuth = @{ "authorization" = "Basic $EncodedOAuth" }
                    $Authbody = 'grant_type=client_credentials'
                    $AuthResult = Invoke-RESTMethod -Method Post -Uri $AuthURI -Body $AuthBody -Headers $HeadersAuth
                    $global:token = $AuthResult.access_token
                    $Global:TokenAge = (get-date)
                }

                $headersReq = @{ "Authorization" = "Bearer $global:Token" }
                $ReqBody = @{ servicetags = $SourceDevice }
                $WarReq = Invoke-RestMethod -Uri "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements" -Headers $headersReq -Body $ReqBody -Method Get -ContentType "application/json"
                $warlatest = $warreq.entitlements.enddate | sort-object | select-object -last 1
                $WarrantyState = if ($warlatest -le $today) { "Expired" } else { "OK" }
                if ($warreq.entitlements.serviceleveldescription) {
                    $WarObj = [PSCustomObject]@{
                        'Warranty Product name' = $warreq.entitlements.serviceleveldescription -join "`n"
                        'StartDate'             = (($warreq.entitlements.startdate | sort-object -Descending | select-object -last 1) -split 'T')[0]
                        'EndDate'               = (($warreq.entitlements.enddate | sort-object | select-object -last 1) -split 'T')[0]
                        'Warranty Status'       = $WarrantyState
                    }
                }
                else {
                    $WarObj = [PSCustomObject]@{
                        'Warranty Product name' = 'Could not get warranty information'
                        'StartDate'             = $null
                        'EndDate'               = $null
                        'Warranty Status'       = 'Could not get warranty information'
                    }
                }
                Return $WarObj
            }

            $Warranty = get-DellWarranty -SourceDevice $SourceDevice

  

        }
    }
}

if (Test-Path -Path "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe") {
    $NVSMILocation = "C:\Program Files\NVIDIA Corporation\NVSMI"
}
elseif (Test-Path -Path "C:\Windows\System32\nvidia-smi.exe") {
    $NVSMILocation = "C:\Windows\System32"
}


$Model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
$OS = (Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName).ProductName #-ExpandProperty ProductName
$Path = "$NVSMILocation\nvidia-smi.exe"
if (Test-Path $path) {
    $GPUs = & "$NVSMILocation\nvidia-smi.exe" --query-gpu=name --format=csv | select-object -skip 1
    $GPUDriver = & "$NVSMILocation\nvidia-smi.exe" --query-gpu=driver_version --format=csv | select-object -skip 1 | Select-Object -First 1
    $GPUSN = (& "$NVSMILocation\nvidia-smi.exe" -a)
    $GPUSN = $GPUSN  | Where-Object { $_ -match "Serial Number" }
    $GPUSN = $GPUSN -replace "    Serial Number                   :", ""

}
Else {
    $GPUs = "N/A"
    $GPUDriver = "N/A"      
}
#Checks to see if file exists, removes it if it does.
$Path = "C:\users\$env:UserName\desktop\MachineInfo.txt"

if (Test-Path $Path) {
    Remove-Item $Path
}

Start-Sleep -Milliseconds 100

Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "$Make $Model"
Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Serial Number: $SN"
Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Hostname: $env:COMPUTERNAME"
Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Installed OS: $OS"
Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "GPU(s): $GPUs"
Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "GPU Driver: $GPUDriver"
if ($Null -ne $GPUSN) {
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "GPU Serial Number(s): $GPUSN"
}
#Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "$GPUSN"
if ($Null -ne $PWD) {
    $Password = $PWD
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "The Local Admin pw: $Password"
}
if ($Null -ne $Warranty) {
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "The support Information for ServiceTag $SN is:"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" $Warranty
}

$MachineInfo = @()
$machineInfo += New-Object psobject -prop $([ordered]@{
        'Make'             = $make
        'Model'            = $model
        'Serial'           = $SN
        'Hostname'         = $env:COMPUTERNAME
        'Operating System' = $OS
        'GPU(s)'           = $GPUs
        'GPU Driver'       = $GPUDriver
    })

if ($Null -ne $Warranty) {

    $machineInfo += New-Object psobject -prop $([ordered]@{
            'Warranty Product name' = $Warranty.'Warranty Product name'
            'StartDate'             = $Warranty.StartDate
            'EndDate'               = $Warranty.EndDate
            'Warranty Status'       = $Warranty.'Warranty Status'
        })
}


if ($RemotelogDirectory -ne $null) {

    $RemotelogFilePath = Join-Path "$RemotelogDirectory" "MachineInventory.txt"
    $MachineInfo | ConvertTo-Json -Compress | Out-File -FilePath $RemotelogFilePath -Append

}