#------------------------------------------------------
# Name:        DellWarranty
# Purpose:     Makes API request to Dell to get support information for Service Tag
# Author:      John Burriss
# Created:     10/7/2019  12:13 PM 
#------------------------------------------------------
[CmdletBinding()]

Param(
[Parameter()]
$PWD
)

if ($null -ne $pwd ){
$Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($PWD)
}

$SN = get-ciminstance win32_bios | Select-object SerialNumber -ExpandProperty SerialNumber

$url=''

$postdata=''

$content=''

$auth_response=''

$url='https://apigtwb2c.us.dell.com/auth/oauth/v2/token'

$postdata= @{client_id='XXXXXXXXXX';client_secret='XXXXXXXX';grant_type='client_credentials'}

$content='application/x-www-form-urlencoded'
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$auth_response=Invoke-RestMethod -URI $url -Method Post -Body $postdata -ContentType $content

$Token = $auth_response.access_token


 $params = @{
    Uri         = "https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements?servicetags=$SN"
    Headers     = @{ 'Authorization' = "Bearer $Token" }
    Method      = 'GET'
    Body        = $jsonSample
    ContentType = 'application/json'
    }

    $Details = Invoke-RestMethod @params

    $Details1 = $Details | where-Object { $_ -match "entitlements" }
    $Model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    $Make = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer -ExpandProperty Manufacturer
    $OS = Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName -ExpandProperty ProductName
    $Path = "C:\Program Files\NVIDIA CORPORATION\NVSMI\nvidia-smi.exe"
    if(Test-Path $path){
    $GPUs = & "C:\Program Files\NVIDIA CORPORATION\NVSMI\nvidia-smi.exe" --query-gpu=name --format=csv | select-object -skip 1
    $GPUDriver = & "C:\Program Files\NVIDIA CORPORATION\NVSMI\nvidia-smi.exe" --query-gpu=driver_version --format=csv | select-object -skip 1
    }
    Else{
      $GPUs = "N/A"
      $GPUDriver = "N/A"      
    }

    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "$Make $Model"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Serial Number: $SN"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Hostname: $env:COMPUTERNAME"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "Installed OS: $OS"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "GPU(s): $GPUs"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "GPU Driver: $GPUDriver"
    if($Null -ne $PWD){
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "The Local Admin pw: $Password"
    }
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" "The support Information for ServiceTag $SN is:"
    Add-Content "C:\users\$env:UserName\desktop\MachineInfo.txt" $Details1.entitlements
