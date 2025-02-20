<#
.SYNOPSIS
    Prepares files to be consumed by setup and launches setup in a new window.

.DESCRIPTION
    This script sets the execution policy to unrestricted, unblocks files in the current directory, 
    removes specific registry entries related to AutoAdminLogon, ensures necessary directories exist, 
    copies required files, sets .NET framework properties, and then launches the setup script in a new PowerShell window.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\Launcher.ps1
    Runs the script to prepare the environment and launch the setup script.

.NOTES
    Author: John Burriss
    Created: 9/30/2019
    Modified: 10/31/2022
    Version: 0.03
    Requires: Run as Administrator

#>
#Requires -RunAsAdministrator

set-ExecutionPolicy Unrestricted

$RunLocation = split-path -parent $MyInvocation.MyCommand.Definition

Get-ChildItem -Path "$RunLocation\" -Recurse | Unblock-File

$RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$RegistryRunOncePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"

if (Get-ItemProperty -Path $RegistryRunOncePath -Name "NextRun" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RegistryRunOncePath -Name "NextRun" }
if (Get-ItemProperty -Path $RegistryPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RegistryPath -Name "AutoAdminLogon" }
if (Get-ItemProperty -Path $RegistryPath -Name "DefaultUsername" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RegistryPath -Name "DefaultUsername" }
if (Get-ItemProperty -Path $RegistryPath -Name "DefaultPassword" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RegistryPath -Name "DefaultPassword" }
if (Get-ItemProperty -Path $RegistryPath -Name "DefaultDomainName" -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $RegistryPath -Name "DefaultDomainName" }

$Path = "C:\Users\$env:UserName\Documents\WindowsPowerShell\Modules"

if (!(Test-Path $Path)) { 
    New-Item -ItemType Directory -Path "C:\Users\$env:UserName\Documents\WindowsPowerShell\Modules"
}
$Path = "C:\Program Files\PackageManagement\ProviderAssemblies"

if (!(Test-Path $Path)) { 
    Copy-Item "$RunLocation\bin\NuGet" -Destination "C:\Program Files\PackageManagement\ProviderAssemblies"
}

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord

$Run = "$RunLocation\setup.ps1"

start-process powershell -ArgumentList "-file $Run"

exit
