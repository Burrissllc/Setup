# Windows Server Setup Script

A comprehensive PowerShell script for automating the setup and configuration of Windows servers, particularly focused on SQL Server and RayStation installation.

## Overview

This script provides automated installation and configuration of various components including:

- SQL Server installation and configuration
- RayStation application setup
- GPU driver installation
- Citrix VDA installation
- Windows system configurations
- Local group management
- Drive formatting and configuration
- Various service installations (DICOM, License Agent, etc.)

## Prerequisites

- Windows Server operating system
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection (for some components)
- Setup.json configuration file in the same directory as the script

## Configuration

The script uses a Setup.json file for all configuration settings. Key configuration sections include:

### General Settings

```json
{
    "GENERAL": {
        "MACHINENAME": "",
        "INSTALLJAVA": "Y/N",
        "INSTALLADOBE": "Y/N",
        "INSTALLDOTNET": "Y/N",
        "INSTALLSQL": "Y/N",
        "INSTALLGPUDRIVER": "Y/N",
        "INSTALLRAYSTATION": "Y/N",
        "INSTALLCITRIX": "Y/N",
        "INSTALLLMX": "Y/N",
        "FORMATDRIVES": "Y/N",
        "UPDATEWINDOWS": "Y/N",
        "AUTOREBOOT": "Y/N",
        "CLEANUP": "Y/N",
        "LOCALGROUPS": "Y/N",
        "ENABLEAUTOLOGON": "Y/N",
        "REMOTELOGGINGLOCATION": ""
    }
}
```

### SQL Server Settings

```json
{
    "SQL": {
        "ISOPATH": "",
        "FEATURES": "",
        "DATADIR": "",
        "BACKUPDIR": "",
        "TEMPDBDIR": "",
        "TEMPLOGDIR": "",
        "FILESTREAMDRIVE": "",
        "FILESTREAMSHARENAME": "",
        "PORT": "",
        "INSTANCENAME": "",
        "SAPASSWORD": "",
        "SERVICEACCOUNTNAME": "",
        "SERVICEACCOUNTPASSWORD": "",
        "PRODUCTKEY": "",
        "USETRANSFERBITS": "Y/N",
        "ENABLEPROTOCOLS": "Y/N"
    }
}
```

## Features

1. **Base System Configuration**
   - Machine naming
   - Auto-logon configuration
   - Default Windows settings
   - Local group creation

2. **Software Installation**
   - Java Runtime Environment
   - Adobe Reader
   - .NET Framework 4.8
   - Dell Open Manage (for Dell servers)

3. **SQL Server Setup**
   - Drive configuration
   - SQL Server installation
   - FileStream configuration
   - SQL Server Management Studio (SSMS) installation

4. **GPU Configuration**
   - NVIDIA driver removal (optional)
   - New GPU driver installation
   - GPU configuration for RayStation

5. **Application Installation**
   - Citrix VDA
   - RayStation
   - DICOM Service
   - License Agent

6. **System Maintenance**
   - Windows Updates
   - System cleanup
   - Automatic rebooting (optional)

## Security Features

- Secure password handling using AES encryption
- Service account validation
- Path existence verification
- Input validation for critical parameters

## Logging

The script includes comprehensive logging functionality:

- Local logging to `[ScriptDirectory]\Logs\MachineSetup.json`
- Remote logging capability (when configured)
- Severity levels: Info, Warn, Error, Start, End
- Includes timestamp, hostname, severity, and message

## Usage

1. Configure the Setup.json file with your desired settings

2. Run the script as administrator:

```powershell
.\Setup.ps1
```

## Requirements

- Windows Server (tested on 2019)
- PowerShell execution policy allowing script execution
- Administrator privileges
- Network access (for downloading components)
- Sufficient disk space for installations

## Error Handling

The script includes comprehensive error checking:

- Path validation
- Service account format verification
- Drive availability checking
- Installation prerequisite verification

## Notes

- The script must be run with administrator privileges
- Some features require internet connectivity
- Certain installations may require system reboots
- All passwords are encrypted using AES encryption
- The script creates detailed logs of all operations

## Author

- John Burriss
- Created: 8/26/2019
- Modified: 10/12/2022
- Version: 0.07
