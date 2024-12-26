# RayStation Server Setup

A comprehensive PowerShell script for automating the setup and configuration of Windows servers, particularly focused on SQL Server and RayStation installation.

## Windows Server Setup

### Overview

This script provides automated installation and configuration of various components including:

- SQL Server installation and configuration
- RayStation application setup
- GPU driver installation
- Citrix VDA installation
- Windows system configurations
- Local group management
- Drive formatting and configuration
- Various service installations (DICOM, License Agent, etc.)

### Prerequisites

- Windows Server operating system
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection (for some components)
- Setup.json configuration file in the same directory as the script

### Configuration

The script uses a Setup.json file for all configuration settings. Key configuration sections include:

#### General Settings

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

#### SQL Server Settings

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

### Features

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

### Security Features

- Secure password handling using AES encryption
- Service account validation
- Path existence verification
- Input validation for critical parameters

### Logging

The script includes comprehensive logging functionality:

- Local logging to `[ScriptDirectory]\Logs\MachineSetup.json`
- Remote logging capability (when configured)
- Severity levels: Info, Warn, Error, Start, End
- Includes timestamp, hostname, severity, and message

### Usage

1. Configure the Setup.json file with your desired settings

2. Run the script as administrator:

```powershell
.\Setup.ps1
```

### Requirements

- Windows Server (tested on 2019)
- PowerShell execution policy allowing script execution
- Administrator privileges
- Network access (for downloading components)
- Sufficient disk space for installations

### Error Handling

The script includes comprehensive error checking:

- Path validation
- Service account format verification
- Drive availability checking
- Installation prerequisite verification

### Notes

- The script must be run with administrator privileges
- Some features require internet connectivity
- Certain installations may require system reboots
- All passwords are encrypted using AES encryption
- The script creates detailed logs of all operations

## Setup.json Configuration Documentation

This document explains the configuration options available in the Setup.json file and their corresponding functionality in the Setup.ps1 script.

### SQL Section

Configuration options for SQL Server installation and setup.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| INSTANCENAME | SQL Server instance name | Used during SQL installation to set the instance name |
| ISOPATH | Path to SQL Server installation ISO | Validated at script start, used for SQL installation |
| SERVICEACCOUNTPASSWORD | Password for SQL service account | Encrypted using AES key before SQL installation |
| TEMPLOGDIR | Directory for temporary log files | Validated and created if needed before SQL installation |
| FILESTREAMDRIVE | Drive letter for FileStream storage | Used to configure FileStream after SQL installation |
| FILESTREAMSHARENAME | Share name for FileStream | Configured during SQL installation |
| PRODUCTKEY | SQL Server product key | Passed to SQL installer |
| PORT | SQL Server port number | Validated to be numeric, defaults to 1433 |
| TEMPDBDIR | Directory for TempDB files | Created and validated before SQL installation |
| DATADIR | Directory for SQL data files | Validated and created before SQL installation |
| SAPASSWORD | SQL SA account password | Encrypted using AES key before SQL installation |
| USETRANSFERBITS | Use BITS for file transfer | Controls file transfer method during installation |
| FEATURES | SQL Server features to install | Passed to SQL installer, defaults to SQLEngine |
| ENABLEPROTOCOLS | Enable SQL protocols | Configures SQL protocols post-installation |
| BACKUPDIR | Directory for backups | Validated and created before SQL installation |

### RAYSTATION Section

RayStation application installation and configuration settings.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| IndexServicePort | Port for Index Service | Used during RayStation service configuration |
| FEATURES | RayStation features to install | Controls which components are installed |
| TransferServicePwd | Transfer Service password | Encrypted using AES key |
| GenerateSelfSignedCert | Generate SSL certificate | Controls certificate generation during installation |
| WAITFORSQLCONNECTION | Wait for SQL connection | Controls installation sequence |
| INDEXSERVICESERVER | Index Service server names | Used for service configuration |
| DATABASESUFFIX | Database name suffix | Used for database configuration |
| TRANSFERSERVICESERVER | Transfer Service server names | Used for service configuration |
| DATABASEADDRESS | Database server address | Used for database connection configuration |
| DATABASEINSTANCE | Database instance name | Used for database connection configuration |
| RAYSTATIONLOCATION | Installation file location | Validated at script start |

### CITRIX Section

Citrix Virtual Apps and Desktops installation settings.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| DELIVERYCONTROLLERS | Citrix controller addresses | Used during VDA installation |
| OMITTEDSERVERS | Servers to skip | Controls where Citrix is not installed |
| CITRIXISOLOCATION | Citrix installation ISO path | Validated at script start |

### LICENSING Section

RayStation licensing configuration.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| LOCALLICENSE | Use local license | Controls license configuration |
| DESIGNATEDSERVER | License server names | Used for license service configuration |
| LICENSELOCATION | License file location | Validated at script start |
| CONFIGUREHAL | Configure HAL | Controls hardware abstraction layer setup |

### SERVICES Section

Configuration for various RayStation services.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| SCPPORT | DICOM SCP port | Used for DICOM service configuration |
| SECUREHOSTING | Enable secure hosting | Controls security settings |
| SERVICEPWD | Service account password | Encrypted using AES key |
| LICENSEAGENTSERVER | License agent servers | Used for license service configuration |
| DICOMSERVICELOCATION | DICOM service installer path | Validated at script start |
| GenerateSelfSignedCert | Generate SSL certificate | Controls certificate generation |
| SERVICEUSER | Service account username | Validated for correct format |

### DRIVES Section

Drive configuration for SQL and application data.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| DriveLetter | Drive letter to use | Used for drive formatting and configuration |
| DriveNumber | Physical drive number | Used to identify correct drive |
| DriveLabel | Drive label | Applied during drive formatting |

### GPU Section

NVIDIA GPU driver installation settings.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| DRIVERLOCATION | GPU driver installer path | Validated at script start |
| CLEANINSTALL | Perform clean installation | Controls driver installation method |
| NVIDIALICENSETOKENLOCATION | License token file path | Validated at script start |
| REMOVECURRENTDRIVER | Remove existing driver | Controls driver removal before installation |

### GENERAL Section

General installation and configuration options.

| Option | Description | Script Reference |
|--------|-------------|------------------|
| INSTALLCITRIX | Install Citrix VDA | Controls Citrix installation |
| ENABLEAUTOLOGON | Enable auto-logon | Configures Windows auto-logon |
| BUILDRAYSTATIONGPUCONFIGS | Configure GPU settings | Controls GPU configuration for RayStation |
| AUTOUPDATEGPUUUID | Auto-update GPU UUID | Controls GPU UUID updates |
| INSTALLSQL | Install SQL Server | Controls SQL Server installation |
| FORMATDRIVES | Format drives | Controls drive initialization |
| INSTALLLMX | Install licensing | Controls license installation |
| AUTOREBOOT | Auto-reboot after install | Controls system reboot behavior |
| CLEANUP | Perform cleanup | Controls post-installation cleanup |
| UPDATEWINDOWS | Update Windows | Controls Windows Update execution |
| INSTALLRAYSTATION | Install RayStation | Controls RayStation installation |
| INSTALLDICOM | Install DICOM service | Controls DICOM service installation |
| TIMEZONE | System timezone | Used to set system timezone |

### Author

- John Burriss
- Created: 8/26/2019
- Modified: 10/12/2022
- Version: 0.07
