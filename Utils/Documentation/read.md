## PowerShell Machine Monitoring Script

This script automates the monitoring and management of machine setup processes through JSON log files. It identifies new machine check-ins, starts monitoring jobs for each machine, and ensures all machines complete their setup processes. Any machine that does not check in within a specified timeout is logged as a warning. Once all machines are setup, a remote inventory collection process is initiated.

### Features

- Monitors for `*MachineSetup.json` log files in a specified directory.
- Tracks machine check-ins and initiates parallel monitoring jobs.
- Logs warnings for machines that do not check in within a specified timeout.
- Automatically initiates a remote inventory collection process after all machines complete.
- Includes detailed logging for all actions.

### Requirements

- PowerShell 5.1 or later.
- Necessary permissions to access the log directory and execute remote inventory scripts.

### Usage

#### Parameters

- `logDirectory`: Specifies the directory containing machine setup log files.
  
- `timeout`: Defines the timeout period for machine check-ins.

#### Example

```powershell

# Example to run the script with a specified log directory
$logDirectory = "C:\Setup\Logs"
.
Run the script to monitor the directory for new machine setup log files.
