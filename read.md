#/
Copy the entire Setup Directory to the C: drive. Edit the setup.json file with the needed parameters using only capital Y or N for the General Section of the file then run the launcher.ps1 as Administrator
Once the Script is started it should be left alone until it completes. Depending on parameters in the setup.json it will reboot and logon automatically.
Depending on the options selected the machine will reboot a couple of times to complete the install.
Remote Machine setup can be completed by adding the machine IP Addresses to the remoteMachine.txt file one per line then running the RemoteLauncher.ps1 file and follow the prompts.
If running the RemoteLauncher.ps1 please do not use Autologon option in the Setup.json as it breaks the automation
This is not a finished script so please report any errors with the attached transcript log to john.burriss@raysearchlabs.com
