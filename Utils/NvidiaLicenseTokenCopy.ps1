$remoteMachines = Read-Host "Enter the path to the Machine List"
$TokenLocation = Read-Host "Enter the path to the Nvidia License Token"

if(Test-Path -Path $remoteMachines){

    if(Test-path -Path $TokenLocation){

        foreach($Machine in $remoteMachines){
            
            try{
                Copy-Item -Path $TokenLocation -Destination "\\$machine\Program Files\NVIDIA Corporation\vGPU Licensing\ClientConfigToken\" -Force
                $ServiceName = 'NVDisplay.ContainerLocalSystem'
                Get-Service -ComputerName $machine -Name $ServiceName | Restart-Service -Force

            }
            catch{
                Write-Host "Failed to Copy Token and Restart NVDisplay Service"
            }

        }

    }

}
