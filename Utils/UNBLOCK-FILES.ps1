try {
    # Get current directory in a way that works with EXE
    $currentPath = [System.IO.Path]::GetDirectoryName([System.Windows.Forms.Application]::ExecutablePath)
    if ([string]::IsNullOrEmpty($currentPath)) {
        $currentPath = [System.Environment]::CurrentDirectory
    }

    # Add Windows Forms assembly for MessageBox
    Add-Type -AssemblyName System.Windows.Forms
    
    # Unblock all files recursively
    Get-ChildItem -Path $currentPath -Recurse | Unblock-File
    
    # Show success message
    [System.Windows.Forms.MessageBox]::Show("All files have been unblocked successfully!", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
catch {
    # Show error message if something goes wrong
    [System.Windows.Forms.MessageBox]::Show("Error unblocking files: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
}