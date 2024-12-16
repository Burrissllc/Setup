<#
.SYNOPSIS
    JSON Editor for Setup Configuration.

.DESCRIPTION
    This script provides a WPF GUI for editing the setup configuration JSON file. It allows users to modify various settings through a graphical interface.

.PARAMETER None
    This script does not take any parameters.

.EXAMPLE
    .\JSONBuilder.ps1
    Opens the JSON editor GUI.

.NOTES
    Author: John Burriss
    Created: 8/26/2019
#>
# Load required assemblies
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# Define the XAML for the WPF GUI
[xml]$xaml = @"
<Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="JSON Editor" Height="600" Width="800">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>
        <TabControl Grid.Row="0">
            <TabItem Header="GENERAL">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Enable Auto Logon" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxEnableAutoLogon" Grid.Row="0" Grid.Column="1" VerticalAlignment="Center"/>
                        <Label Content="Leave Unchecked for Remote Deployment" Grid.Column="1" VerticalAlignment="Center" Margin="34,0,-24,0"/>

                        <Label Content="Machine Name" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxMachineName" Grid.Row="1" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Time Zone" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ComboBox x:Name="comboBoxTimeZone" Grid.Row="2" Grid.Column="1" Margin="0,5,0,5">
                            <ComboBoxItem Content=""/>
                            <ComboBoxItem Content="EST"/>
                            <ComboBoxItem Content="CST"/>
                            <ComboBoxItem Content="MST"/>
                            <ComboBoxItem Content="PST"/>
                            <ComboBoxItem Content="AST"/>
                            <ComboBoxItem Content="HST"/>
                        </ComboBox>

                        <Label Content="Install Adobe" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallAdobe" Grid.Row="3" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install Java" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallJava" Grid.Row="4" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install .NET" Grid.Row="5" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallDotNet" Grid.Row="5" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Create Local Groups" Grid.Row="6" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxLocalGroups" Grid.Row="6" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Format Drives" Grid.Row="7" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxFormatDrives" Grid.Row="7" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install SQL" Grid.Row="8" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallSql" Grid.Row="8" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install GPU Driver" Grid.Row="9" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallGpuDriver" Grid.Row="9" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install LMX" Grid.Row="10" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallLmx" Grid.Row="10" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install Citrix" Grid.Row="11" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallCitrix" Grid.Row="11" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install RayStation" Grid.Row="12" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallRaystation" Grid.Row="12" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install DICOM Service" Grid.Row="13" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallDICOM" Grid.Row="13" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Install License Agent" Grid.Row="14" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxInstallLicenseAgent" Grid.Row="14" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Build RayStation GPU Configs" Grid.Row="15" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxBuildRaystationGpuConfigs" Grid.Row="15" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Update Windows" Grid.Row="16" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxUpdateWindows" Grid.Row="16" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Auto Reboot" Grid.Row="17" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxAutoReboot" Grid.Row="17" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Cleanup" Grid.Row="18" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxCleanup" Grid.Row="18" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Remote Logging Location" Grid.Row="19" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxRemoteLoggingLocation" Grid.Row="19" Grid.Column="1" Margin="0,5,0,5"/>
                            <TextBlock IsHitTestVisible="False" Text="Normally Empty" Grid.Row="19" Grid.Column="1" VerticalAlignment="Center" Margin="5,0,0,0" Foreground="DarkGray">
                                <TextBlock.Style>
                                    <Style TargetType="{x:Type TextBlock}">
                                        <Style.Triggers>
                                            <DataTrigger Binding="{Binding Text, ElementName=textBoxRemoteLoggingLocation}" Value="">
                                                <Setter Property="Visibility" Value="Visible"/>
                                            </DataTrigger>
                                            <DataTrigger Binding="{Binding Text, ElementName=textBoxRemoteLoggingLocation}" Value="{x:Null}">
                                                <Setter Property="Visibility" Value="Visible"/>
                                            </DataTrigger>
                                            <DataTrigger Binding="{Binding IsFocused, ElementName=textBoxRemoteLoggingLocation}" Value="True">
                                                <Setter Property="Visibility" Value="Collapsed"/>
                                            </DataTrigger>
                                        </Style.Triggers>
                                        <Setter Property="Visibility" Value="Collapsed"/>
                                    </Style>
                                </TextBlock.Style>
                            </TextBlock>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="DRIVES">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Drives" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxDrives" Grid.Row="0" Grid.Column="1" Height="200" Margin="0,5,0,5"/>

                        <Grid Grid.Row="1" Grid.Column="1">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Label Content="Drive Letter:" Grid.Column="0" VerticalAlignment="Center"/>
                            <TextBox x:Name="textBoxDriveLetter" Grid.Column="1" Margin="5,0,5,0"/>
                            <Label Content="Drive Number:" Grid.Column="2" VerticalAlignment="Center"/>
                            <TextBox x:Name="textBoxDriveNumber" Grid.Column="3" Margin="5,0,5,0"/>
                            <Label Content="Drive Label:" Grid.Column="4" VerticalAlignment="Center"/>
                            <TextBox x:Name="textBoxDriveLabel" Grid.Column="5" Margin="5,0,5,0"/>
                        </Grid>

                        <StackPanel Grid.Row="2" Grid.Column="1" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,10,0,0">
                            <Button x:Name="AddDrive" Content="Add Drive" Margin="0,0,10,0" Padding="10,5"/>
                            <Button x:Name="RemoveDrive" Content="Remove Drive" Padding="10,5"/>
                        </StackPanel>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="DESIGNATED SQL SERVER">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Designated SQL Servers" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxDesignatedSqlServer" Grid.Row="0" Grid.Column="1" Height="200" Margin="0,5,0,5"/>

                        <StackPanel Grid.Row="1" Grid.Column="1" Orientation="Horizontal" Margin="0,10,0,0">
                            <TextBox x:Name="textBoxNewDesignatedSqlServer" Width="200" Margin="0,0,10,0"/>
                            <Button x:Name="AddDesignatedSqlServer" Content="Add" Margin="0,0,10,0" Padding="10,5"/>
                            <Button x:Name="RemoveDesignatedSqlServer" Content="Remove" Padding="10,5"/>
                        </StackPanel>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="SQL">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition/>
                            <ColumnDefinition Width="Auto" MinWidth="63.28"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="ISO Path" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlIsoPath" Grid.Row="0" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlIsoPath" Content="Browse" Grid.Row="0" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Features" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlFeatures" Grid.Row="1" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Install Directory" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlInstallDir" Grid.Row="2" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlInstallDir" Content="Browse" Grid.Row="2" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Data Directory" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlDataDir" Grid.Row="3" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlDataDir" Content="Browse" Grid.Row="3" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Backup Directory" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlBackupDir" Grid.Row="4" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlBackupDir" Content="Browse" Grid.Row="4" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Temp Directory" Grid.Row="5" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlTempDbDir" Grid.Row="5" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlTempDbDir" Content="Browse" Grid.Row="5" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Temp Log Directory" Grid.Row="6" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlTempLogDir" Grid.Row="6" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>
                        <Button x:Name="BrowseSqlTempLogDir" Content="Browse" Grid.Row="6" Grid.Column="2" Margin="5,4,0,4"/>

                        <Label Content="Filestream Drive" Grid.Row="7" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlFileStreamDrive" Grid.Row="7" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Filestream Share Name" Grid.Row="8" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlFileStreamShareName" Grid.Row="8" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Port" Grid.Row="9" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlPort" Grid.Row="9" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Instance Name" Grid.Row="10" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlInstanceName" Grid.Row="10" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="SA Password" Grid.Row="11" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <PasswordBox x:Name="passwordBoxSqlSaPassword" Grid.Row="11" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Service Account Name" Grid.Row="12" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="25"/>
                        <TextBox x:Name="textBoxSqlServiceAccountName" Grid.Row="12" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Service Account Password" Grid.Row="13" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <PasswordBox x:Name="passwordBoxSqlServiceAccountPassword" Grid.Row="13" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Product Key" Grid.Row="14" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <TextBox x:Name="textBoxSqlProductKey" Grid.Row="14" Grid.Column="1" Margin="0,5,65,5" Grid.ColumnSpan="2"/>

                        <Label Content="Use Transfer Bits" Grid.Row="15" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <CheckBox x:Name="checkboxUseTransferBits" Grid.Row="15" Grid.Column="1" VerticalAlignment="Center" Grid.ColumnSpan="2" Height="15" Margin="0,0,47,0"/>

                        <Label Content="Enable Protocols" Grid.Row="16" Grid.Column="0" VerticalAlignment="Center" Margin="0,0,10,0" Height="26"/>
                        <CheckBox x:Name="checkboxEnableProtocols" Grid.Row="16" Grid.Column="1" VerticalAlignment="Center" Grid.ColumnSpan="2" Height="15" Margin="0,0,47,0"/>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="GPU">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Remove Current Driver" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxRemoveCurrentDriver" Grid.Row="0" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Driver Location" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDriverLocation" Grid.Row="1" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseDriverLocation" Content="Browse" Grid.Row="1" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Clean Install" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxCleanInstall" Grid.Row="2" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Nvidia License Token" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxNvidiaLicenseTokenLocation" Grid.Row="3" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseNvidiaLicenseTokenLocation" Content="Browse" Grid.Row="3" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Omitted Servers" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxGpuOmittedServers" Grid.Row="4" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="4" Grid.Column="2">
                            <TextBox x:Name="textBoxNewGpuOmittedServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddGpuOmittedServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveGpuOmittedServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="LICENSING">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Configure HAL" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxConfigureHal" Grid.Row="0" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Local License" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxLocalLicense" Grid.Row="1" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="License Location" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxLicenseLocation" Grid.Row="2" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseLicenseLocation" Content="Browse" Grid.Row="2" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Designated Servers" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxDesignatedServer" Grid.Row="3" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="3" Grid.Column="2">
                            <TextBox x:Name="textBoxNewDesignatedServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddDesignatedServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveDesignatedServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="HAL Server 1" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxHalServer1" Grid.Row="4" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="HAL Server 2" Grid.Row="5" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxHalServer2" Grid.Row="5" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="HAL Server 3" Grid.Row="6" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxHalServer3" Grid.Row="6" Grid.Column="1" Margin="0,5,0,5"/>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="CITRIX">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Omitted Servers" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxOmittedServers" Grid.Row="0" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="0" Grid.Column="2">
                            <TextBox x:Name="textBoxNewOmittedServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddOmittedServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveOmittedServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="Delivery Controllers" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDeliveryControllers" Grid.Row="1" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Citrix ISO Location" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxCitrixIsoLocation" Grid.Row="2" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseCitrixIsoLocation" Content="Browse" Grid.Row="2" Grid.Column="2" Margin="5,5,0,5"/>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="RAYSTATION">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="Omitted Servers" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxRaystationOmittedServers" Grid.Row="0" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="0" Grid.Column="2">
                            <TextBox x:Name="textBoxNewRaystationOmittedServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddRaystationOmittedServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveRaystationOmittedServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="RayStation Location" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxRaystationLocation" Grid.Row="1" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseRaystationLocation" Content="Browse" Grid.Row="1" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Features" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxRaystationFeatures" Grid.Row="2" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Address" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDatabaseAddress" Grid.Row="3" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Port" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDatabasePort" Grid.Row="4" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Instance" Grid.Row="5" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDatabaseInstance" Grid.Row="5" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Suffix" Grid.Row="6" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDatabaseSuffix" Grid.Row="6" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Wait for SQL Connection" Grid.Row="7" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxWaitForSqlConnection" Grid.Row="7" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Index Service Server" Grid.Row="8" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxIndexServiceServer" Grid.Row="8" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="8" Grid.Column="2">
                            <TextBox x:Name="textBoxNewIndexServiceServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddIndexServiceServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveIndexServiceServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="Index Service User" Grid.Row="9" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxIndexServiceUser" Grid.Row="9" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Index Service Password" Grid.Row="10" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <PasswordBox x:Name="passwordBoxIndexServicePwd" Grid.Row="10" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Index Service Port" Grid.Row="11" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxIndexServicePort" Grid.Row="11" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Generate Self Signed Cert" Grid.Row="12" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxGenerateSelfSignedCert" Grid.Row="12" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Index Service Cert" Grid.Row="13" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxIndexServiceCert" Grid.Row="13" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseIndexServiceCert" Content="Browse" Grid.Row="13" Grid.Column="2" Margin="5,0,0,0"/>

                        <Label Content="Transfer Service Server" Grid.Row="14" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxTransferServiceServer" Grid.Row="14" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="14" Grid.Column="2">
                            <TextBox x:Name="textBoxNewTransferServiceServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddTransferServiceServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveTransferServiceServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="Transfer Service User" Grid.Row="15" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxTransferServiceUser" Grid.Row="15" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Transfer Service Password" Grid.Row="16" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <PasswordBox x:Name="passwordBoxTransferServicePwd" Grid.Row="16" Grid.Column="1" Margin="0,5,0,5"/>
                    </Grid>
                </ScrollViewer>
            </TabItem>

            <TabItem Header="SERVICES">
                <ScrollViewer>
                    <Grid Margin="10">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>

                        <Label Content="DICOM Service Server" Grid.Row="0" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxDicomServiceServer" Grid.Row="0" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="0" Grid.Column="2">
                            <TextBox x:Name="textBoxNewDicomServiceServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddDicomServiceServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveDicomServiceServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="DICOM Service Location" Grid.Row="1" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxDicomServiceLocation" Grid.Row="1" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseDicomServiceLocation" Content="Browse" Grid.Row="1" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="SCP Title" Grid.Row="2" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxScpTitle" Grid.Row="2" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="SCP Port" Grid.Row="3" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxScpPort" Grid.Row="3" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="SCP Folder" Grid.Row="4" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxScpFolder" Grid.Row="4" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseScpFolder" Content="Browse" Grid.Row="4" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="SCP Days" Grid.Row="5" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxScpDays" Grid.Row="5" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="License Service Server" Grid.Row="6" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <ListBox x:Name="listBoxLicenseAgentServer" Grid.Row="6" Grid.Column="1" Height="100" Margin="0,5,0,5"/>
                        <StackPanel Grid.Row="6" Grid.Column="2">
                            <TextBox x:Name="textBoxNewLicenseAgentServer" Width="100" Margin="5,5,0,5" Height="25"/>
                            <Button x:Name="AddLicenseAgentServer" Content="Add" Margin="5,5,0,5"/>
                            <Button x:Name="RemoveLicenseAgentServer" Content="Remove" Margin="5,0,0,0"/>
                        </StackPanel>

                        <Label Content="License Service Location" Grid.Row="7" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxLicenseSetupExe" Grid.Row="7" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseLicenseSetupExe" Content="Browse" Grid.Row="7" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Service User" Grid.Row="8" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServiceUser" Grid.Row="8" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Service Password" Grid.Row="9" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <PasswordBox x:Name="passwordBoxServicePwd" Grid.Row="9" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Service Port" Grid.Row="10" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServicePort" Grid.Row="10" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Secure Hosting" Grid.Row="11" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxSecureHosting" Grid.Row="11" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Offline Mode" Grid.Row="12" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxOfflineMode" Grid.Row="12" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="License Server End Point" Grid.Row="13" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxLicenseServiceEndpoint" Grid.Row="13" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Generate Self Signed Cert" Grid.Row="14" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <CheckBox x:Name="checkboxServicesGenerateSelfSignedCert" Grid.Row="14" Grid.Column="1" VerticalAlignment="Center"/>

                        <Label Content="Cert Subject" Grid.Row="15" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxCertSubject" Grid.Row="15" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Cert Store" Grid.Row="16" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxCertStore" Grid.Row="16" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Cert Location" Grid.Row="17" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxCertLocation" Grid.Row="17" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseCertLocation" Content="Browse" Grid.Row="17" Grid.Column="2" Margin="5,5,0,5"/>

                        <Label Content="Database Address" Grid.Row="18" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServicesDatabaseAddress" Grid.Row="18" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Instance" Grid.Row="19" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServicesDatabaseInstance" Grid.Row="19" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Database Port" Grid.Row="20" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServicesDatabasePort" Grid.Row="20" Grid.Column="1" Margin="0,5,0,5"/>

                        <Label Content="Install Directory" Grid.Row="21" Grid.Column="0" VerticalAlignment="Center" Margin="0,5,10,5"/>
                        <TextBox x:Name="textBoxServicesInstallDir" Grid.Row="21" Grid.Column="1" Margin="0,5,0,5"/>
                        <Button x:Name="BrowseServicesInstallDir" Content="Browse" Grid.Row="21" Grid.Column="2" Margin="5,5,0,5"/>
                    </Grid>
                </ScrollViewer>
            </TabItem>
        </TabControl>

        <Button x:Name="SaveButton" Content="Save" Grid.Row="1" HorizontalAlignment="Right" VerticalAlignment="Bottom" Margin="0,10,20,20" Padding="20,10" FontSize="16"/>
    </Grid>
</Window>
"@

# Load the XAML
$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

#Function to browse for folder
function Browse-Folder {
    param($textBoxName)
    $folder = New-Object System.Windows.Forms.FolderBrowserDialog
    $result = $folder.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $textBox = $window.FindName($textBoxName)
        if ($textBox -and $textBox.GetType().GetProperty("Text")) {
            $textBox.Text = $folder.SelectedPath
        }
        else {
            Write-Warning "TextBox '$textBoxName' not found or doesn't have a Text property."
        }
    }
}


# Function to load existing JSON
function Load-ExistingJSON {
    $jsonPath = Join-Path $PSScriptRoot "setup.json"
    if (Test-Path $jsonPath) {
        $script:jsonContent = Get-Content $jsonPath | ConvertFrom-Json

        # GENERAL tab
        $window.FindName("checkboxEnableAutoLogon").IsChecked = $jsonContent.GENERAL.ENABLEAUTOLOGON -eq "Y"
        $window.FindName("textBoxMachineName").Text = $jsonContent.GENERAL.MACHINENAME
        # Set Time Zone
        $comboBoxTimeZone = $window.FindName("comboBoxTimeZone")
        $timezone = $jsonContent.GENERAL.TIMEZONE
        if ($timezone) {
            $comboBoxTimeZone.SelectedItem = $comboBoxTimeZone.Items | Where-Object { $_.Content -eq $timezone }
        }
        else {
            $comboBoxTimeZone.SelectedIndex = 0  # Select the empty option if no timezone is set
        }
        $window.FindName("checkboxInstallAdobe").IsChecked = $jsonContent.GENERAL.INSTALLADOBE -eq "Y"
        $window.FindName("checkboxAutoReboot").IsChecked = $jsonContent.GENERAL.AUTOREBOOT -eq "Y"
        $window.FindName("checkboxLocalGroups").IsChecked = $jsonContent.GENERAL.LOCALGROUPS -eq "Y"
        $window.FindName("checkboxInstallLmx").IsChecked = $jsonContent.GENERAL.INSTALLLMX -eq "Y"
        $window.FindName("checkboxInstallCitrix").IsChecked = $jsonContent.GENERAL.INSTALLCITRIX -eq "Y"
        $window.FindName("checkboxInstallJava").IsChecked = $jsonContent.GENERAL.INSTALLJAVA -eq "Y"
        $window.FindName("checkboxInstallGpuDriver").IsChecked = $jsonContent.GENERAL.INSTALLGPUDRIVER -eq "Y"
        $window.FindName("checkboxInstallDotNet").IsChecked = $jsonContent.GENERAL.INSTALLDOTNET -eq "Y"
        $window.FindName("checkboxCleanup").IsChecked = $jsonContent.GENERAL.CLEANUP -eq "Y"
        $window.FindName("checkboxBuildRaystationGpuConfigs").IsChecked = $jsonContent.GENERAL.BUILDRAYSTATIONGPUCONFIGS -eq "Y"
        $window.FindName("checkboxInstallSql").IsChecked = $jsonContent.GENERAL.INSTALLSQL -eq "Y"
        $window.FindName("checkboxUpdateWindows").IsChecked = $jsonContent.GENERAL.UPDATEWINDOWS -eq "Y"
        $window.FindName("checkboxInstallRaystation").IsChecked = $jsonContent.GENERAL.INSTALLRAYSTATION -eq "Y"
        $window.FindName("checkboxInstallDICOM").IsChecked = $jsonContent.GENERAL.INSTALLDICOM -eq "Y"
        $window.FindName("checkboxInstallLicenseAgent").IsChecked = $jsonContent.GENERAL.INSTALLLICENSEAGENT -eq "Y"
        $window.FindName("checkboxFormatDrives").IsChecked = $jsonContent.GENERAL.FORMATDRIVES -eq "Y"
        $window.FindName("textBoxRemoteLoggingLocation").Text = $jsonContent.GENERAL.REMOTELOGGINGLOCATION

        # DRIVES tab
        $listBoxDrives = $window.FindName("listBoxDrives")
        $listBoxDrives.Items.Clear()
        foreach ($drive in $jsonContent.DRIVES) {
            $listBoxDrives.Items.Add([PSCustomObject]@{
                    DriveLetter = $drive.DriveLetter
                    DriveNumber = $drive.DriveNumber
                    DriveLabel  = $drive.DriveLabel
                })
        }

        # DESIGNATED SQL SERVER tab
        $listBoxDesignatedSqlServer = $window.FindName("listBoxDesignatedSqlServer")
        $listBoxDesignatedSqlServer.Items.Clear()
        foreach ($server in $jsonContent.DESIGNATEDSQLSERVER.DESIGNATEDSQLSERVER) {
            $listBoxDesignatedSqlServer.Items.Add($server)
        }

        # SQL tab
        $window.FindName("textBoxSqlIsoPath").Text = $jsonContent.SQL.ISOPATH
        $window.FindName("textBoxSqlFeatures").Text = $jsonContent.SQL.FEATURES
        $window.FindName("textBoxSqlInstallDir").Text = $jsonContent.SQL.INSTALLDIR
        $window.FindName("textBoxSqlDataDir").Text = $jsonContent.SQL.DATADIR
        $window.FindName("textBoxSqlBackupDir").Text = $jsonContent.SQL.BACKUPDIR
        $window.FindName("textBoxSqlTempDbDir").Text = $jsonContent.SQL.TEMPDBDIR
        $window.FindName("textBoxSqlTempLogDir").Text = $jsonContent.SQL.TEMPLOGDIR
        $window.FindName("textBoxSqlFileStreamDrive").Text = $jsonContent.SQL.FILESTREAMDRIVE
        $window.FindName("textBoxSqlFileStreamShareName").Text = $jsonContent.SQL.FILESTREAMSHARENAME
        $window.FindName("textBoxSqlPort").Text = $jsonContent.SQL.PORT
        $window.FindName("textBoxSqlInstanceName").Text = $jsonContent.SQL.INSTANCENAME
        $window.FindName("passwordBoxSqlSaPassword").Password = $jsonContent.SQL.SAPASSWORD
        $window.FindName("textBoxSqlServiceAccountName").Text = $jsonContent.SQL.SERVICEACCOUNTNAME
        $window.FindName("passwordBoxSqlServiceAccountPassword").Password = $jsonContent.SQL.SERVICEACCOUNTPASSWORD
        $window.FindName("textBoxSqlProductKey").Text = $jsonContent.SQL.PRODUCTKEY
        $window.FindName("checkboxUseTransferBits").IsChecked = $jsonContent.SQL.USETRANSFERBITS -eq "Y"
        $window.FindName("checkboxEnableProtocols").IsChecked = $jsonContent.SQL.ENABLEPROTOCOLS -eq "Y"

        # GPU tab
        $window.FindName("checkboxRemoveCurrentDriver").IsChecked = $jsonContent.GPU.REMOVECURRENTDRIVER -eq "Y"
        $window.FindName("textBoxDriverLocation").Text = $jsonContent.GPU.DRIVERLOCATION
        $window.FindName("checkboxCleanInstall").IsChecked = $jsonContent.GPU.CLEANINSTALL -eq "Y"
        $window.FindName("textBoxNvidiaLicenseTokenLocation").Text = $jsonContent.GPU.NVIDIALICENSETOKENLOCATION
        $listBoxGpuOmittedServers = $window.FindName("listBoxGpuOmittedServers")
        $listBoxGpuOmittedServers.Items.Clear()
        if ($jsonContent.GPU.OMITTEDSERVERS) {
            foreach ($server in $jsonContent.GPU.OMITTEDSERVERS) {
                $listBoxGpuOmittedServers.Items.Add($server)
            }
        }

        # LICENSING tab
        $window.FindName("checkboxConfigureHal").IsChecked = $jsonContent.LICENSING.CONFIGUREHAL -eq "Y"
        $window.FindName("checkboxLocalLicense").IsChecked = $jsonContent.LICENSING.LOCALLICENSE -eq "Y"
        $window.FindName("textBoxLicenseLocation").Text = $jsonContent.LICENSING.LICENSELOCATION
        $listBoxDesignatedServer = $window.FindName("listBoxDesignatedServer")
        $listBoxDesignatedServer.Items.Clear()
        foreach ($server in $jsonContent.LICENSING.DESIGNATEDSERVER) {
            $listBoxDesignatedServer.Items.Add($server)
        }
        $window.FindName("textBoxHalServer1").Text = $jsonContent.LICENSING.HALSERVER1
        $window.FindName("textBoxHalServer2").Text = $jsonContent.LICENSING.HALSERVER2
        $window.FindName("textBoxHalServer3").Text = $jsonContent.LICENSING.HALSERVER3

        # CITRIX tab
        $listBoxOmittedServers = $window.FindName("listBoxOmittedServers")
        $listBoxOmittedServers.Items.Clear()
        foreach ($server in $jsonContent.CITRIX.OMITTEDSERVERS) {
            $listBoxOmittedServers.Items.Add($server)
        }
        $window.FindName("textBoxDeliveryControllers").Text = $jsonContent.CITRIX.DELIVERYCONTROLLERS
        $window.FindName("textBoxCitrixIsoLocation").Text = $jsonContent.CITRIX.CITRIXISOLOCATION

        # RAYSTATION tab
        $listBoxRaystationOmittedServers = $window.FindName("listBoxRaystationOmittedServers")
        $listBoxRaystationOmittedServers.Items.Clear()
        foreach ($server in $jsonContent.RAYSTATION.OMITTEDSERVERS) {
            $listBoxRaystationOmittedServers.Items.Add($server)
        }
        $window.FindName("textBoxRaystationLocation").Text = $jsonContent.RAYSTATION.RAYSTATIONLOCATION
        $window.FindName("textBoxRaystationFeatures").Text = $jsonContent.RAYSTATION.FEATURES
        $window.FindName("textBoxDatabaseAddress").Text = $jsonContent.RAYSTATION.DATABASEADDRESS
        $window.FindName("textBoxDatabasePort").Text = $jsonContent.RAYSTATION.DATABASEPORT
        $window.FindName("textBoxDatabaseInstance").Text = $jsonContent.RAYSTATION.DATABASEINSTANCE
        $window.FindName("textBoxDatabaseSuffix").Text = $jsonContent.RAYSTATION.DATABASESUFFIX
        $window.FindName("checkboxWaitForSqlConnection").IsChecked = $jsonContent.RAYSTATION.WAITFORSQLCONNECTION -eq "Y"
        $listBoxIndexServiceServer = $window.FindName("listBoxIndexServiceServer")
        $listBoxIndexServiceServer.Items.Clear()
        foreach ($server in $jsonContent.RAYSTATION.INDEXSERVICESERVER) {
            $listBoxIndexServiceServer.Items.Add($server)
        }
        $window.FindName("textBoxIndexServiceUser").Text = $jsonContent.RAYSTATION.IndexServiceUser
        $window.FindName("passwordBoxIndexServicePwd").Password = $jsonContent.RAYSTATION.IndexServicePwd
        $window.FindName("textBoxIndexServicePort").Text = $jsonContent.RAYSTATION.IndexServicePort
        $window.FindName("checkboxGenerateSelfSignedCert").IsChecked = $jsonContent.RAYSTATION.GenerateSelfSignedCert -eq "Y"
        $window.FindName("textBoxIndexServiceCert").Text = $jsonContent.RAYSTATION.INDEXSERVICECERT
        $listBoxTransferServiceServer = $window.FindName("listBoxTransferServiceServer")
        $listBoxTransferServiceServer.Items.Clear()
        foreach ($server in $jsonContent.RAYSTATION.TRANSFERSERVICESERVER) {
            $listBoxTransferServiceServer.Items.Add($server)
        }
        $window.FindName("textBoxTransferServiceUser").Text = $jsonContent.RAYSTATION.TransferServiceUser
        $window.FindName("passwordBoxTransferServicePwd").Password = $jsonContent.RAYSTATION.TransferServicePwd

        # SERVICES tab
        $listBoxDicomServiceServer = $window.FindName("listBoxDicomServiceServer")
        $listBoxDicomServiceServer.Items.Clear()
        foreach ($server in $jsonContent.SERVICES.DICOMSERVICESERVER) {
            $listBoxDicomServiceServer.Items.Add($server)
        }
        $window.FindName("textBoxDicomServiceLocation").Text = $jsonContent.SERVICES.DICOMSERVICELOCATION
        $window.FindName("textBoxScpTitle").Text = $jsonContent.SERVICES.SCPTITLE
        $window.FindName("textBoxScpPort").Text = $jsonContent.SERVICES.SCPPORT
        $window.FindName("textBoxScpFolder").Text = $jsonContent.SERVICES.SCPFOLDER
        $window.FindName("textBoxScpDays").Text = $jsonContent.SERVICES.SCPDAYS
        $listBoxLicenseAgentServer = $window.FindName("listBoxLicenseAgentServer")
        $listBoxLicenseAgentServer.Items.Clear()
        foreach ($server in $jsonContent.SERVICES.LICENSEAGENTSERVER) {
            $listBoxLicenseAgentServer.Items.Add($server)
        }
        $window.FindName("textBoxLicenseSetupExe").Text = $jsonContent.SERVICES.LICENSESETUPEXE
        $window.FindName("textBoxServiceUser").Text = $jsonContent.SERVICES.SERVICEUSER
        $window.FindName("passwordBoxServicePwd").Password = $jsonContent.SERVICES.SERVICEPWD
        $window.FindName("textBoxServicePort").Text = $jsonContent.SERVICES.SERVICEPORT
        $window.FindName("checkboxSecureHosting").IsChecked = $jsonContent.SERVICES.SECUREHOSTING -eq "Y"
        $window.FindName("checkboxOfflineMode").IsChecked = $jsonContent.SERVICES.OFFLINEMODE -eq "Y"
        $window.FindName("textBoxLicenseServiceEndpoint").Text = $jsonContent.SERVICES.LICENSESERVICEENDPOINT
        $window.FindName("checkboxServicesGenerateSelfSignedCert").IsChecked = $jsonContent.SERVICES.GenerateSelfSignedCert -eq "Y"
        $window.FindName("textBoxCertSubject").Text = $jsonContent.SERVICES.CERTSUBJECT
        $window.FindName("textBoxCertStore").Text = $jsonContent.SERVICES.CERTSTORE
        $window.FindName("textBoxCertLocation").Text = $jsonContent.SERVICES.CERTLOCATION
        $window.FindName("textBoxServicesDatabaseAddress").Text = $jsonContent.SERVICES.DATABASEADDRESS
        $window.FindName("textBoxServicesDatabaseInstance").Text = $jsonContent.SERVICES.DATABASEINSTANCE
        $window.FindName("textBoxServicesDatabasePort").Text = $jsonContent.SERVICES.DATABASEPORT
        $window.FindName("textBoxServicesInstallDir").Text = $jsonContent.SERVICES.INSTALLDIR
    }
}

# Function to save JSON
function Save-JSON {
    $jsonPath = Join-Path $PSScriptRoot "setup.json"

    $jsonObject = @{
        GENERAL             = @{
            ENABLEAUTOLOGON           = if ($window.FindName("checkboxEnableAutoLogon").IsChecked) { "Y" } else { "N" }
            MACHINENAME               = $window.FindName("textBoxMachineName").Text
            TIMEZONE                  = $window.FindName("comboBoxTimeZone").SelectedItem.Content
            INSTALLADOBE              = if ($window.FindName("checkboxInstallAdobe").IsChecked) { "Y" } else { "N" }
            AUTOREBOOT                = if ($window.FindName("checkboxAutoReboot").IsChecked) { "Y" } else { "N" }
            LOCALGROUPS               = if ($window.FindName("checkboxLocalGroups").IsChecked) { "Y" } else { "N" }
            INSTALLLMX                = if ($window.FindName("checkboxInstallLmx").IsChecked) { "Y" } else { "N" }
            INSTALLCITRIX             = if ($window.FindName("checkboxInstallCitrix").IsChecked) { "Y" } else { "N" }
            INSTALLJAVA               = if ($window.FindName("checkboxInstallJava").IsChecked) { "Y" } else { "N" }
            INSTALLGPUDRIVER          = if ($window.FindName("checkboxInstallGpuDriver").IsChecked) { "Y" } else { "N" }
            INSTALLDOTNET             = if ($window.FindName("checkboxInstallDotNet").IsChecked) { "Y" } else { "N" }
            CLEANUP                   = if ($window.FindName("checkboxCleanup").IsChecked) { "Y" } else { "N" }
            BUILDRAYSTATIONGPUCONFIGS = if ($window.FindName("checkboxBuildRaystationGpuConfigs").IsChecked) { "Y" } else { "N" }
            INSTALLSQL                = if ($window.FindName("checkboxInstallSql").IsChecked) { "Y" } else { "N" }
            UPDATEWINDOWS             = if ($window.FindName("checkboxUpdateWindows").IsChecked) { "Y" } else { "N" }
            INSTALLRAYSTATION         = if ($window.FindName("checkboxInstallRaystation").IsChecked) { "Y" } else { "N" }
            INSTALLDICOM              = if ($window.FindName("checkboxInstallDICOM").IsChecked) { "Y" } else { "N" }
            INSTALLLICENSEAGENT       = if ($window.FindName("checkboxInstallLicenseAgent").IsChecked) { "Y" } else { "N" }
            FORMATDRIVES              = if ($window.FindName("checkboxFormatDrives").IsChecked) { "Y" } else { "N" }
            REMOTELOGGINGLOCATION     = $window.FindName("textBoxRemoteLoggingLocation").Text
        }
        DESIGNATEDSQLSERVER = @{
            DESIGNATEDSQLSERVER = @($window.FindName("listBoxDesignatedSqlServer").Items)
        }
        DRIVES              = @(
            $window.FindName("listBoxDrives").Items | ForEach-Object {
                @{
                    DriveLetter = $_.DriveLetter
                    DriveNumber = $_.DriveNumber
                    DriveLabel  = $_.DriveLabel
                }
            }
        )
        SQL                 = @{
            ENABLEPROTOCOLS        = if ($window.FindName("checkboxEnableProtocols").IsChecked) { "Y" } else { "N" }
            PORT                   = $window.FindName("textBoxSqlPort").Text
            INSTALLDIR             = $window.FindName("textBoxSqlInstallDir").Text
            TEMPDBDIR              = $window.FindName("textBoxSqlTempDbDir").Text
            SERVICEACCOUNTNAME     = $window.FindName("textBoxSqlServiceAccountName").Text
            SAPASSWORD             = $window.FindName("passwordBoxSqlSaPassword").Password
            BACKUPDIR              = $window.FindName("textBoxSqlBackupDir").Text
            FILESTREAMDRIVE        = $window.FindName("textBoxSqlFileStreamDrive").Text
            DATADIR                = $window.FindName("textBoxSqlDataDir").Text
            USETRANSFERBITS        = if ($window.FindName("checkboxUseTransferBits").IsChecked) { "Y" } else { "N" }
            TEMPLOGDIR             = $window.FindName("textBoxSqlTempLogDir").Text
            PRODUCTKEY             = $window.FindName("textBoxSqlProductKey").Text
            SERVICEACCOUNTPASSWORD = $window.FindName("passwordBoxSqlServiceAccountPassword").Password
            FILESTREAMSHARENAME    = $window.FindName("textBoxSqlFileStreamShareName").Text
            ISOPATH                = $window.FindName("textBoxSqlIsoPath").Text
            FEATURES               = $window.FindName("textBoxSqlFeatures").Text
            INSTANCENAME           = $window.FindName("textBoxSqlInstanceName").Text
        }
        LICENSING           = @{
            CONFIGUREHAL     = if ($window.FindName("checkboxConfigureHal").IsChecked) { "Y" } else { "N" }
            LOCALLICENSE     = if ($window.FindName("checkboxLocalLicense").IsChecked) { "Y" } else { "N" }
            HALSERVER1       = $window.FindName("textBoxHalServer1").Text
            HALSERVER2       = $window.FindName("textBoxHalServer2").Text
            LICENSELOCATION  = $window.FindName("textBoxLicenseLocation").Text
            DESIGNATEDSERVER = @($window.FindName("listBoxDesignatedServer").Items)
            HALSERVER3       = $window.FindName("textBoxHalServer3").Text
        }
        CITRIX              = @{
            DELIVERYCONTROLLERS = $window.FindName("textBoxDeliveryControllers").Text
            OMITTEDSERVERS      = @($window.FindName("listBoxOmittedServers").Items)
            CITRIXISOLOCATION   = $window.FindName("textBoxCitrixIsoLocation").Text
        }
        GPU                 = @{
            DRIVERLOCATION             = $window.FindName("textBoxDriverLocation").Text
            CLEANINSTALL               = if ($window.FindName("checkboxCleanInstall").IsChecked) { "Y" } else { "N" }
            REMOVECURRENTDRIVER        = if ($window.FindName("checkboxRemoveCurrentDriver").IsChecked) { "Y" } else { "N" }
            NVIDIALICENSETOKENLOCATION = $window.FindName("textBoxNvidiaLicenseTokenLocation").Text
        }
        RAYSTATION          = @{
            DATABASEPORT           = $window.FindName("textBoxDatabasePort").Text
            TransferServiceUser    = $window.FindName("textBoxTransferServiceUser").Text
            TransferServicePwd     = $window.FindName("passwordBoxTransferServicePwd").Password
            OMITTEDSERVERS         = @($window.FindName("listBoxRaystationOmittedServers").Items)
            RAYSTATIONLOCATION     = $window.FindName("textBoxRaystationLocation").Text
            IndexServicePwd        = $window.FindName("passwordBoxIndexServicePwd").Password
            TRANSFERSERVICESERVER  = @($window.FindName("listBoxTransferServiceServer").Items)
            DATABASEADDRESS        = $window.FindName("textBoxDatabaseAddress").Text
            DATABASESUFFIX         = $window.FindName("textBoxDatabaseSuffix").Text
            WAITFORSQLCONNECTION   = if ($window.FindName("checkboxWaitForSqlConnection").IsChecked) { "Y" } else { "N" }
            DATABASEINSTANCE       = $window.FindName("textBoxDatabaseInstance").Text
            IndexServiceUser       = $window.FindName("textBoxIndexServiceUser").Text
            GenerateSelfSignedCert = if ($window.FindName("checkboxGenerateSelfSignedCert").IsChecked) { "Y" } else { "N" }
            FEATURES               = $window.FindName("textBoxRaystationFeatures").Text
            INDEXSERVICECERT       = $window.FindName("textBoxIndexServiceCert").Text
            IndexServicePort       = $window.FindName("textBoxIndexServicePort").Text
            INDEXSERVICESERVER     = @($window.FindName("listBoxIndexServiceServer").Items)
        }
        SERVICES            = @{
            DATABASEPORT           = $window.FindName("textBoxServicesDatabasePort").Text
            SCPPORT                = $window.FindName("textBoxScpPort").Text
            CERTLOCATION           = $window.FindName("textBoxCertLocation").Text
            SECUREHOSTING          = if ($window.FindName("checkboxSecureHosting").IsChecked) { "Y" } else { "N" }
            SCPFOLDER              = $window.FindName("textBoxScpFolder").Text
            SERVICEPWD             = $window.FindName("passwordBoxServicePwd").Password
            LICENSEAGENTSERVER     = @($window.FindName("listBoxLicenseAgentServer").Items)
            DICOMSERVICESERVER     = @($window.FindName("listBoxDicomServiceServer").Items)
            DATABASEINSTANCE       = $window.FindName("textBoxServicesDatabaseInstance").Text
            SCPDAYS                = $window.FindName("textBoxScpDays").Text
            CERTSTORE              = $window.FindName("textBoxCertStore").Text
            SERVICEUSER            = $window.FindName("textBoxServiceUser").Text
            DATABASEADDRESS        = $window.FindName("textBoxServicesDatabaseAddress").Text
            LICENSESERVICEENDPOINT = $window.FindName("textBoxLicenseServiceEndpoint").Text
            DICOMSERVICELOCATION   = $window.FindName("textBoxDicomServiceLocation").Text
            SCPTITLE               = $window.FindName("textBoxScpTitle").Text
            SERVICEPORT            = $window.FindName("textBoxServicePort").Text
            INSTALLDIR             = $window.FindName("textBoxServicesInstallDir").Text
            GenerateSelfSignedCert = if ($window.FindName("checkboxServicesGenerateSelfSignedCert").IsChecked) { "Y" } else { "N" }
            CERTSUBJECT            = $window.FindName("textBoxCertSubject").Text
            OFFLINEMODE            = if ($window.FindName("checkboxOfflineMode").IsChecked) { "Y" } else { "N" }
            LICENSESETUPEXE        = $window.FindName("textBoxLicenseSetupExe").Text
        }
    }

    $errors = Validate-InputData

    if ($errors.Count -gt 0) {
        $errorMessage = "The following errors were found:`n`n" + ($errors -join "`n")
        [System.Windows.MessageBox]::Show($errorMessage, "Validation Errors", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
        return
    }
    
    $jsonObject | ConvertTo-Json -Depth 5 | Set-Content $jsonPath

    [System.Windows.MessageBox]::Show("Save completed successfully!", "Save Successful", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)
}

function Validate-InputData {
    $errors = @()

    # Machine name validation
    $machineName = $window.FindName("textBoxMachineName").Text
    if ($machineName -and $machineName.Length -gt 15) {
        $errors += "Machine name must be 15 characters or less."
    }

    # Time Zone validation
    $selectedTimeZone = $window.FindName("comboBoxTimeZone").SelectedItem.Content
    $validTimeZones = @("", "EST", "CST", "MST", "PST", "AST", "HST")
    if ($selectedTimeZone -notin $validTimeZones) {
        $errors += "Invalid Time Zone selected."
    }

    $textBoxRemoteLogging = $window.FindName("textBoxRemoteLoggingLocation").Text
    if ($textBoxRemoteLogging -and $textBoxRemoteLogging -notmatch '^\\\\(?:[a-zA-Z0-9_.-]+|(?:\d{1,3}\.){3}\d{1,3})\\[a-zA-Z0-9$_.-]+(?:\\[a-zA-Z0-9$_.-]+)*$') {
        $errors += "Remote Logging Location is not a valid directory path format."
    }

    # Drive validation
    $drives = $window.FindName("listBoxDrives").Items
    $driveLetters = @()
    $driveNumbers = @()
    $driveLabels = @()
    foreach ($drive in $drives) {
        if ($drive.DriveLetter -and $drive.DriveLetter -notmatch '^[A-Z]$') {
            $errors += "Drive letter '$($drive.DriveLetter)' is invalid. It should be a single letter A-Z."
        }
        if ($drive.DriveLetter -and $driveLetters -contains $drive.DriveLetter) {
            $errors += "Drive letter '$($drive.DriveLetter)' is not unique."
        }
        $driveLetters += $drive.DriveLetter

        if ($drive.DriveNumber -and $drive.DriveNumber -notmatch '^\d+$') {
            $errors += "Drive number '$($drive.DriveNumber)' is invalid. It should be an integer."
        }
        if ($drive.DriveNumber -and $driveNumbers -contains $drive.DriveNumber) {
            $errors += "Drive number '$($drive.DriveNumber)' is not unique."
        }
        $driveNumbers += $drive.DriveNumber

        if ($drive.DriveLabel -and $drive.DriveLabel -notmatch '^\w+$') {
            $errors += "Drive label '$($drive.DriveLabel)' is invalid. It should be a single word."
        }
        if ($drive.DriveLabel -and $driveLabels -contains $drive.DriveLabel) {
            $errors += "Drive label '$($drive.DriveLabel)' is not unique."
        }
        $driveLabels += $drive.DriveLabel
    }

    # File path validations
    $pathFields = @(
        @{Name = "SQL ISO Path"; Control = "textBoxSqlIsoPath"; Extension = ".iso" },
        @{Name = "SQL Install Directory"; Control = "textBoxSqlInstallDir"; IsDirectory = $true },
        @{Name = "SQL Data Directory"; Control = "textBoxSqlDataDir"; IsDirectory = $true },
        @{Name = "SQL Backup Directory"; Control = "textBoxSqlBackupDir"; IsDirectory = $true },
        @{Name = "SQL TempDB Directory"; Control = "textBoxSqlTempDbDir"; IsDirectory = $true },
        @{Name = "SQL Temp Log Directory"; Control = "textBoxSqlTempLogDir"; IsDirectory = $true },
        @{Name = "License Location"; Control = "textBoxLicenseLocation"; Extension = ".lic" },
        @{Name = "Citrix ISO Location"; Control = "textBoxCitrixIsoLocation"; Extension = ".iso" },
        @{Name = "RayStation Location"; Control = "textBoxRaystationLocation"; Extension = ".exe" },
        @{Name = "Index Service Cert"; Control = "textBoxIndexServiceCert"; Extension = ".pfx,.cer" },
        @{Name = "Driver Location"; Control = "textBoxDriverLocation"; Extension = ".exe" },
        @{Name = "NVIDIA License Token Location"; Control = "textBoxNvidiaLicenseTokenLocation"; Extension = ".tok" },
        @{Name = "Cert Location"; Control = "textBoxCertLocation"; Extension = ".pfx,.cer" },
        @{Name = "SCP Folder"; Control = "textBoxScpFolder"; IsDirectory = $true },
        @{Name = "DICOM Service Location"; Control = "textBoxDicomServiceLocation"; Extension = ".msi" },
        @{Name = "Services Install Directory"; Control = "textBoxServicesInstallDir"; IsDirectory = $true },
        @{Name = "License Setup Exe"; Control = "textBoxLicenseSetupExe"; Extension = ".exe" }
    )

    foreach ($field in $pathFields) {
        $path = $window.FindName($field.Control).Text
        if ($path) {
            if ($field.IsDirectory) {
                if ($path -notmatch '^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$') {
                    $errors += "$($field.Name) is not a valid directory path format."
                }
            }
            else {
                if ($path -notmatch '^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\.[^\\/:*?"<>|\r\n]+$') {
                    $errors += "$($field.Name) is not a valid file path format."
                }
                elseif ($field.Extension -and ($path -notmatch "($($field.Extension.Replace(',','|')))$")) {
                    $errors += "$($field.Name) should have extension $($field.Extension)."
                }
            }
        }
    }

    # Filestream Drive validation
    $filestreamDrive = $window.FindName("textBoxSqlFileStreamDrive").Text
    if ($filestreamDrive -and $filestreamDrive -notmatch '^[A-Z]:$') {
        $errors += "Filestream Drive should be in '[A-Z]:' format."
    }

    # Username validations
    $usernameFields = @(
        @{Name = "SQL Service Account Name"; Control = "textBoxSqlServiceAccountName" },
        @{Name = "Index Service User"; Control = "textBoxIndexServiceUser" },
        @{Name = "Transfer Service User"; Control = "textBoxTransferServiceUser" },
        @{Name = "Service User"; Control = "textBoxServiceUser" }
    )

    foreach ($field in $usernameFields) {
        $username = $window.FindName($field.Control).Text
        if ($username -and $username -notmatch '^[^@]+@[^@]+\.[^@]+$') {
            $errors += "$($field.Name) should be in username@domain.domain format."
        }
    }

    # Port validations
    $portFields = @(
        @{Name = "SQL Port"; Control = "textBoxSqlPort" },
        @{Name = "Database Port"; Control = "textBoxDatabasePort" },
        @{Name = "Index Service Port"; Control = "textBoxIndexServicePort" },
        @{Name = "SCP Port"; Control = "textBoxScpPort" },
        @{Name = "Service Port"; Control = "textBoxServicePort" },
        @{Name = "Services Database Port"; Control = "textBoxServicesDatabasePort" }
    )

    foreach ($field in $portFields) {
        $port = $window.FindName($field.Control).Text
        if ($port -and $port -notmatch '^\d+$') {
            $errors += "$($field.Name) should be an integer."
        }
    }

    # SQL Features validation
    $validSqlFeatures = @('SQL', 'SQLEngine', 'Replication', 'FullText', 'DQ', 'PolyBase', 'AdvancedAnalytics', 'AS', 'RS', 'DQC', 'IS', 'MDS', 'SQL_SHARED_MR', 'Tools', 'BC', 'BOL', 'Conn', 'DREPLAY_CLT', 'SNAC_SDK', 'SDK', 'LocalDB')
    $sqlFeatures = $window.FindName("textBoxSqlFeatures").Text -split ',' | ForEach-Object { $_.Trim() }
    foreach ($feature in $sqlFeatures) {
        if ($feature -and $feature -notin $validSqlFeatures) {
            $errors += "Invalid SQL feature: $feature"
        }
    }

    $sqlProductKey = $window.FindName("textBoxSqlProductKey").Text
    if ($sqlProductKey -and $sqlProductKey -notmatch '^\d{5}-\d{5}-\d{5}-\d{5}-\d{5}$') {
        $errors += "SQL Product Key should be in the format '22222-00000-00000-00000-00000'."
    }

    # RayStation Features validation
    $validRayStationFeatures = @("RayStation", "Storagetool", "Indexservice", "licenseservice", "transferservice")
    $rayStationFeatures = $window.FindName("textBoxRaystationFeatures").Text -split ',' | ForEach-Object { $_.Trim() }
    foreach ($feature in $rayStationFeatures) {
        if ($feature -and $feature -notin $validRayStationFeatures) {
            $errors += "Invalid RayStation feature: $feature"
        }
    }

    # SCP Title validation
    $scpTitle = $window.FindName("textBoxScpTitle").Text
    if ($scpTitle -and $scpTitle.Length -gt 15) {
        $errors += "SCP Title must be 15 characters or less."
    }

    # SCP Days validation
    $scpDays = $window.FindName("textBoxScpDays").Text
    if ($scpDays -and $scpDays -notmatch '^\d+$') {
        $errors += "SCP Days should be an integer."
    }

    return $errors
}

# Function to browse for file
function Browse-File {
    param($textBoxName, $filter)
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = $filter
    $result = $openFileDialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $textBox = $window.FindName($textBoxName)
        if ($textBox -and $textBox.GetType().GetProperty("Text")) {
            $textBox.Text = $openFileDialog.FileName
        }
        else {
            Write-Warning "TextBox '$textBoxName' not found or doesn't have a Text property."
        }
    }
}

# Functions for adding and removing list items
function Add-ListItem {
    param($listBoxName, $textBoxName)
    $listBox = $window.FindName($listBoxName)
    $textBox = $window.FindName($textBoxName)
    if ($listBox -and $textBox -and $textBox.Text -ne "") {
        $listBox.Items.Add($textBox.Text)
        $textBox.Clear()
    }
    else {
        Write-Warning "ListBox '$listBoxName' or TextBox '$textBoxName' not found or TextBox is empty."
    }
}

function Remove-ListItem {
    param($listBoxName)
    $listBox = $window.FindName($listBoxName)
    if ($listBox -and $listBox.SelectedItem) {
        $listBox.Items.Remove($listBox.SelectedItem)
    }
    else {
        Write-Warning "ListBox '$listBoxName' not found or no item selected."
    }
}

# Function to add a drive
function Add-Drive {
    $driveLetter = $window.FindName("textBoxDriveLetter").Text
    $driveNumber = $window.FindName("textBoxDriveNumber").Text
    $driveLabel = $window.FindName("textBoxDriveLabel").Text
    $listBoxDrives = $window.FindName("listBoxDrives")
    if ($driveLetter -and $driveNumber -and $driveLabel -and $listBoxDrives) {
        $drive = [PSCustomObject]@{
            DriveLetter = $driveLetter
            DriveNumber = $driveNumber
            DriveLabel  = $driveLabel
        }
        $listBoxDrives.Items.Add($drive)
        $window.FindName("textBoxDriveLetter").Clear()
        $window.FindName("textBoxDriveNumber").Clear()
        $window.FindName("textBoxDriveLabel").Clear()
    }
    else {
        Write-Warning "One or more Drive fields are empty or ListBox not found."
    }
}

# Function to remove a drive
function Remove-Drive {
    $listBoxDrives = $window.FindName("listBoxDrives")
    if ($listBoxDrives -and $listBoxDrives.SelectedItem) {
        $listBoxDrives.Items.Remove($listBoxDrives.SelectedItem)
    }
    else {
        Write-Warning "ListBox 'listBoxDrives' not found or no item selected."
    }
}

# Add event handlers
$elements = @(
    @{Name = "BrowseSqlInstallDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxSqlInstallDir" },
    @{Name = "BrowseSqlTempDbDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxSqlTempDbDir" },
    @{Name = "BrowseSqlBackupDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxSqlBackupDir" },
    @{Name = "BrowseSqlDataDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxSqlDataDir" },
    @{Name = "BrowseSqlTempLogDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxSqlTempLogDir" },
    @{Name = "BrowseSqlIsoPath"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxSqlIsoPath"; Filter = "ISO files (*.iso)|*.iso" },
    @{Name = "BrowseLicenseLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxLicenseLocation"; Filter = "License files (*.lic)|*.lic" },
    @{Name = "BrowseCitrixIsoLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxCitrixIsoLocation"; Filter = "ISO files (*.iso)|*.iso" },
    @{Name = "BrowseRaystationLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxRaystationLocation"; Filter = "Executable files (*.exe)|*.exe" },
    @{Name = "BrowseIndexServiceCert"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxIndexServiceCert"; Filter = "Certificate files (*.pfx;*.cer)|*.pfx;*.cer" },
    @{Name = "BrowseDriverLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxDriverLocation"; Filter = "Executable files (*.exe)|*.exe" },
    @{Name = "BrowseNvidiaLicenseTokenLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxNvidiaLicenseTokenLocation"; Filter = "Token files (*.tok)|*.tok" },
    @{Name = "BrowseCertLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxCertLocation"; Filter = "Certificate files (*.pfx;*.cer)|*.pfx;*.cer" },
    @{Name = "BrowseScpFolder"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxScpFolder" },
    @{Name = "BrowseDicomServiceLocation"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxDicomServiceLocation"; Filter = "MSI files (*.msi)|*.msi" },
    @{Name = "BrowseServicesInstallDir"; Type = "Browse"; TargetType = "Folder"; TextBox = "textBoxServicesInstallDir" },
    @{Name = "BrowseLicenseSetupExe"; Type = "Browse"; TargetType = "File"; TextBox = "textBoxLicenseSetupExe"; Filter = "Executable files (*.exe)|*.exe" },
    @{Name = "AddDesignatedSqlServer"; Type = "Add"; ListBox = "listBoxDesignatedSqlServer"; TextBox = "textBoxNewDesignatedSqlServer" },
    @{Name = "RemoveDesignatedSqlServer"; Type = "Remove"; ListBox = "listBoxDesignatedSqlServer" },
    @{Name = "AddDrive"; Type = "Custom"; Function = { Add-Drive } },
    @{Name = "RemoveDrive"; Type = "Custom"; Function = { Remove-Drive } },
    @{Name = "AddDesignatedServer"; Type = "Add"; ListBox = "listBoxDesignatedServer"; TextBox = "textBoxNewDesignatedServer" },
    @{Name = "RemoveDesignatedServer"; Type = "Remove"; ListBox = "listBoxDesignatedServer" },
    @{Name = "AddOmittedServer"; Type = "Add"; ListBox = "listBoxOmittedServers"; TextBox = "textBoxNewOmittedServer" },
    @{Name = "RemoveOmittedServer"; Type = "Remove"; ListBox = "listBoxOmittedServers" },
    @{Name = "AddRaystationOmittedServer"; Type = "Add"; ListBox = "listBoxRaystationOmittedServers"; TextBox = "textBoxNewRaystationOmittedServer" },
    @{Name = "RemoveRaystationOmittedServer"; Type = "Remove"; ListBox = "listBoxRaystationOmittedServers" },
    @{Name = "AddTransferServiceServer"; Type = "Add"; ListBox = "listBoxTransferServiceServer"; TextBox = "textBoxNewTransferServiceServer" },
    @{Name = "RemoveTransferServiceServer"; Type = "Remove"; ListBox = "listBoxTransferServiceServer" },
    @{Name = "AddIndexServiceServer"; Type = "Add"; ListBox = "listBoxIndexServiceServer"; TextBox = "textBoxNewIndexServiceServer" },
    @{Name = "RemoveIndexServiceServer"; Type = "Remove"; ListBox = "listBoxIndexServiceServer" },
    @{Name = "AddLicenseAgentServer"; Type = "Add"; ListBox = "listBoxLicenseAgentServer"; TextBox = "textBoxNewLicenseAgentServer" },
    @{Name = "RemoveLicenseAgentServer"; Type = "Remove"; ListBox = "listBoxLicenseAgentServer" }
    @{Name = "AddGpuOmittedServer"; Type = "Add"; ListBox = "listBoxGpuOmittedServers"; TextBox = "textBoxNewGpuOmittedServer" },
    @{Name = "RemoveGpuOmittedServer"; Type = "Remove"; ListBox = "listBoxGpuOmittedServers" }
)

foreach ($element in $elements) {
    $control = $window.FindName($element.Name)
    if ($control) {
        switch ($element.Type) {
            "Browse" {
                if ($element.TargetType -eq "Folder") {
                    $textBoxName = $element.TextBox
                    $control.Add_Click({
                            $folder = New-Object System.Windows.Forms.FolderBrowserDialog
                            if ($folder.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                $textBox = $window.FindName($textBoxName)
                                if ($textBox) { $textBox.Text = $folder.SelectedPath }
                            }
                        }.GetNewClosure())
                }
                elseif ($element.TargetType -eq "File") {
                    $textBoxName = $element.TextBox
                    $filter = $element.Filter
                    $control.Add_Click({
                            $dialog = New-Object System.Windows.Forms.OpenFileDialog
                            $dialog.Filter = $filter
                            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                                $textBox = $window.FindName($textBoxName)
                                if ($textBox) { $textBox.Text = $dialog.FileName }
                            }
                        }.GetNewClosure())
                }
            }
            "Add" {
                $listBoxName = $element.ListBox
                $textBoxName = $element.TextBox
                $control.Add_Click({
                        $listBox = $window.FindName($listBoxName)
                        $textBox = $window.FindName($textBoxName)
                        if ($listBox -and $textBox -and $textBox.Text -ne "") {
                            $listBox.Items.Add($textBox.Text)
                            $textBox.Clear()
                        }
                    }.GetNewClosure())
            }
            "Remove" {
                $listBoxName = $element.ListBox
                $control.Add_Click({
                        $listBox = $window.FindName($listBoxName)
                        if ($listBox -and $listBox.SelectedItem) {
                            $listBox.Items.Remove($listBox.SelectedItem)
                        }
                    }.GetNewClosure())
            }
            "Custom" {
                $control.Add_Click($element.Function)
            }
        }
    }
}

# Function to update label text
function Update-LabelText {
    $labels = $window.FindName("Grid").Children | Where-Object { $_ -is [System.Windows.Controls.Label] }
    foreach ($label in $labels) {
        $newContent = $label.Name -replace "label", "" -replace "([A-Z])", " `$1"
        $label.Content = $newContent.Trim()
    }
}

# Load existing JSON if available
Load-ExistingJSON

# Update label text
Update-LabelText

$saveButton = $window.FindName("SaveButton")
if ($saveButton) {
    $saveButton.Add_Click({
            Save-JSON
        })
}
else {
    Write-Warning "SaveButton not found in the XAML."
}

# Show the window
$window.ShowDialog() | Out-Null