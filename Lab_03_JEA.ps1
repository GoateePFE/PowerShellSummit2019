break

# Lab 03 - Just Enough Administration (JEA) 

 ## Objective 

 ## Background 

 ## Overview 

 ## Exercise 3.1 - Auditing JEA 

 ### 3.1.1 - Set up the server PowerShell policies 

 Set-GPLink -Name 'PowerShell Security' -Target 'DC=training,DC=com' -LinkEnabled Yes 

 gpupdate /force /wait:0 

 Get-ChildItem HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ -Recurse 

 ### 3.1.2 - Configure JEA on the server 

 ### 3.1.3 - Connect from the client 

 ### 3.1.4 - Investigate the activity 

 ### LabJEA-Server.ps1 

 #region
 break 
  
 #region ==== Set up AD accounts =============================================== 

 #region ==== Set up AD accounts =============================================== 
  
 $Domain = $env:USERDOMAIN 
  
 $pw = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force 
 $cred_alice   = New-Object -TypeName PSCredential -ArgumentList "$Domain\alice",$pw 
 $cred_bob     = New-Object -TypeName PSCredential -ArgumentList "$Domain\bob",$pw 
 $cred_charlie = New-Object -TypeName PSCredential -ArgumentList "$Domain\charlie",$pw 
  
 $alice   = New-ADUser -Name Alice   -AccountPassword $pw -Enabled $true -PassThru 
 $bob     = New-ADUser -Name Bob     -AccountPassword $pw -Enabled $true -PassThru 
 $charlie = New-ADUser -Name Charlie -AccountPassword $pw -Enabled $true -PassThru 
  
 New-ADGroup -Name GGStorage -GroupCategory Security -GroupScope Global 
 New-ADGroup -Name GGNetwork -GroupCategory Security -GroupScope Global 
  
 Add-ADGroupMember -Identity GGStorage -Members $alice,$charlie 
 Add-ADGroupMember -Identity GGNetwork -Members $bob,$charlie 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== WinRM WSMan Remoting ============================================= 

 #region ==== WinRM WSMan Remoting ============================================= 
  
 Get-PSSessionConfiguration 
 # Notice permissions on Microsoft.PowerShell, the default endpoint... 

 # Notice permissions on Microsoft.PowerShell, the default endpoint... 
 # This is what you connect to with Enter-PSSession or Invoke-Command. 

 # This is what you connect to with Enter-PSSession or Invoke-Command. 
  
 # Remoting configuration 

 # Remoting configuration 
 dir WSMan:\localhost 
 dir WSMan:\localhost\Service 
 dir WSMan:\localhost\Listener\Listener_1084132640 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Setup JEA Module ================================================= 

 #region ==== Setup JEA Module ================================================= 
  
 # Create a folder for the module 

 # Create a folder for the module 
 $modulePath = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\SummitJEA" 
  
 # Create an empty script module and module manifest. 

 # Create an empty script module and module manifest. 
 New-Item -ItemType File -Path (Join-Path $modulePath "SummitJEAFunctions.psm1") -Force 
 New-ModuleManifest -Path (Join-Path $modulePath "SummitJEA.psd1") -RootModule "SummitJEAFunctions.psm1" 
  
 # Create the RoleCapabilities folder and copy in the PSRC file 

 # Create the RoleCapabilities folder and copy in the PSRC file 
 $rcFolder = Join-Path $modulePath "RoleCapabilities" 
 New-Item -ItemType Directory $rcFolder 
 Set-Location $rcFolder 
  
 # Observe the folder structure for JEA 

 # Observe the folder structure for JEA 
 cls; Get-ChildItem $modulePath -Recurse 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Scope capabilities =============================================== 

 #region ==== Scope capabilities =============================================== 
  
 # Constrained Language Mode 

 # Constrained Language Mode 
 Get-Help New-PSRoleCapabilityFile 
 Get-Help about_Language_Modes 
  
 # Identify the modules to import and the command types 

 # Identify the modules to import and the command types 
 Get-Command -Name 'Sort-Object','Format-Table','Format-List' | Format-Table -AutoSize 
 Get-Command -Name 'Get-SmbShare','Get-ChildItem' | Format-Table -AutoSize 
 Get-Command -Name 'Get-Disk','Get-Volume','Get-Partition' | Format-Table -AutoSize 
 Get-Command -Name 'Get-NetAdapter','Test-NetConnection' | Format-Table -AutoSize 
 Get-Command -Name ping,ipconfig,whoami | Format-Table -AutoSize 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Set up JEA with role capabilities ================================ 

 #region ==== Set up JEA with role capabilities ================================ 
  
 $rc_disk = @{ 
     Description             = 'View Disks and Shares' 
     ModulesToImport         = 'Storage','SmbShare' # Already imported by default: 'Microsoft.PowerShell.Management' 
     VisibleAliases          = 'cd', 'dir','ft','fl' 
     VisibleCmdlets          = 'Get-*Item','Set-Location','Sort-Object','Format-Table','Format-List' 
     VisibleFunctions        = 'TabExpansion2','prompt','SmbShare\Get*','Storage\Get*' 
     VisibleProviders        = 'FileSystem' 
     VisibleExternalCommands = 'C:\Windows\System32\whoami.exe' 
 } 
 New-PSRoleCapabilityFile -Path .\ViewDisksAndShares.psrc @rc_disk 
  
 $rc_network = @{ 
     Description             = 'View Network' 
     ModulesToImport         = 'NetAdapter', 'NetTCPIP' 
     VisibleAliases          = 'ft','fl' 
     VisibleCmdlets          = 'Sort-Object','Format-Table','Format-List' 
     VisibleFunctions        = 'TabExpansion2','NetAdapter\Get*','NetTCPIP\Get*','Test-NetConnection' 
     VisibleExternalCommands = 'C:\Windows\System32\whoami.exe','C:\Windows\System32\ping.exe','C:\Windows\System32\ipconfig.exe' 
 } 
 New-PSRoleCapabilityFile -Path .\ViewNetwork.psrc @rc_network 
  
 $pssc = @{ 
     SessionType         = 'RestrictedRemoteServer' 
     LanguageMode        = 'NoLanguage' 
     ExecutionPolicy     = 'Restricted' 
     RunAsVirtualAccount = $true 
     TranscriptDirectory = 'C:\PSTranscriptsJEA\' 
     RoleDefinitions     = @{ 
         "$Domain\GGStorage" = @{ RoleCapabilities = 'ViewDisksAndShares' } 
         "$Domain\GGNetwork" = @{ RoleCapabilities = 'ViewNetwork' } 
     } 
 } 
 New-PSSessionConfigurationFile -Path .\JEAConfig.pssc @pssc 
  
 Test-PSSessionConfigurationFile -Path .\JEAConfig.pssc 
  
 Register-PSSessionConfiguration -Path .\JEAConfig.pssc -Name SummitJEA 
  
 cd C:\Labs 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Test JEA ========================================================= 

 #region ==== Test JEA ========================================================= 
  
 $Domain = $env:USERDOMAIN 
  
 Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\alice" 
 Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\bob" 
 Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\charlie" 
  
 ### RDP TO CLIENT-01 AND RUN THROUGH THE LabJEA-Client.ps1 TEST SCRIPT. 

 ### RDP TO CLIENT-01 AND RUN THROUGH THE LabJEA-Client.ps1 TEST SCRIPT. 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Fingerprints ===================================================== 

 #region ==== Fingerprints ===================================================== 
  
 # Use these commands as a starting point. Adjust the parameters and pipelines 

 # Use these commands as a starting point. Adjust the parameters and pipelines 
 # to find specific events of interest. 

 # to find specific events of interest. 
  
 Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 10 -FilterXPath '*[System[(EventID=193)]]' | Format-Table -Wrap 
 Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 10 -FilterXPath '*[System[(EventID=193)]]' | Format-List * 
  
 Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 20 -FilterXPath '*[System[(EventID=800)]]' | Format-Table -Wrap 
  
 Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20 -FilterXPath '*[System[(EventID=4103 or EventID=4104)]]' | Format-Table -Wrap 
  
 # How can you differentiate between the local test sessions with Get-PSSessionCapability 

 # How can you differentiate between the local test sessions with Get-PSSessionCapability 
 # and the actual remoting sessions? Browse the transcript files and open then directly. 

 # and the actual remoting sessions? Browse the transcript files and open then directly. 
  
 dir C:\PSTranscriptsJEA -Recurse 
  
 ise (dir C:\PSTranscriptsJEA | Sort-Object LastWriteTime -Descending)[0].FullName 
  
 dir C:\PSTranscriptsJEA\ -Recurse | Sort-Object LastWriteTime | Where-Object Length -gt 0 | Select-String "stop-service" 
  
 dir C:\PSTranscripts -Recurse 
  
 dir C:\PSTranscripts\ -Recurse | Sort-Object LastWriteTime | Where-Object Length -gt 0 | Select-String "stop-service" 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
  
  
 #region ==== Reset demo ==================================================== 

 #region ==== Reset demo ==================================================== 
  
 $ErrorActionPreference = 'SilentlyContinue' 
 'alice','bob','charlie' | ForEach-Object {Get-ADUser -Identity $_ | Remove-ADUser -Confirm:$false} 
 'GGStorage','GGNetwork' | ForEach-Object {Get-ADGroup -Identity $_ | Remove-ADGroup -Confirm:$false} 
 Get-PSSessionConfiguration | 
     Where-Object {$_.Name -notin 'microsoft.powershell', 
                                  'microsoft.powershell.workflow', 
                                  'microsoft.powershell32', 
                                  'microsoft.windows.servermanagerworkflows'} | 
     ForEach-Object {Unregister-PSSessionConfiguration $_.Name} 
 #Remove-Item -Path WSMan:\localhost\Plugin\SummitJEA -Recurse -Force -Confirm:$false 

 #Remove-Item -Path WSMan:\localhost\Plugin\SummitJEA -Recurse -Force -Confirm:$false 
 cd \ 
 Remove-Item C:\PSTranscriptsJEA\ -Force -Recurse 
 Remove-Item (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\SummitJEA") -Force -Recurse 
 $ErrorActionPreference = 'Continue' 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
 #endregion

 ### LabJEA-Client.ps1 

 #region
 break 
  
 #region ==== Test JEA ========================================================= 

 #region ==== Test JEA ========================================================= 
  
 ### RUN THESE LINES FROM CLIENT-01 

 ### RUN THESE LINES FROM CLIENT-01 
  
 $Domain = $env:USERDOMAIN 
 $pw = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force 
 $cred_alice   = New-Object -TypeName PSCredential -ArgumentList "$Domain\alice",$pw 
 $cred_bob     = New-Object -TypeName PSCredential -ArgumentList "$Domain\bob",$pw 
 $cred_charlie = New-Object -TypeName PSCredential -ArgumentList "$Domain\charlie",$pw 
  
 # Within each of the following three remoting sessions try the following commands. 

 # Within each of the following three remoting sessions try the following commands. 
 # Test TAB expansion as you go along. 

 # Test TAB expansion as you go along. 
 Get-Command 
 format C: 
 Stop-Service NTDS -Force 
 Get-NetAdapter 
 Get-NetAdapterStatistics 
 Get-NetTCPConnection 
 Get-SmbShare 
 dir C:\ 
 Get-Disk 
 Get-Volume 
 Get-Partition 
 # try some commands of your own 

 # try some commands of your own 
 Exit 
  
 # Disks 

 # Disks 
 Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_alice 
  
 # Shares 

 # Shares 
 Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_bob 
  
 # Disks & Shares 

 # Disks & Shares 
 Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_charlie 
  
 #endregion ==================================================================== 

 #endregion ==================================================================== 
 #endregion


