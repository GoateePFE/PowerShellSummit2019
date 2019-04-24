break

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


#region ==== WinRM WSMan Remoting =============================================

Get-PSSessionConfiguration
# Notice permissions on Microsoft.PowerShell, the default endpoint...
# This is what you connect to with Enter-PSSession or Invoke-Command.

# Remoting configuration
dir WSMan:\localhost
dir WSMan:\localhost\Service
dir WSMan:\localhost\Listener\Listener_1084132640

#endregion ====================================================================


#region ==== Setup JEA Module =================================================

# Create a folder for the module
$modulePath = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\SummitJEA"

# Create an empty script module and module manifest.
New-Item -ItemType File -Path (Join-Path $modulePath "SummitJEAFunctions.psm1") -Force
New-ModuleManifest -Path (Join-Path $modulePath "SummitJEA.psd1") -RootModule "SummitJEAFunctions.psm1"

# Create the RoleCapabilities folder and copy in the PSRC file
$rcFolder = Join-Path $modulePath "RoleCapabilities"
New-Item -ItemType Directory $rcFolder
Set-Location $rcFolder

# Observe the folder structure for JEA
cls; Get-ChildItem $modulePath -Recurse

#endregion ====================================================================


#region ==== Scope capabilities ===============================================

# Constrained Language Mode
Get-Help New-PSRoleCapabilityFile
Get-Help about_Language_Modes

# Identify the modules to import and the command types
Get-Command -Name 'Sort-Object','Format-Table','Format-List' | Format-Table -AutoSize
Get-Command -Name 'Get-SmbShare','Get-ChildItem' | Format-Table -AutoSize
Get-Command -Name 'Get-Disk','Get-Volume','Get-Partition' | Format-Table -AutoSize
Get-Command -Name 'Get-NetAdapter','Test-NetConnection' | Format-Table -AutoSize
Get-Command -Name ping,ipconfig,whoami | Format-Table -AutoSize

#endregion ====================================================================


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


#region ==== Test JEA =========================================================

$Domain = $env:USERDOMAIN

Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\alice"
Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\bob"
Get-PSSessionCapability -ConfigurationName 'SummitJEA' -Username "$Domain\charlie"

### RDP TO CLIENT-01 AND RUN THROUGH THE LabJEA-Client.ps1 TEST SCRIPT.

#endregion ====================================================================


#region ==== Fingerprints =====================================================

# Use these commands as a starting point. Adjust the parameters and pipelines
# to find specific events of interest.

Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 10 -FilterXPath '*[System[(EventID=193)]]' | Format-Table -Wrap
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 10 -FilterXPath '*[System[(EventID=193)]]' | Format-List *

Get-WinEvent -LogName 'Windows PowerShell' -MaxEvents 20 -FilterXPath '*[System[(EventID=800)]]' | Format-Table -Wrap

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 20 -FilterXPath '*[System[(EventID=4103 or EventID=4104)]]' | Format-Table -Wrap

# How can you differentiate between the local test sessions with Get-PSSessionCapability
# and the actual remoting sessions? Browse the transcript files and open then directly.

dir C:\PSTranscriptsJEA -Recurse

ise (dir C:\PSTranscriptsJEA | Sort-Object LastWriteTime -Descending)[0].FullName

dir C:\PSTranscriptsJEA\ -Recurse | Sort-Object LastWriteTime | Where-Object Length -gt 0 | Select-String "stop-service"

dir C:\PSTranscripts -Recurse

dir C:\PSTranscripts\ -Recurse | Sort-Object LastWriteTime | Where-Object Length -gt 0 | Select-String "stop-service"

#endregion ====================================================================


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
cd \
Remove-Item C:\PSTranscriptsJEA\ -Force -Recurse
Remove-Item (Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\SummitJEA") -Force -Recurse
$ErrorActionPreference = 'Continue'

#endregion ====================================================================
