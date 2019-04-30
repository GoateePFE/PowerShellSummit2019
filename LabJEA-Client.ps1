break

#region ==== Test JEA =========================================================

### RUN THESE LINES FROM CLIENT-01

$Domain = $env:USERDOMAIN
$pw = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force
$cred_alice   = New-Object -TypeName PSCredential -ArgumentList "$Domain\alice",$pw
$cred_bob     = New-Object -TypeName PSCredential -ArgumentList "$Domain\bob",$pw
$cred_charlie = New-Object -TypeName PSCredential -ArgumentList "$Domain\charlie",$pw

# Within each of the following three remoting sessions try the following commands.
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
Exit

# Disks
Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_alice

# Network
Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_bob

# Disks & Network
Enter-PSSession -ComputerName ts1 -ConfigurationName SummitJEA -Credential $cred_charlie

#endregion ====================================================================
