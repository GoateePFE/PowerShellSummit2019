break

# Lab 02 - PowerShell Policies in Core

## Objective

## Background

## Overview

## Exercise 2.1 - Implement logging settings

### 2.1.1 Get connected

pwsh

$PSVersionTable

### 2.1.2 PSReadLine

Get-Module

Get-Command -Module PSReadLine

Get-PSReadLineOption

### 2.1.3 PowerShell policies JSON

cd $pshome

dir *.json

cat powershell.config.lab.json

#region
    {
        "Microsoft.PowerShell:ExecutionPolicy": "RemoteSigned",
        "PowerShellPolicies": {
            "ScriptBlockLogging": {
            "EnableScriptBlockInvocationLogging": false,
            "EnableScriptBlockLogging": true
            },
            "ModuleLogging": {
            "EnableModuleLogging": false,
            "ModuleNames": [
                "*"
            ]
            },
            "Transcription": {
            "EnableTranscripting": true,
            "EnableInvocationHeader": true,
            "OutputDirectory": "/var/tmp/pstranscripts/"
            }
        },
        "LogLevel": "verbose"
    }
#endregion

sudo cp ./powershell.config.lab.json ./powershell.config.json

dir *.json

## Exercise 2.2 - Generate PowerShell activity

### 2.2.1 Generate PowerShell activity

exit

pwsh

"Hello, world."

$env:PSModulePath

Get-Process | Sort-Object CPU -Descending | Select-Object -First 5

Test-Connection ts1

exit

## Exercise 2.3 - Find PowerShell activity in the logs

### 2.3.1 PSReadLine

pwsh

(Get-PSReadLineOption).HistorySavePath

cat (Get-PSReadLineOption).HistorySavePath

/home/user/.local/share/powershell/PSReadLine/ConsoleHost_history.txt

exit

cat /home/user/.local/share/powershell/PSReadLine/ConsoleHost_history.txt

### 2.3.2 Script block logging

cd /var/log

sudo grep powershell messages

TIMESTAMP MACHINENAME powershell[PID]: (COMMITID:TID:CID)

sudo tail -f messages

pwsh

Get-Process

dir

### 2.3.3 Transcripts

ls -lR /var/tmp/pstranscripts

cd /var/tmp/pstranscripts

ls

cd USE_DATE_DIRECTORY_HERE

ls -l

nano PASTED_TXT_FILE_NAME (Use PgUp/PgDn to view the file and CTRL-X to exit.)

cat PASTED_TXT_FILE_NAME

cd /var/tmp/pstranscripts

grep -iR KEYWORD_HERE

## 2.4 Considerations for PowerShell Core logging

