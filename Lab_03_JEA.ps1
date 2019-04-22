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
