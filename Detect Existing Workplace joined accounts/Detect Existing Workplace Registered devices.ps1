<#
.SYNOPSIS
This is the detection script of a Proactive Remedation designed to detect if a machine has existing Workplace join (Entra registered) accounts...

This should be deployed as only a detection script, use 64-bit mode, and run it as the logged on credential.

.NOTES
Author:     Maxton Allen
Contact:    @AzureToTheMax
Created:    2024-09-15
Updated:    N/A
Version:    1.0

#>

$DsOutput = dsregcmd.exe /status

if($DsOutput -like "*WorkplaceJoined : YES*"){
    #Workplace joined account found
    Write-host "A workplace account has been detected!"
    Exit 1
}

if($DsOutput -like "*WorkplaceJoined : NO*"){
    #Workplace Joined account not found
    Write-Host "A workplace account was not detected."
    exit 0
}