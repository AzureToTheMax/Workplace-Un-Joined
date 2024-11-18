<#
.SYNOPSIS
This is the detection script of a Proactive Remediation designed to detect if a machine has existing Workplace join (Entra registered) accounts...

This should be deployed as only a detection script, use 64-bit mode, and run it as the logged on credential.

.NOTES
Author:     Maxton Allen
Contact:    @AzureToTheMax
Created:    2024-09-15
Updated:    2024-11-18
Version:    2.3
Website:    AzureToTheMax.Net

2.0
    -This script was updated to now report what the secondary accounts are, rather than simply confirm if some account(s) appear(s) to be present.
    -This was largely cannibalized from my Automated removal script.

2.1
    -Corrected a wrong Else loop on the user determination which was causing a null user to always be returned on physical devices.

2.2
    -Added logic to the Get-CurrentUserSID to account for the possibility that there is no owner of explorer.exe currently (no user is on).
        This prevents an error from logging when further attempts to check registry keys do not work.
    -Altered logic for checking if any secondary accounts are present via the AAD\Storage\Https://login.Microsoftonline.com key to check if the key is present before attempting to pull the value.

2.3
    -Added logic to handle a missing "JoinInfo\$($RegUPNTempPath.PSChildName)" key and instead report back the tenant ID and expected location of key rather than the current null response.

#>


Function Get-CurrentUserSID{
    #Gets the SID of the current user. This is a bit fancy to also account for devices using RDP where get-ciminstance won't work.
    $ComputerNameForSID = $env:COMPUTERNAME

    If ($ComputerNameForSID -notlike "*CPC-*") {
        #If this is not a CPC, try pulling the current user SID via Get-CimInstance
            $CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
        if (-not ([string]::IsNullOrEmpty($CurrentLoggedOnUser))) {
            $AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
            $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
            $UserSid = $strSID.Value
        } else {
        $UserSid = $null
        }
    }

    If ($null -eq $UserSid) {
    #Write-Host "Current user not found by Get-CimInstance, checking Explorer.exe"
    #User is Null. This may be an RDP session, use the owner of explorer.exe.
    $user = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User

    #Check if nothing was found and if so, return null to exit the function and ultimately cause the script to conclude that nobody is logged in.
        if($null -eq $user){
            return $null
        }

        #Mount HKU if it is not already. 
        if(test-path "HKU:\"){
            #write-host "Users Root Registry (HKU) is already mounted, ignoring."
            } else {
            #Set HKU drive if not set
            New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
            }

        #Find the username values in SID path
        $value1 = (Get-ChildItem 'HKU:\*\Volatile Environment\' -ErrorAction SilentlyContinue ) | Get-ItemProperty -name 'USERNAME' 
        #Get the path to that matching key
        $value2 = $value1 | Where-Object {$_."USERNAME" -like "$($user)"} | Select-Object PSParentPath
        #pull the string not the full values
        $value2 = $value2.PSParentPath
        #Remove first 47 characters before the SID "Microsoft.PowerShell.Core\Registry::HKEY_USERS\"
        $value3 = $value2.substring(47)
        $UserSid = $value3



    }

    return $UserSid

}

Function Get-CurrentUser{
    #This item, similar to Get-CurrentUserSID, returns the User ID of the current user. This is done rather than $ENV:UserName because this script runs as System.
    #This method works great across the board.
    $user = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User
    return $user
}

$UserSid = $null #leave this
$UserSid = Get-CurrentUserSID #Get the SID of the current user
$user = Get-CurrentUser #Get the current User

if ($null -eq $UserSid){
Write-host "A user could not be determined at this time."
exit 1
}

#Mount HKU if it is not already. 
if(test-path "HKU:\"){
    #write-host "Users Root Registry (HKU) is already mounted, ignoring."
    } else {
    #Set HKU drive if not set
    New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
    }


if (Test-Path "HKU:\$UserSid") {

    #This is a better way of first checking if that path exists at all, rathen than checking it and then seeing if the return is null.
    if((Test-Path "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com") -eq $false){
        Write-Host "A workplace account was not detected. AAD\Storage\https://login.microsoftonline.com key not found."
        exit 0 
    }

    $AADStorageKey = Get-ItemProperty "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com" -ErrorAction SilentlyContinue
        
        #If no secondary accounts are found, go ahead and exit.
        if($null -eq $AADStorageKey){
            Write-Host "A workplace account was not detected."
            exit 0
        }

        
        #Now that we know we have secondary accounts ($AADStorageKey is not null), we can see what they are.
        #Ugly but the only way I seem to be able to get the Value Names given I don't know what they are to begin with
        $AADStorageKey = ($AADStorageKey | Get-Member | Where-Object Definition -like "*System.String*" | Select-Object Definition).Definition

        $RegKeys = @() #Create our array
        $AccountID = @() #Create our array
        $AccountUPNs = @()

        $AADStorageKey | ForEach-Object {
            $Temp = $_.substring(9,$_.length-9-16)
            $RegKeys += $Temp # $ReyKeys now holds the value name
            $Temp1 = $_.substring(11,$_.length-11-16)
            $AccountID += $Temp1 # $AccountID now holds the Account IDS
        }
} else {
    Write-Host "Something went wrong with SID determination"
    exit 1
}

#loop through all the accounts we found to determine and thus report their UPN
$RegKeys | ForEach-Object {

    #Find the tenantID (I can just take it from the universal ID rather than cracking open the settings.Dat)
    $StringTenantId = $_.Substring(39) #Must be calculated per account loop
    #write-host "Tenant ID is $($StringTenantId)"

    #Locate the UPN for this account
    $RegUPN = (Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\*") | Get-ItemProperty -name 'TenantId' -ErrorAction SilentlyContinue
    $RegUPNTempPath = $RegUPN | Where-Object {$_."TenantId" -eq "$StringTenantId"} | Select-Object PSChildName -ErrorAction SilentlyContinue
    #Store the paths we need to delete for later
    $StringUPN = Get-ItemProperty "HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\$($RegUPNTempPath.PSChildName)" -Name "UserEmail" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserEmail
    if ($null -eq $stringUPN){
        #If the String result is null (likely because the key for that tenant was not found), set it so we know why this has happened.
        $StringUPN = "UPN of account ID $($_) in Tenant ID $($stringTenantId) not found in 'WorkplaceJoin\JoinInfo\$($($RegUPNTempPath.PSChildName))'"
    }
    $AccountUPNs += $StringUPN

}

write-host "The following workplace joined accounts were detected: $($AccountUPNs)"
exit 1

