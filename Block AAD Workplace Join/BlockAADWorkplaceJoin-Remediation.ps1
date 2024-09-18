<#
.SYNOPSIS
This is the remediation script of a Proactive Remedation designed to detect and correct the BlockAADWorkplaceJoin key...
See: https://learn.microsoft.com/en-us/entra/identity/devices/faq#how-can-i-block-users-from-adding-more-work-accounts--microsoft-entra-registered--on-my-corporate-windows-10-11-devices

.NOTES
Author:     Maxton Allen
Contact:    @AzureToTheMax
Created:    2024-09-15
Updated:    N/A
Version:    1.0

Credit to Sandy Zeng and Jan Ketil Skanke of the MSEndpointMGR team for the original script based version of this reg deployment back in 2021.

#>


$RegistryLocation = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\"
$keyname = "BlockAADWorkplaceJoin"

#Check if the key is already in place, in which case we can simply exit
$CheckKey = Get-ItemProperty "$($RegistryLocation)" -ErrorAction SilentlyContinue
if ($CheckKey. BlockAADWorkplaceJoin -eq "1"){
Write-Output "Key alreeady in place"
Exit 0

}

#Create the path if it is missing
if (!(Test-Path -Path $RegistryLocation) ){
Write-Output "Registry location missing. Creating"
New-Item $RegistryLocation | Out-Null
}

#Force create the key at the path now that it has been created (if it was missing)
New-ItemProperty -Path $RegistryLocation -Name $keyname -PropertyType DWord -Value 1 -Force | Out-Null

#Check the key now
$CheckKey = Get-ItemProperty "$($RegistryLocation)" -ErrorAction SilentlyContinue
if ($CheckKey. BlockAADWorkplaceJoin -eq "1"){
    Write-Output "Key now in place"
Exit 0
} else {
    Write-Error "Key still missing!"
    exit 1
}