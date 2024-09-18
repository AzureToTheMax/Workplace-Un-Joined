<#
.SYNOPSIS
This is the detection script of a Proactive Remedation designed to detect and correct the BlockAADWorkplaceJoin key...
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

$CheckKey = Get-ItemProperty "$($RegistryLocation)" -ErrorAction SilentlyContinue
if ($CheckKey. BlockAADWorkplaceJoin -eq "1"){
    Write-Output "Key in place"
    Exit 0
} else {
    Write-Error "Key missing"
    exit 1
}