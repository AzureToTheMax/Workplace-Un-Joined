#Automated Removal of Secondary Azure Accounts (AzureAccountCleanup)

<#
.SYNOPSIS
This script is designed to check for additional Work or School accounts which have been added to a machine and remove them.
This is in order to restore the functionality of Enterprise Activation which is (as of 2024) negatively impacted by having any secondary accounts on the machine.

When ran, this will locate secondary accounts and attempt to remove them. It may take a reboot to full take effect, certainly for subscription activation to re-attempt in any reasonable amount of time.

.DESCRIPTION
WARNING - This is still in beta testing!

Known Issues:
    -Odd behavior has been noticed when deletion occurs while some apps are open and using a given secondary profile. For example, if Teams is signed into and active on Secondary account X, which account X was also joined to Windows rather than only signed into Teams, and you attempt deletion, it may fail.
    -If an account is added to a device BUT not ever signed into any app (such as manually adding it via the settings menu but never actually using it in an app to authenticate) it may not be detected

.NOTES
Author:     Maxton Allen
Contact:    @AzureToTheMax
Created:    2024-09-20
Updated:    2024-11-19
Version:    1.0
Website:    AzureToTheMax.Net

Credit:
    A thank you to ExpendaBubble and ChrisDent on the WinAdmins Discord for helping with the insanity that is dealing with Registry keys from an app reg (The Token Brokers settings.dat) that lack a data type.

    An additional huge thank you to Rudy Ooms (https://call4cloud.nl/) for reaching out to me to share his work on this issue.
    Importantly, a test script which had the very important line I had completely overlooked to stop the TokenBroker service. This turned out to be the key as to why my script was producing such unusual results.

V0.1:
    Script creation with the initial version being that which could detect and locate all elements to be deleted. Actual attempts to delete were flaky.

V0.2:
    -Added Rudy's logic to stop the Token Broker service, fixing the scripts ability to reliably action and delete accounts.
    -Added logging and trace, especially required for testing.
    -Added automatic backup of Settings.Dat file
    -Corrected and updated code comments, and largely removed the testing code from V0.1.
    -Finalized script for release in Beta.

v0.3
    -Added logic to the Get-CurrentUserSID to account for the possibility that there is no owner of explorer.exe currently (no user is on).
        This prevents an error from logging when further attempts to check registry keys do not work.
    -Altered logic for checking if any secondary accounts are present via the AAD\Storage\Https://login.Microsoftonline.com key to check if the key is present before attempting to pull the value.        

    
v0.4
    -Added the same error trimming and null UPN detection that V2.3 of the detection got. For this script, it also contains logging. 

V1.0
    -No changes made from V0.4 as a result of initial deployment. This change is simply marking the tool as no longer "beta." As such, I am not updating the last updated date.

#>


#Set $FileDate for use in creating transcripts, log files, and backup settings.Dat files. I want this declared here once so that all files use the same date/time. This is used by the variables section so I need to declare it now.
$FileDate = Get-Date -Format MM-dd-yyyy-HH-mm


#Region Variables
#This region contains the primary configurable variables. All explanations of what values should be are for a production deployment sense of the standard version of this script.



    $RemoveSecondaryAccounts = $true #This determines if secondary accounts are only looked up ($False) or looked up AND DELETED ($True)

    #Testing Values - do NOT touch these unless you are developing your own version of this tool!

    #$Load and $Unload control whether or not we load and unload the settings.dat of the AAD Token Broker. These are useful for when you want to instead load a static copy/backup of the Settings.Dat file for testing.
    $Load = $true #Should be $true 
    $UnLoad = $true

    #Create transcripts
    $CreateTranscripts = $True #Whether or not we create a transcript file for each execution. Disable to have less extra log files get written.

    #Storage and cache locations
	$LogFileParentFolder = "C:\Windows\AzureToTheMax"

	#The folder which will specifically be used for the cache and logging of this specific script. This includes the log file and image.
	$LogFileFolder = "C:\Windows\AzureToTheMax\AzureAccountCleanup"

	#The log file which will be made by this script. New data is always appending to the existing file.
	$LogFileName = "AzureAccountCleanup"
    #Make the log name above contain the date, time, and .Log. This makes it such that each execution is it's own log file, rather than generating one massive file.
    $LogFileName = $LogFileName+$FileDate+".Log"

#endregion





#region Functions

Function Stop-AADTokenBroker {
    #Ends the AAD Token Broker service and process.
    #THANK YOU RUDY!
    Stop-Service -Name "TokenBroker" -Force -ErrorAction SilentlyContinue
    (Get-Service "TokenBroker").WaitForStatus('Stopped') #Adding this, it helps ensure we don't move on until the service is stopped. I like this more than a random start-sleep buffer.
    get-process -name "Microsoft.AAD.brokerplugin" -ErrorAction SilentlyContinue | stop-process -Force
}





function Test-FileLock {
    #Credit to Arno Peters, this function checks to see if a file is currently in use or not. This is used on the settings.dat file.
    param (
      [parameter(Mandatory=$true)][string]$Path
    )
  
    $oFile = New-Object System.IO.FileInfo $Path
  
    if ((Test-Path -Path $Path) -eq $false) {
      return $false
    }
  
    try {
      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  
      if ($oStream) {
        $oStream.Close()
      }
      #File is not locked
      return $false
    } catch {
      # file is locked by a process.
      return $true
    }
}





function New-HiddenDirectory {
        #Used to create our storage paths if they do not exist

        param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the path to create.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path
        )

        #Only Create our folders if they don't exist to avoid errors
        if (Test-Path $Path) {
            write-host "Log File Location folder Folder exists already."
            } else {
            New-Item $Path -ItemType Directory -force -ErrorAction SilentlyContinue > $null 
            $folder = Get-Item "$Path" 
            $folder.Attributes = 'Directory','Hidden' 
            }
}





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
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Function Get-CurrentUserSID: Found User SID $($UserSid) via Get-CimInstance." -Force
        } else {
        $UserSid = $null
        }
    }

    If ($null -eq $UserSid) {
    Write-Host "Current user not found by Get-CimInstance, checking Explorer.exe"
    #User is Null. This may be an RDP session, use the owner of explorer.exe.
    $user = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User

        #Check if nothing was found and if so, return null to exit the function and ultimately cause the script to conclude that nobody is logged in.
        if($null -eq $user){
            return $null
        }

        #Mount HKU if it is not already. 
        if(test-path "HKU:\"){
            write-host "Users Root Registry (HKU) is already mounted, ignoring."
            } else {
            #Set HKU drive if not set
            New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
            }

        #Find the username values in SID path
        $value1 = (Get-ChildItem 'HKU:\*\Volatile Environment\') | Get-ItemProperty -name 'USERNAME' 
        #Get the path to that matching key
        $value2 = $value1 | Where-Object {$_."USERNAME" -like "$($user)"} | Select-Object PSParentPath
        #pull the string not the full values
        $value2 = $value2.PSParentPath
        #Remove first 47 characters before the SID "Microsoft.PowerShell.Core\Registry::HKEY_USERS\"
        $value3 = $value2.substring(47)
        $UserSid = $value3

        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Function Get-CurrentUserSID: Found User SID $($UserSid) via Explorer.exe owner." -Force

    }

    return $UserSid

}





Function Get-CurrentUser{
    #This item, similar to Get-CurrentUserSID, returns the User ID of the current user. This is done rather than $ENV:UserName because this script runs as System.
    #This method works great across the board.
    $user = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User
    return $user
}




Function Backup-SettingsDat{
    #This is used to backup the settings.dat file
    param(
            [parameter(Mandatory = $true, HelpMessage = "Specify the path to the Settings.Dat file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
            [parameter(Mandatory = $true, HelpMessage = "Specify the name for the Settings.Dat file (new file will be Settings-XXXXX.Dat where XXXXX is the supplied value).")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName
        )

    #This is used to backup the settings.dat file
    #Uses -Path and -FileName

    Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Creating backup Settings.Dat from $($path)\Settings.Dat to $($path)\Settings-$($FileName).Dat" -Force

    try {
        if((test-path "$($path)\Settings-$($FileName).Dat") -eq $false){
            #The settings.dat backup does not yet exist, so make it
            Copy-Item "$($Path)\Settings.Dat" "$($Path)\Settings-$($FileName).Dat" -Force
        } else {
            #I wrote this thinking that this backup occurred inside the loop for each account and thus could run twice, then realized that was not the case, but figured there was no reason to remove this check.
            Write-Warning "Settings-$($FileName).Dat already exists?"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Settings-$($FileName).Dat already exists." -Force
        }
    }
    catch {
        Write-Warning "Settings.Dat could not be copied, is it already copied?"
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Backup appears to have failed!" -Force
    }

    Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): backup attempt complete." -Force
    
}


#endregion





#Start Script

#Region create storage paths
    #Before anything else, including starting logging, our storage paths must exist.

    write-host "Calling for path creation: $($LogFileParentFolder)"
    New-HiddenDirectory -Path $LogFileParentFolder

    write-host "Calling for path creation: $($LogFileFolder)"
    New-HiddenDirectory -Path $LogFileFolder

#Endregion


#Region Script Prep
#Start log for this session.
    Add-Content "$($LogFileFolder)\$($LogFileName)" "

$(get-date): Azure Account Cleanup running on $($env:COMPUTERNAME)" -Force

    
    if($CreateTranscripts -eq $true){
        Write-Host "Transcript creation is enabled." -ForegroundColor Blue
        #Start writing transcript...
        Start-Transcript "$($LogFileFolder)\AzureAccountCleanup-Transcript-$($FileDate).log"

        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Started Transcript $($LogFileFolder)\AzureAccountCleanup-Transcript-$($FileDate).log" -Force
    }


#get the current user SID
    $UserSid = Get-CurrentUserSID #Logging is handled within the function
    If($null -eq $UserSid){
        #The SID returned was empty. This could just be because nobody is logged in.
        #We were unable to find the HKU:\SID
        Write-warning "Returned UserSid of -$($UserSid)- is null, exiting."
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Returned UserSid of -$($UserSid)- is null, exiting." -Force
        Stop-Transcript #Just in case.
        exit 0
    }

#Get the current User
    $user = Get-CurrentUser
    If($null -eq $User){
        #The User returned is empty. This again could just be because we have no active user, and is somewhat redundant to the above check.
        Write-warning "Returned User of -$($User)- is null, exiting."
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Returned User of -$($User)- is null, exiting." -Force
        Stop-Transcript #Just in case.
        exit 0
    }

#Mount HKU if it is not already. 
    if(test-path "HKU:\"){
        write-host "Users Root Registry (HKU) is already mounted, ignoring."
        } else {
        #Set HKU drive if not set
        New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
        }

#Endregion




#region Check for Secondary Accounts
#Test the registry path to validate our SID before all else.
    if (Test-Path "HKU:\$UserSid") {

        #This is a better way of first checking if that path exists at all, rathen than checking it and then seeing if the return is null.
        if((Test-Path "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com") -eq $false){
            write-warning "No accounts found! AAD\Storage\https://login.microsoftonline.com key not found."
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: No secondary accounts found, AAD\Storage\https://login.microsoftonline.com key not found, exiting." -Force
            Stop-Transcript
            exit 0
        }

        #By looking up if this key exists, we will know if secondary accounts are on the machine or not.
        $AADStorageKey = Get-ItemProperty "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com" -ErrorAction SilentlyContinue
        
        #If no secondary accounts are found, go ahead and exit.
        if($null -eq $AADStorageKey){
            write-warning "No accounts found!"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: No secondary accounts found, but the AAD\Storage\https://login.microsoftonline.com key did exist. Exiting." -Force
            Stop-Transcript
            exit 0
        }

        
        #Now that we know we have secondary accounts ($AADStorageKey is not null), we can see what they are.
        #Ugly but the only way I seem to be able to get the Value Names given I don't know what they are to begin with
        $AADStorageKey = ($AADStorageKey | Get-Member | Where-Object Definition -like "*System.String*" | Select-Object Definition).Definition

        $RegKeys = @() #Create our array
        $AccountID = @() #Create our array

        $AADStorageKey | ForEach-Object {
            $Temp = $_.substring(9,$_.length-9-16)
            $RegKeys += $Temp # $ReyKeys now holds the value name
            $Temp1 = $_.substring(11,$_.length-11-16)
            $AccountID += $Temp1 # $AccountID now holds the Account IDS
        }

        #Locate Microsoft.AAD.BrokerPlugin in case its _Garble ever changes.
        $BrokeFolder = Get-ChildItem -path "C:\users\$($user)\AppData\Local\Packages" | Where-Object {$_.Name -like "Microsoft.AAD.BrokerPlugin*"} | Select-Object -ExpandProperty Name
#endregion


#Region Mount Settings.Dat

        #If we are greenlit to load the Settings.Dat file, this is a testing value and should not be changed.
        If($Load -eq $true){

            #Fill in $Regfile with the full path to our Settings.dat application registry
            $RegFile = "C:\users\$($user)\AppData\Local\Packages\$($BrokeFolder)\Settings\Settings.Dat"
            $RegFileLocation = "C:\users\$($user)\AppData\Local\Packages\$($BrokeFolder)\Settings"

            #Now that we know we have secondary accounts to remove, we need to stop the Broker Plugin such that the next check (if settings.dat is in use) will succeed.
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Calling the shutdown of the TokenBroker service and Microsoft.AAD.brokerplugin process."
            Stop-AADTokenBroker #call the function to stop the service and application

            #Check if the application registry (Settings.dat) is in use
                if (Test-FileLock -Path $RegFile){
                    #The settings.dat file is busy, we cannot continue.
                    Write-Warning "The file RegFile is currently locked or does not exist!
                    RegPath: $($RegFile)"
                    Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: The file RegFile is currently locked or does not exist!
                    RegPath: $($RegFile)" -Force
                    Stop-Transcript #just in case.
                    exit 1
                } else {
                    #The settings.dat file is free

                    #The settings.dat should now be free and before ANYTHING else, let's back it up.
                    Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Backing up the Settings.Dat file." -Force
                    Write-Host "Backing up the Settings.Dat file."
                    Backup-SettingsDat -path $RegFileLocation -FileName $FileDate #Passes the Application Registry file path set just above. Uses the $FileDate also used by the transcript so all files match.

                    Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Mounting Settings.Dat: $($RegFile)"
                    #Mount it in the registry
                    reg load 'HKU\SettingsMount' $RegFile
                    #Add that mounting as PS Drive HKU\SettingsMount
                    New-PSDrive -Name HKSettingsMount -PSProvider Registry -Root HKU\SettingsMount
                }

            } else {
                Write-warning "Warning: Load set to false! Do you have a Settings.Dat file manually mounted?"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Load set to false! Do you have a Settings.Dat file manually mounted?"
            }
#Endregion



#Region Query Settings.Dat

        #We now loop through each account found in $AADStorageKey to see what correlates inside of Settings.Dat. We will then log and (if set to) delete the values.
        $RegKeys | ForEach-Object {
     
        $UniversalAccountID = $_ #Store this in a more temporary value for the delete section

        #Get tenant ID for this account (I could have got it from HKEY_USERS\XXXXX\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\XXXXX)
        $RegTenantId = reg query "HKU\SettingsMount\LocalState\SSOUsers\$($_)" /v TenantId | Where-Object { $_ -match '\s+(\S+)$'} | ForEach-Object {$matches[1] -split '(?<=\G.{2})(?!$)' -replace '^', '0x' -as [byte[]]}
        $StringTenantId = [System.Text.Encoding]::UTF8.GetString($RegTenantId)
        #Clean the data from weird problems
        $StringTenantId = $StringTenantId -replace '[^A-Za-z0-9:\-\.]+',''
        [string]$StringTenantId = $StringTenantId.Substring(0,36) #remove trailing characters
        

        #Locate the UPN for this account
        $RegUPN = (Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\*" -ErrorAction SilentlyContinue) | Get-ItemProperty -name 'TenantId' -ErrorAction SilentlyContinue
        $RegUPNTempPath = $RegUPN | Where-Object {$_."TenantId" -eq "$StringTenantId"} | Select-Object PSChildName -ErrorAction SilentlyContinue
        #Store the paths we need to delete for later
        $StringUPN = Get-ItemProperty "HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\$($RegUPNTempPath.PSChildName)" -Name "UserEmail" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UserEmail
        if ($null -eq $stringUPN){
            #If the String result is null (likely because the key for that tenant was not found), set it so we know why this has happened.
            Write-Warning "UPN of account ID $($_) in Tenant ID $($stringTenantId) not found in 'WorkplaceJoin\JoinInfo\$($($RegUPNTempPath.PSChildName))'"
            Write-Warning "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: UPN of account ID $($_) in Tenant ID $($stringTenantId) not found in 'WorkplaceJoin\JoinInfo\$($($RegUPNTempPath.PSChildName))'"
        }


        #Find the account IDs to delete
        $AccountsIDsToDelete = @() #Clear out  $AccountsIDsToDelete between loops
        $AllAccountIds = Get-ItemProperty "HKU:\SettingsMount\LocalState\AccountID" | out-string -stream | Where-Object { $_ -NOTMATCH '^ps.+' }
        $allaccountids = $allaccountids -replace ':',"$Null"
        ForEach ($I in $allaccountids ){
            if ($I -ne ""){
            $I = $I.trim()
            #Write-host "Checking AccountID $($I)" 
            $TempReg = reg query "HKU\SettingsMount\LocalState\AccountID" /v "$($I)" | Where-Object { $_ -match '\s+(\S+)$'} | ForEach-Object {$matches[1] -split '(?<=\G.{2})(?!$)' -replace '^', '0x' -as [byte[]]}
            [string]$TempString = [System.Text.Encoding]::UTF8.GetString($TempReg)
            $TempString = $TempString -replace '[^A-Za-z0-9:\-\.]+','' #Fix hidden garble
            #Remove anything after character 75
            [string]$TempString = $TempString.Substring(0,75)
            #write-host "This ID translates to $($TempString)"
            if($tempstring -eq $_){
                write-host "Matching Universal ID found on AccountID: $($I)" -ForegroundColor Green
                $AccountsIDsToDelete += $I #add it to the list to remove
            }
            }
        }


        #Find all the Tokens for the account
        $AllTokens = @()
        $TokensToDelete = @()
        $AllTokens = (Get-ChildItem "C:\Users\$($user)\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\*.tbacct") | Select-Object -ExpandProperty Name 
        ForEach ($C in $AllTokens ){
        #write-host "Checking token: $($C)"
        [string]$TokenContent = (Get-Content "C:\Users\$($user)\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\$($C)" -raw) -replace '\u0000'
        
            if ($TokenContent -like "*$($_)*"){
            Write-Host "Found matching Token to UPN! $($C)" -ForegroundColor Green
            $TokensToDelete += $C
            }
        }


        #Find the Account Client IDS for this account
        #These values do not seem to correlate to ANYTHING, however I want to leave this in the code just in case someone else figured it out.
        #The script will not report on or delete these values.
        <#
        $AccountsClientIDToDelete = @()
        #Find what AccountIDs to delete
        $AllAccountClientIDs = Get-ItemProperty "HKU:\SettingsMount\LocalState\AccountClientID" | out-string -stream | Where-Object { $_ -NOTMATCH '^ps.+' }
        $AllAccountClientIDs = $AllAccountClientIDs -replace ':',"$Null"
        ForEach ($B in $AllAccountClientIDs ){
            if ($B -ne ""){
            $B = $B.trim()
            #Write-host "Checking AccountID $($I)" 
            $TempReg = reg query "HKU\SettingsMount\LocalState\AccountClientID" /v "$($B)" | Where-Object { $_ -match '\s+(\S+)$'} | ForEach-Object {$matches[1] -split '(?<=\G.{2})(?!$)' -replace '^', '0x' -as [byte[]]}
            [string]$TempString = [System.Text.Encoding]::UTF8.GetString($TempReg)
            #Fix hidden garble
            $TempString = $TempString -replace '[^A-Za-z0-9:\-\.]+',''

            #Write-Host $TempString
            #Remove anything after character 75
            #[string]$TempString = $TempString.Substring(0,75)
            #write-host "This Account Client ID translates to $($TempString)"
            if($TokensToDelete -contains $tempstring){
                write-host "Matching account client ID found! : $($B)" -ForegroundColor Green
                $AccountsClientIDToDelete += $B
            }
        
            }
        }
        #>


        #Write to console and log all the values we just determined.
            write-host "On Account $($_)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): On Account $($_)"

            write-host "Account is $($StringUPN)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Account is $($StringUPN)"

            write-host "Tenant ID is $($StringTenantId)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Tenant ID is $($StringTenantId)"

            write-host "Found SSO path: $(Test-Path "HKU:\SettingsMount\LocalState\SSOUsers\$($_)")"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Found SSO path: $(Test-Path "HKU:\SettingsMount\LocalState\SSOUsers\$($_)")"

            if (Get-ItemProperty "HKU:\SettingsMount\LocalState\UniversalToAccountID" -name $_ -ErrorAction SilentlyContinue) {
            write-host "Found Universal To Account ID path: HKU:\SettingsMount\LocalState\UniversalToAccountID\$($_)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Found Universal To Account ID path: HKU:\SettingsMount\LocalState\UniversalToAccountID\$($_)"
            } else {
            Write-Warning "ToACcountID not found for HKU:\SettingsMount\LocalState\UniversalToAccountID\$($_)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: ToACcountID not found for HKU:\SettingsMount\LocalState\UniversalToAccountID\$($_)"
            }

            if (Get-ItemProperty "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com" -name $_ -ErrorAction SilentlyContinue) {
                write-host "Found AAD Storage path: HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com\$($_)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Found AAD Storage path: HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com\$($_)"
            } else {
                Write-Warning "AAD Storage path not found"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: AAD Storage path not found: HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com\$($_)"
                }

            if (Get-ItemProperty "HKU:\SettingsMount\LocalState\AccountPicture" -name $StringUPN -ErrorAction SilentlyContinue) {
                write-host "Found AccountPicture for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Found AccountPicture for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)"
            } else {
                Write-Warning "Account Picture not found"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Account Picture not found for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)"
                }
            
            if (Get-ItemProperty "HKU:\SettingsMount\LocalState\AccountPicture" -name "$($StringUPN)|perUser" -ErrorAction SilentlyContinue) {
                write-host "Found Per USer AccountPicture for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)|perUser"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "Found Per USer AccountPicture for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)|perUser"
            }else {
                Write-Warning "Per User Account Picture not found"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Per User Account Picture not found for $($StringUPN): HKU:\SettingsMount\LocalState\AccountPicture\$($StringUPN)|perUser"
                }
            
            if (Get-ItemProperty "HKU:\$UserSid\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\$($StringTenantId)" -ErrorAction SilentlyContinue) {
                write-host "Found Tenant Key in WorkplaceJoin\TenantInfo - $($StringTenantId)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "Found Tenant Key in WorkplaceJoin\TenantInfo - $($StringTenantId)"
            } else {
                Write-Warning "TenantInfo key not found for $($StringTenantId)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: TenantInfo key not found for $($StringTenantId)"
                }
            
            Write-host "Also to be deleted: HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\$($RegUPNTempPath.PSChildName)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "Also to be deleted: HKU:\$($UserSid)\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo\$($RegUPNTempPath.PSChildName)"

            ForEach ($X in $AccountsIDsToDelete ){
                if(get-ItemProperty "HKU:\SettingsMount\LocalState\AccountID" -name $X -ErrorAction SilentlyContinue){
                    if (''-ne $X){
                    write-host "I would also remove HKU:\SettingsMount\LocalState\AccountID\$($X)"
                    Add-Content "$($LogFileFolder)\$($LogFileName)" "I would also remove HKU:\SettingsMount\LocalState\AccountID\$($X)"
                    }
            } else {
            Write-Warning "Not Found: HKU:\SettingsMount\LocalState\AccountID\$($X)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Not Found: HKU:\SettingsMount\LocalState\AccountID\$($X)"
            }
            }


            if (Get-ItemProperty "C:\Users\$($user)\AppData\Local\Packages\$($BrokeFolder)\AC\TokenBroker\Accounts\" -ErrorAction SilentlyContinue) {
                write-host "Found Tenant Key in WorkplaceJoin\TenantInfo - $($StringTenantId)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "Found Tenant Key in WorkplaceJoin\TenantInfo - $($StringTenantId)"
            } else {
                Write-Warning "TenantInfo key not found for $($StringTenantId)"
                Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: TenantInfo key not found for $($StringTenantId)"
                }

                    
            ForEach ($Z in $TokensToDelete ){
                if(test-path "C:\Users\$($user)\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\$($Z)" -ErrorAction SilentlyContinue){
                    write-host "I would also remove Token HKU:\SettingsMount\LocalState\AccountClientID\$($Z)"   
                    Add-Content "$($LogFileFolder)\$($LogFileName)" "I would also remove Token HKU:\SettingsMount\LocalState\AccountClientID\$($Z)"
            } else {
            Write-Warning "Not Found Token: $($Z)"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Not Found Token: $($Z)"
            }
            }

       

        #See note in the section that fills the value for $AccountsClientIDToDelete
        <#
        ForEach ($Z in $AccountsClientIDToDelete ){
            if(get-ItemProperty "HKU:\SettingsMount\LocalState\AccountClientID" -name $Z -ErrorAction SilentlyContinue){
                if (''-ne $Z){
                write-host "I would also remove HKU:\SettingsMount\LocalState\AccountClientID\$($Z)"
                }
        } else {
        Write-Warning "Not Found: HKU:\SettingsMount\LocalState\AccountClientID\$($Z)"
        }
        }
        #>


#Endregion
        




#Region Delete Values
        if($RemoveSecondaryAccounts -eq $true){
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Deletion is ENABLED, starting."

        #remove the SSOUsers\U:Account.Tenant and all values inside
        Remove-Item -path "HKU:\SettingsMount\LocalState\SSOUsers\$($_)" -Recurse -Force

        #Remove the Universal To Account ID entry with name matching U:Account.Tenant
        Remove-ItemProperty "HKU:\SettingsMount\LocalState\UniversalToAccountID" -name $UniversalAccountID -Force

        #Remove the account picture entry matching the UPN
        Remove-ItemProperty "HKU:\SettingsMount\LocalState\AccountPicture" -name $StringUPN -Force

        #Remove the second account entry picture matching the UPN "Per user" entry 
        Remove-ItemProperty "HKU:\SettingsMount\LocalState\AccountPicture" -name "$($StringUPN)|perUser" -Force

        #Remove the entry is AAD\Storage\etc matching U:Account.Tenant
        Remove-ItemProperty "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\AAD\Storage\https://login.microsoftonline.com" -name $UniversalAccountID -Force

        #Remove Tenant Info in WorkplaceJoin\TenantInfo looking for tenant ID
        Remove-Item -path "HKU:\$UserSid\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\TenantInfo\$($StringTenantId)" -Recurse -Force

        #Cycle through the AccountIDs to delete
        ForEach ($X in $AccountsIDsToDelete ){
            Remove-ItemProperty "HKU:\SettingsMount\LocalState\AccountID" -name $X.ToString() -Force
            if ($X -ne ""){
            #write-host "I would removeHKU:\SettingsMount\LocalState\AccountID\$($X)"
            }
        }

        <#
        #See note in the section that fills the value for $AccountsClientIDToDelete
        #Cycle through Account Client IDs to delete
        ForEach ($Z in $AccountsClientIDToDelete ){
            Remove-ItemProperty "HKU:\SettingsMount\LocalState\AccountClientID" -name $Z.ToString()
            if ($Z -ne ""){
            #write-host "I would removeHKU:\SettingsMount\LocalState\AccountID\$($X)"
            }
        }
        #>

        ForEach ($Z in $TokensToDelete ){
            if(test-path "C:\Users\$($user)\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\$($Z)" -ErrorAction SilentlyContinue){
                Remove-Item -path "C:\Users\$($user)\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\AC\TokenBroker\Accounts\$($Z)" -force
        } else {
        Write-Warning "Not Found Token: $($Z)"
        }
        }

        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Deletion complete."
        


        } else {
        Write-warning "Warning: Remove is set to false!"
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Deletion is DISABLED!"
        }
#Endregion

} #Close the loop for the for "$RegKeys | ForEach-Object {". AGain, this is cycled through one per account found.





#Region Unload Settings.Dat
#Now that all accounts have been cycled through, we can unload our settings.dat file.
        If($Unload -eq $true){
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Unloading Settings.Dat!"
            Remove-PSDrive HKSettingsMount
            [gc]::collect()
            start-sleep 10 #Give it 10 seconds to let our accesses files be freed from the PowerShell process such that we can thus unmount the settings.Dat file and 
            reg unload 'HKU\SettingsMount'
            } else {
            Write-warning "Warning: Unload of Settings.DAT is set to false!"
            Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: Unload of Settings.Dat is DISABLED!"
        }
#endregion





#region End Script
#We can now bring the script to a clean close by starting the tokenBroker again, stopping our log file, stopping the transcript, and exiting.
        #Get the Token Broker going again
        Start-service -name "tokenbroker" -ErrorAction Ignore

        #Stop Logging
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Script ending."

        #Stop Transcript
        Stop-Transcript

        #Exit
        exit 0

#Endregion
       

#Region Catch false HKU:\SID
#Super far loop back for the else to if we were unable to find the HKU:\SID, but it was not null. I may relocate this eventually.
    } else {
        Write-warning "HKU:\$($UserSid) not found, exiting."
        Add-Content "$($LogFileFolder)\$($LogFileName)" "$(get-date): Warning: HKU:\$($UserSid) not found, exiting." -Force
        Stop-Transcript #Just in case.
        exit 1
}
#EndRegion







