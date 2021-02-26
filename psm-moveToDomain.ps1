### Script to help move the PSM users from local to domain users

#Default variables
$global:pvwaAddress = ""
$global:psmConnectUsername = ""
$global:result = ""
$global:psmRootInstallLocation = "C:\Program Files (x86)\CyberArk\PSM"
$global:psmConnectPassword = ""

function Get-Variables{
    $global:domain = Read-Host "Please enter the pre-2000 domain name (e.g. DOMAIN): "
    $defaultPSMConnectUsername = $domain + "\PSMConnect"
    $defaultPSMAdminConnectUsername = $domain + "\PSMAdminConnect"

    $psmConnectCredentials = Get-Credential -Message "Please enter the domain PSMConnect credentials"
    $global:psmConnectUsername = $psmConnectCredentials.UserName
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psmConnectCredentials.Password)
    $global:psmConnectPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Need to check if this is the most secure way to do this

    ##Replaced by Get-Crential above
    #$global:psmConnectUsername = Read-Host "Please enter the PSMConnect username [$defaultPSMConnectUsername]:"
    #if([string]::IsNullOrWhiteSpace($psmConnectUsername)){$psmConnectUsername = $defaultPSMConnectUsername}

    $global:psmAdminConnectUsername = Read-Host "Please enter the PSMAdminConnect username [$defaultPSMAdminConnectUsername]:"
    if([string]::IsNullOrWhiteSpace($psmAdminConnectUsername)){$psmAdminConnectUsername = $defaultPSMAdminConnectUsername}

    $defaultPSMRootInstallLocation = "C:\Program Files (x86)\CyberArk\PSM"
    $global:psmRootInstallLocation = Read-Host "Please enter the root PSM install location [$global:defaultPSMRootInstallLocation]:"
    if([string]::IsNullOrWhiteSpace($global:psmRootInstallLocation)){$global:psmRootInstallLocation = $defaultPSMRootInstallLocation}

    $global:pvwaAddress = Read-Host "Please enter the Privilege Cloud Portal web address, e.g. https://subdomain.privilegecloud.cyberark.com/"
}

$global:pvwaToken = function New-ConnectionToRestAPI{
    # Get PVWA and login informatioN
    $tinaCreds = Get-Credential -Message "Please enter your Privilege Cloud admin credentials"
    $url = $global:pvwaAddress + "PasswordVault/API/auth/Cyberark/Logon"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tinaCreds.Password)

    $headerPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    $body  = @{
    username =$tinacreds.UserName
    password =$headerPass
    }
    $json= $body | ConvertTo-Json
    $global:pvwaToken = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -ContentType 'application/json'
    #Write-Host $result
    #return $result
}

function Restart-PSM{
    Restart-Service "Cyber-Ark Privileged Session Manager"
}

function Stop-PSM{
    Stop-Service "Cyber-Ark Privileged Session Manager"
}

function Backup-PSMConfig{
    Copy-Item $global:psmRootInstallLocation\Hardening\PSMHardening.ps1 -Destination $global:psmRootInstallLocation\Hardening\PSMHardening-backup.ps1
    Copy-Item $global:psmRootInstallLocation\Hardening\PSMConfigureAppLocker.ps1 -Destination $global:psmRootInstallLocation\Hardening\PSMConfigureAppLocker-backup.ps1
}

function Update-PSMConfig{
    $psmHardeningContent = Get-Content -Path $global:psmRootInstallLocation\Hardening\PSMHardening.ps1
    $psmApplockerContent = Get-Content -Path $global:psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1

    $newPsmHardeningContent = $psmHardeningContent -replace "COMPUTER\\PSMConnect","$global:domain\PSMConnect"
    $newPsmHardeningContent = $newPsmHardeningContent -replace "COMPUTER\\PSMAdminConnect","$global:domain\PSMAdminConnect"

    $newPsmHardeningContent | Set-Content -Path 'C:\test-psmhardening.ps1' #Commit changes

    #PSMApplocker    

    $newPsmApplockerContent = $psmApplockerContent -replace '"PSMConnect"',"""$global:domain\PSMConnect"""
    $newPsmApplockerContent = $newPsmApplockerContent -replace '"PSMAdminConnect"',"""$global:domain\PSMAdminConnect"""

    $newPsmApplockerContent | Set-Content -Path 'C:\test-psm-applocker.ps1'

    Copy-Item -Path 'C:\test-psm-applocker.ps1' -Destination $psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1 -Force
    
}

function Invoke-PSMHardening{
    Write-Verbose "Starting PSM Hardening"
    $hardeningScriptRoot = "$global:psmRootInstallLocation\Hardening"
    & "$hardeningScriptRoot\PSMHardening.ps1"

}

function Invoke-PSMConfigureAppLocker{
    Write-Verbose "Starting PSMConfigureAppLocker"
    $hardeningScriptRoot = "$global:psmRootInstallLocation\Hardening"
    Set-Location $hardeningScriptRoot
    & ".\PSMConfigureAppLocker.ps1"   
}

function New-VaultAdminObjects{

    $body  = @{
    name ="PSMObjectName"
    address ="$global:domain"
    userName ="$global:psmConnectUsername"
    safeName ="PSM"
    secretType ="$global:psmConnectPassword"
    secret ="PasswordHere"
    platformID ="PlatformID"
    logonDomain = "DOMAIN"
    }
    $url = $global:pvwaAddress + "PasswordVault/api/Accounts"
    $json= $body | ConvertTo-Json
    Write-Host $json
    Write-Host "Auth: $global:pvwaToken"
    $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $global:pvwaToken } -ContentType 'application/json'

}


function Update-RDS{
    wmic.exe /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSPermissionsSetting WHERE (TerminalName="RDP-Tcp") CALL AddAccount "$global:domain\\PSMAdminConnect",0
    wmic.exe /namespace:\\root\cimv2\TerminalServices PATH Win32_TSAccount WHERE "TerminalName='RDP-Tcp' AND AccountName='$global:domain\\PSMAdminConnect'" CALL ModifyPermissions TRUE,4
    Net stop termservice
    Net start termservice
    
    Restart-PSM
}


Get-Variables
New-ConnectionToRestAPI
Write-Host $result #remove before release
New-VaultAdminObjects
Stop-PSM
Backup-PSMConfig
Update-PSMConfig
Update-RDS
Invoke-PSMHardening
Invoke-PSMConfigureAppLocker
Restart-PSM