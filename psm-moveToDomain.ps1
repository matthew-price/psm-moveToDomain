### Script to help move the PSM users from local to domain users

#Default variables
$global:pvwaAddress = ""
$global:psmConnectUsername = ""
$global:result = ""
$global:psmRootInstallLocation = "C:\Program Files (x86)\CyberArk\PSM"
$global:psmConnectPassword = ""
$global:psmAdminUsername = ""
$global:psmAdminPassword = ""
$global:domain = ""

function IsUserDomainJoined{
	Process {
		try {
		    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
            if($UserPrincipal.ContextType -eq "Domain")
            {
                return $true
            }
            else
            {
                return $false
            }   
        }
        catch {
            return $false
        }
	}
}

function Get-Variables{
    $global:domain = Read-Host "Please enter the pre-2000 domain name (e.g. DOMAIN): "
    $defaultPSMConnectUsername = $domain + "\PSMConnect"
    $defaultPSMAdminConnectUsername = $domain + "\PSMAdminConnect"

    $psmConnectCredentials = Get-Credential -Message "Please enter the domain PSMConnect credentials"
    $global:psmConnectUsername = $psmConnectCredentials.UserName
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psmConnectCredentials.Password)
    $global:psmConnectPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Need to check if this is the most secure way to do this

    $psmAdminCredentials = Get-Credential -Message "Please enter the domain PSMAdminConnect credentials"
    $global:psmAdminUsername = $psmAdminCredentials.UserName
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psmAdminCredentials.Password)
    $global:psmAdminPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR) #Need to check if this is the most secure way to do this

    ##Replaced by Get-Crential above
    #$global:psmConnectUsername = Read-Host "Please enter the PSMConnect username [$defaultPSMConnectUsername]:"
    #if([string]::IsNullOrWhiteSpace($psmConnectUsername)){$psmConnectUsername = $defaultPSMConnectUsername}

    #$global:psmAdminConnectUsername = Read-Host "Please enter the PSMAdminConnect username [$defaultPSMAdminConnectUsername]:"
    #if([string]::IsNullOrWhiteSpace($psmAdminConnectUsername)){$psmAdminConnectUsername = $defaultPSMAdminConnectUsername}

    $defaultPSMRootInstallLocation = "C:\Program Files (x86)\CyberArk\PSM"
    $global:psmRootInstallLocation = Read-Host "Please enter the root PSM install location [$defaultPSMRootInstallLocation]:"
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

    $newPsmHardeningContent = $psmHardeningContent -replace [Regex]::Escape('$COMPUTER\PSMConnect'),"$global:domain\$global:PsmConnectUsername"
    $newPsmHardeningContent = $newPsmHardeningContent -replace [Regex]::Escape('$COMPUTER\PSMAdminConnect'),"$global:domain\$global:PsmAdminUsername"

    $newPsmHardeningContent | Set-Content -Path 'C:\test-psmhardening.ps1' #Commit changes

    #PSMApplocker    

    $newPsmApplockerContent = $psmApplockerContent -replace '"PSMConnect"',"""$global:domain\PSMConnect"""
    $newPsmApplockerContent = $newPsmApplockerContent -replace '"PSMAdminConnect"',"""$global:domain\PSMAdminConnect"""

    $newPsmApplockerContent | Set-Content -Path 'C:\test-psm-applocker.ps1'

    Copy-Item -Path 'C:\test-psm-applocker.ps1' -Destination $psmRootInstallLocation\Hardening\PSMConfigureApplocker.ps1 -Force
    Copy-Item -Path 'C:\test-psmhardening.ps1' -Destination $psmRootInstallLocation\Hardening\PSMHardening.ps1 -Force
    
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
    name ="PSMConnect"
    address ="$global:domain"
    userName ="$global:psmConnectUsername"
    safeName ="PSM"
    secretType ="password"
    secret ="$global:psmConnectPassword"
    platformID ="WinDomain"
    platformAccountProperties = @{"LogonDomain"=$global:domain}
    }
    $url = $global:pvwaAddress + "PasswordVault/api/Accounts"
    $json= $body | ConvertTo-Json
    Write-Host $json
    Write-Host "Auth: $global:pvwaToken"
    $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $global:pvwaToken } -ContentType 'application/json'

}

function New-VaultAdminObjects2{

    $body  = @{
    name ="PSMAdminConnect"
    address ="$global:domain"
    userName ="$global:psmAdminUsername"
    safeName ="PSM"
    secretType ="password"
    secret ="$global:psmAdminPassword"
    platformID ="PlatformID"
    platformAccountProperties = @{"LogonDomain"=$global:domain}
    }
    $url = $global:pvwaAddress + "PasswordVault/api/Accounts"
    $json= $body | ConvertTo-Json
    Write-Host $json
    Write-Host "Auth: $global:pvwaToken"
    $Postresult = Invoke-RestMethod -Method 'Post' -Uri $url -Body $json -Headers @{ 'Authorization' = $global:pvwaToken } -ContentType 'application/json'

}


function Update-RDS{
    wmic.exe /namespace:\\root\CIMV2\TerminalServices PATH Win32_TSPermissionsSetting WHERE `(TerminalName="RDP-Tcp"`) CALL AddAccount "$global:domain\\PSMAdminConnect",0
    wmic.exe /namespace:\\root\cimv2\TerminalServices PATH Win32_TSAccount WHERE "TerminalName='RDP-Tcp' AND AccountName='$global:domain\\PSMAdminConnect'" CALL ModifyPermissions TRUE,4
    Stop-Service -Force -Name "termservice"
    Start-Service -Name "termservice"
    
    Restart-PSM
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if(IsUserDomainJoined){
    Get-Variables
    New-ConnectionToRestAPI
    Write-Host $result #remove before release
    New-VaultAdminObjects
    New-VaultAdminObjects2
    Stop-PSM
    Backup-PSMConfig
    Update-PSMConfig
    Update-RDS
    Invoke-PSMHardening
    Invoke-PSMConfigureAppLocker
    Restart-PSM
} else{
    Write-Host "Stopping. Please run this script as a domain user"
}