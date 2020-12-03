###############################
##Рабочая папка
$posh_dir = 'C:\PoSh'

$user = 'esmirnov'
$password = 'ПАРОЛЬ'

##Рабочая папка
$posh_dir = 'C:\PoSh'
$reportPath = "$($posh_dir)\Resource_Pools_$(get-date -Format yyyy-MM-dd).xlsx"

$devnull = Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false -DisplayDeprecationWarnings:$false
$devnull = Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false -DisplayDeprecationWarnings:$false

#Модули
Import-Module -Name VMware.PowerCLI
Import-Module -Name VMware.VimAutomation.Core
Import-Module -Name PSExcel
Import-Module C:\PoSh\_Modules\HTAwareMitigation-1.0.0.19\HTAwareMitigation.psm1


if (((Get-Module -Name VMware.PowerCLI) -and (Get-Module -Name VMware.VimAutomation.Core)) -and (Get-Module -Name PSExcel) -eq $false){
    Set-PSRepository -InstallationPolicy Trusted -Name PSGallery
    Install-Module -Name VMware.PowerCLI -Confirm:$false
    Install-Module -Name VMware.VimAutomation.Core -Confirm:$false
    Install-Module -Name PSExcel -Confirm:$false
    Import-Module -Name VMware.PowerCLI
    Import-Module -Name VMware.VimAutomation.Core
    Import-Module -Name PSExcel
    }

#Подключение к VC
$devnull = Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope AllUsers -Confirm:$false
$VCs = @(Get-Content $posh_dir\VC_list_invent.txt)

if ((Test-Path $posh_dir\vc_creds\$user.vicred) -eq $false){
    foreach ($VC in $VCs){
    New-VICredentialStoreItem -User "CLOUD\$($user)" -Host $VC -File c:\PoSh\vc_creds\$user.vicred -Password $password
    }

}

##Подключаемся к каждому VC
foreach ($VC in $VCs){
    Write-Progress -Activity 'Подключаемся к VC' -CurrentOperation $VC -PercentComplete (($VCs.IndexOf($VC) / $VCs.count) * 100) -Status ('VC '+$VCs.IndexOf($VC)+' из '+$VCs.count)
    $VICred = VICredentialStoreItem -File $posh_dir\vc_creds\$($user).vicred -Host $VC -User "CLOUD\$($user)"
    Connect-VIServer -Server $VC -User "CLOUD\$($user)" -Password $VICred.Password
    }


#Connect-VIServer -Server DF-VCSA-Premium-DC1.cloud.local

$VMHost = Get-VMHost| ?{$_.name -eq "dc2-esxhp-03.cloud.local"}

$LUNs = $VMHost | Get-ScsiLun -LunType disk | Where {$_.MultipathPolicy -notlike "RoundRobin" -and $_.vendor -eq "3PARdata"}
foreach ($LUN in $LUNs){
    Write-Progress -Activity 'Настраиваем Multipathing' -CurrentOperation $LUN.CanonicalName -PercentComplete (($LUNs.IndexOf($LUN) / $LUNs.count) * 100) -Status ('LUN '+$LUNs.IndexOf($LUN)+' из '+$LUNs.count)
    $LUN | Set-Scsilun -MultiPathPolicy RoundRobin
}

#Создание правила
$VMHostESXCLi = Get-esxCLI -VMHost $VMHost
$VMHostESXCLi.storage.nmp.satp.rule.list() | where {$_.description -like "*3par*"}
$VMHostESXCLi.storage.nmp.satp.rule.add($null,"tpgs_on","HP 3PAR Custom iSCSI/FC/FCoE ALUA Rule",$null,$null,$null,"VV",$null,"VMW_PSP_RR","iops=1","VMW_SATP_ALUA",$null,$null,"3PARdata")

#Настройка SCA
Set-HTAwareMitigationConfig -VMHostName $VMHost.Name -SCAv2
##Set-HTAwareMitigationConfig -VMHostName $VMHost.Name -Disable
##Get-HTAwareMitigationConfig -VMHostName $VMHost.Name

#Настройка NTP
Add-VmHostNtpServer -VMHost $VMHost -NtpServer 10.55.0.174
Get-VMHostFirewallException -VMHost $VMHost | where {$_.Name -eq "NTP client"} | Set-VMHostFirewallException -Enabled:$true
Get-VmHostService -VMHost $VMHost | Where-Object {$_.key -eq "ntpd"} | Start-VMHostService
Get-VmHostService -VMHost $VMHost | Where-Object {$_.key -eq "ntpd"} | Set-VMHostService -policy "automatic"

#Натсройка SSH
Get-VmHostService -VMHost $VMHost | Where-Object {$_.key -eq "TSM-SSH"} | Start-VMHostService
Get-VmHostService -VMHost $VMHost | Where-Object {$_.key -eq "TSM-SSH"} | Set-VMHostService -policy "automatic"
$VMHost | Get-AdvancedSetting UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 1 -Confirm:$false

#Настройка логов
#$VMHost | Get-AdvancedSetting Syslog.global.logDir | Set-AdvancedSetting -Value "[HP1.2-Scratch-Bronze-13] logs/.locker-$($VMHost.name)/log" -Confirm:$false

#Настройка Power Management
$view = (Get-VMHost $vmHost | Get-View)
(Get-View $view.ConfigManager.PowerSystem).ConfigurePowerPolicy(1)

Disconnect-VIServer *


