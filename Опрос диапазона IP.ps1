################################################################################################
### Опрос IP сети управления
### Автор:  Смирнов
### Дата:   2019-09-25
### Версия: 0.1
################################################################################################


##############################
#Переменные
##############################
##Рабочая папка
$posh_dir = 'C:\PoSh'
##Путь к файлу отчета
$reportPath = "$($posh_dir)\namp\nmap_$(get-date -Format yyyy-MM-dd).xlsx"


#Подключение к VC
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope AllUsers -Confirm:$false
$VCs = @(Get-Content $posh_dir\VC_list_invent.txt)
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
Set-PowerCLIConfiguration -DefaultVIServerMode Multiple -Scope AllUsers -Confirm:$false

##Шифрование кредлов
<#
foreach ($VC in $VCs){
    New-VICredentialStoreItem -User 'CLOUD\esmirnov' -Host $VC -File c:\PoSh\vc_creds\esmirnov.vicred -Password ПАРОЛЬ
    }
#>

##Подключаемся к каждому VC
foreach ($VC in $VCs){
    $VICred = VICredentialStoreItem -File $posh_dir\vc_creds\esmirnov.vicred -Host $VC -User 'CLOUD\esmirnov'
    Connect-VIServer -Server $VC -User 'CLOUD\esmirnov' -Password $VICred.Password
    }

$VMNICs = Get-VM | Get-NetworkAdapter
$HostNICs = Get-VMHostNetworkAdapter 

$IPs = 1..254 | ForEach-Object {"10.55.5.$_"}
#$IPs = '10.55.0.122'

$IP_list = $null

$IP_list = 

foreach ($ip in $IPs){
    Write-Progress -Activity 'Опрашиваем IP' -CurrentOperation $ip -PercentComplete (($ips.IndexOf($ip) / $ips.count) * 100) -Status ('Адрес '+$ips.IndexOf($ip)+' из '+$ips.count)
    
    if (Test-Connection $ip -Count 1 -Quiet){
    #$IP='10.55.0.122'
    $nmapExec = & 'C:\Program Files (x86)\Nmap\nmap.exe' -sV -T4 -O -F --version-light $ip -oX C:\PoSh\nmap\nmap.xml
    $nmap = [xml](Get-content C:\PoSh\nmap\nmap.xml)
    Remove-Item C:\PoSh\nmap\nmap.xml -Force

    $IP_mac = $(($nmap.nmaprun.host.address | ? {$_.addrtype -eq 'mac'}).addr)
    $IP_vendor = $(($nmap.nmaprun.host.address | ? {$_.addrtype -eq 'mac'}).vendor)
    $IP_DNS_Hostname = $($nmap.nmaprun.host.hostnames.hostname.name)
    $IP_OS = $($nmap.nmaprun.host.os.osmatch.name | Select-Object -first 1)
    $IP_VM_Name = (($VMNICs | ? {$_.MacAddress -eq $IP_mac} | Select-Object parent).parent).name
    $IP_ESXi_hostname = if (($HostNICs | ? {$_.Mac -eq $IP_mac}).count -gt 0){($HostNICs | ? {$_.Mac -eq $IP_mac})[0].VMHost.name}

    New-Object -TypeName PSObject -Property @{
    'IP' = $IP
    'Status' = 'ONLINE'
    'MAC' = $IP_mac
    'Vendor' = $IP_vendor
    'DNS Hostname' = $IP_DNS_Hostname
    'OS' = $IP_OS
    'VM Name' = $IP_VM_Name
    'ESXi hostname' = $IP_ESXi_hostname
        }
    } else {
    New-Object -TypeName PSObject -Property @{
    'IP' = $IP
    'Status' = 'OFFLINE'
    'MAC' = $null
    'Vendor' = $null
    'DNS Hostname' = $null
    'OS' = $null
    'VM Name' = $null
    'ESXi hostname' = $null
        }
    
    }
    Clear-Variable nmap
}


$IP_list | Select-Object IP,status,MAC,vendor,'DNS Hostname','VM Name','ESXi hostname',OS | Export-Csv -Path C:\PoSh\nmap\nmap_vlan554_1.csv
