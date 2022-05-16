#DNS-
$DNS1= Read-Host "Enter your primary DNS server address"
$DNS2= Read-Host "Enter your secondary DNS server address"
$dnsserver= $DNS1,$DNS2
$AllNetAdapters=Get-NetAdapter
Set-DnsClientServerAddress -InputObject $AllNetAdapters -ServerAddresses $dnsserver

#IP-
$IP= Read-Host "Enter desired IP address"
$Gateway= Read-Host "Enter desird gateway"
$CIDR= Read-Host "Enter the CIDR value of desired subnet mask... e.g. 24"
New-NetIPAddress –InterfaceAlias “Wired Ethernet Connection” –IPv4Address “$IP” –PrefixLength $CIDR -DefaultGateway $Gateway

	
If ((Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"){
	#Do something here
}else {
	Write-Warning "Please connect to Wi-Fi"
}
