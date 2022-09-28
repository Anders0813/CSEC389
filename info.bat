sc query > services.log
set > enviromentVaribles.log

::Networking Info
>network.log (
	echo [ipconfig]
	ipconfig
	echo [ARP]
	arp -a
	echo [Default Routes]
	route print
	echo [DNS]
	ipconfig /all
)
::Open connections
netstat -abno >shares.log

::Shares
>shares.log (
	echo [Network Share]
	net share
	echo [Network Drives]
	net use
)
::User Info
>users.log (
	echo [Local Users]
	net user
	echo [Domain Users]
	net user /domain
)
::Group Info
>groups.log (
	echo [Local Groups]
	net localgroup
	echo [Local Administrators]
	net localgroup administrators
	echo [Local Domain Administrators]
	net localgroup administrators /domain
	echo [Domain Groups]
	net group /domain
)
::General Info
>general.log (
	echo [OS/Version]
	systeminfo
	echo [Open Ports]
	netstat -an|find "LIST"
	echo [Logged in Users]
	quser
	echo [Services]
	sc query
)
pause
