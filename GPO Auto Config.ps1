#Add OU Structure
New-ADOrganizationalUnit -Name "corp" -Path "DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Service Accounts" -Path "OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Domain Users" -Path "OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Domain Groups" -Path "OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Unmanaged" -Path "OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "managed" -Path "OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Linux" -Path "OU=managed,OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=managed,OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "RDP Enabled" -Path "OU=Servers,OU=managed,OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=managed,OU=corp,DC=ad,DC=depaulseclabs,DC=com"
New-ADOrganizationalUnit -Name "RDP Enabled" -Path "OU=Workstations,OU=managed,OU=corp,DC=ad,DC=depaulseclabs,DC=com"

#Add Regular Users
$secpasswd = ConvertTo-SecureString -String "RK5A&i09" -AsPlainText -Force
New-ADUser -Name "Ethan Anderson" -GivenName "Ethan" -Surname "Anderson" -SamAccountName "eanderson" -UserPrincipalName "eanderson@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "B3iP08@1" -AsPlainText -Force
New-ADUser -Name "Andrew Green" -GivenName "Andrew" -Surname "Green" -SamAccountName "agreen" -UserPrincipalName "agreen@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "HV0d!2y*" -AsPlainText -Force
New-ADUser -Name "John Capparelli" -GivenName "John" -Surname "Capparelli" -SamAccountName "jcapparelli" -UserPrincipalName "jcapparelli@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "6Vz3%i0R" -AsPlainText -Force
New-ADUser -Name "Rolando Monarrez" -GivenName "Rolando" -Surname "Monarrez" -SamAccountName "rmonarrez" -UserPrincipalName "rmonarrez@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "rtA05H0^" -AsPlainText -Force
New-ADUser -Name "Ratvik Patel" -GivenName "Ratvik" -Surname "Patel" -SamAccountName "rpatel" -UserPrincipalName "rpatel@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "9iM0!BUa" -AsPlainText -Force
New-ADUser -Name "Victor Atanasov" -GivenName "Victor" -Surname "Atanasov" -SamAccountName "vatanasov" -UserPrincipalName "vatanasov@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true

#Add Privileged Users
$secpasswd = ConvertTo-SecureString -String "D&^%B!Noq2T8" -AsPlainText -Force
New-ADUser -Name "Privileged - Ethan Anderson" -GivenName "Ethan" -Surname "Anderson" -SamAccountName "p-eanderson" -UserPrincipalName "eanderson@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "z4h4nt3C#jzA" -AsPlainText -Force
New-ADUser -Name "Privileged - Andrew Green" -GivenName "Andrew" -Surname "Green" -SamAccountName "p-agreen" -UserPrincipalName "p-agreen@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "5&GY6gt8LKcK" -AsPlainText -Force
New-ADUser -Name "Privileged - John Capparelli" -GivenName "John" -Surname "Capparelli" -SamAccountName "p-jcapparelli" -UserPrincipalName "p-jcapparelli@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "L26Ia1ms&!7b" -AsPlainText -Force
New-ADUser -Name "Privileged - Rolando Monarrez" -GivenName "Rolando" -Surname "Monarrez" -SamAccountName "p-rmonarrez" -UserPrincipalName "p-rmonarrez@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "@oE2WT35w&&$" -AsPlainText -Force
New-ADUser -Name "Privileged - Ratvik Patel" -GivenName "Ratvik" -Surname "Patel" -SamAccountName "p-rpatel" -UserPrincipalName "p-rpatel@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "*bDJU&674DIb" -AsPlainText -Force
New-ADUser -Name "Privileged - Victor Atanasov" -GivenName "Victor" -Surname "Atanasov" -SamAccountName "p-vatanasov" -UserPrincipalName "p-vatanasov@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true

#Add Domain Admins
$secpasswd = ConvertTo-SecureString -String "!vNxsIdY8247Mp0*" -AsPlainText -Force
ew-ADUser -Name "Domain - Ethan Anderson" -GivenName "Ethan" -Surname "Anderson" -SamAccountName "d-eanderson" -UserPrincipalName "eanderson@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "ReallyBadStuffIsHappening!" -AsPlainText -Force
ew-ADUser -Name "Zachary Musgrave" -GivenName "Zachary" -Surname "Musgrave" -SamAccountName "zmusgrave" -UserPrincipalName "zmusgrave@ad.depaulseclabs.com" -Path "OU='Domain Users',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true

#Add Service Accounts
$secpasswd = ConvertTo-SecureString -String "^4yaWLk8%BFw" -AsPlainText -Force
ew-ADUser -Name "Domain Join" -GivenName "Domain" -Surname "Join" -SamAccountName "domain" -UserPrincipalName "domain@ad.depaulseclabs.com" -Path "OU='Service Accounts',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "S!lu2CI4sgQ7" -AsPlainText -Force
ew-ADUser -Name "svc-splunk" -GivenName "Splunk" -Surname "Service" -SamAccountName "svc-splunk" -UserPrincipalName "svc-splunk@ad.depaulseclabs.com" -Path "OU='Service Accounts',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true
$secpasswd = ConvertTo-SecureString -String "c!oOHA4%7aiu" -AsPlainText -Force
ew-ADUser -Name "svc-nessus" -GivenName "Nessus" -Surname "Service" -SamAccountName "svc-nessus" -UserPrincipalName "svc-nessus@ad.depaulseclabs.com" -Path "OU='Service Accounts',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -AccountPassword $secpasswd  -Enabled $true

#Add Groups
New-ADGroup -Name "G-Domain Admins" -SamAccountName "G-Domain Admins" -GroupCategory Security -GroupScope Global -DisplayName "G-Domain Admins" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Domain Admins"
New-ADGroup -Name "G-Local Admin" -SamAccountName "G-Local Admin" -GroupCategory Security -GroupScope Global -DisplayName "G-Local Admin" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Local Admins"
New-ADGroup -Name "G-Linux Admins" -SamAccountName "G-Linux Admins" -GroupCategory Security -GroupScope Global -DisplayName "G-Linux Admins" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Linux Admins"
New-ADGroup -Name "G-Linux Users" -SamAccountName "G-Linux Users" -GroupCategory Security -GroupScope Global -DisplayName "G-Linux Users" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Linux Users"
New-ADGroup -Name "G-Domain Users" -SamAccountName "G-Domain Users" -GroupCategory Security -GroupScope Global -DisplayName "G-Domain Users" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Domain Users"
New-ADGroup -Name "G-Domain Join" -SamAccountName "G-Domain Join" -GroupCategory Security -GroupScope Global -DisplayName "G-Domain Join" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "This Group is reserved for the Domain account whos primary function is to join devices to the domain"
New-ADGroup -Name "G-RDP Enabled" -SamAccountName "G-RDP Enabled" -GroupCategory Security -GroupScope Global -DisplayName "G-RDP Enabled" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are RDP Enabled"
New-ADGroup -Name "G-Service Accounts" -SamAccountName "G-Service Accounts" -GroupCategory Security -GroupScope Global -DisplayName "G-Service Accounts" -Path "OU='Domain Groups',OU=corp,DC=ad,DC=depaulseclabs,DC=com" -Description "Members of this group are Service Accounts"

#Add Users to Groups
Add-ADGroupMember -Identity "G-Service Accounts" -Member domain
Add-ADGroupMember -Identity "G-Service Accounts" -Member svc-splunk
Add-ADGroupMember -Identity "G-Service Accounts" -Member svc-nessus

Add-ADGroupMember -Identity "G-Domain Admins" -Member zmusgrave
Add-ADGroupMember -Identity "G-Domain Admins" -Member d-eanderson

Add-ADGroupMember -Identity "G-Local Admin" -Member p-eanderson
Add-ADGroupMember -Identity "G-Local Admin" -Member p-agreen
Add-ADGroupMember -Identity "G-Local Admin" -Member p-jcapparelli
Add-ADGroupMember -Identity "G-Local Admin" -Member p-rmonarrez
Add-ADGroupMember -Identity "G-Local Admin" -Member p-rpatel
Add-ADGroupMember -Identity "G-Local Admin" -Member p-vatanasov
Add-ADGroupMember -Identity "G-Local Admin" -Member svc-splunk
Add-ADGroupMember -Identity "G-Local Admin" -Member svc-nessus

Add-ADGroupMember -Identity "G-Linux Admins" -Member p-eanderson
Add-ADGroupMember -Identity "G-Linux Admins" -Member svc-splunk
Add-ADGroupMember -Identity "G-Linux Admins" -Member svc-nessus

Add-ADGroupMember -Identity "G-Domain Users" -Member agreen
Add-ADGroupMember -Identity "G-Domain Users" -Member eanderson
Add-ADGroupMember -Identity "G-Domain Users" -Member jcapparelli
Add-ADGroupMember -Identity "G-Domain Users" -Member rmonarrez
Add-ADGroupMember -Identity "G-Domain Users" -Member rpatel
Add-ADGroupMember -Identity "G-Domain Users" -Member vatanasov
Add-ADGroupMember -Identity "G-Domain Users" -Member zmusgrave


Add-ADGroupMember -Identity "G-Domain Join" -Member domain

Add-ADGroupMember -Identity "G-RDP Enabled" -Member agreen
Add-ADGroupMember -Identity "G-RDP Enabled" -Member eanderson
Add-ADGroupMember -Identity "G-RDP Enabled" -Member jcapparelli
Add-ADGroupMember -Identity "G-RDP Enabled" -Member rmonarrez
Add-ADGroupMember -Identity "G-RDP Enabled" -Member rpatel
Add-ADGroupMember -Identity "G-RDP Enabled" -Member vatanasov
Add-ADGroupMember -Identity "G-RDP Enabled" -Member zmusgrave
