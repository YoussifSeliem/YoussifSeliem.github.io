---
title: "Domain Enumeration"
tags:
    - active directory
date: "2024-07-16"
thumbnail: "/assets/img/thumbnail/kerberos.png"
bookmark: true
---

Here we are going to cover some enumeration & credentials dumping techniques.

# Powerview
---
It's a powerfull powershell script that can be used for enumerating a domain after you have already gained a shell in the system(Post Exploitation).

## installation
You can download it from <a href="https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1">here</a>.
Send it to the victim.

## usage
- `powershell -ep bypass` : to bypass execution policy and run powershell scripts in more free way (It's just exists to prevent us from executing scripts by accident so we can shut it off using the previous command)
- `. .\PowerView.ps1` : to start powerview
Now we are able to do some enumeration


```powershell
PS C:\Users\Administrator\Desktop> Get-NetDomain


Forest                  : rift.local
DomainControllers       : {NINJA-DC.rift.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : NINJA-DC.rift.local
RidRoleOwner            : NINJA-DC.rift.local
InfrastructureRoleOwner : NINJA-DC.rift.local
Name                    : rift.local
```

Users Enumeration
```powershell
PS C:\Users\Administrator\Desktop> Get-NetUser | select cn

cn
--
Administrator
Guest
DefaultAccount
Eng
krbtgt
kayn
jax
zed
SQL Service
abdo kandil
ahmed
sphinky
7aidor
```

Group Enumeration
```powershell
PS C:\Users\Administrator\Desktop> Get-NetGroup -name *admin* | select cn

cn
--
Administrators
Hyper-V Administrators
Storage Replica Administrators
Schema Admins
Enterprise Admins
Domain Admins
Key Admins
Enterprise Key Admins
DnsAdmins
```

Shares Enumeration
```powershell
PS C:\Users\Administrator\Desktop> Invoke-ShareFinder

Name           Type Remark              ComputerName
----           ---- ------              ------------
ADMIN$   2147483648 Remote Admin        NINJA-DC.rift.local
C$       2147483648 Default share       NINJA-DC.rift.local
hackme            0                     NINJA-DC.rift.local
IPC$     2147483651 Remote IPC          NINJA-DC.rift.local
NETLOGON          0 Logon server share  NINJA-DC.rift.local
SYSVOL            0 Logon server share  NINJA-DC.rift.local
```

OS enumeration of the computers in the domain
```powershell
PS C:\Users\Administrator\Desktop> Get-NetComputer | select operatingsystem

operatingsystem
---------------
Windows Server 2016 Datacenter
Windows 10 Enterprise LTSC
```
use `Get-NetComputer -fulldata | select operatingsystem` if the previous command didn't work

This is a brief intro about installing and using powerview (OFC you can use it in more enumerations)

# BloodHound
---
It uses graph theory to represent the relationships between the components within Active Directory.
It visualizes the gathered data so identifing the complex paths within the Active Directory.

We actually have 3 main parts `Neo4j`, `SharpHound` & `BloodHound`
- `Neo4j`: is a native graph database that implements a true graph model all the way down to the storage level.
- `SharpHound`: is the script that actually collects the data.
- `BloodHound`: is used for visualizing the collected data by SharpHound

## installation
- `apt-get install bloodhound` : to install bloodhound on your attacking machine.
- `neo4j console` : starting neo4j console and you will have neo4j:neo4j default credentials you will change the password and use the new creds in the next logins
- You can download SharpHound from <a href="https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1">here</a>.
- Send it to the victim.

## usage
- On the target bypass exec policy like we did in powerview `powershell -ep bypass`
- `. .\SharpHound.ps1` to start sharphound.
- `Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip` This will result in zip file called loot.zip contains the collected data.
- Sent that zip file to the attacking machine
- open bloodhound on the attacking machine using `bloodhound`
- drag the zip file to bloodhound and now you can use the ready queries or create a custom query to be visualized

This's example of visualizing of `Find all Domain Admins` query
<img src="/assets/img/active dir/capture3.jpg" alt="bloodhound">