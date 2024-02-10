---
title: "Misc: GitMeow (medium)"
date: "2024-02-10"
thumbnail: "/assets/img/thumbnail/0xl4ugh24.png"
---

# Description
---

Just another annoying git challenge :)

Author: zAbuQasem

nc 172.190.120.133 50001


# Solution
---

There's an attached code with the challange and we will care about `challange.py` file in it
The content is

```py
import os
from banner import monkey

BLACKLIST = ["|", "\"", "'", ";", "$", "\\", "#", "*", "(", ")", "&", "^", "@", "!", "<", ">", "%", ":", ",", "?", "{", "}", "`","diff","/dev/null","patch","./","alias","push"]

def is_valid_utf8(text):
    try:
        text.encode('utf-8').decode('utf-8')
        return True
    except UnicodeDecodeError:
        return False

def get_git_commands():
    commands = []
    print("Enter git commands (Enter an empty line to end):")
    while True:
        try:
            user_input = input("")
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input:
            break

        if not is_valid_utf8(user_input):
            print(monkey)
            exit(1337)

        for command in user_input.split(" "):
            for blacklist in BLACKLIST:
                if blacklist in command:
                    print(monkey)
                    exit(1337)
            

        commands.append("git " + user_input)

    return commands

def execute_git_commands(commands):
    for command in commands:
        output = os.popen(command).read()
        if "{f4k3_fl4g_f0r_n00b5}" in output:
            print(monkey)
            exit(1337)
        else:
            print(output)
            


commands = get_git_commands()
execute_git_commands(commands)
```

- When we analyze the code carefully, we will find many important things
    - The program accepts input from user and this input is used in git command in the format `git input`
    - The input is tested against the words in the blacklist
    - you can execute more than one command
    - supplying endline means no more input

So we need to make use of git commands to get the flag.
Let's start the challange

```bash
──(youssif㉿youssif)-[~]
└─$ nc 172.190.120.133 50004

 _____ _ _  ___  ___                   
|  __ (_) | |  \/  |                   
| |  \/_| |_| .  . | ___  _____      __ 
| | __| | __| |\/| |/ _ \/ _ \ \ /\ / / 
| |_\ \ | |_| |  | |  __/ (_) \ V  V /  
 \____/_|\__\_|  |_/\___|\___/ \_/\_/   

[+] Welcome challenger to the epic GIT Madness, can you read /flag.txt?
Enter git commands (Enter an empty line to end):
```

- I started by trying simple commands like `git status`, `git log` and this is done by supplying `status` & `log` as inputs

```bash
[+] Welcome challenger to the epic GIT Madness, can you read /flag.txt?
Enter git commands (Enter an empty line to end):
status
log
   
On branch master
Untracked files:
  (use "git add <file>..." to include in what will be committed)
        ../../.dockerenv
        ../../bin/
        ../../dev/
        ../../etc/
        ../
        ../../lib/
        ../../proc/
        ../../run/
        ../../sbin/
        ../../sys/
        ../../tmp/
        ../../usr/
        ../../var/

nothing added to commit but untracked files present (use "git add" to track)

commit c208c6664cc72304ec7803c612c10a4f468338e8
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Sat Feb 10 00:31:43 2024 +0000

    .

commit 14f7055bac6cffb5e5c052577c4b607ef776de6c
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 21:05:03 2024 +0000

    i

commit bc7f31f90f4c9071af36e50059a61fd7630dc2a2
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 19:58:48 2024 +0000

    a

commit ab5579000510625d0c8340b5b5ee06fbb32ac3d0
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 19:48:05 2024 +0000

    a

commit f57b0e151d5ed760ed6b78af993d8f69a48a0b1a
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 17:03:30 2024 +0000

    dummy

commit 76877ac666f00e4928cbdad873eb1b3d2011ebbb
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 16:57:01 2024 +0000

    dummy

commit 504f31a3c83e8cca42a9ef17d4bf74b89bff9d66
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 16:57:00 2024 +0000

    dummy
```

- After them i tried to make use of `git diff` but i got error and the error because `diff` is blacklisted
- So we need to search more and after searching i found it
- The command `git log --stat -M` which provides a detailed overview of the commit history, including file modifications and renames.

```bash
[+] Welcome challenger to the epic GIT Madness, can you read /flag.txt?
Enter git commands (Enter an empty line to end):
log --stat -M

commit 4d6f6931ab8c2de5d54755d933ef0c629a2e821b
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Sat Feb 10 00:26:34 2024 +0000

    .

Notes:
    0xL4ugh{GiT_D0c3_F0r_Th3_WiN}

 flag.txt | 1 +
 1 file changed, 1 insertion(+)

commit b02cbef94904b3d8247d96568290432a3031b152
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 19:49:18 2024 +0000

    a

 archive123.zip | Bin 1927 -> 28391 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)

commit 27adc7dc97eef4a627344c44df44b2058002e9d0
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 17:00:50 2024 +0000

    dummy

 archive123.zip | Bin 0 -> 1927 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)

commit 90f6d50253dd542fcad7ab2def60e79403212ccd
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 16:24:39 2024 +0000

    dummy

 git-diagnostics-2024-02-09-1624.zip | Bin 0 -> 14631 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)

commit 5926449b1592558e499f72e5820fc5518def581a
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 16:21:38 2024 +0000

    dummy

 git-diagnostics-2024-02-09-1621.zip | Bin 0 -> 14490 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)

commit ca244e18bb33e611af1d4d7397d9ab31d0af7972
Author: zAbuQasem <zAbuQasem@0xL4ugh.com>
Date:   Fri Feb 9 16:11:24 2024 +0000

    KAY

 .gitconfig                          |   5 ++++
 __pycache__/banner.cpython-311.pyc  | Bin 0 -> 966 bytes
 banner.py                           |  20 +++++++++++++
 challenge.py                        |  56 ++++++++++++++++++++++++++++++++++++
 entrypoint.sh                       |  22 ++++++++++++++
 exec.sh                             |  18 ++++++++++++
 git-diagnostics-2024-02-09-1540.zip |   0
 git-diagnostics-2024-02-09-1545.zip |   0
 git-diagnostics-2024-02-09-1546.zip |   0
 git-diagnostics-2024-02-09-1548.zip |   0
 git-diagnostics-2024-02-09-1552.zip |   0
 git-diagnostics-2024-02-09-1556.zip |   0
 12 files changed, 121 insertions(+)
 ```
You got it look at the output again the flag is right there.
The flag: `0xL4ugh{GiT_D0c3_F0r_Th3_WiN}`