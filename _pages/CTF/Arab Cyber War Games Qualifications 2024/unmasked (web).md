---
title: "Web: unmasked"
date: "2024-08-03"
tags:
    - sqli
thumbnail: "/assets/img/thumbnail/ascwgs24.png"
---


# Description
---
You need to read the flag stored in /flag.txt

# Solution
---
When we start the challange we will see this login page and register page
<img src="/assets/img/ascwgs/sign up.png">
After examining the register page i tried to register an account with username = admin and i got error as the name is used before
The interesting part the i get the query in the response in case of error
<img src="/assets/img/ascwgs/query.png">
This response gave me interesting information about the query.
We knew it's `INSERT` query and we knew how the parameters we provide are put into this query.
i created a normal user account and logged in to see the next page and i found an upload page.
<img src="/assets/img/ascwgs/sign in.png">
There's many interesting notes in this page like
- The userId
- The email of the user is reflected in page

I tried to upload different files(php files, images, etc)
but there's no way to access them
I guessed there's a directory for uploads at `/uploads` and this was true but i got status code `403 forbidden`

Anyway i went back to register and my main goal was to get access on admin's account
I thought i can get access to more resources by getting access on admin's account.

I made sure that username is vulnerable to sqli and from errors I knew it's MariaDB database.
After Thinking and attempts i reached to the idea of using stacked queries in this sequence `Insert Update Insert`

I tried this
```
username=admin1','y@g.c','8870b2ae75733c08f557a6333e1aa7502ca50541');UPDATE+users+SET+password+%3d+'8870b2ae75733c08f557a6333e1aa7502ca50541'+WHERE+username+=+'admin';+INSERT+INTO+users(username,+email,+password)+VALUES+('kakashi2&email=adminqqq%40admin.com&password=admin
```
By using this payload i though i'll be able to insert a user whose name is `admin1` and update the password of `admin` and insert another user whose name is `kakashi2` but i got this error..
<img src="/assets/img/ascwgs/error.png">
Actually, I couldn't solve it so i tried a different approache which is SSTI in email parameter but also no interesting output.
I read the challange again and found that we just need to read `/flag.txt`
After searching i found that there's a function called `LOAD_FILE(file path)` in MariaDB <a href="https://mariadb.com/kb/en/load_file/">here</a>.
I used it to load /flag.txt in email parameter and this because email parameter is reflected in the next page so we can see the file in that page.

I modified the payload to be this
```
username=admin3',LOAD_FILE('/flag.txt'),'8870b2ae75733c08f557a6333e1aa7502ca50541')#;&email=adminqqq%40admin.com&password=admin
```
Then login using this account AND .....
<img src="/assets/img/ascwgs/flag.png">
GG !!!