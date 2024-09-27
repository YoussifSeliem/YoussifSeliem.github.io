---
title: "Web: Coco Elda3eef Revenge (Hard) -- My First Blood --"
date: "2024-09-27"
thumbnail: "/assets/img/thumbnail/ieee-victoris.png"
---

# Solution
---
This challenge is the hard version of `coco elda3eef`.

When we get the files of the challenge we will see this file hierarchy and it's exactly the same like coco elda3eef easy challenge.
<img src="/assets/img/ieee-victoris/capture.png">

We have a web server running by nodeJS and there's an nginx proxy between the client and the server
The `server.js` code is very simple and the same as the previous challenge.
```js
const express = require('express');
const app = express();
const port = 3000;

app.get('/', (req, res) => {
  res.sendfile('index.html');
});

app.get('/internal', (req, res) => {
  resp = process.env.FLAG || "IEEE{test_flag}"
  res.send(resp);
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
```

It's running on port 3000, and to get the flag you need to visit `/internal` endpoint.
But when we look at `nginx.conf` and here is the difference
```js
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    server {
        listen 80;

        location ~* ^/internal$ { 
            allow 127.0.0.1;
            deny all;
            return 403;
        }

        location ~* ^/internal/ { 
            allow 127.0.0.1;
            deny all;
            return 403;
        }

        location / {
            proxy_pass http://ghazy-corp:3000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```
from the code of the proxy we see that if we visit `/internal` directly we will get `403 forbidden status code`.
But this can't be bypassed like the previous challenge because of this
<img src="/assets/img/ieee-victoris/capture2.png">
so we can't use `/InTernal` to bypass it.
After searching i found this <a href="https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass#nodejs-express">candy</a>
The interesting part is here
<img src="/assets/img/ieee-victoris/capture3.png">
we have characters that nginx can see it but nodeJS removes it.
so we can append this character to `/internal` so bypassing the nginx rule and it this appended character will be removed by nodeJS resulting in visiting `/internal and getting the flag

from the blog we need the character whose hex is `A0` so we will change the hex of the appended character to `A0`.
<img src="/assets/img/ieee-victoris/capture4.png">
Let's apply changes and send the request
<img src="/assets/img/ieee-victoris/capture5.png">
And Congratzzzzzzzzzzzz.