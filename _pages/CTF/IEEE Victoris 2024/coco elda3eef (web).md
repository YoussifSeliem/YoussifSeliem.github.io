---
title: "Web: Coco Elda3eef (Easy)"
date: "2024-09-27"
thumbnail: "/assets/img/thumbnail/ieee-victoris.png"
---

# Solution
---
When we get the files of the challenge we will see this file hierarchy.
<img src="/assets/img/ieee-victoris/capture.png">

We have a web server running by nodeJS and there's an nginx proxy between the client and the server
The `server.js` code is very simple
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
But when we look at `nginx.conf`
```js
worker_processes 1;

events {
    worker_connections 1024;
}

http {
    server {
        listen 80;

        location = /internal {
            allow 127.0.0.1;
            deny all;
            return 403;
        }

        location = /internal/ {
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
This can be bypassed easily by visiting `/InTernal` as example (change the case of any character)
<img src="/assets/img/ieee-victoris/capture1.png">
And Congratzzzzzzzzzzzz.