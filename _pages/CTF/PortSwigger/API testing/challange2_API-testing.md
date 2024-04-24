---
title: "API testing: challange 2"
date: "2024-03-05"
thumbnail: "/assets/img/thumbnail/API.png"
---

# Finding and exploiting an unused API endpoint
---

Link: https://portswigger.net/web-security/api-testing/lab-exploiting-unused-api-endpoint

To solve the lab, exploit a hidden API endpoint to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter

### solution

- Start the challange by logging using wiener:peter credentials
- I navigated through the website to find api endpoints
- After some navigation, I found that when you go to `https://0ad4003703ff9a3680c8767500820061.web-security-academy.net/product?productId=1` you will visit the API endpoint `/api/products/1/price`
- After some trials i found that when i change the request method the response gives me this `Allow: GET, PATCH`
- when i try `PATCH` request method, i get this in the response
```{"type":"ClientError","code":400,"error":"Only 'application/json' Content-Type is supported"}```'
- So let's add this header ```Content-Type: application/json``` and i got internal server error
- After trials i found that by adding `{}` in the body of the request i get this message in the response ```{"type":"ClientError","code":400,"error":"'price' parameter missing in body"}```
- So i added the price parameter in the request body and set it to 0 like this ```{"price":0}```
- Nice, when i go to my cart i find that the total price = 0 so i can purchase now
- Congratzzzzzzzzzzzzzz