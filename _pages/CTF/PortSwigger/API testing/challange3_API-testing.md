---
title: "API testing: challange 3"
date: "2024-03-05"
thumbnail: "/assets/img/thumbnail/API.png"
---

# Exploiting a mass assignment vulnerability
---

Link: https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability

To solve the lab, find and exploit a mass assignment vulnerability to buy a Lightweight l33t Leather Jacket. You can log in to your own account using the following credentials: wiener:peter. 

### solution

- Start the challange by logging using wiener:peter credentials
- I navigated through the website to find api endpoints
- After navigation i found it when you add item to cart, go to your cart and click `place order`
- This moves you to this API endpoint `/api/checkout` and this is the request body when the request method is `POST`
```json
{
    "chosen_products":[
        {
            "product_id":"1",
            "quantity":1,
            "item_price":0
        }
    ]
}
```
- I tried to change the request method to PUT and i found in the response that only GET, POST are the allowed methods
- When i change the request method to `GET` i get this response
```json
{
    "chosen_discount":{
        "percentage":0
    },
    "chosen_products":[
        {
            "product_id":"1",
            "name":"Lightweight \"l33t\" Leather Jacket",
            "quantity":2,
            "item_price":133700
        }
    ]
}
```
- We note that there's `chosen_discount` Let's add it the body of the request and send the post request but after making the chosen_discount = 100
- Congratzzzzzzzzzzzzzzzzzz