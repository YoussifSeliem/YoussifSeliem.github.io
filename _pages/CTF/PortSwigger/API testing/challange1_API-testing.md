---
title: "API testing: challange 1"
date: "2024-03-05"
thumbnail: "/assets/img/thumbnail/API.png"
---

# Exploiting an API endpoint using documentation
---

Link: https://portswigger.net/web-security/api-testing/lab-exploiting-api-endpoint-using-documentation

To solve the lab, find the exposed API documentation and delete carlos. You can log in to your own account using the following credentials: wiener:peter

### solution

- Start the challange by logging using wiener:peter credentials
- I navigated through the website to find api endpoints but i didn't find
- I tried to find if there's an exposed api documentation by visiting the url `https://0a3c005a033bf00881c694ba005c0041.web-security-academy.net/api/`
- I found this page
<img src="/assets/img/portswigger/api testing/Capture.PNG" alt="exposed APIs">
- The info we need are here we can delete the user carlos now by visiting `https://0a3c005a033bf00881c694ba005c0041.web-security-academy.net/api/user/carlos` and making the request `DELETE`
- Congratzzzzzzzzzzzz
