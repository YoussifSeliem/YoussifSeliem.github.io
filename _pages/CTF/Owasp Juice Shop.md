---
title: "Owasp Juice Shop"
date: "2024-04-24"
thumbnail: "/assets/img/thumbnail/Juice.png"
---

# Getting started
---

OWASP Juice Shop is probably the most modern and sophisticated insecure web application! It can be used in security trainings, awareness demos, CTFs and as a guinea pig for security tools! Juice Shop encompasses vulnerabilities from the entire OWASP Top Ten along with many other security flaws found in real-world applications!

You can solve it <a href="https://github.com/juice-shop/juice-shop/tree/master">here</a>.


## ★ Finding Score board
---

When you start the challange you will get alerts from the site telling you that you need to find the score board to start.
You can consider it as the first challange, so let's go.

When we look at the source code carefully we will find JS files but `main.js` seems to be more interesting.
I opened it and sent it to <a href="https://beautifier.io/">JS Beautifier</a> to make it more organized.
I searched using the keyword `score` and found this.
<img src="/assets/img/juice shop/1.png" width=300>
The endpoint is /score-board congratzzzzz
<img src="/assets/img/juice shop/2.png" width=300>

## ★ DOM XSS
---

Perform a DOM XSS attack with ```<iframe src="javascript:alert(`xss`)">```.
After examining the site you will find an input to search functionality.
I tried to put things like `<h1>` and it's rendered successfully so let's try our payload.
<img src="/assets/img/juice shop/3.png" width=300>
Congratzzzzzz