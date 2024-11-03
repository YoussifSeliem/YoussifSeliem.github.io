---
title: "Mobile: catch it"
date: "2024-11-03"
tags:
    - android
thumbnail: "/assets/img/thumbnail/cyctf2024.png"
---


# solution
---
We are given in this challenge 2 APKs the main challenge is the sealing version of the apk with the real flag and the second one is the fake version with the fake flag used for testing.
The fake version contains a fake flag, but once u get the approach and get the flag you can use the same approach to get the real flag from the sealing app.

I got the source code using `Jadx`.
First thing i do usually is looking in `AndroidMainfest.xml` file.
<img src="/assets/img/cyctf qual 24/capture.png">
We have many interesting information here like
- `android:debuggable="true"` & `android:allowBackup="true"`
- We have 2 activities
    - `MainActivity` which is exported so we can access it using adb shell or by another app we create
    - `AnotherView` which isn't exported (can be accessed by activity within the same app only), It has the category `browsable` which will move us to think about deep links and webviews

Let's dig into these activities
This is the code of `MainActivity`
```java
package com.cyctf.catchit;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent reintent = getIntent();
        Uri url = reintent.getData();
        if (url != null) {
            if ("cyshield.com".equals(url.getHost())) {
                Intent intent = new Intent();
                intent.putExtra("url", String.valueOf(url));
                intent.setClass(this, AnotherView.class);
                startActivity(intent);
                return;
            }
            Intent intent2 = new Intent(this, (Class<?>) AnotherView.class);
            startActivity(intent2);
            return;
        }
        Intent intent3 = new Intent(this, (Class<?>) AnotherView.class);
        startActivity(intent3);
    }
}
```
When we analyze the code carefully we see that it sends an intent to start `AnotherView` activity, but the intent contains the Uri whose host is `cyshield.com` the intent will have an extra string with `key: url` and `value: <output of String.valueOf(url)`

Let's look at the source code of `AnotheView` activity
```java
package com.cyctf.catchit;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes3.dex */
public class AnotherView extends AppCompatActivity {
    private WebView webView;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_another_view);
        this.webView = (WebView) findViewById(R.id.webView);
        configureWebView();
        Intent intent = getIntent();
        String url = intent.getStringExtra("url");
        if (url != null) {
            intent.getData();
            this.webView.loadUrl(url);
        } else {
            this.webView.loadUrl("https://cyshield.com");
        }
    }

    private void configureWebView() {
        WebSettings webSettings = this.webView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        webSettings.setSafeBrowsingEnabled(false);
        this.webView.setWebChromeClient(new WebChromeClient());
        this.webView.setWebViewClient(new WebViewClient());
        this.webView.addJavascriptInterface(new JavaScriptInterface(), "Jester");
    }

    /* loaded from: classes3.dex */
    public class JavaScriptInterface {
        public JavaScriptInterface() {
        }

        @JavascriptInterface
        public void showFlag() {
            Toast.makeText(AnotherView.this, "Check Logs For Your Reward!!", 1).show();
            Log.d("Jester", new String("CyCtf{Fake_Flag_don't_Sumbit}"));
        }
    }
}
```
Here we have many interesting things
- We have a webview (basically you are able to navigate website within the application)
- The webview has interesting configurations in `configureWebView()` function
    - `setJavaScriptEnabled(true)`: This enables execution of JS codes which will move us to think of the attacks that involves JS like XSS, etc....
    - `setSafeBrowsingEnabled(false)`: disables the safe browsing, so the app is object to loading malicious pages (maybe used in another solution but i didn't use it in my solution actually)
    - `addJavascriptInterface(new JavaScriptInterface(), "Jester");`: This is JSInterface creation which exposes Java object to JS execution, in this case we can access the class `JavaScriptInterface()` in Java using `Jester` object in JS
- We also have have `JavaScriptInterface` class whose functions now can be accessed using `Jester`.
    - It contains `showFlag()` function, so if we can are able to execute JS code we can trigger this function using `Jester.showFlag()`, and this is our objective and we will get the flag in the logs.

After searching in different sites and asking chatgpt also i found idea
<img src="/assets/img/cyctf qual 24/capture1.png">
If i can load a url (whatever it is) and the debugging is enabled, so i can inspect it using `chrome://inspect` on my host and access the dev tools.
After accessing the devtools i can run `Jester.showFlag()` in the console.
This is out approach and let's go to see the steps.

First we need to access `AnotherView` activity, we can do this using the command `.\adb.exe shell am start-activity -n com.cyctf.catchit/.MainActivity -d https://cyshield.com/` Which will access AnotherView activity and will load `https://cyshield.com/`.
<img src="/assets/img/cyctf qual 24/capture2.png">

When we go to `chrome://inspect` on chrome on our **host laptop** we will see this
<img src="/assets/img/cyctf qual 24/capture3.png">

Click inspect and you will get the devtools, go to console to execute `Jester.showFlag()` and make sure you are getting the logs using `adb.exe logcat` and you will get the flag in these logs.
<img src="/assets/img/cyctf qual 24/capture4.png">

Thanks for Reading, I Wish this write up was useful for you.