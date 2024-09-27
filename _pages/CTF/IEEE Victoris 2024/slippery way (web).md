---
title: "Web: Slippery Way (Medium)"
date: "2024-09-27"
thumbnail: "/assets/img/thumbnail/ieee-victoris.png"
---

# Solution
---
When we get the files of the challenge we will see this file hierarchy.
<img src="/assets/img/ieee-victoris/capture6.png">

and this is `app.py`
```py
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
import random
import string
import time
import tarfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "V3eRy$3c43T"

def otp_generator():
    otp = ''.join(random.choices(string.digits, k=4))
    return otp

if not os.path.exists('uploads'):
   os.makedirs('uploads')

@app.route('/', methods=['GET', 'POST'])
def main():
    if 'username' not in session or 'valid_otp' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            filename = secure_filename(uploaded_file.filename)
            file_path = os.path.join('uploads', filename)
            uploaded_file.save(file_path)
            session['file_path'] = file_path
            return redirect(url_for('extract'))
        else:
            return render_template('index.html', message='No file selected')
    
    return render_template('index.html', message='')

@app.route('/extract')
def extract():
    if 'file_path' not in session:
        return redirect(url_for('login'))

    file_path = session['file_path']
    output_dir = 'uploads'
    if not tarfile.is_tarfile(file_path):
        os.remove(file_path)
        return render_template('extract.html', message='The uploaded file is not a valid tar archive')

    with tarfile.open(file_path, 'r') as tar_ref:
        tar_ref.extractall(output_dir)
        os.remove(file_path)

    return render_template('extract.html', files=os.listdir(output_dir))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == 'admin':
            session['username'] = username
            return redirect(url_for('otp'))
        else:
            return render_template('login.html', message='Invalid username or password')
    return render_template('login.html', message='')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp,_otp = otp_generator(),request.form['otp']
        if otp in _otp:
            session['valid_otp'] = True
            return redirect(url_for('main'))
        else:
            time.sleep(10) # please don't bruteforce my OTP
            return render_template('otp.html', message='Invalid OTP')
    return render_template('otp.html', message='')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('valid_otp', None)
    session.pop('file_path', None)
    return redirect(url_for('login'))


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    uploads_path = os.path.join(app.root_path, 'uploads')
    return send_from_directory(uploads_path, filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

When we start the challenge we see this login page
<img src="/assets/img/ieee-victoris/capture7.png">
from the code we will login using `admin:admin` and we will get forwarded to `/otp` endpoint
<img src="/assets/img/ieee-victoris/capture8.png">
We can't go to anyother endpoint without submiting the valid otp.
Trying to brute force  or bypass this page through the otp form is a rabbit hole.

When we look in the source code we will find interesting things.
- Each user of course have a cookie
- This is Flask application which moves us to think about `flask-unsign` cookie
- flask-unsign cookie is something like JWT that needs a secret signing key to forge a cookie
- We already have this secret `app.secret_key = "V3eRy$3c43T"`
- when we decode the cookie we will find this `{"username": "admin"}`
- from the code that if the otp is validated, then `session['valid_otp'] = True`
- So we need to forge a new cookie with username and valid_otp keys
we will use <a href="https://github.com/Paradoxis/Flask-Unsign">flask-unsign</a>
```bash
┌──(youssif㉿youssif)-[~]
└─$ flask-unsign --sign --cookie "{'username': 'admin','valid_otp': True}" --secret 'V3eRy$3c43T' 
eyJ1c2VybmFtZSI6ImFkbWluIiwidmFsaWRfb3RwIjp0cnVlfQ.Zvau5g.TioGBeLlSjBfw2V2CwACLyp9MpM
```
When we use the new cookie we can access the other endpoints
Now visit `/` again and you will find this upload page
<img src="/assets/img/ieee-victoris/capture9.png">

When we go back to upload function in our code we will find that it accepts only tar file
And in `/extract` this uploaded tar got extracted
After searching i found this <a href="https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload">candy</a>
From this article we knew that we can get LFI from tar upload function using
```bash
┌──(youssif㉿youssif)-[~]
└─$ ln -s ../../../../../../../../../etc/passwd kakashi.txt
tar -cvf test.tar kakashi.txt
```
We created a symbolic link from `kakashi.txt` to `../../../../../../../../../etc/passwd`
Then we put it in the tar file.
We will upload the file and when we go to `/extract` it will give us `kakashi.txt`
<img src="/assets/img/ieee-victoris/capture10.png">

open this file
<img src="/assets/img/ieee-victoris/capture11.png">
and GG you got /etc/passwd you can read the flag as the flag path was leaked in `init.sh` file.
Congratzzzzzzzzzzzzzzz