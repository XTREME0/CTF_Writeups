<img src="./imgs/patriotctf/banner.png" style="zoom:80%;" />

# PatriotCTF 2024

### <u>Category:</u> 	*Web*

### <u>Difficulty:</u>	Medium

#### <u>Challenge:</u> 	Impersonate

#### Attachments:	app.py



**app.py:**

```python
#!/usr/bin/env python3
from flask import Flask, request, render_template, jsonify, abort, redirect, session
import uuid
import os
from datetime import datetime, timedelta
import hashlib
app = Flask(__name__)
server_start_time = datetime.now()
server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')
secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
app.secret_key = secure_key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=300)
flag = os.environ.get('FLAG', "flag{this_is_a_fake_flag}")
secret = uuid.UUID('31333337-1337-1337-1337-133713371337')
def is_safe_username(username):
    """Check if the username is alphanumeric and less than 20 characters."""
    return username.isalnum() and len(username) < 20
@app.route('/', methods=['GET', 'POST'])
def main():
    """Handle the main page where the user submits their username."""
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        username = request.values['username']
        password = request.values['password']
        if not is_safe_username(username):
            return render_template('index.html', error='Invalid username')
        if not password:
            return render_template('index.html', error='Invalid password')
        if username.lower().startswith('admin'):
            return render_template('index.html', error='Don\'t try to impersonate administrator!')
        if not username or not password:
            return render_template('index.html', error='Invalid username or password')
        uid = uuid.uuid5(secret, username)
        session['username'] = username
        session['uid'] = str(uid)
        return redirect(f'/user/{uid}')
@app.route('/user/<uid>')
def user_page(uid):
    """Display the user's session page based on their UUID."""
    try:
        uid = uuid.UUID(uid)
    except ValueError:
        abort(404)
    session['is_admin'] = False
    return 'Welcome Guest! Sadly, you are not admin and cannot view the flag.'
@app.route('/admin')
def admin_page():
    """Display the admin page if the user is an admin."""
    if session.get('is_admin') and uuid.uuid5(secret, 'administrator') and session.get('username') == 'administrator':
        return flag
    else:
        abort(401)
@app.route('/status')
def status():
    current_time = datetime.now()
    uptime = current_time - server_start_time
    formatted_uptime = str(uptime).split('.')[0]
    formatted_current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    status_content = f"""Server uptime: {formatted_uptime}<br>
    Server time: {formatted_current_time}
    """
    return status_content
if __name__ == '__main__':
    app.run("0.0.0.0", port=9999)

```



Home page (/):

![image-20240923172325396](/imgs/patriotctf/img1.png)

First i noticed that:

- I can login with any credentials.
- Username cannot start with 'admin'. 

Reading the source code you notice that in order to get the flag user must visit the */admin* route, where the code checks the session cookie for the following:

- *is_admin* must be set to True.
- uid is the same as administrator id.
- username is 'administrator'.

```python
@app.route('/admin')
def admin_page():
    """Display the admin page if the user is an admin."""
    if session.get('is_admin') and uuid.uuid5(secret, 'administrator') and session.get('username') == 'administrator':
        return flag
    else:
        abort(401)
```

First let's look at how the user id is generated:

```python
uid = uuid.uuid5(secret, username)
```

so we need the secret and the username of the user to generate its id.

```python
secret = uuid.UUID('31333337-1337-1337-1337-133713371337')
```

so we already have the secret we can generate the administrator id:

![image-20240923174319661](/imgs/patriotctf/img2.png)

Now that we got the administrator id, we have to find a way to set the session cookie to the values we need, to impersonate the admin.

Session cookies are made using a secret_key, so any tempering with values in the cookie will make it invalid.

So we must have the secret_key used by the server to create cookies, in order to recreate the admin cookie.

Luckily the secret_key is not generated randomly:

```python
server_start_time = datetime.now()
server_start_str = server_start_time.strftime('%Y%m%d%H%M%S')
secure_key = hashlib.sha256(f'secret_key_{server_start_str}'.encode()).hexdigest()
```

we can calculate the server_start_time using the */status* page:

```python
@app.route('/status')
def status():
    current_time = datetime.now()
    uptime = current_time - server_start_time
    formatted_uptime = str(uptime).split('.')[0]
    formatted_current_time = current_time.strftime('%Y-%m-%d %H:%M:%S')
    status_content = f"""Server uptime: {formatted_uptime}<br>
    Server time: {formatted_current_time}
    """
    return status_content
```

![image-20240923181221057](/imgs/patriotctf/img3.png)

(server_start_time = Server time - Server uptime) , formate it into the right format 20240923171014 and then use it to get the secret_key.

(note that sometimes you gotta subtract 1 second for it to work, so i tested with both values against the original cookie to check if the key was actually valid)

![image-20240923191953606](/imgs/patriotctf/img4.png)

Let's hop into Burpsuite and see how that cookie looks:

![image-20240923192720442](/imgs/patriotctf/img5.png)

Now let's generate our cookie using a tool like flask-unsign with the secret_key and the values we want

![image-20240923192308026](/imgs/patriotctf/img6.png)

Next I'm gonna replace that cookie with the one I just generated:

![image-20240923193019372](/imgs/patriotctf/img7.png)

![](/imgs/patriotctf/img8.png)

Now let's visit */admin*:

![](/imgs/patriotctf/img9.png)

Boom we got the flag :  **PCTF{Imp3rs0n4t10n_Iz_Sup3r_Ezz}**
