---
name: Dog
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/426830ea2ae4f05f7892ad89195f8276.png
---

## Enumeration

### Port Scan

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.58 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80 -sCV 10.10.11.58 -o targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 972ad22c898ad3ed4dac00d21e8749a7 (RSA)
|   256 277c3ceb0f26e962590f0fb138c9ae2b (ECDSA)
|_  256 9388474c69af7216094cba771e3b3beb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
|_http-title: Home | Dog
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As we can see, there is a web service running on port 80. This is exposing .git directory, which is a common misconfiguration in web applications. We can use this to our advantage.

We use `git-dumper` to download the contents of the `.git` directory:

```bash
python git_dumper.py http://10.10.11.58/.git/ ./website
```

This way we can download the entire repository, including the source code and configuration files.

We find a file named `settings.php` that contains sensitive information such as database credentials and other configuration details.
```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$config_directories['active'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active';
$config_directories['staging'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/staging';
$settings['hash_salt'] = 'aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ';
```






## User Exploitation



## Machine Access


## Root Exploitation


## Conclusion

