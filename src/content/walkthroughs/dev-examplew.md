---
name: Example Machine 
slug: example2
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
---


## Enumeration
### Nmap Scan
```bash
nmap -sC -sV -oN nmap.txt 10.0.1.3
```
### Results
```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|   Supported Methods: GET HEAD POST OPTIONS
|_  Potentially risky methods: POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Example Machine
```
### Web Enumeration
Access the web server at `http://10.0.1.3`. The page displays a simple message indicating that this is an example machine.
### Directory Enumeration
Use a tool like `gobuster` or `dirb` to enumerate directories:
```bash
gobuster dir -u http://10.0.1.3 -w /usr/share/wordlists/dirb/common.txt
```
### Results
```
/robots.txt            (Status: 200) [Size: 20]
/admin                 (Status: 301) [Size: 310] [--> http://10.0.1.3/admin/]
/admin/index.php       (Status: 200) [Size: 1500]
```
## Exploitation
### SSH Access
The SSH service is running on port 22. We can try to brute-force the SSH login using a tool like `hydra` or `medusa`. However, for this walkthrough, we will assume we have the credentials.
```bash
ssh user@10.0.1.3
```
### Credentials
- Username: `user`
- Password: `password`
### User Flag
Once logged in, we can find the user flag in the home directory:
```bash
cat /home/user/user.txt
```
## Root Privilege Escalation
To escalate privileges to root, we can check for any misconfigurations or vulnerable services. In this case, we will look for a SUID binary that can be exploited.
```bash
find / -perm -4000 -type f 2>/dev/null
```
### Results
```
/usr/bin/suid_binary
```
### Exploiting the SUID Binary
We can exploit the SUID binary to gain root access. Assuming the binary is vulnerable, we can run it with root privileges:
```bash
/usr/bin/suid_binary
```
### Root Flag
After successfully exploiting the SUID binary, we can find the root flag:
```bash
cat /root/root.txt
```
## Conclusion
Congratulations! You have successfully completed the walkthrough for the example machine. You have learned how to enumerate services, exploit vulnerabilities, and retrieve both user and root flags.


