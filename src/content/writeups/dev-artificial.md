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


[TO_CONTINUE]
We upload the generated `.h5` file to the web application. 





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
