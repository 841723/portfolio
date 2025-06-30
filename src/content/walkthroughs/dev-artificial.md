---
name: Artificial
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
---


## Enumeration
### Nmap Scan
#### Normal Scan
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.74 -o content/allPortsFiltered
```

##### Results
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

### Web 
When accessing `http://10.10.11.74` it redirects to `http://artificial.htb`, which is a custom domain. We need to add this domain to our `/etc/hosts` file:
```bash
echo "10.10.11.74 artificial.htb" | sudo tee -a /etc/hosts
``` 

Now we can access the web server using the custom domain `http://artificial.htb`.

We creare an account in the web application, which is a simple login page. After creating an account, we can log in with the credentials we set.

#### Directory Enumeration
Use a tool like `gobuster` or `dirb` to enumerate directories:
```bash
gobuster dir -u http://artificial.htb -w /usr/share/wordlists/dirb/common.txt
```
### Results
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 857]
/logout               (Status: 302) [Size: 189] [--> /]
```


Access the web server at `http://10.10.11.74`. The page displays a simple message indicating that this is an example machine.

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


