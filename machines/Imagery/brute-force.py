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
            
