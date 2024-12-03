
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256, HMAC
from Crypto.Util.Padding import pad
# args 1 nom du fichier a chiffrer
password = input("enter password : ")
def protect_file(oasswird,infile,outfile):
    if not os.path.exists(infile):
        print("la f ichier n'existe pas")
        exit(1)
    salt = get_random_bytes(64)
    key = scrypt(oasswird, salt, 64, N=2**14, r=8, p=1)
    h1 = SHA256.new()
    h1.update(key + (0).to_bytes(4,'little'))
    h2 = SHA256.new()
    h2.update(key + (1).to_bytes(4,'little'))
    key1 = h1.digest()
    key2 = h2.digest()
    
    with open(infile,"rb") as f:
        trtrt =get_random_bytes(16)
        cipher = AES.new(key1, AES.MODE_CBC, iv=trtrt)
        data = f.read()
    
    ciphertext = cipher.encrypt(pad(data, 16))
    #faire le reste et concaténer
    
    ci = trtrt + salt + ciphertext
    #hmac
    hmac = HMAC.new(key2, digestmod=SHA256)
    hmac.update(ci)
    
    ci += hmac.digest() #len hmac 32

    with open(outfile, "wb") as f:
        f.write(ci)
    
protect_file(password, "message.txt", "crype")

def unprotect_file(filecry, passwd, fileout):
    #check integrity
    file_size = os.path.getsize(filecry)
    with open(filecry, "rb") as f:
        iv = f.read(16)
        file_size -=16
        salt = f.read(64)
        file_size-=64
        rest = f.read()
        check = rest[-32:]
        rest = rest[: len(rest) -32]
        key = scrypt(passwd, salt, 64, N=2**14, r=8, p=1)
        h1 = SHA256.new()
        h1.update(key + (0).to_bytes(4,'little'))
        h2 = SHA256.new()
        h2.update(key + (1).to_bytes(4,'little'))
        key1 = h1.digest()
        key2 = h2.digest()
        hymac = HMAC.new(key2, digestmod=SHA256)
        hymac.update(iv + salt + rest)
        if hymac.digest == check:
            print("intégrité verifié")
        else:
            print("integrité non verifiée, aborting")
            exit(1)
    

        


