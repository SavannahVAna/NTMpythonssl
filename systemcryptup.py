from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256, HMAC

password = input("Enter password: ")

def protect_file(oasswird, infile, outfile, block_size=128):
    if not os.path.exists(infile):
        print("Le fichier n'existe pas")
        exit(1)
    
    salt = get_random_bytes(64)
    key = scrypt(oasswird, salt, 64, N=2**14, r=8, p=1)
    
    h1 = SHA256.new()
    h1.update(key + (0).to_bytes(4, 'little'))
    h2 = SHA256.new()
    h2.update(key + (1).to_bytes(4, 'little'))
    key1 = h1.digest()
    key2 = h2.digest()

    iv = get_random_bytes(16)
    cipher = AES.new(key1, AES.MODE_CBC, iv=iv)
    file_size = os.path.getsize(infile)
    itere = file_size//block_size
    taille_last = file_size - itere*block_size
    with open(infile, "rb") as f_in, open(outfile, "wb") as f_out:
        f_out.write(iv)  # Écrire l'IV
        f_out.write(salt)  # Écrire le sel
        
        hmac = HMAC.new(key2, digestmod=SHA256)
        hmac.update(iv + salt)
        
        for i in range(itere):
            chunk = f_in.read(block_size)
            
            if taille_last == 0 and i == itere-1:
                chunk = pad(chunk, 16)
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)
            hmac.update(ciphertext)
        if taille_last !=0:
            chunk = f_in.read()
            chunk = pad(chunk, 16)
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)
            hmac.update(ciphertext)
        
        f_out.write(hmac.digest())  # Écrire le HMAC à la fin

def unprotect_file(filecry, passwd, fileout, block_size=128):
    file_size = os.path.getsize(filecry)
    file_size -= (16+64+32)
    itere = file_size//block_size
    taille_last = file_size - itere*block_size
    with open(filecry, "rb") as f_in, open(fileout, "wb") as f_out:
        iv = f_in.read(16)
        salt = f_in.read(64)
        
        if len(iv) != 16 or len(salt) != 64 :
            print("Erreur : Structure du fichier incorrecte.")
            exit(1)

        key = scrypt(passwd, salt, 64, N=2**14, r=8, p=1)
        h1 = SHA256.new()
        h1.update(key + (0).to_bytes(4, 'little'))
        h2 = SHA256.new()
        h2.update(key + (1).to_bytes(4, 'little'))
        key1 = h1.digest()
        key2 = h2.digest()

        hymac = HMAC.new(key2, digestmod=SHA256)
        hymac.update(iv + salt)

        cipher = AES.new(key1, AES.MODE_CBC, iv=iv)

        for i in range(itere):
            bloc = f_in.read(block_size)
            hymac.update(bloc)
            plaintext_chunk = cipher.decrypt(bloc)
            
            # Ne pas ajouter de padding aux derniers blocs, seulement aux précédents
            if taille_last == 0 and i == itere - 1:
                plaintext_chunk = unpad(plaintext_chunk, 16)
            f_out.write(plaintext_chunk)

        if taille_last != 0:
            print(taille_last)
            lst = f_in.read(taille_last)
            print(len(lst))
            hymac.update(lst)  # Assurez-vous de mettre à jour HMAC avec les derniers bytes
            plaintext_chunk = cipher.decrypt(lst)
            print(plaintext_chunk)
            plaintext_chunk = unpad(plaintext_chunk, 16)  # Unpadding du dernier bloc
            f_out.write(plaintext_chunk)
        hmac_check = f_in.read()
        if hymac.digest() != hmac_check:
            print("Intégrité non vérifiée, aborting")
            exit(1)
        else:
            print("Intégrité vérifiée")
            


protect_file(password, "message.txt", "crype")
unprotect_file("crype", password, "mess.txt")
