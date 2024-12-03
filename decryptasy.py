
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256

def decode_rsa(passw:str, inp, out):
    pwd = passw.encode()
    with open("otherprivatekey.pem", "rb") as f:

        data = f.read()

        key2 = RSA.import_key(data, pwd)

    with open("mypublickey.pem", "rb") as f:

        data = f.read()

        key = RSA.import_key(data, pwd)

    block_size = 128
    file_size = os.path.getsize(inp)
    file_size -= (16 + 384 + 256)  # Enlever IV, salt et HMAC
    itere = file_size // block_size
    taille_last = file_size - itere * block_size
    with open(inp, 'rb') as f, open(out, "wb") as f_out:
        iv = f.read(16)
        Wkc = f.read(384)
        #déchiffrer le message wkc
        ci = PKCS1_OAEP.new(key2)
        kc = ci.decrypt(Wkc)
        #decrypt aes
        cipher = AES.new(kc, AES.MODE_CBC, iv=iv)
        h = SHA256.new(iv + Wkc)
        for i in range(itere):
            bloc = f.read(block_size)
            h.update(bloc)
            plaintext_chunk = cipher.decrypt(bloc)
            

            # Ne pas ajouter de padding aux derniers blocs, seulement aux précédents
            if taille_last == 0 and i == itere - 1:
                plaintext_chunk = unpad(plaintext_chunk, 16)
            f_out.write(plaintext_chunk)
            

        if taille_last != 0:
            lsat = f.read(taille_last)
            h.update(lsat)
            plaintext_chunk = cipher.decrypt(lsat)
            plaintext_chunk = unpad(plaintext_chunk, 16)  # Unpadding du dernier bloc
            f_out.write(plaintext_chunk)
        verifier = pss.new(key)
        signature = f.read()
        #print(signature)
        try:
            verifier.verify(h, signature)
            print("The signature is authentic.")
        except (ValueError):
            print("The signature is not authentic.")
            print(h.hexdigest())
            exit(1)



