import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def encrypt_rsa(pwde: str, in_file: str, outfile: str):
    try:
        pwd = pwde.encode()

        # Charger la clé publique
        with open("otherpublickey.pem", "rb") as f:
            data = f.read()
            key = RSA.import_key(data, pwd)

        cipher = PKCS1_OAEP.new(key)
        kc = get_random_bytes(32)
        ciphertext3 = cipher.encrypt(kc)
        ive = get_random_bytes(16)

        ciphere = AES.new(kc, AES.MODE_CBC, iv=ive)

        # Charger la clé privée pour la signature
        with open("myprivatekey.pem", "rb") as f:
            data = f.read()
            key2 = RSA.import_key(data, pwd)

        # Vérifier que le fichier à chiffrer existe
        if not os.path.exists(in_file):
            raise FileNotFoundError(f"Le fichier '{in_file}' n'existe pas.")

        block_size = 128
        file_size = os.path.getsize(in_file)
        itere = file_size // block_size
        taille_last = file_size - itere * block_size

        with open(in_file, "rb") as f, open(outfile, 'wb') as fO:
            fO.write(ive)
            fO.write(ciphertext3)
            hmac = SHA256.new(ive + ciphertext3)

            for i in range(itere):
                chunk = f.read(block_size)
                if taille_last == 0 and i == itere - 1:
                    chunk = pad(chunk, 16)
                ciphertext = ciphere.encrypt(chunk)
                fO.write(ciphertext)
                hmac.update(ciphertext)

            if taille_last != 0:
                chunk = f.read()
                chunk = pad(chunk, 16)
                ciphertext = ciphere.encrypt(chunk)
                fO.write(ciphertext)
                hmac.update(ciphertext)

            fO.write(pss.new(key2).sign(hmac))  # Écrire la signature à la fin

        print(f"Fichier chiffré avec succès : {outfile}")
    except FileNotFoundError as e:
        print(f"Erreur de fichier : {e}")
        exit(1)
    except ValueError as e:
        print(f"Erreur de clé ou de chiffrement : {e}")
        exit(1)
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        exit(1)

def decode_rsa(passw: str, inp: str, out: str):
    try:
        pwd = passw.encode()

        # Charger les clés
        with open("otherprivatekey.pem", "rb") as f:
            data = f.read()
            key2 = RSA.import_key(data, pwd)

        with open("mypublickey.pem", "rb") as f:
            data = f.read()
            key = RSA.import_key(data, pwd)

        # Vérifier que le fichier à déchiffrer existe
        if not os.path.exists(inp):
            raise FileNotFoundError(f"Le fichier '{inp}' n'existe pas.")

        block_size = 128
        file_size = os.path.getsize(inp)
        file_size -= (16 + 384 + 256)  # Enlever IV, Wkc, signature
        itere = file_size // block_size
        taille_last = file_size - itere * block_size

        with open(inp, 'rb') as f, open(out, "wb") as f_out:
            iv = f.read(16)
            Wkc = f.read(384)

            # Déchiffrer Wkc
            ci = PKCS1_OAEP.new(key2)
            kc = ci.decrypt(Wkc)

            # Déchiffrer AES
            cipher = AES.new(kc, AES.MODE_CBC, iv=iv)
            h = SHA256.new(iv + Wkc)

            for i in range(itere):
                bloc = f.read(block_size)
                h.update(bloc)
                plaintext_chunk = cipher.decrypt(bloc)
                if taille_last == 0 and i == itere - 1:
                    plaintext_chunk = unpad(plaintext_chunk, 16)
                f_out.write(plaintext_chunk)

            if taille_last != 0:
                lsat = f.read(taille_last)
                h.update(lsat)
                plaintext_chunk = cipher.decrypt(lsat)
                plaintext_chunk = unpad(plaintext_chunk, 16)
                f_out.write(plaintext_chunk)

            # Vérification de la signature
            verifier = pss.new(key)
            signature = f.read()
            try:
                verifier.verify(h, signature)
                print("La signature est authentique.")
            except ValueError:
                print("Erreur : La signature n'est pas authentique.")
                exit(1)

        print(f"Fichier déchiffré avec succès : {out}")
    except FileNotFoundError as e:
        print(f"Erreur de fichier : {e}")
        exit(1)
    except ValueError as e:
        print(f"Erreur de clé ou de déchiffrement : {e}")
        exit(1)
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        exit(1)

# Exemple d'utilisation
pwd = 'secret'
encrypt_rsa(pwd, "message.txt", "result")
decode_rsa(pwd, "result", "messagera.txt")
