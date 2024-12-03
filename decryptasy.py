
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

pwd = b'secret'
with open("myprivatekey.pem", "rb") as f:

    data = f.read()

    key2 = RSA.import_key(data, pwd)

cipher = PKCS1_OAEP.new(key)

message = cipher.decrypt(ciphertext)