from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256


pwd = b'secret'


with open("otherpublickey.pem", "rb") as f:

    data = f.read()

    key = RSA.import_key(data, pwd)

cipher = PKCS1_OAEP.new(key)
kc = get_random_bytes(32)
ciphertext = cipher.encrypt(kc)

ive = get_random_bytes(16)

ciphere = AES.new(kc, AES.MODE_CBC, iv=ive)

in_file = input("what file you want to encrypt ")

with open(in_file, "rb") as f:
    data = f.read()

ciphertext2 = ciphere.encrypt(pad(data, 16))

to_sign = ive + ciphertext + ciphertext2

with open("myprivatekey.pem", "rb") as f:

    data = f.read()

    key2 = RSA.import_key(data, pwd)

h = SHA256.new(to_sign) # on doit le hacher apparament c le standard
signature = pss.new(key2).sign(h)
print(len(ciphertext))
final = to_sign + signature

with open("result", 'wb') as f:
    f.write(final)