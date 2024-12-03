
from Crypto.PublicKey import RSA

mykey = RSA.generate(3072)


pwd = b'secret'

with open("myprivatekey.pem", "wb") as f:

    data = mykey.export_key(passphrase=pwd,
                                pkcs=8,
                                protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                prot_params={'iteration_count':131072})

    f.write(data)

with open("mypublickey.pem", "wb") as f:

    data = mykey.public_key().export_key()
    f.write(data)

mykey = RSA.generate(3072)
with open("otherprivatekey.pem", "wb") as f:

    data = mykey.export_key(passphrase=pwd,
                                pkcs=8,
                                protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                prot_params={'iteration_count':131072})

    f.write(data)

with open("otherpublickey.pem", "wb") as f:

    data = mykey.public_key().export_key()
    f.write(data)