import binascii
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

def iter_password(mdp:str, salt, iter):
    hash_object = SHA256.new()
    m= mdp.encode()
    a = (0).to_bytes(4,'little')
    hash_object.update(m+salt+a)
    s = hash_object.digest()
    for i in range(1,iter):
        hash_object = SHA256.new()
        i_bytes = i.to_bytes(4, 'little')
        hash_object.update(s + m + salt + i_bytes)
        s = hash_object.digest()
        hash_object = SHA256.new()
    return s

kdf =iter_password("toto", get_random_bytes(16),3)
print(binascii.hexlify(kdf).decode())