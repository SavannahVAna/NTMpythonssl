from Crypto.Hash import SHA256
import Crypto.Random
import Crypto.Random.random
import string

def sha256sum_file(filename: str, chunk_sz=512):
    hash_object = SHA256.new()
    with open(filename, "rb") as file:
        data = file.read(chunk_sz)
        while len(data)!= 0:
            hash_object.update(data)
            data = file.read(chunk_sz)
    return(hash_object.hexdigest())

def generate_password(lenth:int, alphabet:str="ascii"):
    mdp = ""
    if alphabet == "ascii":
        for i in range(lenth):
            mdp += Crypto.Random.random.choice(string.ascii_letters + string.digits + string.punctuation)
    return mdp
            