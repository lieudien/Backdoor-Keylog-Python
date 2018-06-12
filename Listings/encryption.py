from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
            chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
masterkey = hashlib.md5(("comp8505").encode('utf8')).hexdigest()

def encrypt(data):
    raw = pad(data)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(masterkey, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def decrypt(data):
    if len(data) <= 16:
        return ""
    data = base64.b64decode(data)
    iv = data[:16]
    cipher = AES.new(masterkey, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]))

def encryptFile(filename):
    return

def decryptFile(filename):
    return
