from Crypto.Cipher import AES
from Crypto import Random
import base64
import hashlib
import os, random, struct

BLOCK_SIZE = 16
CHUNK_SIZE = 64 * 1024
IV_LEN = 16
FILENAME_SIZE = 64
FILESIZE_SIZE = struct.calcsize('Q')


pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
            chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
masterkey = hashlib.md5(("comp8505").encode('utf8')).hexdigest()
filekey = hashlib.sha256(masterkey.encode('utf8')).digest()

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

def encryptFile(inputFile):
    # Randomize initial vector
    iv = ''.join(chr(random.randint(0, 0xFF)) for _ in range(IV_LEN))
    # Set encryption mode to CBC
    enc = AES.new(filekey, AES.MODE_CBC, iv)

    filesize = os.path.getsize(inputFile)
    encString = (struct.pack('<Q', filesize)) + iv
    encString += (enc.encrypt(struct.pack(str(FILENAME_SIZE) + 's', os.path.basename(inputFile))))

    with open(inputFile, 'rb') as inFile:
        while True:
            chunk = inFile.read(CHUNK_SIZE)
            if len(chunk) == 0:
                break
            # Fill the last chunk with spaces if not 16 bytes long
            elif (len(chunk) % 16 != 0):
                chunk += ' ' * (16 - (len(chunk) % 16))
            encString += enc.encrypt(chunk)

    return encString

def decryptFile(inputFile):
    try:
        with open(inputFile, 'rb') as inFile:
            filesize = struct.unpack('<Q', str(inputFile.read(FILENAME_SIZE)))[0]
            iv = inFile.read(IV_LEN)
            dec = AES.new(filekey, AES.MODE_CBC, iv)
            filename = dec.decrypt(struct.unpack(str(FILENAME_SIZE) + 's', str(inFile.read(FILENAME_SIZE))))[0]
            filename = filename.rstrip('\x00')

            try:
                with open(filename, 'wb') as outFile:
                    while True:
                        chunk = inFile.read(CHUNK_SIZE)
                        if len(chunk) == 0:
                            break

                        decString = dec.decrypt(chunk)
                        outFile.write(decString)

                    outFile.truncate(filesize)
            except IOError as err:
                print("IO Exception: {}".format(str(e)))
                return False
    except IOError as err:
        print("IO Exception: {}".format(str(e)))
        return False

    return True
