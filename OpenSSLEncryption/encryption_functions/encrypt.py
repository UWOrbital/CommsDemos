from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# data = b"This is a test"
KEY = b"My 16 Bit key ad"
IV=b'0000000000000000'
def encrypt(data):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return b64encode(ct).decode('utf-8')

def decrypt(data):
    ct = b64decode(data)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# idk = encrypt(data)
# length = str(b64decode(idk).hex())
# print(length)