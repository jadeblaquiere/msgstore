import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        c = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + c.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        c = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(c.decrypt(enc[AES.block_size:])).decode('utf-8')

    def encrypt_iv(self, raw, iv):
        raw = self._pad(raw)
        iv = hashlib.sha256(iv.encode()).digest()[:AES.block_size]
        c = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(c.encrypt(raw))

    def decrypt_iv(self, enc, iv):
        enc = base64.b64decode(enc)
        iv = hashlib.sha256(iv.encode()).digest()[:AES.block_size]
        c = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(c.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return (s + (self.bs - len(s) % self.bs) *
                chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


if __name__ == '__main__':  # pragma: no cover
    aes = AESCipher('this is my key')
    plaintext = 'hello, I am very hoppy to meet you!'
    print ('plain  =', plaintext)
    ciphertext = aes.encrypt(plaintext)
    print ('cipher =', ciphertext)
    plaintwo = aes.decrypt(ciphertext)
    print ('plain2 =', plaintwo)
    plaintext = 'hello, I am hoppy to meet you too!'
    print ('plain  =', plaintext)
    ciphertext = aes.encrypt_iv(plaintext, 'this is my iv')
    print ('cipher =', ciphertext)
    plaintwo = aes.decrypt_iv(ciphertext, 'this is my iv')
    print ('plain2 =', plaintwo)
