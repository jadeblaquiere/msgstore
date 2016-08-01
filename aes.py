# Copyright (c) 2016, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ciphrtxt nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
