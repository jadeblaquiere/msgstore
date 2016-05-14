from Crypto.Random import random

import binascii
import time
import json

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA

_def_curve = curve_secp256k1
Point.set_curve(_def_curve)
ECDSA.set_curve(_def_curve)
ECDSA.set_generator(Point(_def_curve['G'][0], _def_curve['G'][1]))

class NAK(object):
    n = _def_curve['n']
    G = Point(_def_curve['G'][0], _def_curve['G'][1])
    ecdsa = ECDSA()
    
    def __init__(self, expire=None, pubkey=None, signature=None, privkey=None):
        self.expire = expire
        self.pubkey = pubkey
        self.signature = signature
        self.privkey = privkey
        if privkey is not None and pubkey is None:
            self.pubkey = NAK.G * privkey

    @staticmethod
    def deserialize(rawbytes):
        etime = int(binascii.hexlify(rawbytes[0:4]), 16)
        #print('time = ' + str(time.gmtime(etime)))
        Pkey = Point.decompress(binascii.hexlify(rawbytes[4:37]))
        #print('point = ' + Pkey.compress())
        sig0 = int(binascii.hexlify(rawbytes[37:69]),16)
        sig1 = int(binascii.hexlify(rawbytes[69:101]),16)
        sig = (sig0, sig1)
        #print('sig = (0x%032x, 0x%032x)' % (sig[0], sig[1]))
        #print('verifying %s' % binascii.hexlify(rawbytes[:37]))
        if not NAK.ecdsa.verify(Pkey,sig,rawbytes[:37]):
            #print('verify failed')
            return None
        return NAK(etime, Pkey, sig)

    def serialize(self):
        hexmsg = '%08x' % self.expire
        hexmsg += self.pubkey.compress()
        if self.signature is None:
            if self.privkey is None:
                return None
            else:
                bmsg = binascii.unhexlify(hexmsg)
                self.signature = NAK.ecdsa.sign(self.privkey, bmsg)
        hexmsg += '%064x' % self.signature[0]
        hexmsg += '%064x' % self.signature[1]
        return binascii.unhexlify(hexmsg)

    def randomize(self, expire=None):
        self.privkey = random.randint(1,NAK.n-1)
        self.pubkey = NAK.G * self.privkey
        if expire is not None:
            self.expire = expire
        else:
            self.expire = int(time.time()) + (365*24*60*60)
        self.serialize()

    def dumpjson(self):
        exp = {}
        if self.signature is None:
            serialized = self.serialize()
            if serialized is None:
                return None
        exp['pubkey'] = self.pubkey.compress()
        exp['expire'] = self.expire
        exp['signature'] = self.signature
        return json.dumps(exp)

    @staticmethod
    def loadjson(load):
        try:
            raw = json.loads(load)
            expire = raw['expire']
            pubkey = Point.decompress(raw['pubkey'])
            signature = raw['signature']
            return NAK(expire, pubkey, signature)
        except:
            return None

    def sign(self,message):
        if self.privkey is None:
            return None
        return NAK.ecdsa.sign(self.privkey, message)

    def verify(self,signature,message):
        if self.pubkey is None:
            return False
        return NAK.ecdsa.verify(self.pubkey, signature, message)

    def __eq__(self, r):
        if self.expire != r.expire:
            return False
        if self.pubkey != r.pubkey:
            return False
        return True

    def __ne__(self, r):
        return not (self == r)

    def __gt__(self, r):
        if self.expire == r.expire:
            return self.pubkey.compress() > r.pubkey.compress()
        return self.expire > r.expire

    def __lt__(self, r):
        if self.expire == r.expire:
            return self.pubkey.compress() < r.pubkey.compress()
        return self.expire < r.expire

    def __le__(self, r):
        return not (self > r)

    def __ge__(self, r):
        return not (self < r)
    
    def __str__(self):
        return str(self.pubkey) + ' expires ' + str(time.gmtime(self.expire))
    
    def __repr__(self):
        ser = self.serialize()
        if ser is not None:
            return 'NAK.deserialize(%s)' % ser
        return 'NAK(0x%08x,Point.decompress(%s))' % (self.expire, self.pubkey.compress())