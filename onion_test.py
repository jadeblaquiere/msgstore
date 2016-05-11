import requests
import hashlib
import base64
import json
import sys
import binascii

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

Point.set_curve(curve_secp256k1)
_G = Generator(curve_secp256k1['G'][0], curve_secp256k1['G'][1])
ECDSA.set_generator(_G)

client_p = random.randint(1,curve_secp256k1['n']-1)
client_P = _G * client_p

_server = "http://127.0.0.1:5000/"
_status = "api/status/"
_onion = "onion/"

r = requests.get(_server + _status)
assert r.status_code == 200
rd = r.json()

server_P = Point.decompress(rd['pubkey'])

o_r = {}
o_r['local'] = True
o_r['url'] = 'api/status/'
o_r['action'] = 'get'

message = json.dumps(o_r)

ecdh = server_P * client_p
keybin = hashlib.sha256(ecdh.compress()).digest()
iv = random.randint(0,(1 << 256)-1)
ivbin = binascii.unhexlify('%064x' % iv)
counter = Counter.new(128, initial_value=iv)
cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
ciphertext = cryptor.encrypt(message)
payload = base64.b64encode(ivbin+ciphertext)

r = requests.post(_server + _onion + client_P.compress(), data=payload)
assert r.status_code == 200
print "text = " + r.text

oo_r = {}
oo_r['local'] = False
oo_r['host'] = '127.0.0.1'
oo_r['pubkey'] = client_P.compress()
oo_r['body'] = payload

client_p = random.randint(1,curve_secp256k1['n']-1)
client_P = _G * client_p

message = json.dumps(oo_r)

ecdh = server_P * client_p
keybin = hashlib.sha256(ecdh.compress()).digest()
iv = random.randint(0,(1 << 256)-1)
ivbin = binascii.unhexlify('%064x' % iv)
counter = Counter.new(128, initial_value=iv)
cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
ciphertext = cryptor.encrypt(message)
payload = base64.b64encode(ivbin+ciphertext)

r = requests.post(_server + _onion + client_P.compress(), data=payload)
assert r.status_code == 200
print "text = " + r.text


