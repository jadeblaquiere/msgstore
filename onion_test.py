import requests
import hashlib
import base64
import json
import sys
from binascii import hexlify, unhexlify
import nak

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

client_r = random.randint(1,curve_secp256k1['n']-1)
client_R = _G * client_r

ecdsa=ECDSA()

_server = "http://indigo.bounceme.net:5000/"
_server2 = "http://coopr8.com:5000/"
_server3 = "http://ciphrtxt.com:5000/"
_status = "api/status/"
_onion = "onion/"
_nak_priv = 0xf1a91fc566427a45cd6cdd43f5fc5647b1d6696a5b03f868b9bb8b01b631ae91

nak = nak.NAK(expire = 0, privkey = _nak_priv)
print('nak = %s' % str(nak))
print('nak_pubkey = %s' % nak.pubkey.compress())
nakpubbin = unhexlify(nak.pubkey.compress())

r = requests.get(_server + _status)
assert r.status_code == 200
rd = r.json()

server_P = Point.decompress(rd['pubkey'])
server_R = server_P

o_r = {}
o_r['local'] = True
o_r['url'] = 'api/status/'
o_r['action'] = 'get'
o_r['replykey'] = client_R.compress()

message = json.dumps(o_r)

ecdh = server_P * client_p
keybin = hashlib.sha256(ecdh.compress().encode('UTF-8')).digest()
iv = random.randint(0,(1 << 128)-1)
print('iv = 0x%032x' % iv)
ivbin = unhexlify('%032x' % iv)
counter = Counter.new(128, initial_value=iv)
cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
ciphertext = cryptor.encrypt(message)
raw = ivbin + ciphertext
sig = nak.sign(raw)
signed = nakpubbin + unhexlify('%064x' % sig[0]) + unhexlify('%064x' % sig[1]) + raw
payload = base64.b64encode(signed)

r = requests.post(_server + _onion + client_P.compress(), data=payload)
assert r.status_code == 200
d_bd = base64.b64decode(r.text)
sig = (int(hexlify(d_bd[0:32]),16), int(hexlify(d_bd[32:64]),16))
print('sig = ' + str(sig))
assert ecdsa.verify(server_R, sig, d_bd[64:])
d_ecdh = server_R * client_r
d_keybin = hashlib.sha256(d_ecdh.compress().encode('UTF-8')).digest()
print('ecdh key hex = ' + str(hexlify(d_keybin)))
d_ivcount = int(hexlify(d_bd[64:80]),16)
print('iv hex = ' + str(hexlify(d_bd[64:80])))
d_counter = Counter.new(128,initial_value=d_ivcount)
d_cryptor = AES.new(d_keybin, AES.MODE_CTR, counter=d_counter)
d_plaintext = d_cryptor.decrypt(d_bd[80:])
d_plaintext = d_plaintext.decode('UTF-8')
print("plaintext = " + d_plaintext)

r = requests.get(_server2 + _status)
assert r.status_code == 200
rd = r.json()

server_P2 = Point.decompress(rd['pubkey'])

oo_r = {}
oo_r['local'] = False
oo_r['host'] = 'indigo.bounceme.net'
oo_r['port'] = 5000
oo_r['pubkey'] = client_P.compress()
oo_r['body'] = base64.b64encode(raw).decode('UTF-8')

client_p = random.randint(1,curve_secp256k1['n']-1)
client_P = _G * client_p

message = json.dumps(oo_r)

ecdh = server_P2 * client_p
keybin = hashlib.sha256(ecdh.compress().encode('UTF-8')).digest()
iv = random.randint(0,(1 << 128)-1)
print('iv = 0x%032x' % iv)
ivbin = unhexlify('%032x' % iv)
counter = Counter.new(128, initial_value=iv)
cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
ciphertext = cryptor.encrypt(message)
raw = ivbin + ciphertext
sig = nak.sign(raw)
signed = nakpubbin + unhexlify('%064x' % sig[0]) + unhexlify('%064x' % sig[1]) + raw
payload = base64.b64encode(signed)

r = requests.post(_server2 + _onion + client_P.compress(), data=payload)
assert r.status_code == 200
d_bd = base64.b64decode(r.text)
sig = (int(hexlify(d_bd[0:32]),16), int(hexlify(d_bd[32:64]),16))
print('sig = ' + str(sig))
assert ecdsa.verify(server_R, sig, d_bd[64:])
d_ecdh = server_R * client_r
d_keybin = hashlib.sha256(d_ecdh.compress().encode('UTF-8')).digest()
print('ecdh key hex = ' + str(hexlify(d_keybin)))
d_ivcount = int(hexlify(d_bd[64:80]),16)
print('iv hex = ' + str(hexlify(d_bd[64:80])))
d_counter = Counter.new(128,initial_value=d_ivcount)
d_cryptor = AES.new(d_keybin, AES.MODE_CTR, counter=d_counter)
d_plaintext = d_cryptor.decrypt(d_bd[80:])
d_plaintext = d_plaintext.decode('UTF-8')
print("plaintext = " + d_plaintext)

r = requests.get(_server3 + _status)
assert r.status_code == 200
rd = r.json()

server_P3 = Point.decompress(rd['pubkey'])

ooo_r = {}
ooo_r['local'] = False
ooo_r['host'] = 'coopr8.com'
ooo_r['port'] = 5000
ooo_r['pubkey'] = client_P.compress()
ooo_r['body'] = base64.b64encode(raw).decode('UTF-8')

client_p = random.randint(1,curve_secp256k1['n']-1)
client_P = _G * client_p

message = json.dumps(ooo_r)

ecdh = server_P3 * client_p
keybin = hashlib.sha256(ecdh.compress().encode('UTF-8')).digest()
iv = random.randint(0,(1 << 128)-1)
print('iv = 0x%032x' % iv)
ivbin = unhexlify('%032x' % iv)
counter = Counter.new(128, initial_value=iv)
cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
ciphertext = cryptor.encrypt(message)
raw = ivbin + ciphertext
sig = nak.sign(raw)
signed = nakpubbin + unhexlify('%064x' % sig[0]) + unhexlify('%064x' % sig[1]) + raw
payload = base64.b64encode(signed)

r = requests.post(_server3 + _onion + client_P.compress(), data=payload)
assert r.status_code == 200
d_bd = base64.b64decode(r.text)
sig = (int(hexlify(d_bd[0:32]),16), int(hexlify(d_bd[32:64]),16))
print('sig = ' + str(sig))
assert ecdsa.verify(server_R, sig, d_bd[64:])
d_ecdh = server_R * client_r
d_keybin = hashlib.sha256(d_ecdh.compress().encode('UTF-8')).digest()
print('ecdh key hex = ' + str(hexlify(d_keybin)))
d_ivcount = int(hexlify(d_bd[64:80]),16)
print('iv hex = ' + str(hexlify(d_bd[64:80])))
d_counter = Counter.new(128,initial_value=d_ivcount)
d_cryptor = AES.new(d_keybin, AES.MODE_CTR, counter=d_counter)
d_plaintext = d_cryptor.decrypt(d_bd[80:])
d_plaintext = d_plaintext.decode('UTF-8')
print("plaintext = " + d_plaintext)


