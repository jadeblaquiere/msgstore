from nak import NAK
from Crypto.Random import random
import time
import binascii

#import pdb

_n_tests = 1000

test_naks = []

now = int(time.time())

print("generating %d keys" % _n_tests)

for i in range(0,_n_tests):
    newnak = NAK()
    expire = now + random.randint(1,365) * (24*60*60)
    newnak.randomize(expire)
    test_naks.append(newnak)

print("validating keys are unique and serializable")

count = 0
for nak in test_naks:
    #print('nak %d = %s' % (count, str(nak)))
    #print('repr(nak) = ' + repr(nak))
    
    nmatch = 0
    for nnak in test_naks:
        if nak == nnak:
            nmatch += 1
    assert nmatch == 1
    
    ser = nak.serialize()
    deser = NAK.deserialize(ser)
    assert nak == deser
    
    jnak = nak.dumpjson()
    dejson = NAK.loadjson(jnak)
    assert nak == dejson
    
    count += 1

print ('sort keys forwards')
    
test_naks.sort()
count = 999
for nak in test_naks:
    gtcount = 0
    for nnak in test_naks:
        if nnak > nak:
            gtcount += 1
    assert gtcount == count
    count -= 1

print ('sort keys reverse')

test_naks.sort(reverse=True)
count = 0
for nak in test_naks:
    gtcount = 0
    for nnak in test_naks:
        if nnak > nak:
            gtcount += 1
    assert gtcount == count
    count += 1

print ('validating signtures')

count = 0 
for nak in test_naks:
    print ('sig key %d' % count)
    rval = random.getrandbits(2048)
    hhex = "%0512x" % rval
    hbin = binascii.unhexlify(hhex)
    sig = nak.sign(hbin)
    assert nak.verify(sig, hbin)
    scount = 0
    for nnak in test_naks:
        if nnak.verify(sig, hbin):
            scount += 1
    assert scount == 1
    count += 1
