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
