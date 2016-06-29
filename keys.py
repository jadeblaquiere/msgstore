# coding: utf-8

import time
import random
import hashlib
import hmac
import ecpy.curves as curves
import sys
import base64
import aes
import ecpy.point as point

_C = curves.curve_secp256k1
# _C = eccconstants.curve_secp384r1
# _C = eccconstants.curve_secp112r1
# _C = eccconstants.curve_bauer9

_masksize = min(32, _C['bits'])
_maskbits = (int((_masksize / 3) + 0))

_G_Pt = point.Generator.init(_C['G'][0], _C['G'][1])

# parameters for time based keys, median = 24h, sd = 4h, min 12h, max 36h
_tstarget = (60 * 60 * 24)
_tssigma = (60 * 60 * 4)
_tsmin = (60 * 60 * 12)
_tsmax = (60 * 60 * 36)

# convert integer to hex string
_pfmt = '%%0%dx' % (((_C['bits'] + 7) >> 3) << 1)
_mfmt = '%%0%dx' % (((_masksize + 7) >> 3) << 1)

# v1.0 in fixed point
_format_version = 0x0100


def compress_point(P):
    return ('03' if (P[1] % 2) else '02') + (_pfmt % P[0])


def decompress_point(K):
    P = [0, 0]
    x = P[0] = int(K[2:], 16)
    sign = int(K[:2], 16) & 1
    beta = pow(int(x * x * x + _C['a'] * x + _C['b']),
               int((_C['p'] + 1) // 4), int(_C['p']))
    P[1] = (_C['p']-beta) if ((beta + sign) & 1) else beta
    return (P[0], P[1])


class PublicKey (object):
    def __init__(self, key=None, name=None):
        self.Pkey = {'P': [0, 0],
                     'addr': {'mask': 0, 'mtgt': 0},
                     't0': 0,
                     'ts': 0,
                     'tbk': ({'otp': 0,
                              'T': [0, 0]})}
        self.name = name
        self.metadata = {}
        self.initialized = False
        if key:
            self.pubkey_import(key)
            self.initialized = True

    def set_metadata(self, metakey, metavalue):
        self.metadata[metakey] = metavalue

    def get_metadata(self, metakey):
        if metakey not in self.metadata:
            return None
        return self.metadata[metakey]

    def label(self):
        txt = (_pfmt % self.Pkey['P'][0])[:8]
        if self.name:
            txt = self.name + '_' + txt
        return txt

    def current_pubkey_point(self, timeval=None):
        if not self.initialized:
            return None
        if timeval is None:
            timeval = int(time.time())
        steps = (timeval - self.Pkey['t0']) / self.Pkey['ts']
        P = point.Point(self.Pkey['P'][0], self.Pkey['P'][1])
        for i in range(len(self.Pkey['tbk'])):
            okeyt = _pfmt % (self.Pkey['tbk'][i]['otp'])
            stepsd = '%07d' % (steps % 10000000)
            otphmac = hmac.new(okeyt, stepsd, hashlib.sha256)
            hashv = otphmac.hexdigest()
            hashi = int(hashv, 16) % _C['p']
            S = (point.Point(self.Pkey['tbk'][i]['T'][0],
                             self.Pkey['tbk'][i]['T'][1]) * hashi)
            P = S + P
        return P.affine()

    def pubkey_export64(self):
        def htob64(s):
            import binascii
            return binascii.b2a_base64(s.decode('hex'))
        ekey = 'P%04x' % _format_version
        ekey += ':K' + htob64(compress_point(self.Pkey['P']))
        ekey += ':M' + htob64(_mfmt % self.Pkey['addr']['mask'])
        ekey += ':N' + htob64(_mfmt % self.Pkey['addr']['mtgt'])
        ekey += ':Z' + htob64('%08x' % self.Pkey['t0'])
        ekey += ':S' + htob64('%08x' % self.Pkey['ts'])
        ekey += ':R' + htob64('%04x' % len(self.Pkey['tbk']))
        for tbk in self.Pkey['tbk']:
            ekey += ':F' + htob64(_pfmt % tbk['otp'])
            ekey += ':T' + htob64(compress_point(tbk['T']))
        ekey += ':C' + hashlib.sha256(ekey).hexdigest()[-8:]
        return ekey

    def pubkey_export(self):
        ekey = 'P%04x' % _format_version
        ekey += ':K' + compress_point(self.Pkey['P'])
        ekey += ':M' + (_mfmt % self.Pkey['addr']['mask'])
        ekey += ':N' + (_mfmt % self.Pkey['addr']['mtgt'])
        ekey += ':Z' + ('%08x' % self.Pkey['t0'])
        ekey += ':S' + ('%08x' % self.Pkey['ts'])
        ekey += ':R' + ('%04x' % len(self.Pkey['tbk']))
        for tbk in self.Pkey['tbk']:
            ekey += ':F' + (_pfmt % tbk['otp'])
            ekey += ':T' + compress_point(tbk['T'])
        ekey += ':C' + hashlib.sha256(ekey).hexdigest()[-8:]
        return ekey

    def pubkey_import(self, ikey):
        # verify checksum
        inp = ikey.split(':C')
        if len(inp) != 2:
            return None
        ckck = hashlib.sha256(inp[0]).hexdigest()[-8:]
        if ckck != inp[1]:
            return None
        # verify keys
        inp = inp[0].split(':')
        if len(inp) < 7:
            return None
        if ((inp[0][:1] != 'P') or (inp[1][:1] != 'K') or
                (inp[2][:1] != 'M') or (inp[3][:1] != 'N') or
                (inp[4][:1] != 'Z') or (inp[5][:1] != 'S') or
                (inp[6][:1] != 'R')):
            return None
        # verify version
        if (inp[0][1:] != '0100'):
            return None
        # decompress point
        self.Pkey['P'] = decompress_point(inp[1][1:])
        #
        self.Pkey['addr']['mask'] = int(inp[2][1:], 16)
        self.Pkey['addr']['mtgt'] = int(inp[3][1:], 16)
        self.Pkey['t0'] = int(inp[4][1:], 16)
        self.Pkey['ts'] = int(inp[5][1:], 16)
        # time base key(s)
        ntbk = int(inp[6][1:])
        tbk = []
        for i in range(ntbk):
            key = {}
            key['otp'] = int(inp[7 + (2 * i)][1:], 16)
            key['T'] = decompress_point(inp[8 + (2 * i)][1:])
            tbk.append(key)
        self.Pkey['tbk'] = tbk
        self.initialized = True
        return self.Pkey

    def encode_message(self, text, sig=None, progress_callback=None):
        if not sig:
                sig = random.randint(2, _C['n']-1)
        tval = int(time.time())
        texp = tval + (7 * 24 * 60 * 60)
        P = self.current_pubkey_point(tval)
        P_pt = point.Point(P[0], P[1])
        status = {}
        status['besthash'] = 0
        status['bestbits'] = _masksize
        status['nhash'] = 0
        while True:
            s = random.randint(2, _C['n']-1)
            I = (_G_Pt * s).affine()
            maskval = ((I[0] >> (_C['bits'] - _masksize)) &
                       self.Pkey['addr']['mask'])
            maskmiss = bin(maskval ^ self.Pkey['addr']['mtgt']).count('1')
            if maskmiss < status['bestbits']:
                status['bestbits'] = maskmiss
                status['besthash'] = maskval
            if maskval == self.Pkey['addr']['mtgt']:
                break
            if progress_callback:
                if (status['nhash'] % 10) == 0:
                    progress_callback(status)
            status['nhash'] += 1
        J = (P_pt * s).affine()
        stext = _pfmt % s
        h = int(hashlib.sha256(stext + text).hexdigest(), 16)
        k = (sig * h) % _C['n']
        K = (_G_Pt * k).affine()
        DH = (P_pt * k).affine()
        iv = compress_point(I)
        key = compress_point(DH)
        my_aes = aes.AESCipher(key)
        msg = (_pfmt % s) + ':' + base64.b64encode(text)
        ctext = my_aes.encrypt_iv(msg, iv)
        hdr = ('%08X' % tval) + ':' + ('%08X' % texp) + ':'
        hdr += compress_point(I) + ':' + compress_point(J) + ':'
        hdr += compress_point(K) + ':' + ctext
        sentkey = (P_pt * h).affine()
        return (hdr, compress_point(sentkey))


class PrivateKey (PublicKey):
    def __init__(self, key=None, name=None):
        self.pkey = {'p': 0,
                     'addr': {'mask': 0, 'mtgt': 0},
                     't0': 0,
                     'ts': 0,
                     'tbk': ({'otp': 0,
                              't': 0})}
        self.initialized = False
        super(self.__class__, self).__init__(name=name)
        if key:
            self.privkey_import(key)

    def label(self):
        txt = (_pfmt % self.pkey['p'])[:8]
        if self.name:
            txt = self.name + '_' + txt
        return txt

    def pubkey_label(self):
        return super(self.__class__, self).label()

    def randomize(self, ntbk=1):
        # base key
        self.pkey['p'] = random.randint(2, _C['n']-1)
        # address mask, value
        maskshift, maskval = 0, 0
        while (maskval == 0) or (_C['n'] < maskshift):
            mask, maskval, match = [], 0, 0
            for i in range(_maskbits):
                while True:
                    r = random.randint(0, _masksize-1)
                    if r not in mask:
                        break
                mask.append(r)
                bit = 1 << r
                maskval = maskval + bit
                match += bit * random.randint(0, 1)
                maskshift = match << (_C['bits'] - _masksize)
        self.pkey['addr']['mask'] = maskval
        self.pkey['addr']['mtgt'] = match
        # time zero, step size for rotating key(s)
        self.pkey['t0'] = random.randint(0, int(time.time()))
        while True:
            r = int(random.gauss(_tstarget, _tssigma))
            if (r > _tsmin) and (r > _tsmax):
                break
        self.pkey['ts'] = r
        # time-based-keys
        self.pkey['tbk'] = []
        for i in range(ntbk):
            tbk = {}
            tbk['otp'] = random.getrandbits(_C['bits'])
            tbk['t'] = random.randint(2, _C['n']-1)
            self.pkey['tbk'].append(tbk)
        self.calc_public_key()
        self.initialized = True

    def calc_public_key(self):
        self.Pkey['P'] = (_G_Pt * self.pkey['p']).affine()
        self.Pkey['addr'] = self.pkey['addr']
        self.Pkey['t0'] = self.pkey['t0']
        self.Pkey['ts'] = self.pkey['ts']
        self.Pkey['tbk'] = []
        for i in range(len(self.pkey['tbk'])):
            tbk = {}
            tbk['otp'] = self.pkey['tbk'][i]['otp']
            tbk['T'] = (_G_Pt * self.pkey['tbk'][i]['t']).affine()
            self.Pkey['tbk'].append(tbk)

    def current_privkey_val(self, timeval=None):
        if not self.initialized:
            return None
        if timeval is None:
            timeval = int(time.time())
        steps = (timeval - self.pkey['t0']) / self.pkey['ts']
        p = self.pkey['p']
        for i in range(len(self.pkey['tbk'])):
            okeyt = _pfmt % (self.pkey['tbk'][i]['otp'])
            stepsd = '%07d' % (steps % 10000000)
            otphmac = hmac.new(okeyt, stepsd, hashlib.sha256)
            hashv = otphmac.hexdigest()
            hashi = int(hashv, 16) % _C['p']
            s = (self.pkey['tbk'][i]['t'] * hashi) % _C['n']
            p = (s + p) % _C['n']
        return p

    def privkey_export(self):
        ekey = 'p%04x' % _format_version
        ekey += ':k' + (_pfmt % self.pkey['p'])
        ekey += ':m' + (_mfmt % self.pkey['addr']['mask'])
        ekey += ':n' + (_mfmt % self.pkey['addr']['mtgt'])
        ekey += ':z' + ('%08x' % self.pkey['t0'])
        ekey += ':s' + ('%08x' % self.pkey['ts'])
        ekey += ':r' + ('%04x' % len(self.pkey['tbk']))
        for tbk in self.pkey['tbk']:
            ekey += ':f' + (_pfmt % tbk['otp'])
            ekey += ':t' + (_pfmt % tbk['t'])
        ekey += ':c' + hashlib.sha256(ekey).hexdigest()[-8:]
        return ekey

    def privkey_import(self, ikey):
        # verify checksum
        inp = ikey.split(':c')
        if len(inp) != 2:
            return None
        ckck = hashlib.sha256(inp[0]).hexdigest()[-8:]
        if ckck != inp[1]:
            return None
        # verify keys
        inp = inp[0].split(':')
        if len(inp) < 7:
            return None
        if ((inp[0][:1] != 'p') or (inp[1][:1] != 'k') or
                (inp[2][:1] != 'm') or (inp[3][:1] != 'n') or
                (inp[4][:1] != 'z') or (inp[5][:1] != 's') or
                (inp[6][:1] != 'r')):
            return None
        # verify version
        if (inp[0][1:] != '0100'):
            return None
        self.pkey['p'] = int(inp[1][1:], 16)
        self.pkey['addr']['mask'] = int(inp[2][1:], 16)
        self.pkey['addr']['mtgt'] = int(inp[3][1:], 16)
        self.pkey['t0'] = int(inp[4][1:], 16)
        self.pkey['ts'] = int(inp[5][1:], 16)
        # time base key(s)
        ntbk = int(inp[6][1:])
        tbk = []
        for i in range(ntbk):
            key = {}
            key['otp'] = int(inp[7+(2*i)][1:], 16)
            key['t'] = int(inp[8+(2*i)][1:], 16)
            tbk.append(key)
        self.pkey['tbk'] = tbk
        self.calc_public_key()
        self.initialized = True
        return self.pkey

    def decode_message(self, m):
        hkeys = m.split(':')
        if len(hkeys) != 6:
            return None
        z = {}
        # verify 'to' = me
        z['time'] = int(hkeys[0], 16)
        z['expire'] = int(hkeys[1], 16)
        z['I'] = decompress_point(hkeys[2])
        z['J'] = decompress_point(hkeys[3])
        z['K'] = decompress_point(hkeys[4])
        p = self.current_privkey_val(z['time'])
        pI = (point.Point(z['I'][0], z['I'][1]) * p).affine()
        if pI != z['J']:
            return None
        DH = (point.Point(z['K'][0], z['K'][1]) * p).affine()
        iv = compress_point(z['I'])
        key = compress_point(DH)
        my_aes = aes.AESCipher(key)
        msg = my_aes.decrypt_iv(hkeys[5], iv).split(':')
        z['s'] = int(msg[0], 16)
        z['msg'] = base64.b64decode(msg[1])
        return z

    def decode_sent_message(self, m, altK):
        hkeys = m.split(':')
        if len(hkeys) != 6:
            return None
        z = {}
        # verify 'to' = me
        z['time'] = int(hkeys[0], 16)
        z['expire'] = int(hkeys[1], 16)
        z['I'] = decompress_point(hkeys[2])
        z['J'] = decompress_point(hkeys[3])
        z['K'] = decompress_point(hkeys[4])
        z['altK'] = decompress_point(altK)
        p = self.current_privkey_val(z['time'])
        DH = (point.Point(z['altK'][0], z['altK'][1]) * p).affine()
        iv = compress_point(z['I'])
        key = compress_point(DH)
        my_aes = aes.AESCipher(key)
        try:
            msgraw = my_aes.decrypt_iv(hkeys[5], iv)
            msg = msgraw.split(':')
            z['s'] = int(msg[0], 16)
            if (_G_Pt * z['s']) != point.Point(z['I'][0], z['I'][1]):
                return None
        except:
            return None
        z['msg'] = base64.b64decode(msg[1])
        return z


if __name__ == '__main__':  # pragma: no cover
    import qrcode
    sys.setrecursionlimit(512)
    alice = PrivateKey(name='Alice')
    alice.set_metadata('phone', '919-555-1212')
    print ('name =', alice.name)
    print ('phone=', alice.get_metadata('phone'))
    bob = PrivateKey()
    for i in range(100):
        alice.randomize(4)
        bob.randomize(4)
        print ('p=', alice.pkey)
        print ('P=', alice.Pkey)
        print ('\n')
        ex = alice.pubkey_export64()
        print (ex)
        print ('\n')
        ex = alice.pubkey_export()
        print (ex)
        myqr = qrcode.QRCode()
        myqr.add_data(ex)
        apub = PublicKey(ex)
        print ('Q=', apub.Pkey)
        ex = alice.privkey_export()
        print (x)
        myqr = qrcode.QRCode()
        myqr.add_data(ex)
        apriv = PrivateKey(ex)
        print ('q=', apriv.pkey)
        assert alice.pkey == apriv.pkey
        assert alice.Pkey == apub.Pkey
        ex = bob.pubkey_export()
        bpub = PublicKey(ex)
        msgtext = 'the quick brown fox jumped over the lazy dog'
        cmsg = bpub.encode_message(msgtext, alice.current_privkey_val())
        print ('ctext=', cmsg[0])
        print ('calt=', cmsg[1])
        pmsg = bob.decode_message(cmsg[0])
        print ('pmsg=', pmsg)
        qmsg = alice.decode_sent_message(cmsg[0], cmsg[1])
        print ('qmsg=', qmsg)
        for j in range(10):
            future = int(random.randint(int(time.time()), 0x7fffffff))
            z = alice.current_privkey_val(future)
            Z = alice.current_pubkey_point(future)
            W = (_G_Pt * z).affine()
            assert Z == W
