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

import keys

_header_size = (8+1+8+1+66+1+66+1+66)

class MessageHeader (object):
    def __init__(self):
        self.m = {}
        self.m['time'] = None
        self.m['expire'] = None
        self.m['I'] = None
        self.m['J'] = None
        self.m['K'] = None

    def import_header(self, cmsg):
        if len(cmsg) < _header_size:
            return False
        hdrdata = cmsg[:_header_size].split(':')
        if len(hdrdata) != 5:
            return False
        self.m['time'] = int(hdrdata[0], 16)
        self.m['expire'] = int(hdrdata[1], 16)
        self.m['I'] = keys.decompress_point(hdrdata[2])
        self.m['J'] = keys.decompress_point(hdrdata[3])
        self.m['K'] = keys.decompress_point(hdrdata[4])
        return True
    
    def export_header(self):
        hdr = ('%08X' % self.m['time']) + ':'
        hdr += ('%08X' % self.m['expire']) + ':'
        hdr += keys.compress_point(self.m['I']) + ':'
        hdr += keys.compress_point(self.m['J']) + ':'
        hdr += keys.compress_point(self.m['K'])
        return hdr

    def __eq__(self,h):
        if self.m['time'] != h.m['time']:
            return False
        if self.m['expire'] != h.m['expire']:
            return False
        if self.m['I'] != h.m['I']:
            return False
        if self.m['J'] != h.m['J']:
            return False
        if self.m['K'] != h.m['K']:
            return False
        return True

    def __ne__(self, h):
        return not (self == h)

    def __gt__(self, h):
        if self.m['time'] < h.m['time']:
            return False
        if self.m['time'] > h.m['time']:
            return True
        if self.m['I'] > h.m['I']:
            return True
        return False

    def __lt__(self, h):
        if self.m['time'] > h.m['time']:
            return False
        if self.m['time'] < h.m['time']:
            return True
        if self.m['I'] < h.m['I']:
            return True
        return False

    def __le__(self, h):
        return not (self > h)

    def __ge__(self, h):
        return not (self < h)

    def __str__(self):
        return self.export_header()

    def msgid(self):
        return keys.compress_point(self.m['I'])


class Message (MessageHeader):
    def __init__(self, cmsg=None):
        super(self.__class__, self).__init__()
        self.m['m'] = None
        self.m['from'] = None
        self.m['to'] = None
        self.m['topic'] = None
        self.m['body'] = None
        self.m['cmsg'] = None
        self.m['servertime'] = None
        if cmsg:
            self.import_message(cmsg)

    def import_message(self, cmsg):
        hdrdata = cmsg.split(':')
        if len(hdrdata) != 6:
            return False
        self.import_header(cmsg[:_header_size])
        self.m['m'] = hdrdata[5]
        self.m['s'] = None
        self.m['from'] = None
        self.m['to'] = None
        self.m['topic'] = None
        self.m['body'] = None
        self.m['servertime'] = None
        self.m['cmsg'] = cmsg
        return True

    def export_message(self):
        return self.export_header() + ':' + self.m['m']

    def decode(self, privkey):
        if ((self.m['I'][0] >> (keys._C['bits'] - keys._masksize)) &
                privkey.pkey['addr']['mask']) != privkey.pkey['addr']['mtgt']:
            return False
        ex = self.export_message()
        dec = privkey.decode_message(ex)
        if dec:
            self.m['to'] = privkey.label()
            self.m['s'] = dec['s']
            self.m['body'] = dec['msg']
            return True
        else:
            return False

    def decode_sent(self, privkey, altK):
        ex = self.export_message()
        dec = privkey.decode_sent_message(ex, altK)
        if dec:
            self.m['from'] = privkey.pubkey_label()
            self.m['s'] = dec['s']
            self.m['body'] = dec['msg']
            return True
        else:
            return False
    
    def __str__(self):
        if self.m['cmsg']:
            return self.m['cmsg']
        else:
            return self.export_message()


if __name__ == '__main__':  # pragma: no cover
    import sys
    import model
    model.init()
    sys.setrecursionlimit(512)
    model.ks.clear()
    model.ms.clear()
    model.test_seed_keystore()
    model.test_seed_messagestore()
    for m in model.ms.msglist:
        for pk in model.ks.pvtkeys:
            print('trying', pk.label())
            if m.decode(pk):
                print('decoded!!!!!')
                print(str(m.m))
                break
