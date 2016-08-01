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

from binascii import hexlify, unhexlify
import plyvel
import json
import logging
import time
import os

from msgfile import Message

config = {}
config['dbdir'] = 'msgdb/'
config['message_dir'] = 'messages'

class MessageCache(object):
    def __init__(self):
        self.db = plyvel.DB(config['dbdir'], create_if_missing=True)
        self.messagecount=0
        self.messagesize=0
    
    def scan_message_dir(self):
        filenames = os.listdir(config['message_dir'])
        now = int(time.time())
        for fname in filenames:
            dirpath, I = os.path.split(fname)
            meta = self.db.get(unhexlify(I))
            if meta is None:
                filepath = config['message_dir'] + '/' + fname
                msg = Message()
                if msg.ingest(filepath):
                    if msg.expire > now:
                        #logging.info('adding ' + fname)
                        meta = msg.dumpjson()
                        self.db.put(unhexlify(I), meta.encode('UTF-8'))
                    else:
                        logging.info('expired ' + fname)
                        os.remove(filepath)

    def list_all(self):
        now = time.time()
        l = []
        count = 0
        size = 0
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                size += vdict['size']
                if vdict['expire'] < now:
                    path = vdict['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    l.append(vdict)
        self.messagecount = count
        self.messagesize = size
        return l

    def list_since(self, servertime):
        now = time.time()
        l = []
        count = 0
        size = 0
        stime = int(servertime)
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                size += vdict['size']
                if vdict['expire'] < now:
                    path = vdict['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    if vdict['servertime'] >= stime:
                        l.append(vdict)
        self.messagecount = count
        self.messagesize = size
        return l

    def header_list_all(self):
        now = time.time()
        l = []
        count = 0
        size = 0
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                size += vdict['size']
                if vdict['expire'] < now:
                    path = vdict['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    l.append(vdict['header'])
        self.messagecount = count
        self.messagesize = size
        return l

    def header_list_since(self, servertime):
        now = time.time()
        l = []
        count = 0
        size = 0
        stime = int(servertime)
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                size += vdict['size']
                if vdict['expire'] < now:
                    path = vdict['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    if int(vdict['servertime']) >= stime:
                        l.append(vdict['header'])
        self.messagecount = count
        self.messagesize = size
        return l

    def get(self,I):
        mjson = self.db.get(unhexlify(I))
        if mjson is None:
            return None
        return Message.loadjson(mjson.decode('UTF-8'))

    def add(self,msg):
        val = msg.dumpjson()
        if val is not None:
            self.db.put(unhexlify(msg.I), val.encode('UTF-8'))

