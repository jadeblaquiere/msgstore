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
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                if vdict['expire'] < now:
                    path = vdist['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    l.append(vdict)
        self.messagecount = count
        return l

    def list_since(self, servertime):
        now = time.time()
        l = []
        count = 0
        stime = int(servertime)
        if self.newestfirst is None:
            self._gentimeindex()
        
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                if vdict['expire'] < now:
                    path = vdist['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    if vdict['servertime'] >= stime:
                        l.append(vdict)
        self.messagecount = count
        return l

    def header_list_all(self):
        now = time.time()
        l = []
        count = 0
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                if vdict['expire'] < now:
                    path = vdist['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    l.append(vdict['header'])
        self.messagecount = count
        return l

    def header_list_since(self, servertime):
        now = time.time()
        l = []
        count = 0
        stime = int(servertime)
        with self.db.iterator() as it:
            for k, v in it:
                count += 1
                vdict = json.loads(v.decode('UTF-8'))
                if vdict['expire'] < now:
                    path = vdict['filepath']
                    os.remove(path)
                    self.db.delete(k)
                else:
                    if int(vdict['servertime']) >= stime:
                        l.append(vdict['header'])
        self.messagecount = count
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

