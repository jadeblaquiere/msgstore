import ctcoin.rpc
import binascii
from ctcoin.core.script import *
from nak import NAK
import plyvel
import json
import logging

config = {}
config['rpchost'] = '127.0.0.1'
config['rpcport'] = 7765
config['minconf'] = 6
config['dbdir'] = 'nakdb/'

_config_key = binascii.unhexlify('000000000000000000000000000000000000000000000000000000000000000000')

class NAKCache(object):
    def __init__(self, dbdir=config['dbdir'], host=config['rpchost'], 
                 port=config['rpcport'], rpcuser=None, rpcpass=None, 
                 minconf=config['minconf']):
        self.naklist = []
        self.blockcount = 0
        rpcstr = ''
        if rpcuser is not None and rpcpass is not None:
            rpcstr = rpcuser + ':' + rpcpass + '@'
        url = 'https://' + rpcstr + host + ':' + str(port) + '/'
        self.proxy = ctcoin.rpc.Proxy(service_url=url, service_port=str(port))
        try:
            current = self.proxy.getblockcount()
        except:
            raise ValueError('Cannot connect to RPC Host')
        self.minconf = minconf
        self.db = plyvel.DB(dbdir, create_if_missing=True)
        statusj = self.db.get(_config_key)
        if statusj is not None:
            self.status = json.loads(statusj.decode('UTF-8'))
            self.blockcount = self.status['blockcount']
            logging.info('read blockcount as %d' % self.blockcount)
            logging.info('status = %s' % str(self.status))
        else:
            self.status = {}
            self.status['blockcount'] = 0

    def sync(self):
        current = self.proxy.getblockcount()
        if self.blockcount >= current - self.minconf:
            return False
        #print('sync from height %d to %d' % (self.blockcount, current-self.minconf))
        for i in range(self.blockcount, current - self.minconf):
            if (i & 0x3f) == 0:
                logging.info('checkpointing NAK cache to block %d' % i)
                self.status['blockcount'] = i
                self.db.put(_config_key, json.dumps(self.status).encode('UTF-8'))
            blockhash = self.proxy.getblockhash(i)
            b = self.proxy.getblock(blockhash)
            #print('processing block at height %d, %d txns' % (i, len(b.vtx)))
            for j in range (0,len(b.vtx)):
                tx = b.vtx[j]
                #print('vout len = %d' % len(tx.vout))
                for k in range(0,len(tx.vout)):
                    out = tx.vout[k]
                    s = out.scriptPubKey
                    if s[0] != OP_REGISTERACCESSKEY:
                        continue
                        
                    if s[1] == OP_PUSHDATA1:
                        size = int(binascii.hexlify(s[2:3]), 16)
                        base = 3
                    elif s[1] == OP_PUSHDATA2:
                        size = int(binascii.hexlify(s[2:4]), 16)
                        base = 4
                    elif s[1] == OP_PUSHDATA4:
                        size = int(binascii.hexlify(s[2:6]), 16)
                        base = 6
                    else:
                        continue

                    #print('size =%d' % size)
                    if size != 101:
                        continue
                        
                    nak = NAK.deserialize(s[base:base+101])
                    if nak is not None:
                        logging.info('inserting NAK = ' + str(nak))
                        with self.db.write_batch() as wb:
                            nkey = binascii.unhexlify(nak.pubkey.compress())
                            wb.put(nkey, nak.dumpjson().encode('UTF-8'))
                            self.status['blockcount'] = i
                            self.blockcount = i
                            wb.put(_config_key, json.dumps(self.status).encode('UTF-8'))
        self.status['blockcount'] = current-self.minconf
        self.blockcount = current-self.minconf
        self.db.put(_config_key, json.dumps(self.status).encode('UTF-8'))

    def get_nak(self,keyval):
        nakjson = self.db.get(binascii.unhexlify(keyval))
        if nakjson is None:
            return None
        return NAK.loadjson(nakjson.decode('UTF-8'))


if __name__ == "__main__":
    ncache = NAKCache(rpcuser='theboss', rpcpass='springst33n')
    ncache.sync()
    with ncache.db.iterator() as it:
        for k,v in it:
            print('\nkey = %s' % binascii.hexlify(k))
            print('val = %s' % v)