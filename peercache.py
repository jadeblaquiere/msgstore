from binascii import hexlify, unhexlify
import json
import logging
import time
import os
from tornado.httpclient import HTTPClient, HTTPRequest, HTTPError
from lbr import lbr
from msgstoreclient import MsgStore
import ctcoin.rpc

from ecpy.curves import curve_secp256k1
from ecpy.point import Point

_curve = curve_secp256k1
Point.set_curve(_curve)

_default_port=5000
_default_coin_port=7764
_default_max_age=(4*60*60)    # 4 hours
_default_max_fails=1

_statusPath = 'api/status/'
_peerListPath = 'api/peer/list/'
_peerUpdatePath = 'api/peer/update/'

_peer_msync_timeout = 30
_peer_psync_interval = (2*60)   # 2 minutes

sclient = HTTPClient()

seed_peers = ['ciphrtxt.com:5000', 
              'coopr8.com:5000']

config = {}
config['rpchost'] = '127.0.0.1'
config['rpcport'] = 7765


class PeerListItem (object):
    def __init__(self, host, port=_default_port):
        self.host = host
        self.port = port

    def dumpjson(self):
        d = {}
        d['host'] = self.host
        d['port'] = self.port
        return json.dumps(d)

    @staticmethod
    def loadjson(jin):
        try:
            d = json.loads(jin)
            n = PeerListItem(d['host'], d['port'])
            return n
        except:
            return None

    def dumpdict(self):
        d = {}
        d['host'] = self.host
        d['port'] = self.port
        return d

    @staticmethod
    def loaddict(din):
        try:
            n = PeerListItem(din['host'], din['port'])
            return n
        except:
            return None
    
    def __str__(self):
        return self.dumpjson()

    def __repr__(self):
        return 'PeerListitem.loadjson(' + self.dumpjson() + ')'

    def __eq__(self, r):
        return self.host == r.host
    
    def __ne__(self, r):
        return self.host != r.host
    
    def __gt__(self, r):
        return self.host > r.host
    
    def __lt__(self, r):
        return self.host < r.host
    
    def __ge__(self, r):
        return not self < r
    
    def __le__(self, r):
        return not self > r
        

class PeerHost(object):
    def __init__(self, host, port=_default_port, Pkey=None, coinhost=None, coinport=None):
        self.host = host
        self.port = port
        self.Pkey = Pkey
        self.coinhost = coinhost
        self.coinport = coinport
        self.lastseen = 0
        self.fails = 0
        self.peerlist = []
        self.msgstore = MsgStore(self._baseurl())
        self.last_msgcount = 0
        self.last_fetchtime = 0
        self.score = 0.0
    
    def _baseurl(self):
        return 'http://' + self.host + ':' + str(self.port) + '/'

    def refresh(self):
        r = None
        rtime = time.time()
        logging.info('refresh called for ' + self._baseurl())
        req = HTTPRequest(self._baseurl() + _statusPath, method='GET', connect_timeout=30, request_timeout=60)
        try:
            r = sclient.fetch(req)
        except (HTTPError, ConnectionRefusedError) :
            self.fails += 1
            return False
        if r.code != 200:
            self.fails += 1
            return False
        status = json.loads(r.body.decode('UTF-8'))
        if 'pubkey' in status:
            self.Pkey = Point.decompress(status['pubkey'].encode('UTF-8'))
        if 'coinhost' in status:
            self.coinhost = status['coinhost']
        if 'coinport' in status:
            self.coinport = status['coinport']
        self.lastseen = rtime
        req = HTTPRequest(self._baseurl() + _peerListPath, method='GET', connect_timeout=30, request_timeout=60)
        try:
            r = sclient.fetch(req)
        except (HTTPError, ConnectionRefusedError) :
            self.fails += 1
            return False
        if r.code != 200:
            self.fails += 1
            return False
        rlist = json.loads(r.body.decode('UTF-8'))
        self.peerlist = []
        for r in rlist:
            n = PeerListItem.loaddict(r)
            if n is not None:
                self.add_peer(n)
        self.peerlist.sort()
        self.fails = 0
        return True

    def dumpjson(self):
        j = {}
        j['host'] = self.host
        j['port'] = self.port
        if self.Pkey is not None:
            j['pubkey'] = self.Pkey.compress()
        pl = []
        for li in self.peerlist:
            d = li.dumpdict()
            if d is not None:
                pl.append(d)
        j['peerlist'] = pl
        if self.coinhost is not None:
            j['coinhost'] = self.coinhost
        if self.coinport is not None:
            j['coinport'] = self.coinport
        return json.dumps(j)

    @staticmethod
    def loadjson(j):
        try:
            j = json.loads(j)
            n = PeerHost(j['host'], int(j['port']))
            if 'pubkey' in j:
                n.Pkey = Point.decompress(j['pubkey'])
            n.peerlist = []
            for li in j['peerlist']:
                nli = PeerListItem.loaddict(li)
                if nli is not None:
                    n.peerlist.append(nli)
            if 'coinhost' in j:
                n.coinhost = j['coinhost']
            if 'coinport' in j:
                n.coinhost = j['coinport']
            return n
        except:
            return None

    def peerlistitem(self):
        return PeerListItem(self.host, self.port)

    def sorted_peers(self):
        self.peerlist.sort()
        return self.peerlist
    
    def add_peer(self, n):
        for p in self.peerlist:
            if p == n:
                break
        else:
            self.peerlist.append(n)

    def __str__(self):
        return str(self.dumpjson())

    def __repr__(self):
        return 'PeerHost.loadjson(' + str(self) + ')'

    def __eq__(self, r):
        if self.host == r.host:
            return self.port == r.port
        return False

    def __ne__(self, r):
        return not self == r

    def __gt__(self, r):
        return self.host > r.host
    
    def __lt__(self, r):
        return self.host < r.host
    
    def __ge__(self, r):
        return self.host >= r.host
    
    def __le__(self, r):
        return self.host <= r.host


class PeerCache (object):
    def __init__(self, host, port=_default_port, Pkey=None, coinhost=None, 
                 coinport=_default_coin_port, rpchost=config['rpchost'],
                 rpcport=config['rpcport'], rpcuser=None, rpcpass=None, standalone=False):
        self.max_age = _default_max_age
        self.peers = []
        self.maxpush = 20
        self.hostinfo = PeerHost(host, port, Pkey, coinhost, coinport)
        for s in seed_peers:
            p = s.split(':')
            self.peers.append(PeerHost(p[0], int(p[1])))
            self.hostinfo.peerlist.append(PeerListItem(p[0], p[1]))
        self.standalone = standalone
        if self.standalone:
            self.proxy = None
        else:
            rpcstr = ''
            if rpcuser is not None and rpcpass is not None:
                rpcstr = rpcuser + ':' + rpcpass + '@'
            url = 'https://' + rpcstr + rpchost + ':' + str(rpcport) + '/'
            self.proxy = ctcoin.rpc.Proxy(service_url=url, service_port=str(rpcport))
            try:
                current = self.proxy.getblockcount()
            except:
                raise ValueError('Cannot connect to RPC Host @ ' + url)
        

    def refresh(self):
        now = int(time.time())
        expired = now - self.max_age
        for p in self.peers:
            logging.info('refresh peer ' + p.host + ': fails = ' + str(p.fails))
            p.refresh()
            if p.lastseen < expired or p.fails > _default_max_fails:
                logging.info('dropping peer ' + p.host)
                self.peers.remove(p)

    def discover_peers(self):
        self.refresh()
        for p in self.peers:
            #print(self.hostinfo.peerlist)
            llist = self.hostinfo.sorted_peers()
            #print('llist = ' + str(llist))
            rlist = p.sorted_peers()
            #print('rlist = ' + str(rlist))
            lbr_lists = lbr(llist, rlist)
            for r in lbr_lists['right']:
                n = PeerHost(r.host, r.port)
                if n.refresh():
                    listentry = PeerListItem(r.host, r.port)
                    self.hostinfo.add_peer(listentry)
                    self.add_peer(n)
                    nodeaddr = ''
                    if n.coinhost is not None:
                        nodeaddr = n.coinhost
                        if n.coinport is not None:
                            nodeaddr += ':' + str(n.coinport)
                        if not self.standalone:
                            self.proxy.addnode(nodeaddr)
            pli = self.hostinfo.peerlistitem()
            if pli not in rlist:
                #print('uploading ' + str(pli))
                plijson = pli.dumpjson().encode('UTF-8')
                #print('url = ' + self.hostinfo._baseurl() + _peerUpdatePath)
                req = HTTPRequest(p._baseurl() + _peerUpdatePath, 
                                  method='POST', body=plijson,
                                  connect_timeout=30, request_timeout=60)
                try:
                    r = sclient.fetch(req)
                except HTTPError:
                    p.fails += 1
                    continue
        self.peers.sort()
    
    def list_peers(self):
        l = []
        for p in self.peers:
            listentry = {'host': p.host, 'port': p.port}
            l.append(listentry)
        return l

    def add_peer(self, host, port=_default_port):
        n = PeerHost(host, port)
        for p in self.peers:
            if n == p:
                break
        else:
            self.peers.append(n)
            
    
    def peer_sync_thread(self):
        last_psync = 0
        last_msync = 0
        
        while True:
            try:
                now = time.time()
                if now > (last_psync + _peer_psync_interval):
                    self.discover_peers()
                    last_psync = now

                local = self.hostinfo.msgstore
                remotes = []
                for p in self.peers:
                    if p != self.hostinfo:
                        r = p.msgstore
                        remotes.append(r)

                lhdr = local.get_headers()
                logging.debug('local got %d headers' % len(lhdr))
                rlist = []
                for r in remotes:
                    rhdr = r.get_headers()
                    logging.debug('remote got %d headers' % len(rhdr))
                    rtmp = {}
                    rtmp['store'] = r
                    rtmp['hdrs'] = rhdr
                    rlist.append(rtmp)

                tpush = 0
                for rl in rlist:
                    r = rl['store']
                    rhdr = rl['hdrs']
                    lbr_sort = lbr(lhdr, rhdr, reverse=True)
                    pushcount = 0
                    logging.debug("local left = %d" % len(lbr_sort['left']))
                    for lm in lbr_sort['left']:
                        if lm.m['expire'] > r.servertime:
                            logging.debug('local pull async ' + lm.msgid())
                            if local.get_message_async(lm,r.post_message):
                                pushcount += 1
                                if pushcount > self.maxpush:
                                    break
                        else:
                            logging.debug('ignoring local expiring ' + lm.msgid())
                    tpush += pushcount
                    pushcount = 0
                    logging.debug("remote right = %d" % len(lbr_sort['right']))
                    for rm in lbr_sort['right']:
                        if rm.m['expire'] > local.servertime:
                            logging.debug('remote pull async ' + rm.msgid())
                            if r.get_message_async(rm,local.post_message):
                                pushcount += 1
                                if pushcount > self.maxpush:
                                    break
                        else:
                            logging.debug('ignoring remote expiring ' + lm.msgid())
                    tpush += pushcount

                if tpush == 0:
                    time.sleep(_peer_msync_timeout)
            except:
                logging.exception('peer sync thread: uncaught exception')

                    