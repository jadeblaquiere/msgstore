from binascii import hexlify, unhexlify
import json
import logging
import time
import os
from tornado.httpclient import HTTPClient, HTTPRequest
from lbr import lbr

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

sclient = HTTPClient()

seed_peers = ['ciphrtxt.com:5000', 
              'coopr8.com:5000']

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
    
    def _baseurl(self):
        return 'http://' + self.host + ':' + str(self.port) + '/'

    def refresh(self):
        rtime = time.time()
        req = HTTPRequest(self._baseurl() + _statusPath, method='GET', connect_timeout=30, request_timeout=60)
        r = sclient.fetch(req)
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
        r = sclient.fetch(req)
        if r.code != 200:
            self.fails += 1
            return False
        rlist = json.loads(r.body.decode('UTF-8'))
        self.peerlist = []
        for r in rlist:
            n = PeerListItem.loaddict(r)
            if n is not None:
                self.peerlist.append(n)
        self.peerlist.sort()
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
                 coinport=_default_coin_port):
        self.max_age = _default_max_age
        self.peers = []
        self.hostinfo = PeerHost(host, port, Pkey, coinhost, coinport)
        for s in seed_peers:
            p = s.split(':')
            self.peers.append(PeerHost(p[0], int(p[1])))
            self.hostinfo.peerlist.append(PeerListItem(p[0], p[1]))

    def refresh(self):
        now = int(time.time())
        expired = now - self.max_age
        for p in self.peers:
            if p.lastseen < expired:
                if not p.refresh():
                    if p.fails > _default_max_fails:
                        self.peers.remove(p)

    def discover_peers(self):
        self.refresh()
        for p in self.peers:
            llist = self.hostinfo.sorted_peers()
            #print('llist = ' + str(llist))
            rlist = p.sorted_peers()
            #print('rlist = ' + str(rlist))
            lbr_lists = lbr(llist, rlist)
            for r in lbr_lists['right']:
                n = PeerHost(r['host'], r['port'])
                if n.refresh():
                    listentry = {'host': r['host'], 'port': r['port']}
                    self.hostinfo.peerlist.append(listentry)
                    self.peers.append[n]
            pli = self.hostinfo.peerlistitem()
            if pli not in rlist:
                #print('uploading ' + str(pli))
                plijson = pli.dumpjson().encode('UTF-8')
                #print('url = ' + self.hostinfo._baseurl() + _peerUpdatePath)
                req = HTTPRequest(self.hostinfo._baseurl() + _peerUpdatePath, 
                                  method='POST', body=plijson,
                                  connect_timeout=30, request_timeout=60)
                r = sclient.fetch(req)
        self.peers.sort()
    
    def list_peers(self):
        l = []
        for p in self.peers:
            listentry = {'host': p.host, 'port': p.port}
            l.append(listentry)
        return l

    def add_peer(self, host, port=_default_port):
        n = PeerHost(host, port)
        if n not in self.peers:
            self.peers.append(n)
            
                    
                    