from binascii import hexlify, unhexlify
import json
import logging
import time
import os
from tornado.httpclient import HTTPClient, HTTPRequest
from lbr import lbr

_default_port=5000
_default_max_age=(4*60*60)    # 4 hours
_default_max_fails=1

_statusPath = 'api/status/'
_peerListPath = 'api/peer/list/'
_peerUpdatePath = 'api/peer/update/'

sclient = HTTPClient()

seed_peers = ['ciphrtxt.com:5000', 
              'coopr8.com:5000']

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
        pub = json.loads(r.body.decode('UTF-8'))['pubkey']
        self.Pkey = Point.decompress(pub.encode('UTF-8'))
        self.lastseen = rtime
        req = HTTPRequest(self._baseurl() + _peerListPath, method='GET', connect_timeout=30, request_timeout=60)
        r = sclient.fetch(req)
        if r.code != 200:
            self.fails += 1
            return False
        self.peerlist = json.loads(r.body.decode('UTF-8'))['peers']
        self.peerlist.sort()
        return True

    def dumpjson(self):
        j = {}
        j['host'] = self.host
        j['port'] = self.port
        j['pubkey'] = self.Pkey.compress()
        j['peerlist'] = self.peerlist
        return json.dumps(j)

    @staticmethod
    def loadjson(j):
        try:
            n = PeerHost()
            j = json.loads(j)
            n.host = j['host']
            n.port = int(j['port'])
            n.Pkey = Point.uncompress(j['pubkey'])
            n.peerlist = j['peerlist']
            return n
        except:
            return None

    def sorted_peers(self):
        self.peerlist.sort(key=lambda x: (x['host'], x['port']))
        return sorted(self.peerlist)

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
        return self.host > r.host
    
    def __le__(self, r):
        return self.host < r.host


class PeerCache (object):
    def __init__(self, host, port=_default_port, Pkey=None):
        self.max_age = _default_max_age
        self.peers = []
        self.hostinfo = PeerHost(host, port, Pkey)
        for s in seed_peers:
            p = s.split(':')
            self.peers.append(PeerHost(p[0], int(p[1])))
            self.hostinfo.peerlist.append({'host': p[0], 'port': p[1]})

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
            rlist = p.sorted_peers()
            lbr_lists = lbr(llist, rlist)
            for r in lbr_lists['right']:
                n = PeerHost(r['host'], r['port'])
                if n.refresh:
                    listentry = {'host': r['host'], 'port': r['port']}
                    self.hostinfo.peerlist.append(listentry)
                    seld.peers.append[n]
    
    def list_peers(self):
        l = []
        for p in self.peers:
            listentry = {'host': p.host, 'port': p.port}
            l.append(listentry)
        return l
            
                    
                    