#!/usr/bin/env python3
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

import time
import tornado.escape
import tornado.ioloop
import tornado.web
import tornado.options
import tornado.httpclient
import logging
import os
import mmap
import threading
import socket

from msgfile import Message
from nakcache import NAKCache
from nak import NAK

from msgcache import MessageCache
from peercache import PeerCache

import hashlib
import base64
import json
from binascii import hexlify, unhexlify

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

_curve = curve_secp256k1
Point.set_curve(_curve)
_G = Generator.init(_curve['G'][0], _curve['G'][1])
ECDSA.set_generator(_G)

server_p = random.randint(1,curve_secp256k1['n']-1)
server_P = _G * server_p

config={}
config['receive_dir'] = "recv/"
config['message_dir'] = "messages/"
config['capacity'] = (128*1024*1024*1024)
config['max_file_size'] = (256*1024*1024)
config['header_size'] = (8+1+8+1+66+1+66+1+66)
config['ncache_sleep_interval'] = 30
config['version'] = '0.0.2'

clopts = []
clopts.append({'name':'rpcuser', 'default':None})
clopts.append({'name':'rpcpass', 'default':None})
clopts.append({'name':'rpchost', 'default':'127.0.0.1'})
clopts.append({'name':'rpcport', 'default':7765})
clopts.append({'name':'nakpriv', 'default': None})
clopts.append({'name':'exthost', 'default': None})
clopts.append({'name':'extport', 'default': 5000})
clopts.append({'name':'coinhost', 'default': None})
clopts.append({'name':'coinport', 'default': 7764})
clopts.append({'name':'standalone', 'default': False})

ncache = None
ncache_time_to_die = False

nakpubbin = None
nak = None

mcache = None
pcache = None

ecdsa = ECDSA()

onion_client = tornado.httpclient.AsyncHTTPClient(max_clients=1000)

class TimeHandler(tornado.web.RequestHandler):
    def get(self):
        response = { 'time' : int(time.time()) }
        self.write(response)

class VersionHandler(tornado.web.RequestHandler):
    def get(self):
        response = { 'version': config['version'] }
        self.write(response)

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        mlist = sorted(mcache.list_all(), key=lambda k: k['expire'], reverse=True)
        self.render("templates/index.html", messagelist=mlist)

class MessageUploadHandler(tornado.web.RequestHandler):
    def post(self):
        filereq = self.request
        filedata = self.request.files['message'][0]
        #print('filereq =', filereq)
        #print('filedata =', str(filedata))
        recvpath = config['receive_dir'] + str(int(time.time() * 1000))
        logging.info('receiving file as ' + recvpath )
        fh = open(recvpath, 'wb')
        fh.write(filedata['body'])
        fh.close()
    
        with open(recvpath,'rb') as f :
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            header = mm[:config['header_size']].decode('UTF-8')
            mm.close()
        t = header.split(':')[0]
        e = header.split(':')[1]
        I = header.split(':')[2]
        J = header.split(':')[3]
        K = header.split(':')[4]

        seek = mcache.get(I)
        if seek is not None:
            logging.info ('dup detected')
            os.remove(recvpath)
            self.set_status(400)
            return
        
        m = Message()
        if m.ingest(recvpath,I) != True :
            logging.info('ingest failed for message ' + I)
            os.remove(recvpath)
            self.set_status(400)
            return

        msgpath = config['message_dir'] + I
        m.move_to(msgpath)
        mcache.add(m)
        #messagelist.insert(0,m)
        self.write(m.metadata())


class MessageListHandler(tornado.web.RequestHandler):
    def get(self):
        l = mcache.list_all()
        ml = { "message_list" : l }
        self.write(ml)


class MessageListSinceHandler(tornado.web.RequestHandler):
    def get(self, time_id=0):
        l = mcache.list_since(time_id)
        ml = { "message_list" : l }
        self.write(ml)

class HeaderListSinceHandler(tornado.web.RequestHandler):
    def get(self, time_id=0):
        l = mcache.header_list_since(time_id)
        ml = { "header_list" : l }
        self.write(ml)

class StatusHandler(tornado.web.RequestHandler):
    def get(self):
        status = {}
        storage = {}
        storage["capacity"] = config["capacity"]
        storage["used"] = mcache.messagesize
        storage["max_file_size"] = config["max_file_size"]
        storage['messages'] = mcache.messagecount
        status["storage"] = storage
        status["pubkey"] = server_P.compress().decode()
        self.write(status)

class MessageDownloadHandler(tornado.web.RequestHandler):
    def get(self, msg_id=None):
        logging.info('download hash ' + str(msg_id))
        m = mcache.get(msg_id)
        if m is None:
            self.set_status(404)
            self.finish()
            return
        with m.get_file() as f:
            self.set_header('Content-Type','application/octet-stream' )
            while 1:
                data = f.read(16384) # or some other nice-sized chunk
                if not data: break
                self.write(data)
            self.finish()

class MessageFindHandler(tornado.web.RequestHandler):
    def get(self, msg_id=None):
        m = mcache.get(msg_id)
        if m is None:
            self.set_status(404)
            self.finish()
            return
        self.write(m.metadata())
        self.finish()

class PeerListHandler(tornado.web.RequestHandler):
    def get(self):
        l = pcache.list_peers()
        self.write(json.dumps(l))
        self.finish

class PeerUpdateHandler(tornado.web.RequestHandler):
    def post(self):
        try:
            b = self.request.body
            d = json.loads(b.decode('UTF-8'))
            if d['host'].lower() != 'localhost':
                logging.info('adding candidate peer ' + d['host'])
                pcache.add_peer(d['host'], d['port'])
            self.finish()
        except:
            self.set_status(400)
            self.finish()

class OnionHandler(tornado.web.RequestHandler):
    def callback(self, resp):
        if resp.code != 200:
            self.set_status(400)
            self.finish()
        try:
            self.write(resp.body)
        except:
            self.set_status(400)
        finally:
            self.finish()
        
    def callback_encrypt(self, resp):
        if resp.code != 200:
            self.set_status(400)
            self.finish()
        ecdh = self.client_R * server_p
        keybin = hashlib.sha256(ecdh.compress().encode('UTF-8')).digest()
        #logging.info('ecdh key hex = ' + str(hexlify(keybin)))
        iv = random.randint(0,(1 << 128)-1)
        ivbin = unhexlify('%032x' % iv)
        #logging.info('iv hex = ' + str(hexlify(ivbin)))
        counter = Counter.new(128, initial_value=iv)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        ciphertext = cryptor.encrypt(resp.body)
        sig = ecdsa.sign(server_p, ivbin + ciphertext)
        #logging.info('sig = ' + str(sig))
        sigbin = unhexlify('%064x' % sig[0]) + unhexlify('%064x' % sig[1])
        try:
            self.write(base64.b64encode(sigbin + ivbin + ciphertext))
        except:
            self.set_status(400)
        finally:
            self.finish()
        
    @tornado.web.asynchronous
    def post(self, pubkey=None):
        if pubkey is None:
            self.set_status(400)
            self.finish()
        #logging.info('onion: received request')
        if len(pubkey) != 66:
            self.set_status(400)
            self.finish()
        #logging.info('onion: validated keylength')
            
        try:
            P = Point.decompress(pubkey)
        except:
            self.set_status(400)
            self.finish()
        
        ecdh = P * server_p
        keybin = hashlib.sha256(ecdh.compress().encode('UTF-8')).digest()
        b = self.request.body
        bd = base64.b64decode(b)
        nakpubraw = hexlify(bd[:33])
        if not opts['standalone']:
            nakpub = ncache.get_nak(nakpubraw)
            if nakpub is None:
                self.set_status(400)
                self.finish()
            sig = (int(hexlify(bd[33:65]),16), int(hexlify(bd[65:97]),16))
            if not nakpub.verify(sig,bd[97:]):
                self.set_status(400)
                self.finish()
            logging.info('validated access for NAK %s' % nakpubraw)
        ivcount = int(hexlify(bd[97:113]),16)
        counter = Counter.new(128,initial_value=ivcount)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        plaintext = cryptor.decrypt(bd[113:])
        plaintext = plaintext.decode('UTF-8')
        #logging.info('onion received: ' + plaintext)
        o_r = json.loads(plaintext)
        
        if o_r['local'] is True:
            if o_r['action'].lower() == 'get':
                o_server = 'http://127.0.0.1:5000/'
                o_path = o_r['url']
                self.client_R = Point.decompress(o_r['replykey'])
                req = tornado.httpclient.HTTPRequest(o_server+o_path,
                                                     method='GET', 
                                                     connect_timeout=30, 
                                                     request_timeout=60)
                onion_client.fetch(req, self.callback_encrypt)
            elif o_r['action'].lower() == 'post':
                o_server = 'http://127.0.0.1:5000/'
                o_path = o_r['url']
                self.client_R = Point.decompress(o_r['replykey'])
                req = tornado.httpclient.HTTPRequest(o_server+o_path,
                                                     method='POST',
                                                     body=o_r['body'],
                                                     connect_timeout=30,
                                                     request_timeout=60)
                onion_client.fetch(req, self.callback_encrypt)
        else:
            if nak is None:
                self.set_status(400)
                self.finish()
            if (len(o_r['pubkey']) != 66) or not((o_r['pubkey'][:2] == '02') or
                                                 (o_r['pubkey'][:2] == '03')):
                self.set_status(400)
                self.finish()
            try:
                i = int(o_r['pubkey'],16)
            except:
                self.set_status(400)
                self.finish()
            o_server = 'http://' + o_r['host'] + ':5000/'
            o_path = 'onion/' + o_r['pubkey']
            o_raw = base64.b64decode(o_r['body'])
            sig = nak.sign(o_raw)
            o_body = base64.b64encode(nakpubbin + unhexlify('%064x' % sig[0]) + 
                                      unhexlify('%064x' % sig[1]) + o_raw)
            req = tornado.httpclient.HTTPRequest(o_server+o_path,
                                                 method='POST', 
                                                 body=o_body,
                                                 connect_timeout=30,
                                                 request_timeout=60)
            onion_client.fetch(req, self.callback)
        
            
application = tornado.web.Application([
    (r'/static/(.*)/?', tornado.web.StaticFileHandler, {'path':'static'}),
    (r'/api/message/download/(?P<msg_id>[0-9a-fA-F]+$)/?', MessageDownloadHandler),
    (r'/api/message/find/(?P<msg_id>[0-9a-fA-F]+$)/?', MessageFindHandler),
    (r'/api/message/upload/?', MessageUploadHandler),
    (r'/api/message/list/?', MessageListHandler),
    (r'/api/message/list/since/(?P<time_id>\d+$)/?', MessageListSinceHandler),
    (r'/api/message/list/since/(?P<time_id>-\d+$)/?', MessageListSinceHandler),
    (r'/api/header/list/since/(?P<time_id>\d+$)/?', HeaderListSinceHandler),
    (r'/api/header/list/since/(?P<time_id>-\d+$)/?', HeaderListSinceHandler),
    (r'/api/peer/list/?', PeerListHandler),
    (r'/api/peer/update/?', PeerUpdateHandler),
    (r'/api/status/?', StatusHandler),
    (r'/api/time/?', TimeHandler),
    (r'/api/version/?', VersionHandler),
    (r'/onion/(?P<pubkey>[0-9a-fA-F]+$)/?', OnionHandler),
    (r'/?', IndexHandler),
    (r'/index.html', IndexHandler)
])
 
def nak_sync_thread():
    while not ncache_time_to_die:
        time.sleep(config['ncache_sleep_interval'])
        ncache.sync()

if __name__ == "__main__":
    coinhost = None
    coinport = None
    for opt in clopts:
        tornado.options.define(name=opt['name'], default=opt['default'])
    tornado.options.parse_command_line()
    logging.info('msgstore started unix time ' + str(int(time.time())))
    logging.info('starting NAK cache thread')
    opts = tornado.options.options
    mcache = MessageCache()
    hname = opts['exthost']
    if hname is None:
        logging.info('looking up hostname')
        hname = socket.gethostname()
    logging.info('starting service for ' + hname)
    if not opts['standalone']:
        ncache = NAKCache(host=opts['rpchost'], 
                          port=opts['rpcport'], 
                          rpcuser=opts['rpcuser'], 
                          rpcpass=opts['rpcpass'])
        coinhost = opts['coinhost']
        if coinhost is None:
            coinhost = hname
        coinport = opts['coinport']
    rpcuser = opts['rpcuser']
    rpcpass = opts['rpcpass']
    pcache = PeerCache(hname, opts['extport'], coinhost=coinhost, coinport=coinport, standalone=(coinhost == None), rpcuser=rpcuser, rpcpass=rpcpass)
    if opts['nakpriv'] is not None:
        nak = NAK(privkey=int(opts['nakpriv'], 16))
        nakpubbin = unhexlify(nak.pubkey.compress())
    if not opts['standalone']:
        threading.Thread(target=nak_sync_thread).start()
    logging.info('scanning message inventory')
    mcache.scan_message_dir()
    logging.info('imported messages from filesystem')
    threading.Thread(target=pcache.peer_sync_thread).start()
    application.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
