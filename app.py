#!/usr/bin/env python
import time
import tornado.escape
import tornado.ioloop
import tornado.web
import tornado.options
import tornado.httpclient
import logging
import os
import mmap
from msgfile import Message

import hashlib
import base64
import json
import binascii

from ecpy.curves import curve_secp256k1
from ecpy.point import Point, Generator
from ecpy.ecdsa import ECDSA
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.Util import Counter

_curve = curve_secp256k1
Point.set_curve(_curve)
_G = Generator(_curve['G'][0], _curve['G'][1])
ECDSA.set_generator(_G)

server_p = random.randint(1,curve_secp256k1['n']-1)
server_P = _G * server_p

config={}
config['receive_dir'] = "recv/"
config['message_dir'] = "messages/"
config['capacity'] = (128*1024*1024*1024)
config['max_file_size'] = (256*1024*1024)
config['header_size'] = (8+1+8+1+66+1+66+1+66)
config['version'] = '0.0.2'

messagelist = []

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
        self.render("templates/index.html", messagelist=messagelist)

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
            header = mm[:config['header_size']]
            mm.close()
        t = header.split(':')[0]
        e = header.split(':')[1]
        I = header.split(':')[2]
        J = header.split(':')[3]
        K = header.split(':')[4]

        for l in messagelist:
            if l.time == int(t,16):
                if l.expire == int(e,16):
                    if l.I == I:
                        if l.J == J:
                            if l.K == K:
                                logging.info ('dup detected')
                                os.remove(recvpath)
                                self.write(l.metadata())
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
        messagelist.insert(0,m)
        self.write(m.metadata())

class MessageListHandler(tornado.web.RequestHandler):
    def get(self):
        l = []
        now = int(time.time())
        for m in messagelist:
            if m.expire < now:
                logging.info('deleting expired message ' + m.I)
                messagelist.remove(m)
                m.delete()
            else:
                l.append(m.metadata())
        #print 'l=', l
        ml = { "message_list" : l }
        self.write(ml)


class MessageListSinceHandler(tornado.web.RequestHandler):
    def get(self, time_id=None):
        l = []
        now = int(time.time())
        for m in messagelist:
            if m.expire < now:
                logging.info('deleting expired message ' + m.I)
                messagelist.remove(m)
                m.delete()
            else:
                if m.servertime >= int(time_id):
                    l.append(m.metadata())
        #print 'l=', l
        ml = { "message_list" : l }
        self.write(ml)

class HeaderListSinceHandler(tornado.web.RequestHandler):
    def get(self, time_id=None):
        l = []
        now = int(time.time())
        for m in messagelist:
            if m.expire < now:
                logging.info('deleting expired message ' + m.I)
                messagelist.remove(m)
                m.delete()
            else:
                if m.servertime >= int(time_id):
                    l.append(m.header)
        #print 'l=', l
        ml = { "header_list" : l }
        self.write(ml)

class StatusHandler(tornado.web.RequestHandler):
    def get(self):
        used = 0
        for m in messagelist:
            used += m.size
        status = {}
        storage = {}
        storage["capacity"] = config["capacity"]
        storage["used"] = used
        storage["max_file_size"] = config["max_file_size"]
        storage['messages'] = len(messagelist)
        status["storage"] = storage
        status["pubkey"] = server_P.compress()
        self.write(status)

class MessageDownloadHandler(tornado.web.RequestHandler):
    def get(self, msg_id=None):
        logging.info('download hash ' + str(msg_id))
        for m in messagelist :
            if m.I == msg_id :
                with m.get_file() as f:
                    self.set_header('Content-Type','application/octet-stream' )
                    while 1:
                        data = f.read(16384) # or some other nice-sized chunk
                        if not data: break
                        self.write(data)
                    self.finish()
                    return
        else :
            self.set_status(404)
            self.finish()

class MessageFindHandler(tornado.web.RequestHandler):
    def get(self, msg_id=None):
        for m in messagelist:
            if m.I == msg_id :
                self.write(m.metadata())
                return
        else :
            self.set_status(404)
            self.finish()

class OnionHandler(tornado.web.RequestHandler):
    def callback(self, resp):
        try:
            self.write(resp.body)
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
        keybin = hashlib.sha256(ecdh.compress()).digest()
        b = self.request.body
        bd = base64.b64decode(b)
        ivcount = int(binascii.hexlify(bd[:32]),16)
        counter = Counter.new(128,initial_value=ivcount)
        cryptor = AES.new(keybin, AES.MODE_CTR, counter=counter)
        plaintext = cryptor.decrypt(bd[32:])
        #logging.info('onion received: ' + plaintext)
        
        o_r = json.loads(plaintext)
        if o_r['local'] is True:
            if o_r['action'].lower() == 'get':
                o_server = 'http://127.0.0.1:5000/'
                o_path = o_r['url']
                req = tornado.httpclient.HTTPRequest(o_server+o_path,method='GET')
                onion_client.fetch(req, self.callback)
            elif o_r['action'].lower() == 'post':
                o_server = 'http://127.0.0.1:5000/'
                o_path = o_r['url']
                req = tornado.httpclient.HTTPRequest(o_server+o_path,method='POST',body=o_r['body'])
                onion_client.fetch(req, self.callback)
        else:
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
            o_body = o_r['body']
            req = tornado.httpclient.HTTPRequest(o_server+o_path,method='POST', body=o_r['body'])
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
    (r'/api/status/?', StatusHandler),
    (r'/api/time/?', TimeHandler),
    (r'/api/version/?', VersionHandler),
    (r'/onion/(?P<pubkey>[0-9a-fA-F]+$)/?', OnionHandler),
    (r'/?', IndexHandler),
    (r'/index.html', IndexHandler)
])
 
def rescan_inventory():
    filenames = os.listdir(config['message_dir'])
    now = int(time.time())
    for fname in filenames:
        filepath = config['message_dir'] + '/' + fname
        msg = Message()
        if msg.ingest(filepath):
            for m in messagelist:
                if m.metadata() == msg.metadata:
                    break
            else:
                if msg.expire > now:
                    #logging.info('adding ' + fname)
                    messagelist.append(msg)
                else:
                    logging.info('expired ' + fname)
                    os.remove(filepath)
    messagelist.sort(key=lambda msg: msg.expire, reverse=True)

if __name__ == "__main__":
    tornado.options.parse_command_line()
    logging.info('msgstore started unix time ' + str(int(time.time())))
    logging.info('scanning message inventory')
    rescan_inventory()
    logging.info('imported %d messages' % len(messagelist))
    application.listen(5000)
    tornado.ioloop.IOLoop.instance().start()
