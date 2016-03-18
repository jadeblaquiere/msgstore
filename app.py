#!/usr/bin/env python
import time
import tornado.escape
import tornado.ioloop
import tornado.web
import tornado.options
import logging
import os
import mmap
from msgfile import Message

config={}
config['receive_dir'] = "recv/"
config['message_dir'] = "messages/"
config['capacity'] = (128*1024*1024*1024)
config['max_file_size'] = (256*1024*1024)
config['header_size'] = (8+1+8+1+66+1+66+1+66)

messagelist = []

class TimeHandler(tornado.web.RequestHandler):
    def get(self):
        response = { 'time' : int(time.time()) }
        self.write(response)

class VersionHandler(tornado.web.RequestHandler):
    def get(self):
        response = { 'version': '0.0.1' }
        self.write(response)

class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("templates/index.html", messagelist=messagelist)

class MessageUploadHandler(tornado.web.RequestHandler):
    def post(self):
        filereq = self.request
        filedata = self.request.files['message'][0]
        print('filereq =', filereq)
        print('filedata =', str(filedata))
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

        #app.logger.debug ('checking for dup ' + I)
        #todo: handle duplicate hash
        for l in messagelist:
            if l.time == int(t,16):
                if l.expire == int(e,16):
                    if l.I == I:
                        if l.J == J:
                            if l.K == K:
                                logging.info ('dup detected')
                                os.remove(recvpath)
                                self.write(l.metadata())
        
        #app.logger.debug ('no dup ' + I)

        m = Message()
        if m.ingest(recvpath,I) != True :
            app.logger.debug('ingest failed for message ' + I)
            os.remove(recvpath)
            abort(400)

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
                app.logger.debug('deleting expired message ' + m.I)
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
                app.logger.debug('deleting expired message ' + m.I)
                messagelist.remove(m)
                m.delete()
            else:
                if m.servertime > int(time_id):
                    l.append(m.metadata())
        #print 'l=', l
        ml = { "message_list" : l }
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

application = tornado.web.Application([
    (r'/static/(.*)/?', tornado.web.StaticFileHandler, {'path':'static'}),
    (r'/api/message/download/(?P<msg_id>[0-9a-fA-F]+$)/?', MessageDownloadHandler),
    (r'/api/message/find/(?P<msg_id>[0-9a-fA-F]+$)/?', MessageFindHandler),
    (r'/api/message/upload/?', MessageUploadHandler),
    (r'/api/message/list/?', MessageListHandler),
    (r'/api/message/list/since/(?P<time_id>\d+$)/?', MessageListSinceHandler),
    (r'/api/message/list/since/(?P<time_id>-\d+$)/?', MessageListSinceHandler),
    (r'/api/status/?', StatusHandler),
    (r'/api/time/?', TimeHandler),
    (r'/api/version/?', VersionHandler),
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
                    logging.info('adding ' + fname)
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
