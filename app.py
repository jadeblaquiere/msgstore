#!/usr/bin/env python
from flask import Flask, render_template, send_from_directory, send_file, request, abort, jsonify
from msgfile import Message
import os
import time
import mmap

app = Flask(__name__)

config={}
config['receive_dir'] = "recv/"
config['message_dir'] = "messages/"
config['capacity'] = (128*1024*1024*1024)
config['max_file_size'] = (256*1024*1024)
config['header_size'] = (8+1+8+1+66+1+66+1+66)

messagelist = []

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('static/css',path)

@app.route('/')
def hello_world():
    return render_template('index.html', messagelist=messagelist)

@app.route('/api/message/upload', methods=['POST'])
def receive_message_raw():
    filedata = request.files['message']
    recvpath = config['receive_dir'] + str(int(time.time() * 100))
    #app.logger.debug('receiving file as ' + recvpath )
    filedata.save(recvpath)
    
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
                            app.logger.debug ('dup detected')
                            os.remove(recvpath)
                            return jsonify(l.metadata())
        
    #app.logger.debug ('no dup ' + I)
    
    m = Message()
    if m.ingest(recvpath,I) != True :
        app.logger.debug('ingest failed for message ' + I)
        os.remove(recvpath)
        abort(400)

    msgpath = config['message_dir'] + I
    m.move_to(msgpath)
    messagelist.insert(0,m)
    return jsonify(m.metadata())

@app.route('/api/message/download/<I>', methods=['GET'])
def send_message_raw(I):
    for m in messagelist :
        if m.I == I :
            return send_file(m.get_file())
    else :
        abort(404)

@app.route('/api/message/find/<I>', methods=['GET'])
def find_shard_data(I):
    for m in messagelist:
        if m.I == I :
            return jsonify(m.metadata())
    else :
        abort(404)

@app.route('/api/time', methods=['GET'])
def server_time():
    r = {}
    r['time'] = int(time.time())
    return jsonify(r)

@app.route('/api/message/list', methods=['GET'])
def list_messages():
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
    return jsonify(ml)

@app.route('/api/message/list/since/<T>', methods=['GET'])
def list_messages_since(T):
    l = []
    now = int(time.time())
    for m in messagelist:
        if m.expire < now:
            app.logger.debug('deleting expired message ' + m.I)
            messagelist.remove(m)
            m.delete()
        else:
            if m.servertime > int(T):
                l.append(m.metadata())
    #print 'l=', l
    ml = { "message_list" : l }
    return jsonify(ml)

@app.route('/api/status', methods=['GET'])
def send_status():
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
    return jsonify(status)

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
                    print 'adding', fname
                    messagelist.append(msg)
                else:
                    print 'expired', fname
                    os.remove(filepath)
    messagelist.sort(key=lambda msg: msg.expire, reverse=True)

if __name__ == '__main__' :
    #app.run(host="0.0.0.0", debug=True, port=5000, ssl_context='adhoc')
    print 'scanning message inventory'
    rescan_inventory()
    app.run(host="0.0.0.0", debug=True)
    
