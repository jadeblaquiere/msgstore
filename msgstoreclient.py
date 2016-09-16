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


from ciphrtxt.message import RawMessageHeader, Message
import requests
import requests_futures
from requests_futures.sessions import FuturesSession
from requests.exceptions import Timeout, ConnectionError, HTTPError
import time
import json
import io
from threading import Lock

_baseurl = 'http://ciphrtxt.com:5000/'

_server_time = 'api/time/'
_headers_since = 'api/header/list/since/'
_download_message = 'api/message/download/'
_upload_message = 'api/message/upload/'

_cache_expire_time = 5 # seconds
_high_water = 50
_low_water = 20

_default_timeout = 10 # seconds

class MsgStore (object):
    """Client library for message store server"""
    def __init__(self,baseurl=_baseurl):
        self.baseurl = baseurl
        self.headers = []
        self.cache_dirty = True
        self.last_sync = time.time()
        self.servertime = 0
        self.session = requests.session()
        self.futures_session = FuturesSession(session=self.session)
        self._get_queue = []
        self._post_queue = []
        self._insert_lock = Lock()
        self._gq_lock = Lock()

    def _sync_headers(self):
        now = time.time()
        if not self.cache_dirty:
            delay = now - self.last_sync
            if (now - self.last_sync) < _cache_expire_time:
                return True
        #print('request headers from ' + self.baseurl)
        r = None
        try:
            r = requests.get(self.baseurl + _server_time, timeout = _default_timeout)
        except (Timeout, ConnectionError, HTTPError):
            return False
        if r.status_code != 200:
            return False
        servertime = json.loads(r.text)['time']
        for h in self.headers:
            if servertime > h.expire:
                self._insert_lock.acquire()
                #print('expiring ' + h.Iraw().decode())
                self.headers.remove(h)
                self._insert_lock.release()
        self.last_sync = time.time()
        try:
            r = self.session.get(self.baseurl + _headers_since + str(self.servertime))
        except (Timeout, ConnectionError, HTTPError):
            return False
        if r.status_code != 200:
            return False
        self.servertime = servertime
        self.cache_dirty = False
        remote = sorted(json.loads(r.text)['header_list'],
                        key=lambda k: int(k[6:14],16), reverse=True)
        for rstr in reversed(remote):
            rhdr = RawMessageHeader()
            if rhdr._deserialize_header(rstr.encode()):
                self._insert_lock.acquire()
                if rhdr not in self.headers:
                    self.headers.insert(0, rhdr)
                self._insert_lock.release()
        self._insert_lock.acquire()
        self.headers.sort(reverse=True)
        self._insert_lock.release()
        return True
    
    def get_headers(self):
        self._sync_headers()
        return self.headers

    def get_message(self, hdr, callback=None):
        self._sync_headers()
        if hdr not in self.headers:
            return None
        r = None
        try:
            r = self.session.get(self.baseurl + _download_message + hdr.Iraw().decode(), stream=True)
        except (Timeout, ConnectionError, HTTPError):
            return None
        if r.status_code != 200:
            return None
        raw = b''
        for chunk in r:
            raw += chunk
        msg = Message.deserialize(raw)
        if callback:
            return callback(msg)
        return msg

    def _cb_get_async(self, s, r):
        qen = [qe for qe in self._get_queue if qe[0] == r.url]
        cb = qen[0][1]
        self._gq_lock.acquire()
        self._get_queue.remove(qen[0])
        self._gq_lock.release()
        if cb is None:
            return None
        if r.status_code != 200:
            print('Async Reply Error ' + str(r.status_code) + ' ' + r.url)
            return cb(None)
        msg = Message.deserialize(r.text.encode())
        return cb(msg)

    def get_message_async(self, hdr, callback):
        self._sync_headers()
        if hdr not in self.headers:
            return False
        url = self.baseurl + _download_message + hdr.Iraw().decode()
        qentry = (url, callback)
        if qentry in self._get_queue:
            return False
        if len(self._get_queue) > _high_water:
            while len(self._get_queue) > _low_water:
                time.sleep(1)
        self._gq_lock.acquire()
        self._get_queue.append(qentry)
        self._gq_lock.release()
        r = self.futures_session.get(url, background_callback=self._cb_get_async)
        return True
    
    def post_message(self, msg):
        if msg in self.headers:
            return
        raw = msg.serialize()
        nhdr = RawMessageHeader.deserialize(raw)
        f = io.StringIO(raw.decode())
        files = {'message': ('message', f)}
        try:
            r = self.session.post(self.baseurl + _upload_message, files=files)
        except (Timeout, ConnectionError, HTTPError):
            return
        if r.status_code != 200:
            return
        self._insert_lock.acquire()
        if nhdr not in self.headers:
            self.headers.insert(0,nhdr)
        self._insert_lock.release()
        self.cache_dirty = True


if __name__ == '__main__':  # pragma: no cover
    mstore = MsgStore()
    for h in mstore.get_headers():
        msg = mstore.get_message(h)
        print(msg)
        print()
    while True:
        time.sleep(1)
        mstore._sync_headers()

                
                
            