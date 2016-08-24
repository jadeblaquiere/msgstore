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
import mmap
import os
import shutil
import json
from ciphrtxt.message import MessageHeader, Message, _header_size_w_sig
from ecpy.point import Point

config = {}
config['header_size'] = _header_size_w_sig

class MessageFile(Message):
    def __init__(self):
        super(MessageFile, self).__init__()
        self.filepath = None
        self.size = None
        self.time_str = None
       	self.expire_str = None
        self.servertime = None
        self.header = None
        
    def ingest(self, filepath, I = None):
        # validate header
        with open(filepath, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            header = mm[:config['header_size']]
            mm.close()
            if not self._deserialize_header(header):
                return False
            hsplit = header.split(b':')
            if len(hsplit) != 8:
                return False
            self.sig = (int(hsplit[6], 16), int(hsplit[7], 16))
            self.filepath = filepath
            self.size = os.path.getsize(filepath)
            self.header = header
            self.time_str = time.asctime(time.gmtime(self.time))
            self.expire_str = time.asctime(time.gmtime(self.expire))
            self.servertime = int(os.path.getmtime(filepath))
            return True
        return False

    def move_to(self, filepath):
        if self.filepath is None:
            raise ValueError("Attempt to move empty message")
        shutil.move(self.filepath, filepath)
        self.filepath = filepath

    def delete(self):
        if self.filepath is None:
            raise ValueError("Attempt to delete empty message!")
        try:
            os.remove(self.filepath)
        except OSError:
            print('Error : file not found (continuing)')
        self.filepath = None
        self.time = None
        self.expire = None
        self.I = None
        self.J = None
        self.K = None
        self.sig = None
        self.header = None
        self.size = None
        self.time_str = None
        self.expire_str = None
        self.servertime = None

    def metadata(self):
        if self.filepath is None:
            raise ValueError("Attempt to query empty message!")
        result = {}
        result["time"] = self.time
        result["expire"] = self.expire
        result["I"] = self.I.compress().decode()
        result["J"] = self.J.compress().decode()
        result["K"] = self.K.compress().decode()
        result["signature"] = self.sig
        result["size"] = self.size
        result["time_str"] = self.time_str
        result["expire_str"] = self.expire_str
        result["servertime"] = self.servertime
        return result

    def dumpjson(self):
        if self.filepath is None:
            raise ValueError("Attempt to query empty message!")
        result = {}
        result["filepath"] = self.filepath
        result["time"] = self.time
        result["expire"] = self.expire
        result["I"] = self.I.compress().decode()
        result["J"] = self.J.compress().decode()
        result["K"] = self.K.compress().decode()
        result["size"] = self.size
        result["time_str"] = self.time_str
        result["expire_str"] = self.expire_str
        result["servertime"] = self.servertime
        result["signature"] = self.sig
        result["header"] = self.header.decode()
        return json.dumps(result)

    @staticmethod
    def loadjson(msgjson):
        try:
            mdict = json.loads(msgjson)
            mnew = MessageFile()
            mnew.filepath = mdict['filepath']
            mnew.time = mdict['time']
            mnew.expire = mdict['expire']
            mnew.I = Point.decompress(mdict['I'])
            mnew.J = Point.decompress(mdict['J'])
            mnew.K = Point.decompress(mdict['K'])
            mnew.size = mdict['size']
            mnew.time_str = mdict['time_str']
            mnew.expire_str = mdict['expire_str']
            mnew.servertime = mdict['servertime']
            mnew.sig = mdict['signature']
            mnew.header = mdict['header']
            return mnew
        except:
            return None
    
    def get_file(self):
        return open(self.filepath, "rb")
