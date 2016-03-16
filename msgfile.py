#!/usr/bin/env	python
#
# Copyright (c) 2015, Joseph deBlaquiere
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import time
import mmap
import os
import shutil

config = {}
config['header_size'] = (8+1+8+1+66+1+66+1+66)

class Message(object):
    def __init__(self):
        self.filepath = None
        self.time = None
        self.expire = None
        self.I = None
        self.J = None
        self.K = None
        self.size = None
        self.time_str = None
       	self.expire_str = None
        self.servertime = None
        
    def ingest(self, filepath, I = None):
        # validate header
        with open(filepath, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            header = mm[:config['header_size']]
            mm.close()
            hsplit = header.split(':')
            if len(hsplit) != 5:
                return False
            if I:
                if hsplit[2] != I:
                    return False
            self.filepath = filepath
            self.size = os.path.getsize(filepath)
            self.time = int(hsplit[0],16)
            self.expire = int(hsplit[1],16)
            self.I = hsplit[2]
            self.J = hsplit[3]
            self.K = hsplit[4]
            self.time_str = time.asctime(time.gmtime(self.time))
            self.expire_str = time.asctime(time.gmtime(self.expire))
            self.servertime = int(os.path.getmtime(filepath))
            return True
        return False

    def move_to(self, filepath):
        assert self.filepath is not None, "Attempt to move empty file!"
        shutil.move(self.filepath, filepath)
        self.filepath = filepath

    def delete(self):
        assert self.filepath is not None, "Attempt to delete empty shard!"
        try:
            os.remove(self.filepath)
        except OSError:
            print 'Error : file not found (continuing)'
        self.filepath = None
        self.time = None
        self.expire = None
        self.I = None
        self.J = None
        self.K = None
        self.size = None
        self.time_str = None
        self.expire_str = None
        self.servertime = None

    def metadata(self):
        assert self.filepath is not None, "Attempt to query empty shard!"
        result = {}
        result["time"] = self.time
        result["expire"] = self.expire
        result["I"] = self.I
        result["J"] = self.J
        result["K"] = self.K
        result["size"] = self.size
        result["time_str"] = self.time_str
        result["expire_str"] = self.expire_str
        result["servertime"] = self.servertime
        return result

    def get_file(self):
        return open(self.filepath, "rb")
