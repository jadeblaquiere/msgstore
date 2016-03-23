#!/usr/bin/env	python
#
# Copyright (c) 2015, Joseph deBlaquiere
# All rights reserved.
#

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
