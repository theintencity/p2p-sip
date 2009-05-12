# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC2833 (DTMF in RTP)

'''
Implement the DTMF tone payload in RTP using RFC 2833
'''

import struct

class DTMF(object):
    '''Payload format for DTMF'''
    def __init__(self, value=None, **kwargs):
        '''Construct a new tone using the specified key.'''
        if not value:
            self.event = self.mapkey(kwargs.get('key', None))
            self.E     = kwargs.get('end', False)
            self.R     = False # reserved bit
            self.volume = kwargs.get('volume', 0)
            self.duration=kwargs.get('duration', 200)
        else:
            self.event, second, self.duration = struct.unpack('!BBH', value)
            self.E, self.R = (second & 0x80 != 0), False # ignore the reserved bit
            self.volume = second & 0x3f

    def __repr__(self):
        return struct.pack('!BBH', self.event, (self.E and 0x80 or 0x00) | (self.volume & 0x3f), self.duration)
    
    @staticmethod
    def mapkey(key):
        '''Convert a key to an event.'''
        if not key or len(key)!= 1: return 16 # either empty or not one char
        index = '0123456789*#ABCD'.find(key)
        if index>= 0: return index
        else: return 16

def createDTMFs(keys):
    '''Return an array of DTMF objects with each representing one key in the keys.'''
    result = map(lambda x: DTMF(key=x), keys)
    if result: result[-1].E = True # last one has E set to True
    return result
        