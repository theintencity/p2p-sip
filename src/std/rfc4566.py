# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC4566 (SDP)

import socket, time

class attrs(object):
    '''A generic class that allows uniformly accessing the attribute and items,
    and returns None for invalid attribute instead of throwing an acception.'''
    def __init__(self, **kwargs): 
        for n,v in kwargs.items(): self[n] = v 
    # attribute access: use container if not found
    def __getattr__(self, name): return self.__getitem__(name)
    # container access: use key in __dict__
    def __getitem__(self, name): return self.__dict__.get(name, None)
    def __setitem__(self, name, value): self.__dict__[name] = value
    def __contains__(self, name): return name in self.__dict__
    #def __repr__(self): return repr(self.__dict__)

# @implements RFC4566 P3L3-P3L21
class SDP(attrs):
    '''A SDP packet with dynamic properties. 
    The header names can be accessed as attributes or items. 
    Accessing an unavailable header gives None instead of exception.
    '''

    # header names that can appear multiple times.
    _multiple = 'tramb'
    
    def __init__(self, value=None):
        if value: 
            self._parse(value)

    # @implements RFC4566 P11L1-P12L10
    class originator(attrs):
        '''Represents a o= line with attributes username (str), sessionid (long), 
        version (long), nettype (str), addrtype (str), address (str).'''
        def __init__(self, value=None):
            if value:
                self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address = value.split(' ')
                self.sessionid = int(self.sessionid)
                self.version   = int(self.version)
            else:
                hostname = socket.gethostname()
                self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address = \
                '-', int(time.time()), int(time.time()), 'IN', 'IP4', (hostname.find('.')>0 and hostname or socket.gethostbyname(hostname))
        def __repr__(self):
            return ' '.join(map(lambda x: str(x), [self.username, self.sessionid, self.version, self.nettype, self.addrtype, self.address]))
        
    # @implements RFC4566 P14L7-P16L9    
    class connection(attrs):
        '''Represents a c= line with attributes nettype (str), addrtype (str), address (str)
        and optionally ttl (int) and count (int).'''
        def __init__(self, value=None, **kwargs):
            if value:
                self.nettype, self.addrtype, rest = value.split(' ')
                rest = rest.split('/')
                if len(rest) == 1: self.address = rest[0]
                elif len(rest) == 2: self.address, self.ttl = rest[0], int(rest[1])
                else: self.address, self.ttl, self.count = rest[0], int(rest[1]), int(rest[2])
            elif 'address' in kwargs:
                self.address = kwargs.get('address')
                self.nettype = kwargs.get('nettype', 'IN')
                self.addrtype = kwargs.get('addrtype', 'IP4')
                if 'ttl' in kwargs: self.ttl = int(kwargs.get('ttl'))
                if 'count' in kwargs: self.count = int(kwargs.get('count'))
        def __repr__(self):
            return self.nettype + ' ' + self.addrtype + ' ' + self.address + ('/' + str(self.ttl) if self.ttl else '') + ('/' + str(self.count) if self.count else '')

    # @implements RFC4566 P22L17-P24L33
    class media(attrs):
        '''Represents a m= line and all subsequent lines until next m= or end.
        It has attributes such as media (str), port (int), proto (str), fmt (list).''' 
        def __init__(self, value=None, **kwargs):
            if value:
                self.media, self.port, self.proto, rest = value.split(' ', 3)
                self.port = int(self.port)
                self.fmt = []
                for f in rest.split(' '):
                    a = attrs()
                    try: a.pt = int(f)  # if payload type is numeric
                    except: a.pt = f
                    self.fmt.append(a)
            elif 'media' in kwargs:
                self.media = kwargs.get('media')
                self.port  = int(kwargs.get('port', 0))
                self.proto = kwargs.get('proto', 'RTP/AVP')
                self.fmt   = kwargs.get('fmt', [])
        def __repr__(self):
            result = self.media + ' ' + str(self.port) + ' ' + self.proto + ' ' + ' '.join(map(lambda x: str(x.pt), self.fmt))
            for k in filter(lambda x: x in self, 'icbka'): # order is important
                if k not in SDP._multiple: # single header
                    result += '\r\n' + k + '=' + str(self[k])
                else:
                    for v in self[k]:
                        result += '\r\n' + k + '=' + str(v) 
            for f in self.fmt:
                if f.name:
                    result += '\r\n' + 'a=rtpmap:' + str(f.pt) + ' ' + f.name + '/' + str(f.rate) + (f.params and ('/'+f.params) or '')
            return result
        def dup(self): # use this method instead of SDP.media(str(m)) to duplicate m. Otherwise, fmt will be incomplete
            result = SDP.media(media=self.media, port=self.port, proto=self.proto, fmt=map(lambda f: attrs(pt=f.pt, name=f.name, rate=f.rate, params=f.params), self.fmt))
            for k in filter(lambda x: x in self, 'icbka'): 
                result[k] = self[k][:] if isinstance(self[k], list) else self[k]
            return result
    
    # @implements RFC4566 P8L17-P10L5
    def _parse(self, text):
        g = True # whether we are in global line or per media line?
        for line in text.replace('\r\n', '\n').split('\n'):
            k, sep, v = line.partition('=')
        
            if k == 'o': v = SDP.originator(v)
            elif k == 'c': v = SDP.connection(v)
            elif k == 'm': v = SDP.media(v)

            if k == 'm':   # new m= line
                if not self['m']:
                    self['m'] = []
                self['m'].append(v)
                obj = self['m'][-1]
            elif self['m']:  # not in global
                obj = self['m'][-1]
                # @implements RFC4566 P25L41-P27L7 
                if k == 'a' and v.startswith('rtpmap:'):
                    pt, rest = v[7:].split(' ', 1)
                    name, sep, rest = rest.partition('/')
                    rate, sep, params = rest.partition('/')
                    for f in filter(lambda x: str(x.pt) == str(pt), obj.fmt):
                        f.name = name; f.rate = int(rate); f.params = params or None
                else:
                    obj[k] = (k in SDP._multiple and ((k in obj) and (obj[k]+[v]) or [v])) or v 
            else:          # global
                obj = self
                obj[k] = ((k in SDP._multiple) and ((k in obj) and (obj[k]+[v]) or [v])) or v

    def __repr__(self):
        result = ''
        for k in filter(lambda x: x in self, 'vosiuepcbtam'): # order is important
            if k not in SDP._multiple: # single header
                result += k + '=' + str(self[k]) + '\r\n'
            else:
                for v in self[k]:
                    result += k + '=' + str(v) + '\r\n' 
        return result

#--------------------------- Testing --------------------------------------

# @implements RFC4566 P10L7-P10L21    
def testSDP():
    s = '''v=0\r
o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r
s=SDP Seminar\r
i=A Seminar on the session description protocol\r
u=http://www.example.com/seminars/sdp.pdf\r
e=j.doe@example.com (Jane Doe)\r
c=IN IP4 224.2.17.12/127\r
t=2873397496 2873404696\r
a=recvonly\r
m=audio 49170 RTP/AVP 0\r
m=video 51372 RTP/AVP 99\r
a=rtpmap:99 h263-1998/90000\r
'''
    sdp = SDP(s)
    assert str(sdp) == s
    
if __name__ == '__main__':
    import doctest
    doctest.testmod()
    testSDP()
