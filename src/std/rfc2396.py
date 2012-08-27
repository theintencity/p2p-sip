# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC2396 (URI)
'''
Various forms of addresses such as URI and SIP address.
'''

import re, socket, struct

def isIPv4(data):
    '''Check if the data is a dotted decimal IPv4 address or not?
    >>> isIPv4('10.2.3.4') == True
    True
    >>> False == isIPv4('10.2.3.a') == isIPv4('10.2.3.a.5') == isIPv4('10.2.3.-2') == isIPv4('10.2.3.403')
    True
    '''
    try: 
        m = socket.inet_aton(data)
        # alternatively: len(filter(lambda y: int(y) >= 0 and int(y) < 256, data.split('.', 3))) == 4
        return True
    except:
        return False
    
def isMulticast(data):
    '''Check if the data is a dotted decimal multicast address or not?
    >>> isMulticast('224.0.1.2') == True
    True
    >>> False == isMulticast('10.2.3.4')
    True
    '''
    try:
        m, = struct.unpack('>I', socket.inet_aton(data))
        return ((m & 0xF0000000) == 0xE0000000) # class D: 224.0.0.0/4 or first four bits as 0111
    except:
        return False

def isLocal(data):
    '''Check if the data is a dotted decimal local interface IP address?
    >>> isLocal('127.0.0.1') == True
    True
    >>> False == isLocal('192.1.2.3')
    True
    '''
    return data == '127.0.0.1' # TODO: check for IPv6

def isPrivate(data):
    '''Check if the data is a dotted decimal private IP address behind a NAT?
    >>> isPrivate('10.1.2.3') == True
    True
    >>> False == isPrivate('192.1.2.3')
    True
    '''
    try: # TODO: check for IPv6
        a, b, c, d = struct.unpack('>BBBB', socket.inet_aton(data))
        return a == 10 or a == 172 and 16 <= b < 32 or a == 192 and b == 168
    except:
        return False
    
class URI(object):
    '''A URI object with dynamic properties.
    Attributes and items such as scheme, user, password, host, port, 
    param[name], header[index], give various parts of the URI.
    
    >>> print URI('sip:kundan@example.net')
    sip:kundan@example.net
    >>> print URI('sip:kundan:passwd@example.net:5060;transport=udp;lr?name=value&another=another')
    sip:kundan:passwd@example.net:5060;lr;transport=udp?name=value&another=another
    >>> print URI('sip:192.1.2.3:5060')
    sip:192.1.2.3:5060
    >>> print URI("sip:kundan@example.net") == URI("sip:Kundan@Example.NET")
    True
    >>> print 'empty=', URI()
    empty= 
    >>> print URI('tel:+1-212-9397063')
    tel:+1-212-9397063
    >>> print URI('sip:kundan@192.1.2.3:5060').hostPort
    ('192.1.2.3', 5060)
    '''
    
    # regular expression for URI syntax.
    # TODO: need to extend for host portion.
    _syntax = re.compile('^(?P<scheme>[a-zA-Z][a-zA-Z0-9\+\-\.]*):'  # scheme
            + '(?:(?:(?P<user>[a-zA-Z0-9\-\_\.\!\~\*\'\(\)&=\+\$,;\?\/\%]+)' # user
            + '(?::(?P<password>[^:@;\?]+))?)@)?' # password
            + '(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))'  # host, port
            + '(?:;(?P<params>[^\?]*))?' # parameters
            + '(?:\?(?P<headers>.*))?$') # headers
    _syntax_urn = re.compile(r'^(?P<scheme>urn):(?P<host>[^;\?>]+)$')
    
    def __init__(self, value=''):
        '''Construct from a string representation of a URI, or empty'''
        if value:
            m = URI._syntax.match(value)
            if m: 
                self.scheme, self.user, self.password, self.host, self.port, params, headers = m.groups()
            elif URI._syntax_urn.match(value):
                m = URI._syntax_urn.match(value)
                self.scheme, self.host = m.groups()
                self.user = self.password = self.port = params = headers = None
            else:
                raise ValueError, 'Invalid URI(' + value + ')'
            if self.scheme == 'tel' and self.user is None:
                self.user, self.host = self.host, None
            self.port   = self.port and int(self.port) or None
            self.param  = dict(map(lambda k: (k[0], k[2] if k[2] else None), map(lambda n: n.partition('='), params.split(';')))) if params else {}
            self.header = [nv for nv in headers.split('&')] if headers else []
        else:
            self.scheme = self.user = self.password = self.host = self.port = None
            self.param = {};  self.header = []
            
    def __repr__(self):
        '''Return a string representation of the URI'''
        user,host = (self.user,self.host) if self.scheme != 'tel' else (None, self.user)
        return (self.scheme + ':' + ((user + \
          ((':'+self.password) if self.password else '') + '@') if user else '') + \
          (((host if host else '') + ((':'+str(self.port)) if self.port else '')) if host else '') + \
          ((';'+';'.join([(n+'='+v if v is not None else n) for n,v in sorted(self.param.items())])) if len(self.param)>0 else '') + \
          (('?'+'&'.join(self.header)) if len(self.header)>0 else '')) if self.scheme and host else '';
    
    def dup(self):
        '''Duplicate this object.'''
        return URI(self.__repr__())
    
    def __hash__(self):
        '''Hash is derived from lower-case string, hence causes case insensitive match'''
        return hash(str(self).lower())
    
    def __cmp__(self, other):
        '''Compare two URI objects by comparing their hash values'''
        return cmp(str(self).lower(), str(other).lower())

    @property
    def hostPort(self):
        '''Read-only tuple (host, port) for this uri.'''
        return (self.host, self.port)
    
    def _ssecure(self, value):
        if value and self.scheme in ['sip', 'http']: self.scheme += 's'
    def _gsecure(self):
        return True if self.scheme in ['sips', 'https'] else False
    secure = property(fget=_gsecure, fset=_ssecure)
    
class Address(object):
    '''An address object has displayName (str) and uri (URI) attributes.
    The mustQuote property indicates whether the uri portion must
    be quoted when using a string representation or not.
    
    >>> a1 = Address('"Kundan Singh" <sip:kundan@example.net>')
    >>> a2 = Address('Kundan Singh   <sip:kundan@example.net>')
    >>> a3 = Address('"Kundan Singh" <sip:kundan@example.net>   ')
    >>> a4 = Address('<sip:kundan@example.net>')
    >>> a5 = Address('sip:kundan@example.net')
    >>> print str(a1) == str(a2) and str(a1) == str(a3) and str(a1.uri) == str(a4.uri) and str(a1.uri) == str(a5.uri)
    True
    >>> print a1
    "Kundan Singh" <sip:kundan@example.net>
    >>> print a1.displayable
    Kundan Singh
    '''
    # regular expression for Address syntax.
    # 1. Kundan Singh <sip:kundan@example.net> or <sip:kundan@example.net>
    # 2. "Kundan Singh" <sip:kundan@example.net>
    # 3. sip:kundan@example.net
    _syntax = [re.compile('^(?P<name>[a-zA-Z0-9\-\.\_\+\~\ \t]*)<(?P<uri>[^>]+)>'), 
              re.compile('^(?:"(?P<name>[^"]+)")[\ \t]*<(?P<uri>[^>]+)>'),
              re.compile('^[\ \t]*(?P<name>)(?P<uri>[^;]+)')]
    
    def __init__(self, value=None):
        '''Construct an address from the string representation'''
        self.displayName = self.uri = None 
        self.wildcard = self.mustQuote = False
        if value: self.parse(value)

    def parse(self, value):
        '''Parse a string representation to an address. Returns number of 
        characters parsed.'''
        if str(value).startswith('*'):
            self.wildcard = True
            return 1;
        else:
            for s in Address._syntax:
                m = s.match(value)
                if m: 
                    self.displayName = m.groups()[0].strip()
                    self.uri = URI(m.groups()[1].strip())
                    return m.end()
                
    def __repr__(self):
        '''Return a string representation of the address'''
        return (('"' + self.displayName + '"' + (' ' if self.uri else '')) if self.displayName else '') \
        + ((('<' if self.mustQuote or self.displayName else '') \
        + repr(self.uri) \
        + ('>' if self.mustQuote or self.displayName else '')) if self.uri else '')
    
    def dup(self):
        '''Duplicate this object.'''
        return Address(self.__repr__())
    
    @property
    def displayable(self):
        '''Read-only displayable string representation'''
        return self.getDisplayable(limit=25)
    
    def getDisplayable(self, limit):
        name = self.displayName or self.uri and self.uri.user or self.uri and self.uri.host or ''
        return name if len(name)<limit else (name[0:limit-3] + '...')
    
if __name__ == '__main__':
    import doctest
    doctest.testmod()
