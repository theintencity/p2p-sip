# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3261 (SIP)
# @implements RFC3581 (rport)

'''
The session initiation protocol (SIP) as per RFC 3261.
In my code there is no performance optimization, if it hurts the style and
compactness of the code.
'''

import re, socket, traceback, uuid
from kutil import getlocaladdr
from rfc2396 import isIPv4, isMulticast, isLocal, isPrivate, URI, Address
from rfc2617 import createAuthorization
from socket import gethostbyname # TODO: should replace with getifaddr, SRV, NAPTR or similar

_debug = False

#----------------------- Header and Message -------------------------------

_quote   = lambda s: '"' + s + '"' if s[0] != '"' != s[-1] else s
_unquote = lambda s: s[1:-1] if s[0] == '"' == s[-1] else s

# various header types: standard (default), address, comma and unstructured
_address      = ['contact', 'from', 'record-route', 'refer-to', 'referred-by', 'route', 'to']
_comma        = ['authorization', 'proxy-authenticate', 'proxy-authorization', 'www-authenticate']
_unstructured = ['call-id', 'cseq', 'date', 'expires', 'max-forwards', 'organization', 'server', 'subject', 'timestamp', 'user-agent']
# short form of header names
_short        = ['allow-events', 'u', 'call-id', 'i', 'contact', 'm', 'content-encoding', 'e', 'content-length', 'l', 'content-type', 'c', 'event', 'o', 'from', 'f', 'subject', 's', 'supported', 'k', 'to', 't', 'via', 'v']
# exception for canonicalization of header names
_exception    = {'call-id':'Call-ID','cseq':'CSeq','www-authenticate':'WWW-Authenticate'}
#_canon   = lambda s: '-'.join([x.capitalize() for x in s.split('-')]) if s.lower() not in ['cseq','call-id','www-authenticate'] else {'cseq':'CSeq','call-id':'Call-ID','www-authenticate':'WWW-Authenticate'}[s.lower()]

def _canon(s):
    '''Return the canonical form of the header.
    >>> print _canon('call-Id'), _canon('fRoM'), _canon('refer-to')
    Call-ID From Refer-To
    '''
    s = s.lower()
    return ((len(s)==1) and s in _short and _canon(_short[_short.index(s)-1])) \
        or (s in _exception and _exception[s]) or '-'.join([x.capitalize() for x in s.split('-')])


class Header(object):
    '''A SIP header object with dynamic properties.
    Attributes such as name, and various parameters can be accessed on the object.

    >>> print repr(Header('"Kundan Singh" <sip:kundan@example.net>', 'To'))
    To: "Kundan Singh" <sip:kundan@example.net>
    >>> print repr(Header('"Kundan"<sip:kundan99@example.net>', 'To'))
    To: "Kundan" <sip:kundan99@example.net>
    >>> print repr(Header('Sanjay <sip:sanjayc77@example.net>', 'fRoM'))
    From: "Sanjay" <sip:sanjayc77@example.net>
    >>> print repr(Header('application/sdp', 'conTenT-tyPe'))
    Content-Type: application/sdp
    >>> print repr(Header('presence; param=value;param2=another', 'Event'))
    Event: presence;param=value;param2=another
    >>> print repr(Header('78  INVITE', 'CSeq'))
    CSeq: 78 INVITE
    '''

    def __init__(self, value=None, name=None):
        '''Construct a Header from optional value and optional name.'''
        self.name = name and _canon(name.strip()) or None
        self.value = self._parse(value.strip(), self.name and self.name.lower() or None)

    def _parse(self, value, name):
        '''Parse a header string value for the given header name.'''
        if name in _address: # address header
            addr = Address(); addr.mustQuote = True
            count = addr.parse(value)
            value, rest = addr, value[count:]
            if rest:
                for k, v in self.parseParams(rest): self.__dict__[k] = v
#            for n,sep,v in map(lambda x: x.partition('='), rest.split(';') if rest else []):
#                if n.strip():
#                    self.__dict__[n.lower().strip()] = v.strip()
        elif name not in _comma and name not in _unstructured: # standard
            value, sep, rest = value.partition(';')
            if rest:
                for k, v in self.parseParams(rest): self.__dict__[k] = v
#            for n,sep,v in map(lambda x: x.partition('='), rest.split(';') if rest else []):
#                # TODO: add checks for token
#                self.__dict__[n.lower().strip()] = v.strip()
        if name in _comma:
            self.authMethod, sep, rest = value.strip().partition(' ')
            if rest:
                for k, v in self.parseParams(rest, delimiter=','): self.__dict__[k] = v
#            for n,v in map(lambda x: x.strip().split('='), rest.split(',') if rest else []):
#                self.__dict__[n.lower().strip()] = _unquote(v.strip())
        elif name == 'cseq':
            n, sep, self.method = map(lambda x: x.strip(), value.partition(' '))
            self.number = int(n); value = n + ' ' + self.method
        return value

    @staticmethod
    def parseParams(rest, delimiter=';'):
        '''A generator to parse the parameters using the supplied delimitter.
        >>> print list(Header.parseParams(";param1=value1;param2=value2"))
        [('param1', 'value1'), ('param2', 'value2')]
        >>> print list(Header.parseParams(';param1="value1" ;param2="value2"'))
        [('param1', 'value1'), ('param2', 'value2')]
        >>> print list(Header.parseParams('param1="value1", param2=value2', delimiter=','))
        [('param1', 'value1'), ('param2', 'value2')]
        >>> print list(Header.parseParams('param1="";param2'))
        [('param1', ''), ('param2', '')]
        >>> print list(Header.parseParams('param1="";param2=;'))  # error cases
        [('param1', ''), ('param2', '')]
        '''
        try:
            length, index = len(rest), 0
            while index < length:
                sep1 = rest.find('=', index)
                sep2 = rest.find(delimiter, index)
                if sep2 < 0: sep2 = length # next parameter
                n = v = ''
                if sep1 >= 0 and sep1 < sep2: # parse "a=b;..." or "a=b"
                    n = rest[index:sep1].lower().strip()
                    if rest[sep1+1] == '"':
                        sep1 += 1
                        sep2 = rest.find('"', sep1+1)
                    if sep2 >= 0:
                        v = rest[sep1+1:sep2].strip()
                        index = sep2+1
                    else:
                        v = rest[sep1+1:].strip()
                        index = length
                elif sep1 < 0 or sep1 >= 0 and sep1 > sep2: # parse "a" or "a;b=c" or ";b"
                    n, index = rest[index:sep2].lower().strip(), sep2+1
                else: break
                if n:
                    yield (n, v)
        except:
            if _debug: print 'error parsing parameters'; traceback.print_exc()
        raise StopIteration(None)


    def __str__(self):
        '''Return a string representation of the header value.'''
        # TODO: use reduce instead of join+map
        name = self.name.lower()
        rest = '' if ((name in _comma) or (name in _unstructured)) \
                else (';'.join(['%s'%(x,) if not y else ('%s=%s'%(x.lower(), y) if re.match(r'^[a-zA-Z0-9\-_\.=]*$', str(y)) else '%s="%s"'%(x.lower(), y))for x, y in self.__dict__.iteritems() if x.lower() not in ('name','value', '_viauri')]))
        return str(self.value) + (rest and (';'+rest) or '');

    def __repr__(self):
        '''Return the string representation of header's "name: value"'''
        return self.name + ": " + str(self)

    def dup(self):
        '''Duplicate this object.'''
        return Header(self.__str__(), self.name)

    # container access for parameters: use lower-case key in __dict__
    def __getitem__(self, name): return self.__dict__.get(name.lower(), None)
    def __setitem__(self, name, value): self.__dict__[name.lower()] = value
    def __contains__(self, name): return name.lower() in self.__dict__

    @property
    def viaUri(self):
        '''Read-only URI representing Via header's value.
        >>> print Header('SIP/2.0/UDP example.net:5090;ttl=1', 'Via').viaUri
        sip:example.net:5090;transport=udp
        >>> print Header('SIP/2.0/UDP 192.1.2.3;rport=1078;received=76.17.12.18;branch=0', 'Via').viaUri
        sip:76.17.12.18:1078;transport=udp
        >>> print Header('SIP/2.0/UDP 192.1.2.3;maddr=224.0.1.75', 'Via').viaUri
        sip:224.0.1.75:5060;transport=udp
        '''
        if not hasattr(self, '_viaUri'):
            if self.name != 'Via': raise ValueError, 'viaUri available only on Via header'
            proto, addr = self.value.split(' ')
            type = proto.split('/')[2].lower()  # udp, tcp, tls
            self._viaUri = URI('sip:' + addr + ';transport=' + type)
            if self._viaUri.port == None: self._viaUri.port = 5060
            if 'rport' in self:
                try: self._viaUri.port = int(self.rport)
                except: pass # probably not an int
            if type not in ['tcp','sctp','tls']:
                if 'maddr' in self: self._viaUri.host = self.maddr
                elif 'received' in self: self._viaUri.host = self.received
        return self._viaUri

    @staticmethod
    def createHeaders(value):
        '''Parse a header line and return (name, [Header, Header, Header]) where name
        represents the header name, and the list has list of Header objects, typically
        one but for comma separated header line there can be multiple.
        >>> print Header.createHeaders('Event: presence, reg')
        ('Event', [Event: presence, Event: reg])
        >>> print Header.createHeaders('Contact: <sip:user@1.2.3.4:5060;line=vvl1wrhk>;reg-id=1;q=1.0;+sip.instance="<urn:uuid:bff62662-19cc-4781-8830-0004132E682E>";audio;mobility="fixed";duplex="full";description="snom370";actor="principal";events="dialog";methods="INVITE,ACK,CANCEL,BYE,REFER,OPTIONS,NOTIFY,SUBSCRIBE,PRACK,MESSAGE,INFO"')
        ('Contact', [Contact: <sip:user@1.2.3.4:5060;line=vvl1wrhk>;reg-id=1;mobility=fixed;duplex=full;description=snom370;actor=principal;q=1.0;methods="INVITE,ACK,CANCEL,BYE,REFER,OPTIONS,NOTIFY,SUBSCRIBE,PRACK,MESSAGE,INFO";audio;events=dialog;+sip.instance="<urn:uuid:bff62662-19cc-4781-8830-0004132E682E>"])
        '''
        name, value = map(str.strip, value.split(':', 1))
        value = '"'.join([(x if i % 2 == 0 else re.sub(r',', r'%2C', x)) for i, x in enumerate(value.split('"'))])
        return (_canon(name),  map(lambda x: Header(re.sub(r'%2C', r',', x), name), value.split(',') if name.lower() not in _comma else [value]))



class Message(object):
    '''A SIP message object with dynamic properties.
    The header names can be accessed as attributes or items and
    are case-insensitive. Attributes such as method, uri (URI),
    response (int), responsetext, protocol, and body are available.
    Accessing an unavailable header gives None instead of exception.

    >>> m = Message()
    >>> m.method = 'INVITE'
    '''

    # non-header attributes or items
    _keywords = ['method','uri','response','responsetext','protocol','_body','body']
    # headers that can appear only atmost once. subsequent occurance ignored.
    _single = ['call-id', 'content-disposition', 'content-length', 'content-type', 'cseq', 'date', 'expires', 'event', 'max-forwards', 'organization', 'refer-to', 'referred-by', 'server', 'session-expires', 'subject', 'timestamp', 'to', 'user-agent']

    def __init__(self, value=None):
        self.method = self.uri = self.response = self.responsetext = self.protocol = self._body = None
        if value: self._parse(value)

    # attribute access: use lower-case name, and use container if not found
    def __getattr__(self, name): return self.__getitem__(name)
    def __getattribute__(self, name): return object.__getattribute__(self, name.lower())
    def __setattr__(self, name, value): object.__setattr__(self, name.lower(), value)
    def __delattr__(self, name): object.__delattr__(self, name.lower())
    def __hasattr__(self, name): object.__hasattr__(self, name.lower())
    # container access: use lower-case key in __dict__
    def __getitem__(self, name): return self.__dict__.get(name.lower(), None)
    def __setitem__(self, name, value): self.__dict__[name.lower()] = value
    def __delitem__(self, name): del self.__dict__[name.lower()]
    def __contains__(self, name): return name.lower() in self.__dict__

    def _parse(self, value):
        '''Parse a SIP message as this object. Throws exception on error'''
        # TODO: perform all error checking:
        # 1. no \r\n\r\n in the message. (done)
        # 2. no headers.
        # 3. first line has less than three parts.
        # 4. syntax for protocol, and must be SIP/2.0
        # 5. syntax for method or response attributes
        # 6. first header must not start with a space or tab.
        # 7. detect and ignore header parsing and multiple instance errors.
        # 8. Content-Length if present must match the length of body.
        # 9. mandatory headers are To, From, Call-ID and CSeq.
        # 10. syntax for top Via header and fields: ttl, maddr, received, branch.
        indexCRLFCRLF, indexLFLF = value.find('\r\n\r\n'), value.find('\n\n')
        firstheaders = body = ''
        if indexCRLFCRLF >= 0 and indexLFLF >= 0:
            if indexCRLFCRLF < indexLFLF: indexLFLF = -1
            else: indexCRLFCRLF = -1
        if indexCRLFCRLF >= 0:
            firstheaders, body = value[:indexCRLFCRLF], value[indexCRLFCRLF+4:]
        elif indexLFLF >= 0:
            firstheaders, body = value[:indexLFLF], value[indexLFLF+2:]
        else:
            firstheaders, body = value, '' # assume no body
        try: firstline, headers = firstheaders.split('\n', 1)
        except: raise ValueError, 'No first line found'
        if firstline[-1] == '\r': firstline = firstline[:-1]
        a, b, c = firstline.split(' ', 2)
        try:    # try as response
            self.response, self.responsetext, self.protocol = int(b), c, a # throws error if b is not int.
        except: # probably a request
            self.method, self.uri, self.protocol = a, URI(b), c

        hlist = []
        for h in headers.split('\n'):
            if h and h[-1] == '\r': h = h[:-1]
            if h and (h[0] == ' ' or h[0] == '\t'):
                if hlist:
                    hlist[-1] += h
            else:
                hlist.append(h)
        for h in hlist:
            try:
                name, values = Header.createHeaders(h)
                if name not in self: # doesn't already exist
                    self[name] = values if len(values) > 1 else values[0]
                elif name not in Message._single: # valid multiple-instance header
                    if not isinstance(self[name],list): self[name] = [self[name]]
                    self[name] += values
            except:
                if _debug: print 'error parsing', h
                continue
        bodyLen = int(self['Content-Length'].value) if 'Content-Length' in self else 0
        if body: self.body = body
        if self.body != None and bodyLen != len(body): raise ValueError, 'Invalid content-length %d!=%d'%(bodyLen, len(body))
        for h in ['To','From','CSeq','Call-ID']:
            if h not in self: raise ValueError, 'Mandatory header %s missing'%(h)

    def __repr__(self):
        '''Return the formatted message string.'''
        if self.method != None: m = self.method + ' ' + str(self.uri) + ' ' + self.protocol + '\r\n'
        elif self.response != None: m = self.protocol + ' ' + str(self.response) + ' ' + self.responsetext + '\r\n'
        else: return None # invalid message
        for h in self:
            m += repr(h) + '\r\n'
        m+= '\r\n'
        if self.body != None: m += self.body
        return m

    def dup(self):
        '''Duplicate this object.'''
        return Message(self.__repr__())

    def __iter__(self):
        '''Return iterator to iterate over all Header objects.'''
        h = list()
        for n in filter(lambda x: not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n],list) else [self[n]])
        return iter(h)

    def first(self, name):
        '''Return the first Header object for this name, or None.'''
        result = self[name]
        return isinstance(result,list) and result[0] or result

    def all(self, *args):
        '''Return list of the Header object (or empty list) for all the header names in args.'''
        args = map(lambda x: x.lower(), args)
        h = list()
        for n in filter(lambda x: x in args and not x.startswith('_') and x not in Message._keywords, self.__dict__):
            h += filter(lambda x: isinstance(x, Header), self[n] if isinstance(self[n],list) else [self[n]])
        return h

    def insert(self, header, append=False):
        if header and header.name:
            if header.name not in self:
                self[header.name] = header
            elif isinstance(self[header.name], Header):
                self[header.name] = (append and [self[header.name], header] or [header, self[header.name]])
            else:
                if append: self[header.name].append(header)
                else: self[header.name].insert(0, header)
        # TODO: don't insert multi-instance if single header type.

    def delete(self, name, position=None):
        '''Delete a named header, either all (default) or at given position (0 for first, -1 for last).'''
        if position is None: del self[name] # remove all headers with this name
        else:
            h = self.all(name) # get all headers
            try: del h[position]    # and remove at given position
            except: pass       # ignore any error in index
            if len(h) == 0: del self[name]
            else: self[name] = h[0] if len(h) == 1 else h

    def body():
        '''The body property, when set also sets the Content-Length header field.'''
        def fset(self, value):
            self._body = value
            self['Content-Length'] = Header('%d'%(value and len(value) or 0), 'Content-Length')
        def fget(self):
            return self._body
        return locals()
    body = property(**body())

    @staticmethod
    def _populateMessage(m, headers=None, content=None):
        '''Modify m to add headers (list of Header objects) and content (str body)'''
        if headers:
            for h in headers: m.insert(h, True) # append the header instead of overriding
        if content: m.body = content
        else: m['Content-Length'] = Header('0', 'Content-Length')

    @staticmethod
    def createRequest(method, uri, headers=None, content=None):
        '''Create a new request Message with given attributes.'''
        m = Message()
        m.method, m.uri, m.protocol = method, URI(uri), 'SIP/2.0'
        Message._populateMessage(m, headers, content)
        if m.CSeq != None and m.CSeq.method != method: m.CSeq = Header(str(m.CSeq.number) + ' ' + method, 'CSeq')
        #if _debug: print 'createRequest returned\n', m
        return m

    @staticmethod
    def createResponse(response, responsetext, headers=None, content=None, r=None):
        '''Create a new response Message with given attributes.
        The original request may be specified as the r parameter.'''
        m = Message()
        m.response, m.responsetext, m.protocol = response, responsetext, 'SIP/2.0'
        if r:
            m.To, m.From, m.CSeq, m['Call-ID'], m.Via = r.To, r.From, r.CSeq, r['Call-ID'], r.Via
            if response == 100: m.Timestamp = r.Timestamp
        Message._populateMessage(m, headers, content)
        return m

    # define is1xx, is2xx, ... is6xx and isfinal
    for x in range(1,7):
        exec 'def is%dxx(self): return self.response and (self.response / 100 == %d)'%(x,x)
        exec 'is%dxx = property(is%dxx)'%(x,x)
    @property
    def isfinal(self): return self.response and (self.response >= 200)

#---------------------------Stack------------------------------------------

import random

class Stack(object):
    '''The SIP stack is associated with transport layer and controls message
    flow among different layers.

    The application must provide an app instance with following signature:
    class App():
        def send(self, data, dest): pass
            'to send data (str) to dest ('192.1.2.3', 5060).'
        def sending(self, data, dest): pass
            'to indicate that a given data (Message) will be sent to the dest (host, port).'
        def createServer(self, request, uri): return UserAgent(stack, request)
            'to ask the application to create a UAS for this request (Message) from source uri (Uri).'
        def receivedRequest(self, ua, request): pass
            'to inform that the UAS or Dialog has recived a new request (Message).'
        def receivedResponse(self, ua, request): pass
            'to inform that the UAC or Dialog has recived a new response (Message).'
        def cancelled(self, ua, request): pass
            'to inform that the UAS or Dialog has received a cancel for original request (Message).'
        def dialogCreated(self, dialog, ua): pass
            'to inform that the a new Dialog is created from the old UserAgent.'
        def authenticate(self, ua, header): header.password='mypass'; return True
            'to ask the application for credentials for this challenge header (Header).'
        def createTimer(self, cbObj): return timerObject
            'the returned timer object must have start() and stop() methods, a delay (int)
            attribute, and should invoke cbObj.timedout(timer) when the timer expires.'
    Only the authenticate and sending methods are optional. All others are mandatory.

    The application must invoke the following callback on the stack:
    stack.received(data, src)
        'when incoming data (str) received on underlying transport from
        src ('192.2.2.2', 5060).'

    The application must provide a Transport object which is an object with
    these attributes: host, port, type, secure, reliable, congestionControlled, where
        host: a string representing listening IP address, e.g., '192.1.2.3'
        port: a int representing listening port number, e.g., 5060.
        type: a string of the form 'udp', 'tcp', 'tls', or 'sctp' indicating the transport type.
        secure: a boolean indicating whether this is secure or not?
        reliable: a boolean indicating whether the transport is reliable or not?
        congestionControlled: a boolean indicating whether the transport is congestion controlled?
    '''
    def __init__(self, app, transport, fix_nat=False):
        '''Construct a stack using the specified application (higher) layer and
        transport (lower) data.'''
        self.tag = str(random.randint(0,2**31))
        self.app, self.transport, self.fix_nat = app, transport, fix_nat
        self.closing = False
        self.dialogs, self.transactions = dict(), dict()
        self.serverMethods = ['INVITE','BYE','MESSAGE','SUBSCRIBE','NOTIFY']
    def __del__(self):
        self.closing = True
        for d in self.dialogs: del self.dialogs[d]
        for t in self.transactions: del self.transactions[t]
        del self.dialogs; del self.transactions

    @property
    def uri(self):
        '''Construct a URI for the transport.'''
        transport = self.transport
        return URI(((transport.type == 'tls') and 'sips' or 'sip') + ':' + transport.host + ':' + str(transport.port))

    @property
    def newCallId(self):
        return str(uuid.uuid1()) + '@' + (self.transport.host or 'localhost')

    def createVia(self, secure=False):
        if not self.transport: raise ValueError, 'No transport in stack'
        if secure and not self.transport.secure: raise ValueError, 'Cannot find a secure transport'
        return Header('SIP/2.0/' + self.transport.type.upper() + ' ' + self.transport.host + ':' + str(self.transport.port) + ';rport', 'Via')

    def send(self, data, dest=None, transport=None):
        '''Send a data (Message) to given dest (URI or hostPort), or using the Via header of
        response message if dest is missing.'''
        # TODO: why do we need transport argument?
        if dest and isinstance(dest, URI):
            if not dest.host: raise ValueError, 'No host in destination uri'
            dest = (dest.host, dest.port or self.transport.type == 'tls' and self.transport.secure and 5061 or 5060)
        if isinstance(data, Message):
            if data.method:      # request
                # @implements RFC3261 P143L14-P143L19
                if dest and isMulticast(dest[0]):
                    data.first('Via')['maddr'], data.first('Via')['ttl'] = dest[0], 1
            elif data.response: # response: use Via if dest missing
                if not dest:
                    dest = data.first('Via').viaUri.hostPort
        self.app.send(str(data), dest, stack=self)

    def received(self, data, src):
        '''Callback when received some data (str) from the src ('host', port).'''
        m = Message()
        try:
            m._parse(data)
            uri = URI((self.transport.secure and 'sips' or 'sip') + ':' + str(src[0]) + ':' + str(src[1]))
            if m.method: # request: update Via and call receivedRequest
                if m.Via == None: raise ValueError, 'No Via header in request'
                via = m.first('Via')
                if via.viaUri.host != src[0] or via.viaUri.port != src[1]:
                    via['received'], via.viaUri.host = src[0], src[0]
                if 'rport' in via:
                    via['rport'] = src[1]
                    via.viaUri.port = src[1]
                if self.transport.type == 'tcp': # assume rport
                    via['rport'] = src[1]
                    via.viaUri.port = src[1]
                if self.fix_nat and m.method in ('INVITE', 'MESSAGE'):
                    self._fixNatContact(m, src)
                self._receivedRequest(m, uri)
            elif m.response: # response: call receivedResponse
                if self.fix_nat and m['CSeq'] and m.CSeq.method in ('INVITE', 'MESSAGE'):
                    self._fixNatContact(m, src)
                self._receivedResponse(m, uri)
            else: raise ValueError, 'Received invalid message'
        except ValueError, E: # TODO: send 400 response to non-ACK request
            if _debug: print 'Error in received message:', E
            if _debug: traceback.print_exc()
            if m.method and m.uri and m.protocol and m.method != 'ACK': # this was a non-ACK request
                try: self.send(Message.createResponse(400, str(E), None, None, m))
                except: pass # ignore error since m may be malformed.

    def _fixNatContact(self, m, src):
        if m['Contact']:
            uri = m.first('Contact').value.uri
            if uri.scheme in ('sip', 'sips') and isIPv4(uri.host) and uri.host != src[0] and \
            not isLocal(src[0]) and not isLocal(uri.host) and isPrivate(uri.host) and not isPrivate(src[0]):
                if _debug: print 'fixing NAT -- private contact from', uri,
                uri.host, uri.port = src[0], src[1]
                if _debug: print 'to received', uri

    def _receivedRequest(self, r, uri):
        '''Received a SIP request r (Message) from the uri (URI).'''
        try: branch = r.first('Via').branch
        except AttributeError: branch = ''
        if r.method == 'ACK':
            if branch == '0':
                # TODO: this is a hack to work around iptel.org which puts branch=0 in all ACK
                # hence it matches the previous transaction's ACK for us, which is not good.
                # We need to fix our code to handle end-to-end ACK correctly in findTransaction.
                t = None
            else:
                t = self.findTransaction(branch) # assume final, non 2xx response
                if not t or t.lastResponse and t.lastResponse.is2xx: # don't deliver to the invite server transaction
                    t = self.findTransaction(Transaction.createId(branch, r.method))
        else:
            t = self.findTransaction(Transaction.createId(branch, r.method))
        if not t: # no transaction found
            app = None  # the application layer for further processing
            if r.method != 'CANCEL' and 'tag' in r.To: # for existing dialog
                d = self.findDialog(r)
                if not d: # no dialog found
                    if r.method != 'ACK':
                        u = self.createServer(r, uri)
                        if u: app = u
                        else:
                            self.send(Message.createResponse(481, 'Dialog does not exist', None, None, r))
                            return
                    else: # hack to locate original t for ACK
                        if _debug: print 'no dialog for ACK, finding transaction'
                        if not t and branch != '0': t = self.findTransaction(Transaction.createId(branch, 'INVITE'))
                        if t and t.state != 'terminated':
                            if _debug: print 'Found transaction', t
                            t.receivedRequest(r)
                            return
                        else:
                            if _debug: print 'No existing transaction for ACK'
                            u = self.createServer(r, uri)
                            if u: app = u
                            else:
                                if _debug: print 'Ignoring ACK without transaction'
                                return
                else: # dialog found
                    app = d
            elif r.method != 'CANCEL': # process all other out-of-dialog request except CANCEL
                u = self.createServer(r, uri)
                if u:
                    app = u
                elif r.method == 'OPTIONS':
                    m = Message.createResponse(200, 'OK', None, None, r)
                    m.Allow = Header('INVITE, ACK, CANCEL, BYE, OPTIONS', 'Allow')
                    self.send(m)
                    return
                elif r.method != 'ACK':
                    self.send(Message.createResponse(405, 'Method not allowed', None, None, r))
                    return
            else: # Process a CANCEL request
                o = self.findTransaction(Transaction.createId(r.first('Via').branch, 'INVITE')) # original transaction
                if not o:
                    self.send(Message.createResponse(481, "Original transaction does not exist", None, None, r))
                    return
                else:
                    app = o.app
            if app:
                t = app.createTransaction(r)
                #t = Transaction.createServer(self, app, r, self.transport, self.tag)
                if r.method == 'ACK' and t is not None and t.id in self.transactions:
                    # Asterisk sends the same branch id in the second call's ACK, and should not match the previous
                    # call's ACK. So we don't add ACK to the transactions list. Another option would be to keep
                    # index in self.transactions as call-id + transaction-id instead of just transaction-id.
                    # In that case there should be a way to remove ACK transactions.
                    del self.transactions[t.id]
            elif r.method != 'ACK':
                self.send(Message.createResponse(404, "Not found", None, None, r))
        else:
            if isinstance(t, ServerTransaction) or isinstance(t, InviteServerTransaction):
                t.receivedRequest(r)
            else:
                # TODO: This is a hack! Need to follow RFC 3261 about creating branch param for proxy
                self.send(Message.createResponse(482, 'Loop detected', None, None, r))


    def _receivedResponse(self, r, uri):
        '''Received a SIP response r (Message) from the uri (URI).'''
        if not r.Via: raise ValueError, 'No Via header in received response'
        try: branch = r.first('Via').branch
        except AttributeError: branch = ''
        method = r.CSeq.method
        t = self.findTransaction(Transaction.createId(branch, method))
        if not t:
            if method == 'INVITE' and r.is2xx: # success of INVITE
                d = self.findDialog(r)
                if not d: # no dialog or transaction for success response of INVITE.
                    raise ValueError, 'No transaction or dialog for 2xx of INVITE'
                else:
                    d.receivedResponse(None, r)
            else:
                if _debug: print 'transaction id %r not found'%(Transaction.createId(branch, method),) # do not print the full transactions table
                if method == 'INVITE' and r.isfinal: # final failure response for INVITE, send ACK to same transport
                    # TODO: check if this following is as per the standard
                    m = Message.createRequest('ACK', str(r.To.value.uri))
                    m['Call-ID'], m.From, m.To, m.Via, m.CSeq = r['Call-ID'], r.From, r.To, r.first('Via'), Header(str(r.CSeq.number) + ' ACK', 'CSeq')
                    self.send(m, uri.hostPort)
                raise ValueError, 'No transaction for response'
        else:
            t.receivedResponse(r)

    # following are the main API methods to indicate events from UAS/UAC/Dialog
    def createServer(self, request, uri): return self.app.createServer(request, uri, self)
    def sending(self, ua, message): return self.app.sending(ua, message, self) if hasattr(self.app, 'sending') else None
    def receivedRequest(self, ua, request): self.app.receivedRequest(ua, request, self)
    def receivedResponse(self, ua, response): self.app.receivedResponse(ua, response, self)
    def cancelled(self, ua, request): self.app.cancelled(ua, request, self)
    def dialogCreated(self, dialog, ua): self.app.dialogCreated(dialog, ua, self)
    def authenticate(self, ua, header): return self.app.authenticate(ua, header, self) if hasattr(self.app, 'authenticate') else False
    def createTimer(self, obj): return self.app.createTimer(obj, self)

    def findDialog(self, arg):
        '''Find an existing dialog for given id (str) or received message (Message).'''
        return self.dialogs.get(isinstance(arg, Message) and Dialog.extractId(arg) or str(arg), None)

    def findTransaction(self, id):
        '''Find an existing transaction for given id (str).'''
        return self.transactions.get(id, None)

    def findOtherTransaction(self, r, orig):
        '''Find another transaction other than orig (Transaction) for this request r (Message).'''
        for t in self.transactions.values():
            if t != orig and Transaction.equals(t, r, orig): return t
        return None

class TransportInfo:
    '''Transport information needed by Stack constructor'''
    def __init__(self, sock, secure=False):
        '''The sock argument is the bound socket.'''
        addr = getlocaladdr(sock)
        self.host, self.port, self.type, self.secure, self.reliable, self.congestionControlled = addr[0], addr[1], (sock.type==socket.SOCK_DGRAM and 'udp' or 'tcp'), secure, (sock.type==socket.SOCK_STREAM), (sock.type==socket.SOCK_STREAM)
#---------------------------Transaction------------------------------------

from hashlib import md5
from base64 import urlsafe_b64encode

# @implements RFC3261 P122L34-P124L24
class Transaction(object):
    def __init__(self, server):
        '''Construct a transaction for the SIP method (str) and server (True or False)
        parameters, and uses the Invite/Non-invite Server/Client state machine accordingly.'''
        self.branch = self.id = self.stack = self.app = self.request = self.transport = self.remote = self.tag = None
        self.server, self.timers, self.timer = server, {}, Timer()

    def close(self):
        '''Stop the timers and remove from the lists.'''
        self.stopTimers()
        if self.stack:
            if _debug: print 'closing transaction %r'%(self.id,)
            if self.id in self.stack.transactions: del self.stack.transactions[self.id]

    def state():
        def fset(self, value):
            self._state = value
            if self._state == 'terminated': self.close() # automatically close when state goes terminating
        def fget(self): return self._state
        return locals()
    state = property(**state())

    @property
    def headers(self):
        '''Read-only list of transaction Header objects (To, From, CSeq, Call-ID)'''
        return map(lambda x: self.request[x], ['To', 'From', 'CSeq', 'Call-ID'])

    @staticmethod
    def createBranch(request, server):
        '''Static method to create a branch parameter from request (Message) and server (Boolean)
        or using [To, From, Call-ID, CSeq-number(int)] and server (Boolean).'''
        To, From, CallId, CSeq = (request.To.value, request.From.value, request['Call-ID'].value, request.CSeq.number) if isinstance(request, Message) else (request[0], request[1], request[2], request[3])
        data = str(To).lower() + '|' + str(From).lower() + '|' + str(CallId) + '|' + str(CSeq) + '|' + str(server)
        return 'z9hG4bK' + str(urlsafe_b64encode(md5(data).digest())).replace('=','.')

    @staticmethod
    def createProxyBranch(request, server):
        '''Create branch property from the request, which will get proxied in a new client branch.'''
        via = request.first('Via')
        if via and 'branch' in via: return 'z9hG4bK'+ str(urlsafe_b64encode(md5(via.branch).digest())).replace('=','.')
        else: return Transaction.createBranch(request, server)

    @staticmethod
    def createId(branch, method):
        '''Static method to create a transaction identifier form branch and method'''
        return branch if method != 'ACK' and method != 'CANCEL' else branch + '|' + method

    @staticmethod
    def createServer(stack, app, request, transport, tag, start=True):
        '''Static method to create a server transaction.'''
        t = request.method == 'INVITE' and InviteServerTransaction() or ServerTransaction()
        t.stack, t.app, t.request, t.transport, t.tag = stack, app, request, transport, tag
        t.remote = request.first('Via').viaUri.hostPort
        t.branch = request.first('Via').branch if request.Via != None and 'branch' in request.first('Via') else Transaction.createBranch(request, True)
        t.id = Transaction.createId(t.branch, request.method)
        stack.transactions[t.id] = t
        if start: t.start() # invoke callback in UAS
        else: t.state = 'trying' # already invoked callback in UAS
        return t

    @staticmethod
    def createClient(stack, app, request, transport, remote):
        '''Static method to create a client transaction.'''
        t = request.method == 'INVITE' and InviteClientTransaction() or ClientTransaction()
        t.stack, t.app, t.request, t.remote, t.transport = stack, app, request, remote, transport
        t.branch = request.first('Via').branch if request.Via != None and 'branch' in request.first('Via') else Transaction.createBranch(request, False)
        t.id = Transaction.createId(t.branch, request.method)
        stack.transactions[t.id] = t
        t.start()
        return t

    @staticmethod
    def equals(t1, r, t2):
        '''Compare transaction t1 with new request r and original transaction t2.'''
        t = t1.request
        return  r.To.value.uri == t.To.value.uri and r.From.value.uri == t.From.value.uri \
            and r['Call-ID'].value == t['Call-ID'].value and r.CSeq.value == t.CSeq.value \
            and r.From['tag'] == t.From['tag'] and t2.server == t1.server

    def createAck(self):
        '''Create an ACK request (Message) in this client transaction, else None.'''
        return Message.createRequest('ACK', str(self.request.uri), self.headers) if self.request and not self.server else None

    def createCancel(self):
        '''Create a CANCEL request (Message) in this client transaction, else None.'''
        m = Message.createRequest('CANCEL', str(self.request.uri), self.headers) if self.request and not self.server else None
        if m and self.request.Route: m.Route = self.request.Route
        if m: m.Via = self.request.first('Via') # only top Via included
        return m

    def createResponse(self, response, responsetext):
        '''Create a response (Message) in this server transaction, else None.'''
        m = Message.createResponse(response, responsetext, None, None, self.request) if self.request and self.server else None
        if response != 100 and 'tag' not in m.To: m.To['tag'] = self.tag # TODO: move this to UAS (?)
        return m

    def startTimer(self, name, timeout):
        '''Start a named timer with timeout (int).'''
        if timeout > 0:
            if name in self.timers:
                timer = self.timers[name]
            else:
                timer = self.timers[name] = self.stack.createTimer(self)
            timer.delay = timeout
            timer.start()

    def stopTimers(self):
        '''Stop all the named timers'''
        for v in self.timers.values(): v.stop()
        self.timers.clear()

    def timedout(self, timer):
        '''Callback invoked by Timer returned by stack.createTimer().'''
        if timer.running: timer.stop()
        found = filter(lambda x: self.timers[x] == timer, self.timers.keys())
        if len(found):
            for f in found: del self.timers[f]
            self.timeout(found[0], timer.delay)

# @implements RFC3261 P265L1-P265L40
class Timer(object):
    '''Various transaction timers as defined in RFC 3261.'''
    def __init__(self, T1=500, T2=4000, T4=5000):
        self.T1, self.T2, self.T4 = T1, T2, T4
    def A(self): return self.T1
    def B(self): return 64*self.T1
    def D(self): return max(64*self.T1, 32000)
    def I(self): return self.T4
    A, B, D, E, F, G, H, I, J, K = map(lambda x: property(x), [A, B, D, A, B, A, B, I, B, I])
    # TODO: why no timer C?

# @implements RFC3261 P130L35-P134L6
class ClientTransaction(Transaction):
    '''Non-INVITE client transaction'''
    def __init__(self):
        Transaction.__init__(self, False)
    def start(self):
        self.state = 'trying'
        if not self.transport.reliable:
            self.startTimer('E', self.timer.E)
        self.startTimer('F', self.timer.F)
        self.stack.send(self.request, self.remote, self.transport)

    def receivedResponse(self, response):
        if response.is1xx:
            if self.state == 'trying':
                self.state = 'proceeding'
                self.app.receivedResponse(self, response)
            elif self.state == 'proceeding':
                self.app.receivedResponse(self, response)
        elif response.isfinal:
            if self.state == 'trying' or self.state == 'proceeding':
                self.state = 'completed'
                self.app.receivedResponse(self, response)
                if not self.transport.reliable:
                    self.startTimer('K', self.timer.K)
                else:
                    self.timeout('K', 0)

    def timeout(self, name, timeout):
        if self.state == 'trying' or self.state == 'proceeding':
            if name == 'E':
                timeout = min(2*timeout, self.timer.T2) if self.state == 'trying' else self.timer.T2
                self.startTimer('E', timeout)
                self.stack.send(self.request, self.remote, self.transport)
            elif name == 'F':
                self.state = 'terminated'
                self.app.timeout(self)
        elif self.state == 'completed':
            if name == 'K':
                self.state = 'terminated'

    def error(self, error):
        if self.state == 'trying' or self.state == 'proceeding':
            self.state = 'terminated'
            self.app.error(self, error)

# @implements RFC3261 P137L12-P138L1
# @implements RFC3261 P140L1-P140L42
class ServerTransaction(Transaction):
    '''Non-INVITE server transaction'''
    def __init__(self):
        Transaction.__init__(self, True)
    def start(self):
        self.state = 'trying'
        self.app.receivedRequest(self, self.request)
    def receivedRequest(self, request):
        if self.request.method == request.method: # retransmitted
            if self.state == 'proceeding' or self.state == 'completed':
                self.stack.send(self.lastResponse, self.remote, self.transport)
            elif self.state == 'trying':
                pass # just ignore the retransmitted request
    def timeout(self, name, timeout):
        if self.state == 'completed':
            if name == 'J':
                self.state = 'terminated'
    def error(self, error):
        if self.state == 'completed':
            self.state = 'terminated'
            self.app.error(self, error)
    def sendResponse(self, response):
        self.lastResponse = response;
        if response.is1xx:
            if self.state == 'trying' or self.state == 'proceeding':
                self.state = 'proceeding'
                self.stack.send(response, self.remote, self.transport)
        elif response.isfinal:
            if self.state == 'proceeding' or self.state == 'trying':
                self.state = 'completed'
                self.stack.send(response, self.remote, self.transport)
                if not self.transport.reliable:
                    self.startTimer('J', self.timer.J)
                else:
                    self.timeout('J', 0)

# @implements RFC3261 P125L9-P129L19
class InviteClientTransaction(Transaction):
    '''INVITE client transaction'''
    def __init__(self):
        Transaction.__init__(self, False)
    def start(self):
        self.state = 'calling'
        if not self.transport.reliable:
            self.startTimer('A', self.timer.A)
        self.startTimer('B', self.timer.B)
        self.stack.send(self.request, self.remote, self.transport)

    def receivedResponse(self, response):
        if response.is1xx:
            if self.state == 'calling':
                self.state = 'proceeding'
                self.app.receivedResponse(self, response)
            elif self.state == 'proceeding':
                self.app.receivedResponse(self, response)
        elif response.is2xx:
            if self.state == 'calling' or self.state == 'proceeding':
                self.state = 'terminated'
                self.app.receivedResponse(self, response)
        else: # failure
            if self.state == 'calling' or self.state == 'proceeding':
                self.state = 'completed'
                self.stack.send(self.createAck(response), self.remote, self.transport)
                self.app.receivedResponse(self, response)
                if not self.transport.reliable:
                    self.startTimer('D', self.timer.D)
                else:
                    self.timeout('D', 0)
            elif self.state == 'completed':
                self.stack.send(self.createAck(response), self.remote, self.transport)

    def timeout(self, name, timeout):
        if self.state == 'calling':
            if name == 'A':
                self.startTimer('A', 2*timeout)
                self.stack.send(self.request, self.remote, self.transport)
            elif name == 'B':
                self.state = 'terminated'
                self.app.timeout(self)
        elif self.state == 'completed':
            if name == 'D':
                self.state = 'terminated'

    def error(self, error):
        if self.state == 'calling' or self.state == 'completed':
            self.state = 'terminated'
            self.app.error(self, error)

    # @implements RFC3261 P129L21-P130L12
    def createAck(self, response):
        if not self.request: raise ValueError, 'No transaction request found'
        m = Message.createRequest('ACK', str(self.request.uri))
        m['Call-ID'] = self.request['Call-ID']
        m.From   = self.request.From
        m.To     = response.To if response else self.request.To
        m.Via    = self.request.first("Via") # only top Via
        m.CSeq   = Header(str(self.request.CSeq.number) + ' ACK', 'CSeq')
        if self.request.Route: m.Route = self.request.Route
        return m;

# @implements RFC3261 P134L17-P137L10
# I modified to also have a trying state needed for proxy mode when 100 is not sent immediately.
class InviteServerTransaction(Transaction):
    '''INVITE server transaction'''
    def __init__(self):
        Transaction.__init__(self, True)
    def start(self):
        self.retrans = 0
        self.state = 'proceeding'
        self.sendResponse(self.createResponse(100, 'Trying'))
        self.app.receivedRequest(self, self.request)
    def receivedRequest(self, request):
        if self.request.method == request.method: # retransmitted
            if self.state == 'proceeding' or self.state == 'completed':
                self.retrans = self.retrans + 1
                if _debug: print 'Retransmitting (#%d) INVITE[%s] response due to retransmission from remote endpoint'%(self.retrans, self.id)
                self.stack.send(self.lastResponse, self.remote, self.transport)
        elif request.method == 'ACK':
            if self.state == 'completed':
                self.state = 'confirmed'
                if not self.transport.reliable:
                    self.startTimer('I', self.timer.I)
                else:
                    self.timeout('I', 0)
            elif self.state == 'confirmed':
                pass  # ignore the retransmitted ACK
    def timeout(self, name, timeout):
        if self.state == 'completed':
            if name == 'G':
                self.startTimer('G', min(2*timeout, self.timer.T2))
                self.retrans = self.retrans + 1
                if _debug: print 'Retransmitting (#%d) INVITE[%s] response'%(self.retrans, self.id)
                self.stack.send(self.lastResponse, self.remote, self.transport)
            elif name == 'H':
                self.state = 'terminated'
                self.app.timeout(self)
        elif self.state == 'confirmed':
            if name == 'I':
                self.state = 'terminated'

    def error(self, error):
        if self.state == 'proceeding' or self.state == 'trying' or self.state == 'confirmed':
            self.state = 'terminated'
            self.app.error(self, error)
    def sendResponse(self, response):
        self.retrans = 0
        self.lastResponse = response
        if response.is1xx:
            if self.state == 'proceeding' or self.state == 'trying':
                self.stack.send(response, self.remote, self.transport)
        else: # response.is2xx or failure
            if self.state == 'proceeding' or self.state == 'trying':
                self.state = 'completed'
                if not self.transport.reliable:
                    self.startTimer('G', self.timer.G)
                self.startTimer('H', self.timer.H)
                self.stack.send(response, self.remote, self.transport)


if __name__ == '__main__':
    m = Message('INVITE sip:kundan@example.net SIP/2.0\r\n'
              + 'CSeq: 1 INVITE\r\n'
              + 'To: sip:kundan@example.net\r\n'
              + 'From: sip:sanjayc77@example.net\r\n'
              + 'Call-ID: 783713917681\r\n'
              + '\r\n')
    assert Transaction.createBranch(m, True) == 'z9hG4bK1D-mLC6hGL1liMJ2jjYlTw..'

#---------------------------UserAgent and Dialog---------------------------

# @implements RFC3261 P34L16-P34L36
class UserAgent(object):
    '''Represents both UAS and UAC.'''
    def __init__(self, stack, request=None, server=None):
        '''Construct as UAS (if incoming request Message is supplied) or UAC.'''
        self.stack, self.request = stack, request
        self.server = server if server != None else (request != None)
        self.transaction, self.cancelRequest = None, None

        self.callId = request['Call-ID'].value if request and request['Call-ID'] else stack.newCallId
        self.remoteParty = request.From.value if request and request.From else None
        self.localParty = request.To.value if request and request.To else None
        self.localTag, self.remoteTag  = stack.tag + str(random.randint(0,10*10)), None
        self.subject = request.Subject.value if request and request.Subject else None
        self.secure = (request and request.uri.scheme == 'sips')
        self.maxForwards, self.routeSet = 70, []
        self.localTarget, self.remoteTarget, self.remoteCandidates = None, None, None
        self.localSeq, self.remoteSeq = 0, 0
        self.contact = Address(str(stack.uri))
        if self.localParty and self.localParty.uri.user: self.contact.uri.user = self.localParty.uri.user

        self.autoack = True# whether to send an ACK to 200 OK of INVITE automatically or let application send it.
        self.auth = dict() # to store authentication context

    def __repr__(self):
        '''Just a textual representation of the UserAgent'''
        return '<%s call-id=%s>'%(isinstance(self, Dialog) and 'Dialog' or 'UserAgent', self.callId)

    def createTransaction(self, request):
        '''Create a new server transaction for the UAS request. A stateless proxy may not create a transaction.'''
        return Transaction.createServer(self.stack, self, request, self.stack.transport, self.stack.tag)

    # @implements RFC3261 P35L5-P41L18
    def createRequest(self, method, content=None, contentType=None):
        '''Create new UAC request.'''
        self.server = False
        if not self.remoteParty: raise ValueError, 'No remoteParty for UAC'
        if not self.localParty: self.localParty = Address('"Anonymous" <sip:anonymous@anonymous.invalid>')
        uri = URI(str(self.remoteTarget if self.remoteTarget else self.remoteParty.uri)) # TODO: use original URI for ACK
        if method == 'REGISTER': uri.user = None # no uri.user in REGISTER
        if not self.secure and uri.secure: self.secure = True
        if method != 'ACK' and method != 'CANCEL': self.localSeq = self.localSeq + 1

        # initial headers
        To = Header(str(self.remoteParty), 'To')
        To.value.uri.secure = self.secure
        From = Header(str(self.localParty), 'From')
        From.value.uri.secure = self.secure
        From.tag = self.localTag
        CSeq = Header(str(self.localSeq) + ' ' + method, 'CSeq')
        CallId = Header(self.callId, 'Call-ID')
        MaxForwards = Header(str(self.maxForwards), 'Max-Forwards')
        Via = self.stack.createVia(self.secure)
        Via.branch = Transaction.createBranch([To.value, From.value, CallId.value, CSeq.number], False)
        # Transport adds other parameters such as maddr, ttl

        if not self.localTarget:
            self.localTarget = self.stack.uri.dup()
            self.localTarget.user = self.localParty.uri.user
        # put Contact is every request. app may remove or override it.
        Contact = Header(str(self.localTarget), 'Contact')
        Contact.value.uri.secure = self.secure

        headers = [To, From, CSeq, CallId, MaxForwards, Via, Contact]

        if self.routeSet:
            for route in map(lambda x: Header(str(x), 'Route'), self.routeSet):
                route.value.uri.secure = self.secure
                #print 'adding route header', route
                headers.append(route)
        # app adds other headers such as Supported, Require and Proxy-Require
        if contentType:
            headers.append(Header(contentType, 'Content-Type'))
        self.request = Message.createRequest(method, str(uri), headers, content)
        return self.request

    # @implements RFC3261 P57L12-P59L38
    def createRegister(self, aor):
        '''Create a REGISTER request for given aor (Address).'''
        if aor: self.remoteParty = Address(str(aor))
        if not self.localParty: self.localParty = Address(str(self.remoteParty))
        return self.createRequest('REGISTER')

    # @implements RFC3261 P41L20-P42L15
    def sendRequest(self, request):
        '''Send a UAC request Message.'''
        if not self.request and request.method == 'REGISTER':
            if not self.transaction and self.transaction.state != 'completed' and self.transaction.state != 'terminated':
                raise ValueError, 'Cannot re-REGISTER since pending registration'

        self.request = request # store for future

        if not request.Route: self.remoteTarget = request.uri
        target = self.remoteTarget

        if request.Route:
            routes = request.all('Route')
            if len(routes) > 0:
                target = routes[0].value.uri
                if not target or 'lr' not in target.param: # strict route
                    if _debug: print 'strict route target=', target, 'routes=', routes
                    del routes[0] # ignore first route
                    if len(routes) > 0:
                        if _debug: print 'appending our route'
                        routes.append(Header(str(request.uri), 'Route'))
                    request.Route = routes
                    request.uri = target;

        # TODO: remove any Route header in REGISTER request

        self.stack.sending(self, request)

        # TODO: replace the following with RFC3263 to return multiple candidates. Add TCP and UDP and is possible TLS.
        dest = target.dup()
        dest.port = target.port or target.secure and 5061 or 5060
        if not isIPv4(dest.host):
            try: dest.host = gethostbyname(dest.host)
            except: pass
        if isIPv4(dest.host):
            self.remoteCandidates = [dest]

        # continue processing as if we received multiple candidates
        if not self.remoteCandidates or len(self.remoteCandidates) == 0:
            self.error(None, 'cannot resolve DNS target')
            return
        target = self.remoteCandidates.pop(0)
        if self.request.method != 'ACK':
            # start a client transaction to send the request
            self.transaction = Transaction.createClient(self.stack, self, self.request, self.stack.transport, target.hostPort)
        else: # directly send ACK on transport layer
            self.stack.send(self.request, target.hostPort)

    def retryNextCandidate(self):
        '''Retry next DNS resolved address.'''
        if not self.remoteCandidates or len(self.remoteCandidates) == 0:
            raise ValueError, 'No more DNS resolved address to try'
        target = URI(self.remoteCandiates.pop(0))
        self.request.first('Via').branch += 'A' # so that we create a different new transaction
        self.transaction = Transaction.createClient(self.stack, self, self.request, self.stack.transport, target.hostPort)

    @staticmethod
    def canCreateDialog(request, response):
        '''Whether we can create a dialog for this response of this request?
        Default is to create dialog for 2xx response to INVITE or SUBSCRIBE.'''
        return response.is2xx and (request.method == 'INVITE' or request.method == 'SUBSCRIBE')

    # @implements RFC3261 P42L17-P46L2
    def receivedResponse(self, transaction, response):
        '''Received a new response from the transaction.'''
        if transaction and transaction != self.transaction:
            if _debug: print 'Invalid transaction received %r!=%r'%(transaction, self.transaction)
            return
        if len(response.all('Via')) > 1:
            raise ValueError, 'More than one Via header in response'
        if response.is1xx:
            if self.cancelRequest:
                cancel = Transaction.createClient(self.stack, self, self.cancelRequest, transaction.transport, transaction.remote)
                self.cancelRequest = None
            else:
                self.stack.receivedResponse(self, response)
        elif response.response == 401 or response.response == 407: # authentication challenge
            if not self.authenticate(response, self.transaction): # couldn't authenticate
                self.stack.receivedResponse(self, response)
        else:
            if self.canCreateDialog(self.request, response):
                dialog = Dialog.createClient(self.stack, self.request, response, transaction)
                self.stack.dialogCreated(dialog, self)
                self.stack.receivedResponse(dialog, response)
                if self.autoack and self.request.method == 'INVITE':
                    dialog.sendRequest(dialog.createRequest('ACK'))
            else:
                self.stack.receivedResponse(self, response)

    # @implements RFC3261 P46L4-P49L28
    def receivedRequest(self, transaction, request):
        '''New incoming request in this transaction.'''
        if transaction and self.transaction and transaction != self.transaction and request.method != 'CANCEL':
            raise ValueError, 'Invalid transaction for received request'
        self.server = True # this becomes a UAS
        #if request.method == 'REGISTER':
        #    response = transaction.createResponse(405, 'Method not allowed')
        #    response.Allow = Header('INVITE, ACK, CANCEL, BYE', 'Allow') # TODO make this configurable
        #    transaction.sendResponse(response)
        #    return
        if request.uri.scheme not in ['sip', 'sips', 'urn']:
            transaction.sendResponse(transaction.createResponse(416, 'Unsupported URI scheme'))
            return
        if 'tag' not in request.To: # out of dialog request
            if self.stack.findOtherTransaction(request, transaction): # request merging?
                transaction.sendResponse(transaction.createResponse(482, "Loop detected - found another transaction"))
                return
        if request.Require: # TODO let the application handle Require header
            if request.method != 'CANCEL' and request.method != 'ACK':
                response = transaction.createResponse(420, 'Bad extension')
                response.Unsupported = Header(str(request.Require.value), 'Unsupported')
                transaction.sendResponse(response)
                return
        if transaction: self.transaction = transaction # store it

        if request.method == 'CANCEL':
            original = self.stack.findTransaction(Transaction.createId(transaction.branch, 'INVITE'))
            if not original:
                transaction.sendResponse(transaction.createResponse(481, 'Original transaction not found'))
                return
            if original.state == 'proceeding' or original.state == 'trying':
                original.sendResponse(original.createResponse(487, 'Request terminated'))
            transaction.sendResponse(transaction.createResponse(200, 'OK')) # CANCEL response
            # TODO: the To tag must be same in the two responses
            self.stack.cancelled(self, request) # invoke cancelled on original UA instead of receivedRequest
            return

        self.stack.receivedRequest(self, request)

    # @implements RFC3261 P49L30-P50L27
    def sendResponse(self, response, responsetext=None, content=None, contentType=None, createDialog=True):
        if not self.request:
            raise ValueError, 'Invalid request in sending a response'
        if isinstance(response, int):
            response = self.createResponse(response, responsetext, content, contentType)
        if createDialog and self.canCreateDialog(self.request, response):
            if self.request['Record-Route']: response['Record-Route'] = self.request['Record-Route']
            if not response.Contact:
                contact = Address(str(self.contact))
                if not contact.uri.user: contact.uri.user = self.request.To.value.uri.user
                contact.uri.secure = self.secure
                response.Contact = Header(str(contact), 'Contact')
            dialog = Dialog.createServer(self.stack, self.request, response, self.transaction)
            self.stack.dialogCreated(dialog, self)
            self.stack.sending(dialog, response)
        else:
            self.stack.sending(self, response)

        if not self.transaction: # send on transport
            self.stack.send(response, response.first('Via').viaUri.hostPort)
        else:
            self.transaction.sendResponse(response)

    def createResponse(self, response, responsetext, content=None, contentType=None):
        if not self.request:
            raise ValueError, 'Invalid request in creating a response'
        response = Message.createResponse(response, responsetext, None, content, self.request)
        if contentType: response['Content-Type'] = Header(contentType, 'Content-Type')
        if response.response != 100 and 'tag' not in response.To: response.To['tag'] = self.localTag
        return response;

    # @implements RFC3261 P53L11-P55L48
    def sendCancel(self):
        '''Cancel a request.'''
        if not self.transaction:
            raise ValueError, 'No transaction for sending CANCEL'

        self.cancelRequest = self.transaction.createCancel()
        if self.transaction.state != 'trying' and self.transaction.state != 'calling':
            if self.transaction.state == 'proceeding':
                transaction = Transaction.createClient(self.stack, self, self.cancelRequest, self.transaction.transport, self.transaction.remote)
            self.cancelRequest = None
        # else don't send until 1xx is received

    def timeout(self, transaction):
        '''A client transaction was timedout.'''
        if transaction and transaction != self.transaction: # invalid transaction
            if _debug: print 'invalid transaction in timeout() %r != %r'%(transaction, self.transaction)
            return
        self.transaction = None
        if not self.server: # UAC
            if self.remoteCandidates and len(self.remoteCandidates)>0:
                self.retryNextCandidate()
            else:
                self.receivedResponse(None, Message.createResponse(408, 'Request timeout', None, None, self.request))

    def error(self, transaction, error):
        '''A transaction gave transport error.'''
        if transaction and transaction != self.transaction: # invalid transaction
            return
        self.transaction = None
        if not self.server: # UAC
            if self.remoteCandidates and len(self.remoteCandidates)>0:
                self.retryNextCandidate()
            else:
                self.receivedResponse(None, Message.createResponse(503, 'Service unavailable - ' + error, None, None, self.request))

    def authenticate(self, response, transaction):
        '''Whether we can supply the credentials locally to authenticate or not?
        If we can, then re-send the request in new transaction and return true, else return false'''
        a = response.first('WWW-Authenticate') or response.first('Proxy-Authenticate') or None
        if not a:
            return False
        request = Message(str(transaction.request)) # construct a new message

        resend, present = False, False
        for b in request.all('Authorization', 'Proxy-Authorization'):
            if a.realm == b.realm and (a.name == 'WWW-Authenticate' and b.name == 'Authorization' or a.name == 'Proxy-Authenticate' and b.name == 'Proxy-Authorization'):
                present = True
                break

        if not present and 'realm' in a: # prompt for password
            result = self.stack.authenticate(self, a)
            if not result or 'password' not in a and 'hashValue' not in a:
                return False
            # TODO: hashValue is not used
            value = createAuthorization(a.value, a.username, a.password, str(request.uri), self.request.method, self.request.body, self.auth)
            if value:
                request.insert(Header(value, (a.name == 'WWW-Authenticate') and 'Authorization' or 'Proxy-Authorization'), True)
                resend = True

        if resend:
            self.localSeq = self.localSeq + 1
            request.CSeq = Header(str(self.localSeq) + ' ' + request.method, 'CSeq')
            request.first('Via').branch = Transaction.createBranch(request, False)
            self.request = request
            self.transaction = Transaction.createClient(self.stack, self, self.request, self.transaction.transport, self.transaction.remote)
            return True
        else:
            return False;

# @implements RFC3261 P69L23-P70L18
class Dialog(UserAgent):
    '''A SIP dialog'''
    # @implements RFC3261 P70L20-P71L39
    @staticmethod
    def createServer(stack, request, response, transaction):
        '''Create a dialog from UAS while sending response to request in the transaction.'''
        d = Dialog(stack, request, True)
        d.request = request
        d.routeSet = request.all('Record-Route') if request['Record-Route'] else None
        while d.routeSet and isMulticast(d.routeSet[0].value.uri.host): # remove any multicast address from top of the list.
            if _debug: print 'deleting top multicast routeSet', d.routeSet[0]
            del d.routeSet[0]
            if len(d.routeSet) == 0: d.routeSet = None
        d.secure = request.uri.secure
        d.localSeq, d.remoteSeq = 0, request.CSeq.number
        d.callId = request['Call-ID'].value
        d.localTag, d.remoteTag = response.To['tag'] or '', request.From['tag'] or ''
        d.localParty, d.remoteParty = Address(str(request.To.value)), Address(str(request.From.value))
        if _debug: print 'request contact', request.Contact
        if request.Contact: d.remoteTarget = URI(str(request.first('Contact').value.uri))
        # TODO: retransmission timer for 2xx in UAC
        stack.dialogs[d.id] = d
        return d

    # @implements RFC3261 P71L41-P72L31
    @staticmethod
    def createClient(stack, request, response, transaction):
        '''Create a dialog from UAC on receiving response to request in the transaction.'''
        d = Dialog(stack, request, False)
        d.request = request
        d.routeSet = [x for x in reversed(response.all('Record-Route'))] if response['Record-Route'] else None
        #print 'UAC routeSet=', d.routeSet
        d.secure = request.uri.secure
        d.localSeq, d.remoteSeq = request.CSeq.number, 0
        d.callId = request['Call-ID'].value
        d.localTag, d.remoteTag = request.From['tag'] or '', response.To['tag'] or ''
        d.localParty, d.remoteParty = Address(str(request.From.value)), Address(str(request.To.value))
        if response.Contact: d.remoteTarget = URI(str(response.first("Contact").value.uri))
        stack.dialogs[d.id] = d
        return d

    @staticmethod
    def extractId(m):
        '''Extract dialog identifier string from a Message m.'''
        return m['Call-ID'].value + '|' + (m.To['tag'] if m.method else m.From['tag']) + '|' + (m.From['tag'] if m.method else m.To['tag'])

    def __init__(self, stack, request, server, transaction=None):
        '''Create a dialog for the request in server (True) or client (False) mode for given transaction.'''
        UserAgent.__init__(self, stack, request, server) # base class method
        self.servers, self.clients = [], [] # pending server and client transactions
        self._id = None
        if transaction: transaction.app = self # this is higher layer of transaction

    def close(self):
        if self.stack:
            if self.id in self.stack.dialogs: del self.stack.dialogs[self.id]
            # self.stack = None # TODO: uncomment this to clear reference, but then it causes problem in receivedResponse where self.stack becomes None

    @property
    def id(self):
        '''Dialog identifier string.'''
        if not self._id: self._id = self.callId + '|' + self.localTag + '|' + self.remoteTag
        return self._id

    # @implements RFC3261 P73L12-P75L29
    def createRequest(self, method, content=None, contentType=None):
        '''Create a new SIP request in this dialog.'''
        request = UserAgent.createRequest(self, method, content, contentType)
        if self.remoteTag: request.To.tag = self.remoteTag
        if self.routeSet and len(self.routeSet)>0 and 'lr' not in self.routeSet[0].value.uri.param: # strict route
            request.uri = self.routeSet[0].value.uri.dup()
            if 'lr' in request.uri.param:
                del request.uri.param['lr']
        return request

    def createResponse(self, response, responsetext, content=None, contentType=None):
        '''Create a new SIP response in this dialog'''
        if len(self.servers) == 0: raise ValueError, 'No server transaction to create response'
        request = self.servers[0].request
        response = Message.createResponse(response, responsetext, None, content, request)
        if contentType: response['Content-Type'] = Header(contentType, 'Content-Type')
        if response.response != 100 and 'tag' not in response.To:
            response.To.tag = self.localTag
        return response

    def sendResponse(self, response, responsetext=None, content=None, contentType=None, createDialog=True):
        '''Send a new response in this dialog for first pending server transaction.'''
        if len(self.servers) == 0: raise ValueError, 'No server transaction to send response'
        self.transaction, self.request = self.servers[0], self.servers[0].request
        UserAgent.sendResponse(self, response, responsetext, content, contentType, False)
        code = response if isinstance(response, int) else response.response
        if code >= 200:
            self.servers.pop(0) # no more pending if final response sent

    def sendCancel(self):
        '''Send a CANCEL request for the first pending client transaction.'''
        if len(self.clients) == 0:
            if _debug: print 'No client transaction to send cancel'
            return
        self.transaction, self.request = self.clients[0], self.clients[0].request
        UserAgent.sendCancel(self)

    # @implements RFC3261 P76L10-P77L28
    def receivedRequest(self, transaction, request):
        '''Incoming request in the dialog.'''
        if self.remoteSeq != 0 and request.CSeq.number < self.remoteSeq:
            if _debug: print 'Dialog.receivedRequest() CSeq is old', request.CSeq.number, '<', self.remoteSeq
            self.sendResponse(500, 'Internal server error - invalid CSeq')
            return
        self.remoteSeq = request.CSeq.number

        if request.method == 'INVITE' and request.Contact:
            self.remoteTarget = request.first('Contact').value.uri.dup()

        if request.method == 'ACK' or request.method == 'CANCEL':
            self.servers = filter(lambda x: x != transaction, self.servers) # remove from pending
            if request.method == 'ACK':
                self.stack.receivedRequest(self, request)
            else:
                self.stack.cancelled(self, transaction.request)
            return

        self.servers.append(transaction) # make it pending
        self.stack.receivedRequest(self, request)

    # @implements RFC3261 P75L30-P76L8
    def receivedResponse(self, transaction, response):
        '''Incoming response in a dialog.'''
        if response.is2xx and response.Contact and transaction and transaction.request.method == 'INVITE':
            self.remoteTarget = response.first('Contact').value.uri.dup()
        if not response.is1xx: # final response
            self.clients = filter(lambda x: x != transaction, self.clients) # remove from pending

        if response.response == 408 or response.response == 481: # remote doesn't recognize the dialog
            self.close()

        if response.response == 401 or response.response == 407:
            if not self.authenticate(response, transaction):
                self.stack.receivedResponse(self, response)
        elif transaction:
            self.stack.receivedResponse(self, response)

        if self.autoack and response.is2xx and (transaction and transaction.request.method == 'INVITE' or response.CSeq.method == 'INVITE'):
            self.sendRequest(self.createRequest('ACK'))

#---------------------------Proxy-------------------------------------------

# @implements RFC3261 P91L32-P124L24
class Proxy(UserAgent):
    '''Extends UserAgent to represents a stateless and stateful proxy. The base object represents original UAS.'''
    def __init__(self, stack, request=None, server=None):
        '''Construct as Proxy UAS for the incoming request.'''
        if request is None: raise ValueError('Cannot create Proxy without incoming request')
        UserAgent.__init__(self, stack, request, server)
        self.branches = [] # all the client branches containing Transaction objects

    def createTransaction(self, request):
        '''Delay the creation of transaction when sendResponse or sendRequest is invoked.'''
        self.receivedRequest(None, request) # don't create a transaction, but just invoke the callback
        return None

    def receivedRequest(self, transaction, request):
        '''New incoming request. Transaction may be empty at this point.'''
        if transaction and self.transaction and transaction != self.transaction and request.method != 'CANCEL':
            raise ValueError, 'Invalid transaction for received request'
        self.server = True # this becomes a UAS
        # 16.3 request validation
        if request.uri.scheme not in ['sip', 'sips']:
            self.sendResponse(416, 'Unsupported URI scheme')
            return
        if request['Max-Forwards'] and int(request.first('Max-Forwards').value) < 0:
            self.sendResponse(483, 'Too many hops')
            return
        if 'tag' not in request.To and transaction is not None: # out of dialog request
            if self.stack.findOtherTransaction(request, transaction): # request merging?
                self.sendResponse(482, "Loop detected - found another transaction")
                return
        if request['Proxy-Require']: # TODO let the application handle Require header
            if request.method != 'CANCEL' and request.method != 'ACK':
                response = self.createResponse(420, 'Bad extension')
                response.Unsupported = Header(str(request['Proxy-Require'].value), 'Unsupported')
                self.sendResponse(response)
                return

        if transaction: self.transaction = transaction # store it

        if request.method == 'CANCEL':
            branch = request.first('Via').branch if request.Via != None and 'branch' in request.first('Via') else Transaction.createBranch(request, True)
            original = self.stack.findTransaction(Transaction.createId(branch, 'INVITE'))
            if original:
                if original.state == 'proceeding' or original.state == 'trying':
                    original.sendResponse(original.createResponse(487, 'Request terminated'))
                transaction = Transaction.createServer(self.stack, self, request, self.stack.transport, self.stack.tag, start=False)
                transaction.sendResponse(transaction.createResponse(200, 'OK'))
            self.sendCancel()
            return
            # TODO: the To tag must be same in the two responses

        # 16.4 route information processing
        if not request.uri.user and self.isLocal(request.uri) and 'lr' in request.uri.param and request.Route:
            lastRoute = request.all('Route')[-1]; request.delete('Route', position=-1)
            request.uri = lastRoute.value.uri
        #if 'maddr' in request.uri.param: TODO: handle this case
        if request.Route and self.isLocal(request.first('Route').value.uri):
            request.delete('Route', position=0) # delete first Route header
            request.had_lr = True               # mark it so that a proxy can decide whether to open relay or not

        self.stack.receivedRequest(self, request)

    def isLocal(self, uri):
        '''Check whether the give uri represents local address (host:port) ?'''
        return (self.stack.transport.host == uri.host or uri.host in ('localhost', '127.0.0.1')) and (self.stack.transport.port == uri.port or not uri.port and self.stack.transport.port == 5060) # TODO: what about 5061 for sips

    def sendResponse(self, response, responsetext=None, content=None, contentType=None, createDialog=True):
        '''Invoke the base class to send a response to original UAS. Create a transaction beforehand if needed.'''
        if not self.transaction: # create a transaction if doesn't exist
            self.transaction = Transaction.createServer(self.stack, self, self.request, self.stack.transport, self.stack.tag, start=False)
        UserAgent.sendResponse(self, response, responsetext, content, contentType, False) # never create dialog

    def createRequest(self, method, dest, stateless=False, recordRoute=False, headers=(), route=()):
        '''Create a proxied request from the original request, using destination (host, port). Additional arguments
        modify how the proxied request is generated. The caller must invoke sendRequest to send the returned request.'''
        if method != self.request.method: raise ValueError('method in createRequest must be same as original UAS for proxy')
        request = self.request.dup() # so that original is not modified
        if not stateless and not self.transaction: # need to create a transaction
            self.transaction = Transaction.createServer(self.stack, self, self.request, self.stack.transport, self.stack.tag, start=False)
        if isinstance(dest, Address): request.uri = dest.uri.dup()
        elif isinstance(dest, tuple): request.uri = URI(request.uri.scheme + ':' + request.uri.user + '@' + dest[0] + ':' + str(dest[1]))
        else: request.uri = dest.dup() # so that original is not modified

        request['Max-Forwards'] = Header(str(int(request.first('Max-Forwards').value)-1) if request['Max-Forwards'] else '70', 'Max-Forwards')
        if recordRoute:
            rr = Address(str(self.stack.uri))
            rr.uri.param['lr'] = None
            rr.mustQuote = True
            # TODO: take care of sips URI
            request.insert(Header(str(rr), 'Record-Route'))
        for h in headers: request.insert(h, append=True) # insert additional headers
        for h in reversed(route): request.insert(h, append=False) # insert the routes
        Via = self.stack.createVia(self.secure)
        Via.branch = Transaction.createProxyBranch(request, False)
        request.insert(Via)
        return request

    def sendRequest(self, request):
        '''Proxy a request in a new client transaction.'''
        if not request.Route: target = request.uri
        else:
            routes = request.all('Route')
            if len(routes) > 0:
                target = routes[0].value.uri
                if not target or 'lr' not in target.param: # strict route
                    if _debug: print 'strict route target=', target, 'routes=', routes
                    del routes[0] # ignore first route
                    if len(routes) > 0:
                        if _debug: print 'appending our route'
                        routes.append(Header(str(request.uri), 'Route'))
                    request.Route = routes
                    request.uri = target;

        self.stack.sending(self, request)

        class Branch(object):
            __slots__ = ('request', 'response', 'remoteCandidates', 'transaction', 'cancelRequest')
            def __init__(self): self.request = self.response = self.remoteCandidates = self.transaction = self.cancelRequest = None
        branch = Branch()

        # TODO: replace the following with RFC3263 to return multiple candidates. Add TCP and UDP and if possible TLS.
        dest = target.dup()
        dest.port = target.port or target.secure and 5061 or 5060
        if not isIPv4(dest.host):
            try: dest.host = gethostbyname(dest.host)
            except: pass
        if isIPv4(dest.host):
            branch.remoteCandidates = [dest]

        # continue processing as if we received multiple candidates
        if not branch.remoteCandidates or len(branch.remoteCandidates) == 0:
            self.error(None, 'cannot resolve DNS target')
            return
        target = branch.remoteCandidates.pop(0)
        if request.method != 'ACK':
            # start a client transaction to send the request
            branch.transaction = Transaction.createClient(self.stack, self, request, self.stack.transport, target.hostPort)
            branch.request = request
            self.branches.append(branch)
        else: # directly send ACK on transport layer
            self.stack.send(request, target.hostPort)

    def retryNextCandidate(self, branch):
        '''Retry next DNS resolved address.'''
        if not branch.remoteCandidates or len(branch.remoteCandidates) == 0:
            raise ValueError, 'No more DNS resolved address to try'
        target = URI(branch.remoteCandiates.pop(0))
        branch.request.first('Via').branch += 'A' # so that we create a different new transaction
        branch.transaction = Transaction.createClient(self.stack, self, branch.request, self.stack.transport, target.hostPort)

    def getBranch(self, transaction):
        for branch in self.branches:
            if branch.transaction == transaction: return branch
        return None

    def receivedResponse(self, transaction, response):
        '''Received a new response from the transaction.'''
        branch = self.getBranch(transaction)
        if not branch:
            if _debug: print 'Invalid transaction received %r'%(transaction)
            return
        if response.is1xx and branch.cancelRequest:
            cancel = Transaction.createClient(self.stack, self, branch.cancelRequest, transaction.transport, transaction.remote)
            branch.cancelRequest = None
        else:
            if response.isfinal:
                branch.response = response
                # TODO: self.stack.receivedResponse(self, response)
                self.sendResponseIfPossible()
            else:
                response.delete('Via', position=0)
                self.sendResponse(response)

    def sendResponseIfPossible(self):
        branches = filter(lambda x: x.response and x.response.isfinal, self.branches)
        branches2xx = filter(lambda x: x.response.is2xx, branches)
        if _debug: print 'received %d responses out of %d'%(len(branches), len(self.branches))
        response = None
        if branches2xx: response = branches[0].response
        elif len(branches) == len(self.branches): response = branches[0].response # TODO select best instead of first
        if response:
            self.branches[:] = [] # clear the list so that no more responses are accepted.
            response.delete('Via', position=0) # remove topmost Via header
            self.sendResponse(response)

    def sendCancel(self):
        '''Cancel a request.'''
        for branch in self.branches:
            branch.cancelRequest = branch.transaction.createCancel()
            if branch.transaction.state != 'trying' and branch.transaction.state != 'calling':
                if branch.transaction.state == 'proceeding':
                    transaction = Transaction.createClient(self.stack, self, branch.cancelRequest, branch.transaction.transport, branch.transaction.remote)
                branch.cancelRequest = None
            # else don't send until 1xx is received

    def timeout(self, transaction):
        '''A client transaction was timedout.'''
        branch = self.getBranch(transaction)
        if not branch:  return # invalid transaction
        branch.transaction = None
        if branch.remoteCandidates and len(branch.remoteCandidates)>0:
            self.retryNextCandidate(branch)
        else:
            self.receivedResponse(None, Message.createResponse(408, 'Request timeout', None, None, branch.request))

    def error(self, transaction, error):
        '''A transaction gave transport error.'''
        if transaction is None:
            self.transaction = None
            if self.request.method != 'ACK':
                response = Message.createResponse(503, 'Service unavailable - ' + error, None, None, self.request)
                return self.sendResponse(response)
            else:
                if _debug: print 'warning: dropping ACK:', error
        branch = self.getBranch(transaction)
        if not branch:  return # invalid transaction
        self.transaction = None
        branch.transaction = None
        if branch.remoteCandidates and len(branch.remoteCandidates)>0:
            self.retryNextCandidate(branch)
        else:
            self.receivedResponse(None, Message.createResponse(503, 'Service unavailable - ' + error, None, None, branch.request))


#--------------------------- Testing --------------------------------------
if __name__ == '__main__':
    import doctest
    doctest.testmod()
