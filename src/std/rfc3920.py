# Copyright (c) 2007-2008, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3920 (XMPP core for client)

import time, sys, re, socket, select, base64, md5, multitask, traceback, random
from xml.parsers import expat

if __name__ == '__main__': sys.path.append('../external')
from simplexml import XML, XMLList, parser
import dns, rfc3263, kutil

_debug = False

# This is used as decorator to define a property.
def Property(func): return property(doc=func.__doc__, **func())

# a generator function calls succeed, fail or respond to return a response
def succeed(result): raise StopIteration, (result, None)
def fail(error): raise StopIteration, (None, error)
def respond(*args): raise StopIteration, tuple(args) if len(args) != 1 else args

F = lambda x: x and x[0] or None # return first of a list or None if empty
_quote   = lambda s: '"' + s + '"' if s[0] != '"' != s[-1] else s # quote a string if needed
_unquote = lambda s: s[1:-1] if s[0] == '"' == s[-1] else s # unquote a string is possible

#-----------------------------------------------------------------------------
# Basic Data Structures
#-----------------------------------------------------------------------------

class JID(str):
    '''Jabber ID is basically a string of the form user@domain/resource, where user and resource are optional.
    >>> j1 = JID('kundan@example.net/32'); j2 = JID('kundan@example.net')
    >>> print j1, j2, j1.bareJID, j1.bareJID == j2.bareJID
    kundan@example.net/32 kundan@example.net kundan@example.net True
    >>> print j1.user == j2.user == 'kundan', j1.domain == j2.domain == 'example.net', j2.resource is None, j1.resource == '32'
    True True True True
    >>> try: j3 = JID('user@example.net/32/32')
    ... except ValueError, e: print 'exception', e
    exception Invalid JID(user@example.net/32/32)
    '''
    _syntax = re.compile('^(?:(?P<user>[^@/]*)@)?(?P<domain>[^/]*)(?:/(?P<resource>[^/]*))?$')
    def __new__(cls, value=''):
        m = JID._syntax.match(value)
        if not m: raise ValueError, 'Invalid JID(' + value + ')'
        obj = str.__new__(cls, value)
        obj.user, obj.domain, obj.resource = m.groups()
        obj.bareJID = obj if obj.resource is None else '%s@%s'%(obj.user, obj.domain)
        return obj
    def __eq__(self, other): # compares even if the resource is missing in one
        if str.__eq__(self, other): return True
        if isinstance(other, JID): other = JID
        if self.resource is not None and other.resource is not None: return False
        else: return str.__eq__(self.bareJID, other.bareJID)

class Stanza(XML):
    '''A stanza to be used in message, iq, presence or any other extension in XMPP. The named attributes are to, from, type, 
    and from base class tag, xmlns, attrs, children, elems, cdata, and various forms of access using attribute, container, opertors.'''
    def __init__(self, value=None, **kwargs):
        '''Supply the attributes such as tag, to, frm, type, xmlns, timestamp, etc., as named arguments.'''
        XML.__init__(self, value=value); 
        if not value and 'tag' not in kwargs: self.tag = 'stanza'
        for k,v in kwargs.iteritems(): self.__setattr__(k, str(v)) #should include tag, to, frm, type, timestamp, xmlns
                
    def __setattr__(self, key, value):
        if key in ('to', 'frm', 'type', 'id'): self.attrs[key if key is not 'frm' else 'from'] = str(value) if value is not None else None
        else: XML.__setattr__(self, key, value)
    def __delattr__(self, key):
        if key in ('to', 'frm', 'type', 'id'): del self.attrs[key if key is not 'frm' else 'from']
        else: XML.__delattr__(self, key)
    def __getattribute__(self, key):
        if key in ('to', 'frm'): return JID(self.attrs.get(key if key is not 'frm' else 'from', ''))
        elif key in ('type', 'id'): return self.attrs.get(key, None)
        else: return XML.__getattribute__(self, key)
        
    @Property
    def timestamp():
        '''Get as XML. Set as XML or date-time string or None (to use current date-time)'''
        def fget(self): return F(self('x'))
        def fset(self, value):
            elem = isinstance(value, XML) and value or XML(tag='x', xmlns='nsdelay', attrs={'stamp': value if value else time.strftime('%Y%m%dT%H:%M:%S', time.gmtime())})  
            self.children |= elem
            return elem
        def fdel(self): del self.children['x']
        return locals()
    
    @Property
    def error():
        '''Get as XML. Set as XML or dict(type='mytype', condition='mycondition', xmlns='myxmlns', text='my text')'''
        def fget(self): return F(self('error')) if self.type == 'error' else None
        def fset(self, value): 
            self.type = 'error'
            if isinstance(value, XML): elem = value
            elif isinstance(value, dict): 
                elem = XML(tag='error', attrs=dict(type=value.get('type','error')))
                elem.children += XML(tag=value.get('condition', 'condition'), xmlns=value.get('xmlns', 'urn:ietf:params:xml:ns:xmpp-stanzas'))
                if 'text' in value: elem.children += XML(tag='text', xmlns=value.get('xmlns', 'urn:ietf:params:xml:ns:xmpp-stanzas'), children=[value.get('text')])
            else: elem = XML(tag='error', attrs=dict(type=str(value)))
            self.children |= elem
            return elem
        def fdel(self):
            if self.type == 'error': del self.type
            del self.children['error']
        return locals()
    
    @property
    def properties():
        '''set of xmlns of children elements'''
        return set(map(lambda y: y.xmlns, filter(lambda x: x.xmlns is not None, self())))

#-----------------------------------------------------------------------------
# Client Connection
#-----------------------------------------------------------------------------

class Connection(object):
    '''Main XMPP client to server connection handling. Important attributes include server, proxy, secure, srv. The server attribute is a (host, port)
    tuple. The proxy attribute can be a (host, port) or (host, port, user, password) tuple. The secure and srv boolean attributes indicate whether to
    use secure TLS connection and DNS SRV lookup, or not? 
        If secure is True then it starts TLS from begining before any feature negotiation,
        else if secure is False then it never uses TLS either in begining or after features negotiation (which may result in failure if server requires it),
        else if secure is None then if port is 5223 or 443 it uses TLS from begining else it uses TLS if server requires it on features negotiation,
        else if secure is '' then it uses TLS if server supports it after features negotiation.'''
    def __init__(self, **kwargs): 
        self.__dict__.update(kwargs)
        self.connected, self._sock, self._lastID, self.jid, self._handler = False, None, 0, JID(), kutil.Dispatcher()
    
    def __getattr__(self, name): return None # don't throw exception if not found
    
    def connect(self): 
        '''Generator to connect a stream. returns either (type, None) or (None, error), where type is None, xmpp-tcp, xmpp-tls, jabber-tcp, or jabber-tls'''
        if self.connected: fail('already connected')
        self._connect()                                          # attempt a connection
        if not self.connected: fail('cannot connect to ' + self.server) # if failed, return
        self.sout, self.sin = StreamOut(self._sock, self.server[0]), StreamIn(self._sock, self._handler) # output and input streams
        yield self.sout.open(True)                               # send out stream element
        self.stream = stream = yield self.sin.get()             # incoming stream element
        if not stream or stream.tag == 'error': yield self.disconnect(); fail(stream or 'server didnot send stream') # server closed stream or didn't send
        if not stream._.version: succeed('jabber-tls' if isinstance(self._sock, TLS) else 'jabber-tcp')  # if version is missing in stream tag
        
        self.features = yield self.sin.get()                    # assuming next element will be features
        if not self.features or self.features.tag != 'features': fail(self.features or 'server didnot send features')
        if isinstance(self._sock, TLS): succeed('xmpp-tls')       # already done TLS
        starttls = 'none' if not self.features('starttls') else 'required' if self.features('starttls')('required') else 'optional'
        if starttls == 'none' or starttls == 'optional' and self.secure != '': succeed('xmpp-tcp')
        elif starttls == 'required' and self.secure == False: yield self.disconnect(); fail('server requires TLS')
        
        if _debug: print 'starting TLS'
        yield self.sout.put(XML(tag='starttls', xmlns='urn:ietf:params:xml:ns:xmpp-tls'))
        result = yield self.sin.get() # proceed or failure or None
        if not result or result.tag != 'proceed' or result.xmlns != 'urn:ietf:params:xml:ns:xmpp-tls':
            if not result and result.tag == 'failure': self._sock.close()
            fail(result or 'failed to start TLS')
        
        yield self.sin.close()
        self._sock = TLS(self._sock)
        self.sout, self.sin = StreamOut(self._sock, self.server[0]), StreamIn(self._sock, self._handler) # new child stream for TLS
        yield self.sout.open()                                   # send out stream element
        self.stream = stream = yield self.sin.get()             # incoming stream element
        if not self.stream or self.stream.tag != 'stream': 
            self.disconnect(); fail(self.stream or 'server didnot send stream')
        self.features = yield self.sin.get()                    # features for new stream
        if not self.features or self.features.tag != 'features':
            self.disconnect(); fail(self.features or 'server didnot send features')
            
        succeed('xmpp-tls')
    
    def disconnect(self):
        if self.sout is not None: yield self.sout.close(); self.sout = None
        if self.sin is not None: yield self.sin.close(); self.sin = None
        if self._sock is not None: self._sock.close(); self._sock = None; self.connected = False
        
    def authenticate(self): return authenticate(self) # map it to module function
    def bind(self): return bind(self) # map it to module function too
    
    def nextId(self, type='iq'): return 'id_%s_%d'%(type, ++self._lastID)
    
    def iq(self, msg, type='get', id=None): 
        '''Generator to do request/response of an IQ'''
        id = id or self.nextId('iq')
        stanza = Stanza(tag='iq', type=type, id=id)
        stanza.children += msg
        yield self.put(stanza)
        response = yield self.get(lambda x: not x or x.tag == 'iq' and x.id == id)
        respond(response and (response.type, response.children) or ('error', None))
    
    def message(self, filter=None):
        '''Generator to return the next message Stanza, or None on termination''' 
        response = yield self.get(lambda x: not x or x.tag == 'message' and (not filter or filter(x)))
        respond(response and Stanza(response))
        
    def presence(self, filter=None):
        '''Generator to return the next presence Stanza, or None on termination'''
        response = yield self.get(lambda x: not x or x.tag == 'presence' and (not filter or filter(x)))
        respond(response and Stanza(response))
        
    def put(self, msg, **kwargs): 
        if self.sout is not None: yield self.sout.put(msg, **kwargs)
        
    def get(self, criteria=None, **kwargs): 
        return self.sin.get(criteria=criteria, **kwargs) if self.sin is not None else None
    
    def attach(self, event, func): self._handler.attach(event, func)
    def detach(self, event, func): self._handler.detach(event, func)
    def dispatch(self, data): self._handler.dispatch(data)
    
    def _resolve(self, server, service='xmpp-client', protocol='tcp'): # resolve using DNS SRV for _xmpp-client._tcp.<server> and return (host, port)
        return map(lambda y: (y[0], y[3]), sorted([(x['RDATA']['DOMAIN'].lower(), x['RDATA']['PRIORITY'], x['RDATA']['WEIGHT'], x['RDATA']['PORT']) for x in rfc3263._query(('_%s._%s.%s'%(service, protocol, server[0]), dns.T_SRV))], lambda a,b: a[1]-b[1])) or [server]

    def _connect(self): # internal methods to DNS SRV and connect.
        if not isinstance(self.server, tuple): 
            self.server = (self.server, self.port or self.secure and 5223 or 5222) # if server is just host name, add a port
        for server in (self.proxy and [self.proxy[:2]] or self._resolve(self.server)):
            try: 
                if _debug: print 'connect', server
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.connect(server)
                if self.secure == True or self.secure is None and server[1] in (5223, 443): self._sock = TLS(self._sock)
                self.connected = True
                break
            except socket.error, e:
                if _debug: print 'connect socket.error', e
                if self._sock: self._sock.close() 
                continue
    
class TLS(object):
    '''Secure connection using transport layer security (TLS).'''
    def __init__(self, sock): self._sock = sock; self.ssl = ssl = socket.ssl(sock)
    def fileno(self): return self._sock.fileno()
    def recv(self, size, flags=0): return self.ssl.read(size)
    def send(self, buf, flags=0): self.ssl.write(buf)
    def close(self): self._sock.close()
    
class StreamOut(object):
    '''Output stream to send out XML stanza within a stream.'''
    def __init__(self, sock, server): self._sock, self.decl, self.opening, self.closing = sock, '<?xml version="1.0" encoding="UTF-8"?>','<stream:stream to="%s" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0">'%(server), '</stream:stream>'
    def open(self, first=False): yield self.put((first and self.decl or '') + self.opening)
    def close(self): yield self.put(self.closing)
    def put(self, data, **kwargs):
        raw = unicode(data).encode('utf-8')
        if _debug: print 'SEND: ' + raw
        try: yield multitask.send(self._sock, raw, **kwargs)
        except Exception, e: print 'send error', e
    
class StreamIn(parser):
    '''Input stream to parse incoming XML stanza.'''
    def __init__(self, sock, handler):
        super(StreamIn, self).__init__()
        self._sock, self._handler, self.stream, self._queue = sock, handler, None, multitask.SmartQueue()
        self._gen = self._run(); multitask.add(self._gen)
        
    def get(self, criteria=None, **kwargs):
        if self._queue is not None: item = yield self._queue.get(criteria=criteria, **kwargs)
        else: item = None
        respond(item)
    
    def close(self):
        if self._gen: self._gen.close()
        self._sock = self._handler = self.stream = self._queue = self._gen = None
        yield self.get(lambda x: not x or x.tag == 'closed') 
        if _debug: print 'closing stream-in'
        
    def _put(self, msg, **kwargs):
        if isinstance(self._handler, kutil.Dispatcher): self._handler.dispatch(msg) # trigger the event first
        yield self._queue.put(msg, **kwargs)
    
    def _run(self):
        try:
            while True:
                try:
#                    data = yield multitask.recv(self._sock, 1024)
                    try:
                        sock = self._sock
                        yield multitask.readable(sock.fileno(), timeout=5)
                        data = sock.recv(1024)
                    except multitask.Timeout: continue
                        # No data after 5 seconds

                    if _debug: print 'RECV: ' + data
                    if not data: raise socket.error, 'connection closed'
                    self.update(data)
                except expat.ExpatError, e:
                    if _debug: print 'parse error', e
                except socket.sslerror,e:
                    if _debug: print 'sslerror', e
                    if e[0]==socket.SSL_ERROR_WANT_READ or e[0]==socket.SSL_ERROR_WANT_WRITE: pass
                    raise socket.sslerror, e
        except (GeneratorExit, StopIteration), e: 
            if _debug: print 'exception', type(e), e 
        except Exception, e: 
            # print 'exception', (traceback and traceback.print_exc() or None)
            if _debug: print 'stream-in exception', e
            yield self._put(None)
            self.stream = self._sock = None
        def closed(): 
            if self._queue is not None: yield self._queue.put(XML(tag='closed'))
        multitask.add(closed())
        
    def _StartElementHandler(self, tag, attrs):
        super(StreamIn, self)._StartElementHandler(tag, attrs)
        if self.stream is None and self.xml.tag == 'stream' and self.xml.xmlns == 'http://etherx.jabber.org/streams': 
            self.stream = self.xml; multitask.add(self._put(self.stream))
    def _EndElementHandler(self, tag):
        super(StreamIn, self)._EndElementHandler(tag)
        if self._depth == 1:   # second-level element within stream 
            elem = self.xml.children.pop();  multitask.add(self._put(elem))
        elif self._depth == 0: self._sock.close()  # top-level stream is ended. this will cause the run() loop to exit

#------------------------------------------------------------------------------
# Authentication        
#------------------------------------------------------------------------------

def authenticate(self):
    '''Authenticate the stream, and return either (mechanism, None) or (None, error).'''
    if not self.stream._.version: fail(self.stream or 'no version in stream') # SASL is not supported 
    mechanisms = [x.cdata for x in self.features(lambda x: x.tag == 'mechanisms' and x.xmlns == 'urn:ietf:params:xml:ns:xmpp-sasl')()]
    xml = XML(tag='auth', xmlns='urn:ietf:params:xml:ns:xmpp-sasl')
    if 'DIGEST-MD5' in mechanisms:
        xml._.mechanism = 'DIGEST-MD5'
    elif 'PLAIN' in mechanisms:
        xml._.mechanism = 'PLAIN'
        data = '%s@%s\x00%s\x00%s'%(self.username, self.server[0], self.username, self.password)
        xml.children += base64.encodestring(data)
    else: fail('cannot authenticate using ' + str(mechanisms))
    yield self.put(xml)
    challenge = yield self.get()
    if not challenge or challenge.tag == 'failure' or challenge.xmlns != 'urn:ietf:params:xml:ns:xmpp-sasl': 
        fail(challenge or 'server didnot send challenge')
    elif challenge.tag != 'success' and challenge.tag != 'challenge':
        fail(challenge or 'expected a challenge')
    elif challenge.tag == 'challenge':
        data = base64.decodestring(challenge.cdata)
        data = dict([(y[0], _unquote(y[2])) for y in map(lambda x: x.partition('='), re.findall('(\w+=(?:"[^"]+")|(?:[^,]+))', data))])
        
        if 'auth' not in map(str.strip, data.get('qop','').split(',')):
            fail('no auth in qop to authenticate')
        
        res = dict(username=self.username, realm=self.server[0], nonce=data['nonce'], nc='00000001', qop='auth')
        res['cnonce'] = ''.join([hex(int(random.random()*65536*4096))[2:] for i in xrange(7)])
        res['digest-uri'] = 'xmpp/' + self.server[0]
        
        def HH(some): return md5.new(some).hexdigest()
        def H(some): return md5.new(some).digest()
        def C(some): return ':'.join(some)
        A1 = C([H(C([res['username'], res['realm'], self.password])), res['nonce'], res['cnonce']])
        A2 = C(['AUTHENTICATE', res['digest-uri']])
        res['response'] = HH(C([HH(A1), res['nonce'], res['nc'], res['cnonce'], res['qop'], HH(A2)]))
        res['charset'] = 'utf-8'
        data = ''.join(['%s=%s'%(k, res[k]) if k in ('nc', 'qop', 'response', 'charset') else '%s="%s"'%(k, res[k]) for k in 'charset username realm nonce nc cnonce digest-uri response qop'.split()]);
        xml = XML(tag='response', xmlns='urn:ietf:params:xml:ns:xmpp-sasl')
        xml.children += base64.encodestring(data.replace('\r', '').replace('\n', ''))
        yield self.put(xml)
    
        challenge = yield self.get()
        if not challenge or challenge.tag != 'challenge' or challenge.xmlns != 'urn:ietf:params:xml:ns:xmpp-sasl': 
            fail(challenge or 'server didnot send challenge')
        
        data = base64.decodestring(challenge.cdata)
        data = dict([(y[0], y[2][1:-1] if y[2][:1]=='"'==y[2][-1:] else y[2]) for y in map(lambda x: x.partition('='), re.findall('(\w+=(?:"[^"]+")|(?:[^,]+))', data))])
        
        if 'rspauth' not in data:
            fail(challenge or 'expecting rspauth in challenge')
        
        yield self.put(XML(tag='response', xmlns='urn:ietf:params:xml:ns:xmpp-sasl'))
        
        challenge = yield self.get()
        if not challenge or challenge.tag != 'succees':
            reason = F(challenge.children) if challenge and challenge.children else challenge
            fail(reason or 'authenticate failure')
    
    yield self.sin.close()
    self.sout = StreamOut(self._sock, self.server[0]) # new child stream for TLS
    self.sin = StreamIn(self._sock, self._handler)
    yield self.sout.open()                                   # send out stream element
    self.stream = stream = yield self.sin.get()             # incoming stream element
    if not self.stream or self.stream.tag != 'stream': 
        self.disconnect(); fail(self.stream or 'server didnot send stream')
    self.features = yield self.sin.get()                    # features for new stream
    if not self.features or self.features.tag != 'features':
        self.disconnect(); fail(self.features or 'server didnot send features')
    
    succeed(xml._.mechanism)

#------------------------------------------------------------------------------
# Resource Binding
#------------------------------------------------------------------------------

def bind(self, resource=None):
    if not self.features('bind'): fail('bind not present in features')
    bind = Stanza(tag='bind', xmlns='urn:ietf:params:xml:ns:xmpp-bind')
    if resource is not None: bind.children += XML(tag='resource', children=[resource]) 
    type, response = yield self.iq(type='set', msg=bind)
    if type == 'error' or type != 'result': fail(F(response['error']))
    bind = F(response['bind'])
    self.jid = JID(bind('jid').cdata) if bind else JID()
    self.resource = self.jid.resource
    if _debug: print 'bind jid=', self.jid, 'resource=', self.resource
    
    session = Stanza(tag='session', xmlns='urn:ietf:params:xml:ns:xmpp-session')
    type, response = yield self.iq(type='set', msg=session)
    self.session = type and True or False
    
    succeed(self.jid)

#------------------------------------------------------------------------------
# TESTING        
#------------------------------------------------------------------------------

def _testConn():
    #client = Connection(server='iptel.org', username='kundan', password='mypass')
    #client = Connection(server='iptel.org', proxy=('jabber.iptel.org', 5222), username='kundan', password='mypass')
    #client = Connection(server='iptel.org', proxy=('jabber.iptel.org', 5222), username='kundan', password='mypass', secure='')
    # TODO: change the following to include your credentials
    client = Connection(server='gmail.com', username='kundansingh99', password='mypass')
    
    type, error = yield client.connect()
    if error:  print 'MAIN: error=', error; respond()
    print 'MAIN: transport-type=', type
    mechanism, error = yield authenticate(client)
    if error: print 'MAIN: error=', error; respond()
    print 'MAIN: auth-mechanism=', mechanism
    jid, error = yield bind(client)
    if error: print 'MAIN: error=', error; respond()
    print 'MAIN: bind=', jid
    yield client.disconnect()
    print 'MAIN: exiting'

def _testClose(): yield multitask.sleep(5); exit()

if __name__ == '__main__':
    import doctest; doctest.testmod()    # first run doctest,
    for f in dir():      # then run all _test* functions
        if str(f).find('_test') == 0 and callable(eval(f)):
            multitask.add(globals()[f]())
    try: multitask.run()
    except KeyboardInterrupt: pass
    except select.error: print 'select error'; pass
    sys.exit()
