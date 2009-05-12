# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements draft-ietf-behave-rfc3489bis-10 (STUN)
# implements minimum necessary features (no auth and no TLS)

# @implements draft-ietf-behave-nat-behavior-discovery-01 (NAT behavior discovery) 
# implements only mapping and filtering detection, but not binding lifetime detection.

# @implements draft-rosenberg-midcom-turn-08 (TURN with modifications)


from __future__ import with_statement
from contextlib import closing
from kutil import getlocaladdr
import sys, traceback, struct, socket, multitask, random, time
try:
    from os import urandom # urandom returns random bytes (str) of given length
except:
    # use package random to implement urandom
    def urandom(count):
        import random
        return ''.join([chr(random.randint(0,255)) for x in range(count)])


_debug = False

defaultPort = 3478 # default port number to use
defaultServers = ['sip.iptel.org', 'stun.xten.net', 'stun2.wirlab.net'] # list of default known servers to use
defaultServers = [(x, defaultPort) for x in defaultServers] # update the list with port number to have list elements as (host, port)

# This is used as decorator to define a property.
def Property(func):
    return property(doc=func.__doc__, **func())

def _addr2str(value, family=socket.AF_INET):
    '''Convert bytes to dotted-decimal representation.'''
    return (family == socket.AF_INET) and '.'.join([str(ord(x)) for x in value[:4]]) \
        or (family == socket.AF_INET6) and ':'.join(['%02x'%ord(x) for x in value[:16]]) \
        or None

def _str2addr(value, family=socket.AF_INET):
    '''Convert dotted-decimal representation to bytes.'''
    return (family == socket.AF_INET) and ''.join([chr(int(x)) for x in value.split('.')]) \
        or (family == socket.AF_INET6) and ''.join([(x and chr(int('0x%s'%x)) or '\x00') for x in value.split(':')]) \
        or value

class Attribute(object):
    '''A single attribute in STUN message. Only type (int) and value (str) are
    valid fields in this object.'''
    
    # attribute type definitions. Combines definitions from multiple internet-drafts.
    MAPPED_ADDRESS    = 0x0001;  CHANGE_REQUEST    = 0x0003;  SOURCE_ADDRESS    = 0x0004
    OTHER_ADDRESS     = 0x0005;  USERNAME          = 0x0006;  MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE        = 0x0009;  UNKNOWN_ATTRIBUTE = 0x000A;  LIFETIME          = 0x000D
    'ALTERNATE_SERVER = 0x000E'; BANDWIDTH         = 0x0010;  DESTINATION_ADDRESS=0x0011
    REMOTE_ADDRESS    = 0x0012;  DATA              = 0x0013;  REALM             = 0x0014;
    NONCE             = 0x0015;  XOR_MAPPED_ADDRESS= 0x0020;  XOR_REFLECTED_FROM= 0x0023
    PADDING           = 0x0026;  XOR_RESPONSE_ADDRESS=0x0027;
    # TODO: there is difference in definition of REALM and NONCE in RFC3489bis and TURN. 
    # Also in the ALTERNATE_SERVER. I used RFC3489bis definition.
    # optional
    SERVER            = 0x8022;  ALTERNATE_SERVER  = 0x8023;  CACHE_TIMEOUT     = 0x8026
    FINGERPRINT       = 0x8028;

    # list of comprehension-required attributes on which we don't choke. 
    # Needed for backward compatibility with RFC 3489
    knownTypes = [0x0001, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x000A, 0x0014, 0x0015, 0x0020]
    
    def __init__(self, type=None, value=None):
        '''Construct an empty attribute or parsed one if value is supplied.'''
        self.type, self.value = type, value
        
    @property
    def optional(self):
        '''Whether this attribute is optional or not?'''
        return (self.type & 0x8000) != 0
    
    @Property
    def address():
        '''The address tuple (family, ip, port) where family is socket.AF_INET or AF_INET6,
        ip is dotted IPv4 or IPv6 string and port is int. Must be accessed only for 
        address-based attributes such as MAPPED-ADDRESS, OTHER-ADDRESS and ALTERNATE-SERVER.'''
        def fget(self): 
            ignore, family, port = struct.unpack('!BBH', self.value[:4])
            family = (family == 0x01) and socket.AF_INET or (family == 0x02) and socket.AF_INET6 or socket.AF_UNSPEC
            return (family, _addr2str(self.value[4:], family), port)
        def fset(self, value):
            family, address, port = value
            address = _str2addr(address, family)
            family = (family == socket.AF_INET) and 0x01 or (family == socket.AF_INET6) and 0x02 or 0x00
            self.value = struct.pack('!BBH', 0, family, port) + address
        return locals()
    
    @Property
    def xorAddress():
        '''The address tuple (family, ip, port) with values similar to the address property,
        but used only for XOR-MAPPED-ADDRESS, XOR-REFLECTED-FROM and XOR-RESPONSE-ADDRESS attributes.'''
        def fget(self): 
            ignore, family, port = struct.unpack('!BBH', self.value[:4])
            family = (family == 0x01) and socket.AF_INET or (family == 0x02) and socket.AF_INET6 or socket.AF_UNSPEC
            if family == socket.AF_INET: self.value[4:8] = struct.pack('!l', (struct.unpack('!l', self.value[4:8]) ^ Message.MAGIC))
            else: raise ValueError, 'XOR-ADDRESS not implemented for IPv6'
            return (family, _addr2str(self.value[4:], socket.AF_INET), (port ^ ((Message.MAGIC & 0xffff0000) >> 16)) & 0x00ffff)
        def fset(self, value):
            family, address, port = value
            address = _str2addr(address, family)
            family = (family == socket.AF_INET) and 0x01 or (family == socket.AF_INET6) and 0x02 or 0x00
            self.value = struct.pack('!BBH', 0, family, port) + address
        return locals()

    @Property
    def error():
        '''A tuple (number, text) representing error code for the ERROR-CODE attribute.'''
        def fget(self):
            ignore, cls, num = struct.unpack('!HBB', self.value[:4])
            return ((cls & 0x07) * 100 + (num % 100), self.value[4:])
        def fset(self, value):
            cls, num = value[0] / 100, value[0] % 100
            self.value = struct.pack('!HBB', 0, cls, num) + value[1]
        return locals()

    @Property
    def unknown():
        '''A list [type, type, ...] of attributes for the UNKNOWN-ATTRIBUTE.'''
        def fget(self):
            return [x for x in struct.unpack('!'+str(len(self.value)/2)+'H', self.value)]
        def fset(self, value):
            self.value = ''.join([struct.pack('!H', x) for x in value])
        return locals()
            

class Message(object):
    '''A STUN message definition. The properties method, type and tid are defined in the spec.
    The attrs property is a list of STUN attributes in this Message object.'''
    
    BINDING, ignore, ALLOCATE, SEND, DATA, SET_ACTIVE_DESTINATION = range(1,7) # method: 1,3,4,5,6 
    REQUEST, INDICATION, RESPONSE, ERROR = tuple(range(0, 4)) # type
    MAGIC = 0x2112A442 # magic cookie
    
    def __init__(self, value=None):
        '''Construct a Message. Attributes are method (12-bits), type (two-bits), tid 
        (12 bytes) and list of attr. Parse the value if given.'''
        self.method = self.type = 0 
        self.tid, self.attrs = '', []
        if value:
            type, length, magic, self.tid = struct.unpack('!HHL12s', value[:20])
            if (type & 0xC000) != 0:
                raise ValueError, 'incorrect message type: %x'%type
            if magic != Message.MAGIC:
                raise ValueError, 'incorrect magic cookie: %x'%magic
            if length != (len(value)-20):
                raise ValueError, 'incorrect length: %d != %d'%(length, len(value)-20)
            if (length & 0x0003) != 0:
                raise ValueError, 'incorrect length %d, must be multiple of four'%length
            
            self.method = (type & 0x000F) | ((type & 0x00E0) >> 1) | ((type & 0x3E00) >> 2)
            self.type = ((type & 0x0100) >> 7) | ((type & 0x0010) >> 4)

            value = value[20:]
            while value and len(value)>0:
                attrtype, attrlen = struct.unpack('!HH', value[:4])
                self.attrs.append(Attribute(attrtype, value[4:4+attrlen])) # parse attr
                value = value[(4+attrlen+(4-attrlen%4)%4):]                # padding
            
    def __str__(self):
        '''Format a message into byte stream.'''
        type = (self.method & 0x000F) | ((self.method & 0x0070) << 1) | ((self.method & 0x0F80) << 2) \
                | ((self.type & 0x01) << 4) | ((self.type & 0x02) << 7) 
        if not self.tid:  self.tid = urandom(12)
        attrstr = ''
        for attr in self.attrs:
            value = str(attr.value)
            attrstr += struct.pack('!HH', attr.type, len(value)) + value
            if (len(value) % 4) != 0:
                attrstr += ''.join([chr(0) for x in range(0, (4-len(value)%4)%4)])
        result = struct.pack("!HHL12s", 0x3FFF & type, len(attrstr), Message.MAGIC, self.tid)
        result += attrstr
        return result
    
    def __repr__(self):
        '''User friendly display of the STUN Message.'''
        result = '<rfc3489bis.Message method=%r type=%r tid=%r'%(self.method, self.type, self.tid)
        if self.attrs:
            for attr in self.attrs:
                result += '\n   attr=%d value=%r'%(attr.type, (attr.type in [Attribute.MAPPED_ADDRESS, Attribute.ALTERNATE_SERVER]) and attr.address or attr.value)
        else: result += '>'
        return result

    # container access for message attributes
    def __getitem__(self, name):
        '''Return the first attribute matching the name (attribute type).''' 
        for attr in self.attrs:
            if attr.type == name:
                return attr
        return None
    def __setitem__(self, name, value): 
        '''Override or add an attribute with the name (attribute type) and value.
        Note the different in set and get semantics. In set you set the value (str), but
        get returns an Attribute object.'''
        for attr in self.attrs:
            if attr.type == name:
                attr.value = value
                return
        self.attrs.append(Attribute(name, value))
    def __contains__(self, name): 
        '''Check if the name (attribute type) exists in the message?'''
        for attr in self.attrs:
            if attr.type == name:
                return True
        return False

        
def request(sock, server=None, **kwargs):
    '''Send a STUN client request with retransmissions and return the response.
    This is a generator function, and can be called as
        response, external = yield request(sock, ('stun.iptel.org', 3478))

    It raises ValueError in case of failure and multitask.Timeout in case of timeout
    or failure to connect TCP or invalid response received. For TCP, the sock remains
    connected after successful return or exception from this function.
    
    Arguments are as follows:
        sock: the socket to use for sending request and receiving response.
        server: optional server (ip, port), defaults to defaultServers[0]. For TCP if sock
          is already connected, then server argument is ignored.
        method: optional STUN method, defaults to Message.BINDING.
        tid: optional transaction id, by default generates a new.
        attrs: optional attributes, by default empty list [].
        rto: optional RTO, defaults to 0.1 for UDP and 9.3 for TCP.
        retry: optional retry count, defaults to 7 for UDP and 1 for TCP.
        maxsize: optional maximum packet size, defaults to 1500. 
        handler: optional handler function, that receives any message that was received
          but not handled by the request method. 
    The handler argument allows demultiplexing other types of received messages on the 
    same socket. Note that raising an exception is not good, because we still want to 
    wait for response instead of exiting. The handler is invoked as 
    handler(sock, remote, data) where data is raw data string and remote is usually 
    server (ip, port). If no handler is specified, then invalid data raises a ValueError.
    '''
    
    server = server or defaultServers[0] # use first server if missing
    handler = kwargs.get('handler', None)
    maxsize = kwargs.get('maxsize', 1500)
    
    m = Message()
    m.method = kwargs.get('method', Message.BINDING)
    m.type = Message.REQUEST
    m.tid = kwargs.get('tid', urandom(12))
    m.attrs = kwargs.get('attrs', [])
    mstr = str(m) # formatted message bytes to send
    
    if len(mstr) >= maxsize: raise ValueError, 'Cannot send packet of length>%d'%(maxsize)
    
    if sock.type == socket.SOCK_STREAM:
        remote = None
        try: remote = sock.getpeername()
        except: pass
        if not remote: 
            try: 
                sock.connect(server)
                remote = server # connect if not already connected.
            except: 
                raise multitask.Timeout() # can't connect, then raise a timeout error.
        tcp, rto, retry = True, kwargs.get('rto', 9.3), kwargs.get('retry', 1)
    else:
        tcp, rto, retry = False, kwargs.get('rto', 0.100), kwargs.get('retry', 7) 
    
    while retry>0:
        retry = retry - 1
        if _debug: print 'sending STUN request method=%d, len=%d, remaining-retry=%d'%(m.method, len(mstr), retry)
        if tcp: 
            yield multitask.send(sock, mstr) # send the request
        else: 
            yield multitask.sendto(sock, mstr, server)
        try:
            if tcp: # receiving a TCP packet is complicated. remote is already set
                data = (yield multitask.recv(sock, maxsize, timeout=rto))
                if not data: break
                if _debug: print 'request() received data'
                type, length, magic = struct.unpack('!HHL', data[:8])
                if type & 0xC000 != 0 or magic != Message.MAGIC:
                    raise ValueError, 'invalid STUN response from server type=0x%x, magic=0x%x'%(type, magic)
                if length > (maxsize-8):
                    raise ValueError, 'very large response length[%d]>%d'%(length+8, maxsize)
            else: # receive a UDP datagram
                data, remote = (yield multitask.recvfrom(sock, maxsize, timeout=rto))
                
            if data:
                try:
                    response = Message(data) # parse the message if any
                    if _debug: print 'received STUN message method=%d, type=%d'%(response.method, response.type)
                except:
                    if _debug: print 'received invalid STUN message len=%d'%(len(response))
                    if handler: 
                        handler(sock, remote, data) # allow app to demultiplex
                        continue # retry next
                    else:
                        raise ValueError, 'Invalid response from server'
                    
                if response.tid != m.tid: 
                    if _debug: print 'The tid does not match. ignoring'
                    if handler: handler(sock, remote, data)
                    continue # probably a old response, don't raise exception.
                
                external = None
                for attr in response.attrs:
                    if not attr.optional and attr.type not in Attribute.knownTypes:
                        raise ValueError, 'Attribute 0x%04x not understood in response'%attr.type
                if response.type == Message.RESPONSE: # success response
                    for attr in response.attrs:
                        if m.method == Message.BINDING:
                            if attr.type == Attribute.XOR_MAPPED_ADDRESS:
                                external = attr.xorAddress # (family, ip, port)
                            elif attr.type == Attribute.MAPPED_ADDRESS: # for backward compatibility with RFC 3489
                                external = attr.address 
                elif response.type == Message.ERROR: # error response
                    error = None
                    for attr in response.attrs:
                        if attrs.type == Attribute.ERROR_CODE:
                            error = attrs.error  # (code, reason)
                            break
                    raise ValueError, 'Request failed with error %r'%error
                if external:
                    external = external[1:] # ignore the address family
                    raise StopIteration(response, external) # result to the caller
                # TODO: else do we continue or raise an error?
        except multitask.Timeout:
            rto = rto * 2 # double the rto
        except StopIteration:
            if _debug: print 'request() returning external=' + str(external)
            raise
        except: # any other exception, fall back to Timeout exception
            if _debug: print 'Some ValueError exception', sys.exc_info()
            break
        
    raise multitask.Timeout  # no response after all retransmissions
    

def _createSocket():
    '''Create a socket, bind and return (socket, (localip, localport)).'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.bind(('', 0))
    local = (socket.gethostbyname(socket.gethostname()), sock.getsockname()[1])  # get the local port
    return (sock, local)
    
def discoverBehavior(servers=defaultServers):
    '''Discover the NAT behavior and return the result as a tuple (type, mapping, filtering, external).
    There are four types: public, blocked, good and bad which correspond to as follows:
    public: mapping = filtering = 'Endpoing Independent', i.e., no NAT.
    blocked: mapping = filtering = None, i.e., UDP is blocked.
    good: mapping = 'Endpoint Independent', filtering='Address Independent', i.e., full-cone.
    bad: anything else is a bad NAT, hence requires ICE or tunneling.
    
    If the servers list is not provided, a default servers list (defaultServers)
    is used. Each element in the servers should be 'host:port' of the server.
    This is a generator function and can be invoked as
     nattype, mapping, filtering, external = yield discoverBehavior()
    The external result represents the external (ip, port) and is useful only if the mapping
    is 'Address Independent' or 'Endpoint Independent'.
    '''
    
    sock, local = _createSocket()
    mapping = filtering = external = None
    
    for server in servers:
        try:
            response, external = (yield request(sock, server=server))

            if external == local:
                mapping = filtering = 'Endpoint Independent'
            elif Attribute.OTHER_ADDRESS in response:
                other = response[Attribute.OTHER_ADDRESS].address[1:] # ignore address family
                response, external2 = (yield request(sock, (other[0], server[1])))
                if external == external2:
                    mapping = 'Endpoint Independent'
                else:
                    response, external3 = (yield request(sock, server=other))
                    mapping = external3 == external2 and 'Address Dependent' or 'Address and Port Dependent' 
                
                sock2, local2 = _createSocket() # allocate new socket to detect filtering behavior
                # skip test I of filtering behavior; reuse previous result
                
                try:
                    response, external4 = (yield request(sock2, server, attrs=[Attribute(Attribute.CHANGE_REQUEST, '\x00\x00\x00\x06')])) # change IP and port
                    filtering = 'Address Independent'
                except multitask.Timeout: # didn't receive any
                    try:
                        response, external5 = (yield request(sock2, server, attrs=[Attribute(Attribute.CHANGE_REQUEST, '\x00\x00\x00\x02')])) # change port
                        filtering = 'Address Dependent'
                    except multitask.Timeout: 
                        filtering = 'Address and Port Dependent'
                        
            else: # can't detect behavior. Just make it dependent.
                mapping = filtering = 'Unknown'
                i = servers.index(server)
                if i < len(servers) and servers[i+1][0] != server[0]: # try the next server
                    other = servers[i+1]
                    response, external2 = (yield request(sock, other))
                    if external == external2:
                        mapping = 'Address Independent'
                    else:
                        mapping = 'Address and Port Dependent'
            
            if mapping or filtering: 
                break # no exception means we discovered behavior
            
        except:
            if _debug: print 'Continuing after an exception or timeout with server=', server, (sys and sys.exc_info() or None)

    nattype = (not mapping or not filtering) and 'blocked' \
            or mapping == filtering == 'Endpoint Independent' and 'public' \
            or mapping.find('Independent')>=0 and filtering.find('Independent')>=0 and 'good' \
            or 'bad'
    raise StopIteration(nattype, mapping, filtering, external) # result to the caller


def server(sock1, **kwargs):
    '''A simple server implementation to test the code or to use in real deployment.
    The application should start the server as multitask.add(server(sock)).
    
    The caller should make sure that the sock1 argument is a UDP or TCP socket
    which is already bound. Additionally, sock2, sock3, and sock4 can be supplied
    as keyword arguments and represent the socket to use for change-IP, change-port
    and change IP+port commands respectively. Other keyword arguments are as follows:
      timeout: optional acivity timeout (second) if relay is activated, defaults to 180.
      external: optional external (ip, port) of the socket in case it is behind
        a full-cone NAT and still acts as a (relay) server.
      handler: optional function that gets invoked as handler(sock, remote, data) for 
        non-STUN data, and allows the application to demultiplex other types of data.
      maxsize: optional maximum size of packet to handle, defaults to 1500.'''
        
    sock2, sock3, sock4 = kwargs.get('sock2', None), kwargs.get('sock3', None), kwargs.get('sock4', None)
    addr1 = getlocaladdr(sock1)    
    addr4 = sock4 and getlocaladdr(sock4) or None
    timeout = kwargs.get('timeout', 180) # three minutes
    external = kwargs.get('external', addr1)
    handler = kwargs.get('handler', None)
    maxsize = kwargs.get('maxsize', 1500)
    
    tcp = (sock1.type == socket.SOCK_STREAM) # whether the server is on tcp or udp.
    binding = dict()  # allocated relay bindings if any
    
    def respond(sock, data, remote):
        if sock.type == socket.SOCK_STREAM:
            yield multitask.send(sock, data)
        else:
            yield multitask.sendto(sock, data, remote)
    
    def bindingRequest(sock, m, remote): # Serve a binding request of STUN
        res = Message()
        res.method, res.type, res.tid = Message.BINDING, Message.RESPONSE, m.tid
        mapped = Attribute(Attribute.MAPPED_ADDRESS) # mapped-address attribute
        mapped.address = (sock.family, addr1[0], addr1[1])
        res.attrs.append(mapped)
        if Attribute.CHANGE_REQUEST not in m: # send from same address:port
            if addr4: # add the other address attribute
                other = Attribute(Attribute.OTHER_ADDRESS)
                other.address = (sock4.family, addr4[0], addr4[1])
                res.attrs.append(other)
        else:
            change = m[Attribute.CHANGE_REQUEST]
            sock = change.value == '\x00\x00\x00\x06' and sock4 or change.value == '\x00\x00\x00\x02' and sock3 or change.value == '\x00\x00\x00\x04' and sock2 or None
        if sock:
            yield respond(sock, str(res), remote)
        raise StopIteration()

    def allocateRequest(sock, m, remote): # serve the allocate request of TURN
        fivetuple = (sock.type, getlocaladdr(sock), remote)
        lifetime = timeout
        if Attribute.LIFETIME in m:
            lt = struct.unpack('!L', m[Attribute.LIFETIME].value)
            if lt < lifetime: lifetime = lt
        if fivetuple in binding: # already found
            newsock = binding[fivetuple]
            if lifetime == 0: # terminate the binding
                del binding[fivetuple]
                del binding[newsock]
        else:
            if lifetime > 0: # allocate, otherwise it is already missing.
                newsock = socket.socket(sock.family, sock.type)
                newsock.bind(('0.0.0.0', 0)) # bind to any
                binding[newsock] = fivetuple
                binding[fivetuple] = newsock
            
        res = Message()
        res.method, res.type, res.tid = m.method, Message.RESPONSE, m.tid
        mapped = Attribute(Attribute.MAPPED_ADDRESS) # mapped-address attribute
        mapped.address = (newsock.family, (external, newsock and newsock.getsockname()[1] or 0))
        res.attrs.append(mapped)
        res.attrs.append(Attribute(Attribute.LIFETIME, struct.pack('!L', lifetime)))
        
        if lifetime == 0 and newsock: # close any previous listening function
            newsock.close() # this should trigger close of functions
        else:
            if sock.type == socket.SOCK_STREAM:
                multitask.add(relayaccepter(newsock, fivetuple))
            else:
                multitask.add(relayreceiver(newsock, fivetuple))
                
        yield respond(sock, str(res), remote)

    def relaytcpreceiver(sock, fivetuple):
        pass

    def relayaccepter(sock, fivetuple):
        sock.listen(5) # accept queue
        while True: # start the main listening loop of the tcp server
            try:
                conn, remote = (yield multitask.accept(sock))
                if conn:
                    if _debug: print 'relayaccepter().accept() from', remote
                    sock.close() # close the original listening socket -- no more connections
                    binding[fivetuple] = conn # update the binding
                    del binding[sock]
                    binding[conn] = fivetuple
                    multitask.add(relaytcpreceiver(conn, fivetuple, remote))
                    break
            except: # some other socket error, probably sock is closed.
                break
        if _debug: print 'relaytcpaccepter() exiting'
        
    def relayreceiver(sock, fivetuple):
        while True: # start the main listening loop of the udp server
            try:
                data, remote = (yield multitask.recvfrom(sock, maxsize)) # receive a packet
                if data:
                    if _debug: print 'server().recvfrom() from', remote
                    multitask.add(datahandler(sock1, data, remote))
            except: # some other socket error, probably sock1 is closed.
                break
        if _debug: print 'server() exiting'
        
    def sendRequest(sock, m, remote): # serve the send request of TURN
        fivetuple = (sock.type, getlocaladdr(sock), remote)
        try:
            if fivetuple not in binding: # not found
                raise ValueError, 'no turn binding found'
            newsock = binding[fivetuple]
            destaddr = Attribute.DESTINATION_ADDRESS in m  and m[Attribute.DESTINATION_ADDRESS].address[1:] or None
            data     = Attribute.DATA in m and m[Attribute.DATA] or None
            if sock.type == socket.SOCK_STREAM:
                try: 
                    remote = newsock.getpeername()
                except: 
                    remote = None
                if not remote: 
                    newsock.connect(destaddr)
                    remote = destaddr
                yield multitask.send(newsock, data)
            else:
                yield multitask.sendto(newsock, data, destaddr)
            # TODO: we don't lock to destaddr. This is a security risk.
            result = True
        except:
            if _debug: print 'sendRequest() exception', sys.exc_info()
            result = False
        res = Message()
        res.method, res.type, res.tid = m.method, (result and Message.RESPONSE or Message.ERROR), m.tid
        if not result:
            error = Attribute(Attribute.ERROR_CODE)
            error.error = (400, 'cannot send request') # TODO: be more explicit.
            res.attrs.append(error)
        yield respond(sock, str(res), remote)
    
    def datahandler(sock, data, remote): #handle a new data from given remote (ip, port)
        try: 
            m = Message(data) # parse the message
            func = m.type == Message.REQUEST and ( \
                    m.method == Message.BINDING and bindingRequest \
                    or m.method == Message.ALLOCATE and allocateRequest \
                    or m.method == Message.SEND and sendRequest \
                    ) or None 
            if func:
                yield func(sock, m, remote)
            else:
                raise ValueError, 'unhandled request or message'
        except StopIteration:
            if _debug: print 'datahandler: stop iteration'
            raise
        except: # parsing error or unhandled message
            if _debug: print 'datahandler() exception', sys.exc_info()
            if handler: 
                handler(sock, remote, data) # invoke the application's handler.
        
    def tcpreceiver(sock, remote): # handle a new incoming TCP connection
        while True:
            data = (yield multitask.recv(sock, maxsize))
            if not data: break # socket closed
            type, length, magic = struct.unpack('!HHL', data[:8])
            valid = (type & 0xC000 == 0) and magic == Message.MAGIC and length<=(maxsize-8) # valid
            if valid: 
                yield datahandler(sock, data, remote)
                if _debug: print 'tcpreceiver() finished data handler'
            else: 
                handler(sock, data, remote)

    if tcp: sock1.listen(5) # create the listen queue

    if _debug: print 'server listening on', addr1
    while True: # start the main listening loop of the server
        try: tcp = (sock1.type == socket.SOCK_STREAM)
        except: break # probably a bad file descriptor because sock1 is closed.
        try:
            if tcp:
                conn, remote = (yield multitask.accept(sock1, timeout=5))
                if conn:
                    if _debug: print 'server().accept() from', remote 
                    multitask.add(tcpreceiver(conn, remote))
            else:
                data, remote = (yield multitask.recvfrom(sock1, maxsize, timeout=5)) # receive a packet
                if data:
                    if _debug: print 'server().recvfrom() from', remote
                    multitask.add(datahandler(sock1, data, remote))
        except multitask.Timeout:
            continue
        except: # some other socket error, probably sock1 is closed.
            break
    if _debug: print 'server() exiting'
    
#----------------------------------- Testing ------------------------------

def _testServer():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.bind(('0.0.0.0', 0)) # should use any port for testing
    multitask.add(server(sock))
    sockaddr = getlocaladdr(sock)
    multitask.add(_testDiscoverBehavior([sockaddr, defaultServers[0]]))
    yield multitask.sleep(5)
    sock.close()
    
    
def _testDiscoverBehavior(servers=None):
    nattype, mapping, filtering, external = servers and (yield discoverBehavior(servers)) or (yield discoverBehavior())
    print 'nattype=%r, mapping=%r, filtering=%r, external=%r'%(nattype, mapping, filtering, external)

def _testRequest():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.bind(('0.0.0.0', 0))
    try:
        local = getlocaladdr(sock)
        response, external = yield request(sock, ('stun.iptel.org', defaultPort))
        print 'local=', local, 'external=', external, 'remote=', remote
    except (ValueError, multitask.Timeout), E:
        print 'exception - ValueError or Timeout', E
    except:
        print 'exception', sys.exc_info()

def _testTcpRequest():
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.bind(('0.0.0.0', 0)) # should use any port for testing
        multitask.add(server(sock1))
        sockaddr = getlocaladdr(sock1)
        
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.bind(('0.0.0.0', 0))
        yield multitask.sleep(2) # wait for server to be started.
        response, external = (yield request(sock2, sockaddr))
        print 'external=', external
        sock1.close()
        yield multitask.sleep(6)
        print '_testTcpRequest() exiting'
    except (ValueError, multitask.Timeout), E:
        print 'exception - ValueError or Timeout', E
    except:
        print 'exception', sys.exc_info()

def _testRelay():
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.bind(('0.0.0.0', 0))
        multitask.add(server(sock1))
        sockaddr = getlocaladdr(sock1)
        
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.bind(('0.0.0.0', 0))
        yield multitask.sleep(2)
        response, mapped = request(sock2, sockaddr, method=Message.ALLOCATE)
        print 'mapped=', mapped
        sock1.close()
        sock2.close()
        yield multitask.sleep(6)
    except:
        print 'exception', sys.exc_info(), traceback.print_exc(file=sys.stdout)    

if __name__ == "__main__":
    #multitask.add(_testRequest())
    #multitask.add(_testDiscoverBehavior())
    #multitask.add(_testTcpRequest())
    #multitask.add(_testServer())
    multitask.add(_testRelay())
    multitask.run()
    
    
