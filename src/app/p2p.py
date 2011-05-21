# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
'''
Implements p2p abstraction that allows establishing a peer-to-peer pipe
between two peers. The Network and Connection are two main classes.

Current issues:
Supernode needs to keep list of all attached ordinary nodes, and forward incoming
Connect and Datagram requests to the attached ordinary nodes.
For lookup, keep two levels of indirection:
  identity => nodeId (in data model)
  nodeId => IP:port (using DHT routing)
For super/ordinary node, keep three levels of indirection:
  idenity => nodeId (in data model)
  nodeId => supernodeIds (in data model)
  supernodeIds => IP:port (using DHT routing)
'''

import os, sys, traceback, socket, multitask, time, pickle, re, random, hashlib, struct, select
from binascii import hexlify, unhexlify

from app import dht, dummycrypto as crypto
from app.dht import Node, H, Hsize, Message
from std.rfc3489bis import discoverBehavior, request, defaultServers, getlocaladdr
from std.rfc2396 import URI
from std.rfc2396 import isMulticast, isIPv4

BOOTSTRAP='boot.39peers.net' # address of the bootstrap server if any
ADDRESS='224.0.1.2'          # multicast discovery address
PORT = 5062                  # default port number for Network object

_debug = False

#===============================================================================
# Low-level network related functions and classes such as createSockets and Network
#===============================================================================
def createSockets(preferred=('0.0.0.0', 0)):
    '''Create three listening sockets (UDP, TCP, UDP-multicast) based on the preferred address tuple
    (address, port). The complication is due to different behavior of multicast socket and socket 
    bind on different platforms. For example, Windows does not allow socket bind() with multicast address.
    
    If preferred argument has any '0.0.0.0' or unicast address, then the UDP-multicast socket is not 
    allocated and is set to None in returned tuple.
    
    If preferred argument has multicast address, then the UDP-multicast socket is allocated and returned.
    The returned multicast socket is bound to ('0.0.0.0', port) where port is from preferred argument.
    
    If preferred argument has unicast address then unicast sockets are tried to be bound to that
    address, and if fails then any '0.0.0.0'. 
    
    If preferred argument has a valid port, then unicast sockets are tried to be bound to that port,
    and if fails then any port. There is an exception -- if the preferred argument also has a 
    multicast address then UDP socket is always bound to any port instead of the preferred port.
    This allows the unicast and multicast sockets to be independent of each other and bound to
    different ports.
    
    If preferred argument is not a multicast address, then the unicast sockets (UDP and TCP) are
    tried to be bound to the same ports is possible, where attempt to bind the TCP is made first.
    
    If a UDP-multicast socket is allocated, then ttl and loopback options are set to 1.
    '''
    addr, port = preferred
    udp = tcp = mcast = None # will be returned
    multicast = isMulticast(addr)
    if multicast: 
        mcast = socket.socket(type=socket.SOCK_DGRAM)
        mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError: pass # ignore if no REUSEPORT 
        try: mcast.bind((addr, port))
        except socket.error, E: # on windows we get this error (10049) when binding to multicast addr 
            if E[0] == 10049: 
                mcast.close()
                mcast = socket.socket(type=socket.SOCK_DGRAM) # we need to create a new socket otherwise it gives 10022 Invalid argument error on second bind
                mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try: mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError: pass # ignore if no REUSEPORT 
                try: mcast.bind(('0.0.0.0', port))
                except socket.error:
                    mcast.close()
                    mcast = None; # probably we couldn't bind to the port.
        if mcast is not None:
            mcast.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) # scope to local network only
            mcast.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            mcast.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(addr) + socket.inet_aton('0.0.0.0'))

    tcp = socket.socket(type=socket.SOCK_STREAM)
    try: tcp.bind(('0.0.0.0' if multicast else addr, port))
    except socket.error: # could not bind to address+port 
        tcp.close()
        tcp = socket.socket(type=socket.SOCK_STREAM)
        try:  tcp.bind(('0.0.0.0', 0)) # and if that fails then try bind to any address+port
        except socket.error: tcp.close(); tcp = None # something wrong happened
    
    uaddr = '0.0.0.0' if multicast else addr # use any interface if multicast
    uport = 0 if multicast else (tcp.getsockname()[1] if tcp else port) # prefer same port as tcp.
    
    udp = socket.socket(type=socket.SOCK_DGRAM)
    try: udp.bind((uaddr, uport))
    except socket.error: # could not bind to address+port
        udp.close()
        udp = socket.socket(type=socket.SOCK_DGRAM) 
        try: udp.bind(('0.0.0.0', 0)) # and if that fails then try bind to any port
        except socket.error: udp.close(); udp = None # something wrong happened.
        
    if _debug: print 'createSockets() returning', udp and udp.getsockname(), tcp and tcp.getsockname(), mcast and mcast.getsockname() 
    return (udp, tcp, mcast)

def _testCreateSockets():
    u1, t1, m1 = createSockets(('224.1.2.3', 4567))
    u2, t2, m2 = createSockets(('224.1.2.3', 4567))
    assert t1.getsockname()[1] == 4567 == m1.getsockname()[1] == m2.getsockname()[1] != t2.getsockname()[1]

class Network(object):
    '''A Network abstraction represents the local peer which is bound to a particular identity and 
    service. Ideally this should be a subclass of dht.Network, but in python it doesn't matter.
    It uses three internal sockets, UDP-unicast, UDP-multicast and TCP, for receiving incoming messages. 
    The same set of sockets (ports) are used for peer-to-peer, SIP and STUN messages using application
    level demultiplexing based on data received.'''
    count = 0
    def __init__(self, Ks, cert, port=0):
        '''Construct a new network object. The application must invoke bind() before using any
        other function on this object. The private key Ks and certificate cert must be supplied
        to construct a network object.'''
        Network.count = Network.count + 1; self.name = 'Network[%d]'%(Network.count)
        self.queue = multitask.SmartQueue() # module's default queue for dispatching and receiving Message events
        self.qsip  = multitask.SmartQueue() # queue for SIP messages
        self.qstun = multitask.SmartQueue() # queue for STUN-related messages

        self.Ks, self.cert = Ks, cert
        if port == 0: ip, port = ADDRESS, PORT # use multicast, and any port TCP/UDP
        else: ip, port = '0.0.0.0', port # disable multicast
        self.udp, self.tcp, self.mcast = createSockets(preferred=(ip, port))
        self.tcp.listen(5)
        self.tcpc = dict()  # table of client connections from Node to connected socket if any.
        ip, port = getlocaladdr(self.udp); ignore, ptcp = getlocaladdr(self.tcp)
        self.node = Node(ip=ip, port=port, type=socket.SOCK_DGRAM, guid=H(ip + ':' + str(port))) # TODO: construct this using H(Kp)
        self.nodetcp = Node(ip=ip, port=ptcp, type=socket.SOCK_STREAM, guid=self.node.guid) 
        self.nodemcast = Node(ip=ADDRESS, port=PORT, type=socket.SOCK_DGRAM, guid=self.node.guid)
        self.gen = self.gentcp = self.genmcast = None

    def __del__(self):
        if self.mcast is not None:
            self.mcast.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, socket.inet_aton(ADDRESS) + socket.inet_aton('0.0.0.0'))
        for x in ('udp', 'tcp', 'mcast'): exec 'if self.%s is not None: self.%s.close(); self.%s = None'%(x, x, x)

    def start(self):
        for g,f in dict(gen='udpreceiver', gentcp='tcpreceiver', genmcast='mcastreceiver').items():
            exec 'if self.%s is None: self.%s = self.%s(); multitask.add(self.%s)'%(g, g, f, g)
        return self
    
    def stop(self):
        for x in ('gen', 'gentcp', 'genmcast'): 
            exec 'if self.%s is not None: self.%s.close(); self.%s = None'%(x, x, x)
        return self

    def parse(self, data, addr, type):
        '''Parse a message from given remote (host, port) and return parsed Message and remote Node.
        Returns None as message if can't be parsed.'''
        if len(data)< Hsize: return (None, None)
        guid, data = dht.bin2int(data[0:Hsize]), data[Hsize:] 
        node = Node(ip=addr[0], port=addr[1], type=type, guid=guid)
        try: msg = Message(raw=data)
        except: return (None, None)
        return (msg, node)
    
    def udpreceiver(self, maxsize=16386, timeout=None, interval=30):
        '''A UDP receiver task which also performs network ack.'''
        while True:
            data, addr = yield multitask.recvfrom(self.udp, maxsize, timeout=timeout)
            msg, remote = self.parse(data, addr, self.udp.type)
            if not msg: continue # ignore invalid messages. TODO: handle non-p2p message
            if _debug and msg.name[:4] != 'Hash': print self.name, 'udp-received %s=>%s: %r'%(remote.hostport, self.node.hostport, msg)
            if 'ack' in msg and msg.name != 'Ack:Indication': # the remote requires an ack. send one.
                del msg['ack'] # remove the ack
                ack = dht.Message(name='Ack:Indication', hash=H(data))    # hash of original received packet
                yield self.send(msg=ack, node=remote) # send the NetworkAck message
            msg['remote'] = remote # put remote as an attribute in msg before putting on queue.
            yield self.put(msg)    # put the parsed msg so that other interested party may get it.
            
    def mcastreceiver(self, maxsize=1500, timeout=None, interval=30):
        while True:
            if self.mcast is not None:
                data, addr = yield multitask.recvfrom(self.mcast, maxsize, timeout=timeout)
                msg, remote = self.parse(data, addr, self.mcast.type)
                if not msg: print 'ignoring empty msg'; continue # ignore invalid message. TODO: handle non-p2p message
                if remote == self.node: 
                    if _debug: print 'ignoring our own multicast packet'
                    continue
                if _debug: print self.name, 'mcast-received %s=>%s: %r'%(remote.hostport, self.nodemcast.hostport, msg)
                if 'ack' in msg: del msg['ack'] # just remove ack, but don't send an ack for multicast
                msg['remote'] = remote
                msg['multicast'] = True # so that application knows that this is received on multicast
                yield self.put(msg) 
            else:
                yield dht.randomsleep(interval)
            
    def tcpreceiver(self):
        '''Receive incoming TCP connection.'''
        while True:
            sock, addr = yield multitask.accept(self.tcp)
            if sock:
                multitask.add(self.tcphandler(sock, addr))
    
    def tcphandler(self, sock, addr, maxsize=16386, timeout=60):
        '''Handle an established TCP connection, and close it if no activity for timeout.'''
        remotes = []
        try:
            buffer = '' # buffer of data
            while True:
                try: data = yield multitask.recv(sock, maxsize, timeout=timeout)
                except multitask.Timeout: break # no activity for the timeout
                if not data: continue
                buffer = buffer + data
                if len(buffer) < 2: continue # wait for length atleast
                size = struct.unpack('!H', buffer[:2])
                if size>maxsize: buffer=''; print 'Network.tcphandler() something wrong, ignoring'; continue # TODO: something wrong happened, the protocol went out of sync?
                if len(buffer)<(2+size): continue # we need more data.
                data, buffer = buffer[2:2+size], buffer[2+size:]
                msg, remote = self.parse(data, addr, sock.type)
                if not msg: continue # TODO: handle non-p2p message
                if _debug: print self.name, 'tcp-received %s=>%s: %r'%(remote.hostport, self.nodetcp.hostport, msg)
                if remote not in self.tcpc: 
                    self.tcpc[remote] = sock # update the table, indicating we have a connection to this node.
                    remotes.append(remote)   # store the remote node so that we can clear tcpc on exit
                if 'ack' in msg: del msg['ack'] # just remove the ack attribute. No need to ack on tcp.
                msg['remote'] = remote # put remote as an attribute in msg before putting on queue.
                yield self.put(msg)    # put the parsed msg so that other interested party may get it.
        finally: 
            toremove = map(lambda y: y[0], filter(lambda x: x[1] == sock, self.tcpc.items()))
            for node in toremove: del self.tcpc[node]
                
    def send(self, msg, node, timeout=None):
        '''Send some msg to dest node (Node), and if timeout is specified then return a success (True)
        or failure (False) within that timeout. Otherwise, the function may return immediately.'''
        try:
            start = time.time()
            if node.type==socket.SOCK_DGRAM and timeout is not None: # no ack required for tcp 
                msg['ack'] = True # require a NetworkAck
            data = dht.int2bin(self.node.guid) + str(msg) # TODO: this assumes guid is same for all transports.
            if _debug and msg.name[:4] != 'Hash': print self.name, 'sending %d bytes %s=>%s: %r'%(len(data), self.node.hostport, node.hostport, msg)
            if node.type == socket.SOCK_DGRAM:
                self.udp.sendto(data, (node.ip, node.port))
            else:
                if node in self.tcpc:
                    sock = self.tcpc[node]
                else:
                    sock = socket.socket(type=socket.SOCK_STREAM)
                    sock.setblocking(0)
                    try:
                        if _debug: print 'connecting to %s'%(node.hostport,)
                        sock.connect((node.ip, node.port))
                    except (socket.timeout, socket.error):
                        yield multitask.sleep(2.0)
                        ret = select.select((), (sock,), (), 0)
                        if len(ret[1]) == 0:
                            if _debug: print 'connection timedout to %s'%(node.hostport,)
                            raise multitask.Timeout, 'Cannot connect to the destination'
                    self.tcpc[node] = sock
                    # yield multitask.sleep()
                    multitask.add(self.tcphandler(sock, (node.ip, node.port)))
                data = struct.pack('!H', len(data)) + data # put a length first.
                sock.send(data)
            if msg.ack:
                hash = H(data)    # hash property to associate the ack to the data request.
                ack = yield self.get(lambda x: x.name=='Ack:Indication' and x.hash==hash, timeout=(timeout - (time.time() - start)))
                if _debug: 'received ack %r'%(ack)
                if ack is None: raise StopIteration(False) # no ack received
            raise StopIteration(True)
        except (multitask.Timeout, socket.error):
            raise StopIteration(False) # timeout in sendto or get
        
    def put(self, msg, **kwargs):
        '''Put a message in the internal queue of this network. The message may be received
        by any other interested module such as router, storage, that is associated with this
        network object.'''
        yield self.queue.put(msg, **kwargs)
        
    def get(self, criteria=None, **kwargs):
        '''Get a message (or filtered message) from the internal queue of this network. The
        modules that need to receive some specific message from other modules invoke this method
        to get the message. For example, net.get(lambda:x x.name='Route:Request'). It returns
        the item if valid or None if there is a timeout and timeout keyword argument was given.'''
        try:
            item = yield self.queue.get(criteria=criteria, **kwargs)
            raise StopIteration(item)
        except multitask.Timeout:
            raise StopIteration(None)
    
#===============================================================================
# Client protocol for super-node and ordinary-node distinction.
#===============================================================================
class Client(object):
    '''A client implements the oridinary node functions in a super-node based architecture. The super-
    node is implemented by the dht module using Router and Storage objects. The client can be started as
    client = Client(net).start()
    An optional parameter server=True can be supplied to the constructor to directly start in server
    mode. An optional servers list can be specified in start() to set the bootstrap servers, e.g., from
    hostcache.'''
    def __init__(self, net, server=False):
        self.node, self.net = net.node, net
        self.candidates = self.neighbors = None
        self.server = server # whether we are in server or client mode. Starts with client, but may switch to server later.
        self._gens = None
        
    def start(self, servers=None):
        '''Start the client with the given set of optional servers list.'''
        if not self._gens:
            guid  = H(ADDRESS + ':' + str(PORT))
            try: bs = [Node(ip=socket.gethostbyname(BOOTSTRAP), port=PORT, type=socket.SOCK_STREAM, guid=guid)]
            except: bs = []
            self.candidates = (servers or []) + [self.net.nodemcast] + bs
            if _debug: print 'Client.start candidates=', self.candidates
            self.neighbors  = []
            self._gens = [self.discoverhandler(), self.bootstrap(), self.clienthandler()] # , self.pinghandler()
            for gen in self._gens: multitask.add(gen)
        return self
    
    def stop(self):
        if self._gens: 
            for gen in self._gens: gen.close()
            self._gens[:] = []
        return self
    
    def bootstrap(self, timeout=5, interval=30):
        '''A generator to perform bootstrap function.'''
        candidates = self.candidates[:] # a copy of list of candidates
        while True:
            if _debug: print self.net.name, 'bootstrap server=', self.server, 'neighbors=', len(self.neighbors), 'candidates=', len(candidates)
            if not self.server and not self.neighbors and candidates: # more candidates but no more neighbors
                node = candidates.pop(0)
                if _debug: print 'bootstrap trying node=', repr(node)
                if node.type==socket.SOCK_DGRAM and isMulticast(node.ip): 
                    yield self.net.send(Message(name='Discover:Request'), node=node)
                    msg = yield self.net.get(lambda x: x.name=='Discover:Response' and x.multicast, timeout=timeout)
                else:
                    if not isIPv4(node.ip): # is a IP address?
                        node = Node(ip=socket.gethostbyname(node.ip), port=node.port, type=node.type, guid=node.guid)
                    yield self.net.send(Message(name='Discover:Request'), node=node)
                    msg = yield self.net.get(lambda x: x.name=='Discover:Response' and not x.multicast, timeout=timeout)
                if msg:
                    added = False
                    for node in msg.neighbors:
                        if node.hostport == msg.remote.hostport: # whether msg.remote exists in msg.neighbors, which means remote is a server and we are already connected.
                            if _debug: print 'received neighbor', repr(node)
                            self.neighbors.insert(0, node) # put this as most preferred neighbor.
                            added = True
                        else:
                            if _debug: print 'received candidate', repr(node)
                            candidates.append(node) # put this as the next candidate
                    if added:
                        yield self.net.put(Message(name='Discover:Indication', node=self.node, neighbors=self.neighbors)) # indicate change in client.
                else: 
                    if _debug: print 'bootstrap did not receive response.'
            elif not self.server and self.neighbors: # perform neighbor refresh
                yield dht.randomsleep(timeout)
                result = yield self.net.send(Message(name='Ping:Request'), node=self.neighbors[0], timeout=timeout)
                if not result: # no response received, remove the neighbor
                    del self.neighbors[0]
                    yield self.net.put(Message(name='Discover:Indication', node=self.node, neighbors=self.neighbors)) # indicate change in client.
            elif not self.server and not self.neighbors and not candidates:
                candidates = self.candidates[:]
                yield dht.randomsleep(timeout)
            else: # just wait before trying again.
                yield dht.randomsleep(interval) 

    def discoverhandler(self, timeout=3):
        '''Respond to a Discover:Request message, for both multicast and unicast.'''
        while True:
            msg = yield self.net.get(lambda x: x.name=='Discover:Request')
            if _debug: print 'received discover request'
            if msg.remote.hostport == self.net.node.hostport:
                if _debug: print 'discoverhandler() ignoring our own packet' 
                continue # don't compare Node but only hostport. Ignore if our packet.
            if msg.multicast: # wait randomly before replying to multicast discover
                if _debug: print 'discoverhandler() wait before responding to multicast'
                response = yield self.net.get(lambda x: x.name=='Discover:Response' and x.multicast, timeout=(random.random()+0.5)*timeout)
                if response: # someone else sent a response, we don't have to send anymore
                    continue
            neighbors = ([self.net.node, self.net.nodetcp] if self.server else [])+self.neighbors
            if not msg.multicast or neighbors:
                response = Message(name='Discover:Response', neighbors=neighbors)
                dest = (msg.remote if not msg.multicast else self.net.nodemcast)
                yield self.net.send(msg=response, node=dest)
    
    def pinghandler(self):
        '''Respond to Ping:Request.'''
        while True:
            msg = yield self.net.get(lambda x: x.name=='Ping:Request')
            if _debug: print 'received ping request'
            yield self.net.send(msg=Message(name='Ping:Response'), node=msg.remote)
        
    def clienthandler(self):
        '''Receive requests from client and send to the router module, and viceversa.'''
        net = self.net
        def requesthandler(msg):
            p = msg.payload; response = None
            if self.server: # only if a server
                if p.name=='Put:Request':
                    result = yield dht.put(net, p.dest, p.value, p.nonce, p.expires, p.Ks, p.put)
                    response = Message(name='Put:Response', seq=p.seq, result=result)
                elif p.name=='Get:Request':
                    result = yield dht.get(net, p.dest, p.maxvalues, p.Kp)
                    response = Message(name='Get:Response', seq=p.seq, guid=p.guid, vals=result)
                if response: yield self.net.send(Message(name='Proxy:Response', src=net.node, payload=response), node=msg.src, timeout=5)
        def responsehandler(msg):
            if not self.server: # only if a client
                yield net.put(msg.payload, timeout=5)
        while True:
            msg = yield self.net.get(lambda x: x.name=='Proxy:Request' or x.name=='Proxy:Response')
            if msg: multitask.add(requesthandler(msg) if msg.name=='Proxy:Request' else responsehandler(msg))
            
    def put(self, guid, value, nonce, expires, Ks=None, put=True, timeout=30):
        '''Forward the put request to the connected DHT node.'''
        if self.server or not self.neighbors: # this is a server, or doesn't have valid connections
            if _debug: print 'client.put not a client with valid connections'
            raise StopIteration(False)
        net = self.net
        seq = dht._seq = dht._seq + 1
        request = Message(name='Put:Request', date=time.time(), seq=seq, src=net.node, dest=guid, nonce=nonce, expires=expires, put=put, \
                    value=str(value) if put else None, hash=H(str(value)), Kp=Ks and dht.extractPublicKey(Ks) or None, \
                    sigma=dht.sign(Ks, H(str(guid) + str(value) + str(nonce) + str(expires))) if Ks else None) 
        yield net.send(Message(name='Proxy:Request', src=net.node, payload=request), node=self.neighbors[0], timeout=5)
        response = yield net.get(timeout=timeout, criteria=lambda x: x.seq==seq and x.name=='Put:Response') # wait for response
        raise StopIteration(response and response.result)
    
    def remove(self, guid, value, nonce, expires, Ks=None, timeout=30):
        '''A convenience method that just invokes put(..., put=False,...).'''
        result = yield self.put(guid, value, nonce, expires, Ks=Ks, put=False, timeout=timeout)
        raise StopIteration(result)
    
    def get(self, guid, maxvalues=16, Kp=None, timeout=5):
        '''Invoke the get method on the connected DHT node if this is a client.'''
        if self.server or not self.neighbors:
            if _debug: print 'client.get not a client with valid connections'
            raise StopIteration([])
        net = self.net
        seq = dht._seq = dht._seq + 1
        request = Message(name='Get:Request', seq=seq, src=net.node, dest=guid, maxvalues=maxvalues, hash=Kp and H(str(Kp)) or None)
        yield net.send(Message(name='Proxy:Request', src=net.node, payload=request), node=self.neighbors[0], timeout=5)
        response = yield net.get(timeout=timeout, criteria=lambda x: x.seq == seq and x.name =='Get:Response') # wait for response
        result = [(v.value, k.nonce, v.Kp, k.expires) for k, v in zip(response.get('keyss', [None]*len(response['vals'])), response['vals'])] if response else []
        raise StopIteration(result) # don't use response.values as it is a built-in method of base class dict of Message.
    
def _testClient():
    def internalTest():
        n1 = Network(crypto.PrivateKey(), '').start()
        n2 = Network(crypto.PrivateKey(), '').start()
        c1 = Client(n1, server=True).start()
        c2 = Client(n2).start()
        msg = yield n2.get(lambda x: x.name=='Discover:Indication', timeout=8)
        assert msg is not None and msg.neighbors[0] == n1.node
    multitask.add(internalTest()) # need to use a generator for test
    
#===============================================================================
# High-level P2P abstraction using ServerSocket and Socket.
#===============================================================================
class ServerSocket(object):
    '''A P2P server socket is associated with a Network, and provides API methods similar to that
    of a TCP socket such as bind, connect, accept and close. Instead of using IP address it uses
    user identity and instead of using a port number it uses service name (which is like an application
    name). 
    
    When the start() method is invoked, it starts the P2P modules such as Network and Client.
    Optionally it joins the DHT using Router and Storage module immediately or after a signal from
    the Client module indicating that we can convert from ordinary node to super node. The stop()
    method stops the P2P modules, and abnormally disconnects from the P2P network. 
    
    When the bind() method is invoked, it actually binds a user identity with this object. If no
    bind is called, then connect or accept cannot be invoked. The difference between start() and bind()
    is that start() bootstraps the P2P network whereas bind() registers the local user identity so that
    incoming peer-to-peer connections can be received.'''
    def __init__(self, server=False, port=0):
        '''Create a new server socket. If server argument is False, then it performs bootstrap
        process using external bootstrap ADDRESS and PORT, otherwise it assumes this socket to be 
        a initial bootstrap server.'''
        self.net = self.client = self.router = self.storage = None
        self.server = server
        self._gens = []
        self.port = port
        
    def start(self, net=None, servers=None):
        '''Start the p2p node as ordinary node. Create a network object if none.'''
        if self.net is None:
            self.net = net or Network(Ks=crypto.generateRSA()[0], cert=None, port=self.port) 
            self.net.start()
            
            # convert from serevrs ip:port list to Node list
            if servers:
                servers=[Node(ip=ip, port=port, type=socket.SOCK_DGRAM, guid=H(ip + ':' + str(port))) for ip, port in servers]
                if _debug: print 'using servers=', servers
            
            self.client = Client(self.net, server=self.server).start(servers)
            if self.server:
                if self.router is None: self.router = dht.Router(self.net).start()
                if self.storage is None: self.storage = dht.Storage(self.net, self.router).start()
                if not self.router.initialized: self.router.initialized = True
        if not self._gens:
            for gen in [self.handler()]: multitask.add(gen); self._gens.append(gen)
        return self
    
    def stop(self):
        '''Stop the p2p node.'''
        if self._gens:
            for gen in self._gens: gen.close()
            self._gens[:] = []
        for x in ('client', 'storage', 'router', 'net'): exec 'if self.%s: self.%s.stop(); self.%s = None'%(x, x, x)
        return self
    
    @property
    def isSuperNode(self): return self.client and self.client.server
    
    def handler(self):
        '''Handle various messages from other modules such as Discover:Indication.'''
        supported = ['Discover:Indication']
        gen = None
        while True:
            msg = yield self.net.get(lambda x: x.name in supported)
            if msg.name == 'Discover:Indication':
                if msg.neighbors and gen is None: # need to promote
                    gen = self.promotionhandler(); multitask.add(gen)
                elif not msg.neighbors and gen is not None: # demotion: close promotion handler
                    gen.close(); gen = None
                
    def promotionhandler(self, timeout=10): # TODO: change to 10 min (600) for production use.
        '''Promote the node to super node after some uptime.'''
        yield dht.randomsleep(timeout) # wait for some uptime
        if _debug: print 'promotionhandler invoked'
        if self.client and self.client.neighbors:
            if self.router is None: self.router = dht.Router(self.net).start()
            if self.storage is None: self.storage = dht.Storage(self.net, self.router).start()
            if not self.router.initialized: 
                self.router.bs = self.client.neighbors;
                if _debug: print 'joining the dht'
                joined = yield self.router.join(self.router.bs[0])
                if joined: 
                    self.client.server = True

    # Data API: put, remove, get
    def put(self, guid, value, nonce, expires, timeout=30):
        '''put a (guid, value) pair with the given nonce. The value is signed by this socket's private key. It uses
        either dht.put to put the data using this DHT node or client's put method to send the request to a DHT node.'''
        if _debug: print 'put(guid=%r, value=%r, nonce=%r, expires=%r, timeout=%r)'%(guid, value, nonce, expires, timeout)
        Ks = hasattr(self.net, 'Ks') and self.net.Ks or None
        if self.isSuperNode: result = yield dht.put(self.net, guid, value, nonce, expires, Ks=Ks, timeout=timeout, retry=7)
        else: result = yield self.client.put(guid, value, nonce, expires, Ks=Ks, put=True, timeout=timeout)
        raise StopIteration(result)
    
    def remove(self, guid, value, nonce, expires, timeout=30):
        '''remove a (guid, value) pair with the given nonce. It uses either dht.remove or client's put method.'''
        if _debug: print 'remove(guid=%r, value=%r, nonce=%r, expires=%r, timeout=%r)'%(guid, value, nonce, expires, timeout)
        Ks = hasattr(self.net, 'Ks') and self.net.Ks or None
        if self.isSuperNode: result = yield dht.remove(self.net, guid, value, nonce, expires, Ks=Ks, timeout=timeout, retry=7)
        else: result = yield self.client.put(guid, value, nonce, expires, Ks=Ks, put=False, timeout=timeout)
        raise StopIteration(result)
    
    def get(self, guid, maxvalues=16, Kp=None, timeout=5):
        '''Get the values for the given guid. The return is an array of tuples (value, nonce, Kp, expires)'''
        if _debug: print 'get(guid=%r, maxvalues=%r, Kp=%r, timeout=%r)'%(guid, maxvalues, Kp, timeout)
        if self.isSuperNode: result = yield dht.get(self.net, guid, maxvalues=maxvalues, Kp=Kp, timeout=timeout)
        else: result = yield self.client.get(guid, maxvalues=maxvalues, Kp=Kp, timeout=timeout)
        raise StopIteration(result)
    
    # Service API: bind, close, accept, connect
    def bind(self, identity, interval=3600):
        '''Bind the server socket to the given identity.'''
        if hasattr(self, 'identity'): raise Exception('socket already bound')
        self.identity, self.nonce, self.expires = identity, dht.randomNonce(), time.time()+interval
        result = yield self.put(guid=H(identity), value=self.net.node.guid, nonce=self.nonce, expires=self.expires)
        raise StopIteration(result)
    
    def close(self):
        '''Close the bound socket'''
        if hasattr(self, 'identity'):
            result = yield self.remove(guid=H(self.identity), value=self.net.node.guid, nonce=self.nonce, expires=self.expires)
            del self.identity, self.nonce, self.expires
        raise StopIteration(None)
        
    def connect(self, identity, timeout=30):
        '''Connect to the given identity. It returns a Socket object on success or None on error.'''
        values = yield self.get(guid=H(identity))
        if _debug: print 'connect() found values=%r'%(values)
        for value in map(lambda x: x.value, values):
            try: value = int(value)
            except: print 'invalid non-integer value=%r'%(value); continue
            sock = Socket(sock=self, peer=(identity, value), server=False)
            seq = dht._seq = dht._seq + 1
            net = self.net
            request = Message(name='Connect:Request', src=net.node, dest=value, seq=seq, sock=hasattr(self, 'identity') and self.identity or None, peer=identity)
            if value == net.node.guid: yield net.put(request, timeout=5)
            elif self.isSuperNode: yield net.put(Message(name='Route:Request', src=net.node, dest=value, payload=request), timeout=5)
            else: yield net.send(Message(name='Proxy:Request', src=net.node, payload=request), node=self.client.neighbors[0])
            response = yield net.get(timeout=timeout, criteria=lambda x: x.seq==seq and x.name=='Connect:Response') # wait for response
            if response: raise StopIteration(sock)
            else: sock.close()
        raise StopIteration(None)
        
    def accept(self, timeout=None):
        '''Accept an incoming connection. It returns a Socket object on success or None on error.'''
        net = self.net
        msg = yield net.get(timeout=timeout, criteria=lambda x: x.name=='Connect:Request' and x.peer==self.identity) # wait for request
        if _debug: print 'accept msg=%r'%(msg)
        if not msg: raise StopIteration(None)
        sock = Socket(sock=self, peer=(msg.sock, msg.src.guid), server=True)
        yield net.send(Message(name='Connect:Response', seq=msg.seq, result=True), node=msg.src)
        raise StopIteration(sock)

    def sendto(self, identity, data, timeout=30):
        '''Send a single data object to the remote peer in datagram mode.'''
        values = yield self.get(guid=H(identity))
        for value in map(lambda x: x.value, values):
            try: value = int(value)
            except: print 'invalid non-integer value=%r'%(value); continue
            seq = dht._seq = dht._seq + 1
            net = self.net
            request = Message(name='Datagram:Request', src=net.node, dest=value, seq=seq, sock=hasattr(self, 'identity') and self.identity or None, peer=identity, value=str(data))
            if value == net.node.guid: yield net.put(request, timeout=timeout)
            elif self.isSuperNode: yield net.put(Message(name='Route:Request', src=net.node, dest=value, payload=request), timeout=timeout)
            else: yield net.send(Message(name='Proxy:Request', src=net.node, payload=request), node=self.client.neighbors[0])
        raise StopIteration(None)
        
    def recvfrom(self, timeout=None):
        '''Receive a single data object from any remote peer in datagram mode. It returns (identity, data)'''
        net = self.net
        msg = yield net.get(timeout=timeout, criteria=lambda x: x.name=='Datagram:Request' and x.peer==self.identity) # wait for request
        if not msg: raise StopIteration((None, None))
        raise StopIteration((msg.sock, msg.value))
        
class Socket(object):
    '''A P2P connected socket represents a peer-to-peer pipe between two peers. It is created 
    implicitly by ServerSocket object and returned in its connect() or accept() method.'''
    def __init__(self, sock, peer, server):
        '''Create a connected socket'''
        self.sock, self.peer, self.server = sock, peer, server
    def close(self):
        '''Close the socket connection'''
    def send(self, data):
        '''Send some data to the peer on this socket.'''
    def recv(self):
        '''Receive data from peer on this socket.'''
        
def _testServerSocket():
    def testInternal():
        s1 = ServerSocket(True).start()
        s2 = ServerSocket().start()
    multitask.add(testInternal())
    
def _testAlgorithm():
    def testInternal():
        #global _debug
        #_debug = dht._debug = True
        nodes = [ServerSocket(True).start()]
        for x in xrange(10):
            nodes.append(ServerSocket().start())
        yield
    multitask.add(testInternal())
    
#--------------------------------- Testing --------------------------------
if __name__ == '__main__':
    try:
        #_testCreateSockets()
        #_testClient()
        #_testServerSocket()
        _testAlgorithm()
        multitask.run()
    except KeyboardInterrupt:
        pass

    print 'stopping the test'
    exit()
