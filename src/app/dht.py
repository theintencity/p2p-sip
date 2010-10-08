# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.

import sys, time, hashlib, multitask, socket, struct, random, math, types, traceback, new
from std.kutil import getlocaladdr
from dummycrypto import sign, verify, PublicKey, PrivateKey, extractPublicKey
from std import rfc3489bis as util # we need _str2addr and addr2str. Move these to std.kutils

'''
A DHT implementation inspired by Bamboo DHT of OpenDHT.org.
The implementation assumes that the multitask framework is running.

Conventions:
  guid  - represents any unique id such as DHT key for a resource, or secure Node ID.
  value - represents the DHT value that can be put or retrieved.
  hash  - represents the hash of value or data.
  key   - database key to be used to store any data in underlying database.
  data  - database value associated with a key stored in underlying database.
  Ks    - RSA private key of the owner.
  Kp    - RSA public key of the owner.
  sigma - signature using RSA-hash (SHA1) of some value 
  root  - the DHT node guid responsible for storing a particular resource guid.
  
The Network class defines the low level network interface. As a first step to using this dht
module, the application creates a network object, and starts the message loop.

    n1 = Network().start()

Then the application starts other components such as Router and Storage for this network object.

    r1 = Router(n1).start()
    s1 = Storage(n1, r1).start()

Now that the network, router and storage components are running, the application can use the 
network's message queue to send the put or get command as follows:

    result = yield put(n1, guid=H('mykey'), value='myvalue', nonce=randomNonce(), expires=time.time()+60, Ks=myprivatekey)
    if result == False: print 'put failed'

    values = yield get(n1, guid=H('mykey'), maxvalues=4)
    print values[0] if values else None

The get function can take an optional owner field which is the fingerprint of the publickey of the
owner for which we want to fetch the values.

The remove operation is similar to calling the put function with an additional argument put=False.
For convinience, a shortcut method with name remove also exists. The original value is required in 
remove, so that it can computer the hash and signatures appropriately for the actual DHT message to
remove the value.
'''


#===============================================================================
# High level configuration that defines the DHT implementation.
# The application may override the following if needed, for example to change
# the number space from 160-bits to 128 or 256 bits.
#===============================================================================

H     = lambda x: long(hashlib.sha1(x).hexdigest(),16) # the hash function used in this implementation of the DHT.
Hsize = hashlib.sha1('something').digest_size # this is the global size of the hash function result.
Hmod  = 2**(Hsize*8) # modulus for the hash space, e.g., for SHA1 it is 2*160 in binary.

_seq = 0       # global sequence number used for DHT requests
_debug = False # debug flag for this module

#===============================================================================
# Some utility functions such as random number, distance, and bigint conversion
#===============================================================================
bin2int = lambda x: long(''.join('%02x'%(ord(a)) for a in x), 16)
int2bin = lambda x: (''.join(chr(a) for a in [((x>>c)&0x0ff) for c in xrange((Hsize-1)*8,-8,-8)])) if x is not None else '\x00'*Hsize
dig2int = lambda x, b, d=0: reduce(lambda m, n: (m << b) + n, x, 0)
int2dig = lambda x, b, d: [int((x>>c)&((1<<b)-1)) for c in xrange(b*(d-1), -b, -b)]

distance = lambda a,b: min((Hmod+b-a)%Hmod, (Hmod+a-b)%Hmod)
inrange = lambda L, H, a: L <= (a if L<=a else a+Hmod) <= (H if L<=H else H+Hmod) # whether a is in range [L,H] modulo
randomNonce = lambda: random.randint(0, Hmod)


def _testUtil():
    '''
    >>> print bin2int('\x22\x22'), ','.join(str(ord(a)) for a in int2bin(8738)) # 0x22=34, number=34*256+34
    8738 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,34,34
    >>> print dig2int([0x22, 0x22], 8, 2), int2dig(8738, 8, 4)
    8738 [0, 0, 34, 34]
    >>> print distance(10, 0), distance(0, 10), distance(2**160-10, 0), distance(0, 2**160-10) # Hmod is 2**160 by default
    10 10 10 10
    >>> print inrange(10, 2**160-10, 5), inrange(2**160-10, 10, 5)
    False True
    '''

def find(comp, seq):
    '''Find an element's index in the sequence, or -1 if not found, using the comp as the function to compare.
    >>> print find(lambda x: x==10, [8, 9, 10, 11])
    2
    '''  
    index = 0
    for item in seq:
        if comp(item): return index
        index = index + 1
    return -1
findNode = lambda id, nodes: find(lambda x: x.guid == id, nodes) # find a node from sequence of nodes using the guid of the node


#===============================================================================
# Generic message structure for different types of messages.
#===============================================================================

version = 1  # version number to be used in all messages
_attrs = '''
    bool: ack, add, inbound, put, result, second, wantreply
    int32: level, maxvalues, seq
    int64: time, expires, date
    hash: dest, guid, hash, high, low, nonce, owner
    str: app, error, sock, peer
    list: keyss, leafset, neighbors, nodes, path, vals
    node: client, neighbor, node, returnaddr, src
    bin: key, Kp, sigma, value
    msg: payload
    '''
# TODO: can't use the attribute name as 'keys' because it is a built in method. Hence used keyss
_attrName = map(lambda w: (w[0].strip(), map(str.strip, w[1].split(','))), map(lambda z: z.split(':'), filter(lambda y: y, map(str.strip, _attrs.split('\n')))))
_attrType = dict(sum(map(lambda x: map(lambda y: (y, x[0]), x[1]), _attrName), [])) # dict of attr=>type
_attrList = sum(map(lambda x: x[1], _attrName), []) # list of all attr
_request  = map(str.strip, 'Ack, Discover, Proxy, Join, RoutingTable, LeafSet, Lookup, Neighbor, Ping, Route, Replicate, ReplicaSet, Hash, Keys, Data, Put, Get, Connect, Datagram'.split(','))
_type     = map(str.strip, 'Request, Response, Indication, Error'.split(','))

def _attr2bin(attr):
    '''Convert the attribute name to binary 16-bit value.'''
    try: return struct.pack('!H', 0x08000 | _attrList.index(attr))
    except: pass # throws an error if not found in _attrList
    try:
        r, t = attr.split(':'); r, t = _request.index(r), _type.index(t)
        if r<0 or t<0: raise ValueError, 'invalid attribute', attr
        return struct.pack('!H', ((t<<12) & 0x7000) | (r & 0x0fff))
    except: raise ValueError, 'invalid attribute name %r'%attr

def _bin2attr(value):
    '''Convert the binary 16-bit value to the attribute name.
    >>> for a in _attrList:
    ...     assert a == _bin2attr(_attr2bin(a))
    '''
    value, = struct.unpack('!H', value[:2])
    try:
        if value & 0x8000: return _attrList[value & 0x7fff]
        else: return _request[value & 0x0fff] + ':' + _type[(value & 0x7000) >> 12]
    except: raise ValueError, 'invalid attribute value 0x%x'%value

class Message(dict):
    '''A generic message container that can be used in various scenarios and allows attribute
    access to container items for read. It uses a optimized binary format of type-length-value
    for various attributes. If bandwidth is not a concern one could use built-in pickle module
    instead of this custom binary format.
    
    >>> m = Message(name='Join:Request', path=[])
    >>> print repr(Message(raw=str(m)))
    <Message name=Join:Request path=[]>
    '''
    def __init__(self, raw=None, **kwargs):
        dict.__init__(self)
        if not raw:
            for n,v in kwargs.items(): 
                if v is not None: self[n] = v
        else: # decode the message
            if struct.unpack('!H', raw[:2])[0] != version: raise ValueError, 'invalid version' 
            self.decode(raw[2:]) 
    def __str__(self):
        '''Construct a formatted message, where each element is recursively formatted 
        as type, length, value.'''
        return struct.pack('!H', version) + self.encode()
    def __repr__(self):
        '''Representation of this msg is just the dictionary with a prefix Message.'''
        return '<Message name=%s %s>'%(self.name, ' '.join(map(lambda x: '%s=%r'%(x[0],x[1]), filter(lambda y: y[0] !='name', self.items()))))
    def __getattr__(self, name): return self.get(name, None)
    def dup(self): return Message(str(self))
    
    def encode(self):
        '''Encode this Message into a binary format.'''
        type = _attr2bin(self.name)
        result = ''
        for name, elem in filter(lambda x: x[0] != 'name', self.items()):
            k = _attr2bin(name); t = _attrType[name]
            if t == 'bool': value = struct.pack('!B', elem and 1 or 0)
            elif t == 'int32': value = struct.pack('!I', elem)
            elif t == 'int64': value = struct.pack('!II', int(elem / (2**32)), int(elem % (2**32)))
            elif t == 'hash': value = int2bin(elem)
            elif t == 'node': value = str(elem)
            elif t == 'msg': value = str(elem)
            elif t == 'str': value = struct.pack('!H', len(str(elem))) + str(elem)
            elif t == 'bin': value = struct.pack('!H', len(str(elem))) + str(elem) # ; print 'name=%r value=%r elem=%r len=%r l=%r'%(name, value, elem, len(str(elem)), struct.pack('!H', len(str(elem))))
            elif t == 'list': # in ('nodes', 'neighbors', 'leafset', 'vals', 'path', 'keyss'): # list
                value = struct.pack('!H', len(elem))
                for e in elem:
                    if name in ('nodes', 'neighbors', 'leafset', 'path'): v = str(e)
                    elif name in ('keyss', 'vals'): v = str(e)
                    else: raise ValueError, 'invalid list type', name
                    value += struct.pack('!H', len(v)) + v
            else: raise ValueError, 'invalid element type %r'%t
            if _debug: print 'name=%r elem=%r value=%r len=%r k=%r'%(name, elem, value, struct.pack('!H', len(value)), k)
            result += k + struct.pack('!H', len(value)) + value
        return type + struct.pack('!H', len(result)) + result
    
    def decode(self, value):
        '''Decode from binary format into this Message.'''
        name, l = value[:2], struct.unpack('!H', value[2:4])[0]
        self['name'], value, remaining = _bin2attr(name), value[4:4+l], value[4+l:]
        while len(value)>0:
            k, l = value[:2], struct.unpack('!H', value[2:4])[0]
            elem, value = value[4:4+l], value[4+l:]
            name = _bin2attr(k); t = _attrType[name]
            if t == 'bool': self[name] = (struct.unpack('!B', elem)[0] != 0)
            elif t == 'int32': self[name] = struct.unpack('!I', elem)[0]
            elif t == 'int64': self[name] = struct.unpack('!I', elem[:4])[0] * (2**32) + struct.unpack('!I', elem[4:8])[0]
            elif t == 'hash': self[name] = bin2int(elem)
            elif t == 'node': self[name] = Node(value=elem)
            elif t == 'msg': self[name] = Message(raw=elem)
            elif t == 'str':
                l = struct.unpack('!H', elem[:2])[0]; elem = elem[2:2+l]
                self[name] = unicode(elem)
            elif t == 'bin':
                l = struct.unpack('!H', elem[:2])[0]; elem = elem[2:2+l] 
                self[name] = elem if name in ('Kp', 'sigma', 'value') else (Key(value=elem) if name == 'key' else Value(value=elem))
            elif t == 'list':
                count, elem= struct.unpack('!H', elem[:2])[0], elem[2:]
                self[name] = [] # initialize as empty list
                for i in xrange(0, count):
                    l = struct.unpack('!H', elem[:2])[0]
                    v, elem = elem[2:2+l], elem[2+l:]
                    if name in ('nodes', 'neighbors', 'leafset', 'path'): self[name].append(Node(value=v))
                    elif name in ('keyss'): self[name].append(Key(value=v))
                    elif name in ('vals'): self[name].append(Value(raw=v))
                    else: raise ValueError, 'invalid list name', name 
            else: raise ValueError, 'invalid element type %r'%t

#===============================================================================
# A network abstraction that is used for all communication. It also encapsulates
# secure identifier of the node.
#===============================================================================

class Node(object):
    '''A Node has NodeId and NeighborInfo. This should be immutable. The important properties are
    type (socket.SOCK_STREAM or socket.SOCK_DGRAM for tcp or udp respectively), ip (as a
    dotted decimal string), port (as a int) and guid (as a long int, representing secure ID of
    this node, which is typically derived from hash of public key).'''
    #def __new__(cls, **kwargs):
    #    '''return an existing Node if one is found, else create a new Node.'''
    #    return object.__new__(cls, **kwargs)
    def __init__(self, **kwargs):
        '''Two ways to construct a node: either from binary str representation or specify properties.
        Node(value=binaryStr) or Node(ip='192.1.2.3',port=7028,type=socket.SOCK_DGRAM,guid=892891281928192128)
        '''
        # self.ping = self.pdown = False
        if 'value' in kwargs: # parse from string 
            value = kwargs.get('value')
            ip, self.port, self.type, self.guid = struct.unpack('!4sHB%ds'%Hsize, value)
            self.guid = bin2int(self.guid)
            self.ip = '.'.join([str(ord(x)) for x in ip])
            #print self.ip, self.port
        else: # build using individual components
            for n in ('ip', 'port', 'type', 'guid'):
                exec 'self.%s = kwargs.get("%s", None)'%(n,n)
        # since node is immutable, construct str, repr and hash output beforehand.
        self._str = struct.pack('!4sHB%ds'%Hsize, ''.join([chr(int(x)) for x in self.ip.split('.')]), self.port, self.type, int2bin(self.guid))
        self._repr = '<node ip=%r port=%r type=%r guid=%r>'%(self.ip, self.port, self.type, self.guid)
        self._hash = int(self.guid).__hash__() if self.guid else str(str(self.type) + ':' + self.ip + ':' + str(self.port)).__hash__() 
    def __cmp__(self, other):
        if id(self) == id(other): return 0 # a shortcut to compare identical objects
        elif self.guid and other.guid: return cmp(self.guid, other.guid)
        else: return cmp(self.ip, other.ip) or cmp(self.port, other.port) or cmp(self.type, other.type)
    def __hash__(self): return self._hash
    def __repr__(self): return self._repr
    def __str__(self): return self._str 
    @property
    def hostport(self): return self.ip and (self.ip + ':' + str(self.port)) or ''

class Network(object):
    '''A network abstraction that needs to be supplied by the application to various
    modules that require transport access. The node property represents the local Node.
    There are four important methods: send, recv, put and get. The application such as the p2p
    module implements a subclass of this abstraction to provide the actual secure implementation.'''
    count = 0
    def __init__(self, queue=None):
        '''Construct a UDP-based unsecured network. Application should provide a secure
        subclass implementation using dTLS or TLS.'''
        Network.count = Network.count + 1; self.name = 'Network[%d]'%(Network.count)
        self.queue = queue if queue is not None else multitask.SmartQueue() # module's default queue for dispatching and receiving events
        self.sock = socket.socket(type=socket.SOCK_DGRAM)
        self.sock.bind(('0.0.0.0', 0)) # bind to any address+port
        ip, port = getlocaladdr()[0], self.sock.getsockname()[1]
        self.node = Node(ip=ip, port=port, type=socket.SOCK_DGRAM, guid=H(ip + ':' + str(port)))
        self.gen = None # generator for receiver if start() is called.

    def send(self, msg, node, timeout=None):
        '''Send some msg to dest node (Node), and if timeout is specified then return a success (True)
        or failure (False) within that timeout. Otherwise, the function may return immediately.'''
        if self.sock: 
            try:
                start = time.time()
                if timeout is not None: 
                    msg['ack'] = True # require a NetworkAck
                data = str(msg)
                if _debug: print self.name, 'sending %d bytes %s=>%s: %r'%(len(data), self.node.hostport, node.hostport, msg)
                #yield multitask.sendto(self.sock, data, (node.ip, node.port), timeout=timeout)
                self.sock.sendto(data, (node.ip, node.port))
                if timeout is not None:
                    hash = H(data)    # hash property to associate the ack to the data request.
                    ack = yield self.get(lambda x: x.name=='Ack:Indication' and x.hash==hash, timeout=(timeout - (time.time() - start)))
                    if not ack: raise StopIteration(False) # timeout in get
                #if ack is None: raise StopIteration(False) # no ack received
                #else: 
                raise StopIteration(True)
            except multitask.Timeout:
                raise StopIteration(False) # timeout in sendto
                
    def recv(self, timeout=None, maxsize=1500):
        '''Receive some data from remote, and if timeout is specified then throw a
        multitask.Timeout exception if no data is received in that time.'''
        if self.sock:
            data, remote = yield multitask.recvfrom(self.sock, maxsize, timeout=timeout)
            lastnode = Node(ip=remote[0], port=remote[1], type=socket.SOCK_DGRAM, guid=H(remote[0]+':'+str(remote[1])))
            raise StopIteration((data, lastnode))
        else:
            raise RuntimeError, 'Invalid socket'
        
    def start(self):
        if self.gen is None: 
            self.gen = self.receiver()
            multitask.add(self.gen)
        return self
    
    def stop(self):
        if self.gen: self.gen.close(); self.gen = None
        return self
    
    def receiver(self):
        '''Install a receiver task to receive packets from the network and enqueue them in the queue,
        so that other interested parties can listen for it: multitask.add(net.receiver())
        The task also sends any NetworkAck if needed.
        '''
        while True:
            try: 
                data, remote = yield self.recv()
                msg = Message(raw=data)
            except: 
                if _debug: print 'invalid message', data; traceback.print_exc() 
                continue # ignore it
            if _debug: print self.name, 'received %s=>%s: %r'%(remote.hostport, self.node.hostport, msg)
            if 'ack' in msg and msg.name != 'Ack:Indication': # the remote requires an ack. send one.
                del msg['ack'] # remote the ack
                ack = Message(name='Ack:Indication', hash=H(data))    # hash of original received packet
                # yield multitask.send(self.sock, str(ack), remote) # send the NetworkAck message
                self.sock.sendto(str(ack), (remote.ip, remote.port)) # send the NetworkAck message
            msg['remote'] = remote # put remote as an attribute in msg before putting on queue.
            yield self.put(msg)    # put the parsed msg so that other interested party may get it.
            
    def put(self, msg, **kwargs):
        '''Put a message in the internal queue of this network. The message may be received
        by any other interested module such as router, storage, that is associated with this
        network object.'''
        yield self.queue.put(msg, **kwargs)
        
    def get(self, criteria=None, **kwargs):
        '''Get a message (or filtered message) from the internal queue of this network. The
        modules that need to receive some specific message from other modules invoke this method
        to get the message. For example, net.get(lambda:x x.name='Route:Request')'''
        try:
            item = yield self.queue.get(criteria=criteria, **kwargs)
            raise StopIteration(item)
        except multitask.Timeout:
            raise StopIteration(None)
    
def testNetwork():
    multitask.completed = False
    def sendrecv():
        try:
            n1, n2 = Network(), Network()
            multitask.add(n1.receiver())
            multitask.add(n2.receiver())
            yield n1.send(msg=Message(name='Join:Request'), node=n2.node)
            msg = yield n2.get(lambda x: x.name=='Join:Request', timeout=2)
        except:
            print 'testNetwork() didnot pass'
        multitask.completed = True
    multitask.add(sendrecv())
    while not multitask.completed: 
        multitask.get_default_task_manager().run_next()

#===============================================================================
# Routing logic implements the specific routing algorithm, in this case 
# Pastry/Bamboo.
#===============================================================================

#------------------------------------------------------------------------------ 
# RoutingTable 
#------------------------------------------------------------------------------ 
class RoutingTable(list):
    '''A two-dimensional container for routing table abstraction.'''
    class Entry: pass # routing table entry

    def __init__(self, node, columns=16, scale=0.9):
        '''Construct a new routing table for the given self node, with columns. The modulus is
        same as global Hmod and rows is calculated from columns and modulus.'''
        self.node, self.columns, self.scale = node, columns, scale
        self.bitsPerDigit = int(math.log(columns, 2))
        self.rows = (Hsize*8) / self.bitsPerDigit # modulus==2**(Hsize*8) and rows*columns==modulus
        self.size, self.highestLevel, self.length = 0, -1, self.rows
        self.entry = entry = self.Entry(); entry.node = node; entry.latency = 0.0
        self.digits = self.guid2digits(node.guid)
        for row in xrange(0, self.rows): # initialize the two-dimensional list (array)
            self.append([entry if row==col else None for col in xrange(0, self.columns)]) 
        # print self.columns, self.rows, self.bitsPerDigit, self.digits
        
    def __repr__(self):
        '''Printable representation of the routing table.'''
        entries = '\n  '+'\n  '.join(map(lambda x: 'Level: %d %s'%(x, '\n    '.join(map(lambda y: '[%d] %r'%(y, self[x][y].node), filter(lambda z: self[x][z] is not None, xrange(0, self.columns))))), xrange(0, self.highestLevel+1)))
        return '<RoutingTable node=%r size=%r levels=%r highestLevel=%r %s>'%(self.node, self.size, self.rows, self.highestLevel, entries)

    def __contains__(self, node):
        '''Check if the node exists in the routing table.'''
        dest = self.guid2digits(node.guid)
        first = self.firstdiff(dest)
        return first != self.rows and self.primary(first, dest[first]) and self.primary(first, dest[first]) == node

    def add(self, node, latency=0, pns=False):
        '''Add a node to the routing table if applicable. It returns None if the node could not be added,
        else it returns an existing node if an existing node is replaced, else if not replaced, it returns
        the self node.'''
        dest = self.guid2digits(node.guid)
        first = self.firstdiff(dest)
        if first == self.rows: return None
        ret = None
        #print first, dest[first], dest
        entry = self[first][dest[first]]
        if not entry or not entry.node:
            entry = self[first][dest[first]] = self.Entry()
            entry.node, entry.latency = node, latency
            self.size = self.size + 1
            ret = self.node
        elif entry.node == node: # exists, just update the latency
            entry.latency = latency
        elif pns and latency < self.scale*entry.latency: # found a less RTT node, replace
            ret = entry.node # old node is returned
            entry = self[first][dest[first]] = self.Entry()
            entry.node, entry.latency = node, latency
        if first > self.highestLevel: self.highestLevel = first
        return ret

    def forceAdd(self, node, latency):
        '''Perform a forced add to the routing table.''' 
        dest = self.guid2digits(node.guid)
        first = self.firstdiff(dest)
        if first == self.rows: return # error
        if not self[first][dest[first]]: self.size = self.size + 1
        entry = self[first][dest[first]] = self.Entry()
        entry.node, entry.latency = node, latency
        if first > self.highestLevel: self.highestLevel = first 
        
    def fillsHole(self, node):
        '''Check whether node fills an empty hole in the table.'''
        dest = self.guid2digits(node.guid)
        first = self.firstdiff(dest)
        if first == self.rows: return False
        return self[first][dest[first]] is None

    def remove(self, node):
        '''Remove a node from the routing table. It returns the level of the node or -1 if not found.'''
        dest = self.guid2digits(node.guid)
        first = self.firstdiff(dest)
        if first == self.rows: return -1
        if self[first][dest[first]] and self[first][dest[first]].node == node:
            self[first][dest[first]] = None
            self.size = self.size - 1
            if first == self.highestLevel:
                index = -1
                for i in xrange(first, -1, -1):
                    j = find(lambda y: self[i][y] and self[i][y] != self.entry, xrange(0, self.columns))
                    if j>= 0: index = i; break
                if index<0: self.highestLevel = 0 # not found, reduce the level
            return first
        return -1

    def primary(self, digit, value):
        '''Return the primary node from the routing table entry, or None if missing.'''
        return self[digit][value] and self[digit][value].node or None 

    def randomLevelNode(self, level):
        '''Get a random node from the routing table at the level.'''
        choices = set(filter(lambda y: y and y != self.entry, (self[level][x] for x in xrange(0, self.columns))))
        return choices and random.choice(list(choices)).node or None

    @property
    def weightedRandomLevel(self):
        '''Weigh the valid levels, and return a random level.'''
        if self.size == 0: return 0
        r = random.randint(1, (self.highestLevel+1)*(self.highestLevel+2)/2) # random in range 1 to sum
        level = 0 
        for c in xrange(self.highestLevel, 0, -1):
            r = r - c
            if r <= 0: break 
            level = level + 1
        return level
    
    @property
    def weightedRandomNode(self):
        '''Get the weighted random level and get a random node at the level.'''
        if self.size == 0: return None
        level = self.weightedRandomLevel
        node = self.randomLevelNode(level)
        while node is None and  level <= self.highestLevel:
            level = level + 1 
            node = self.randomLevelNode(level) 
        return node

    @property
    def weightedRandomKey(self):
        '''Get the weighted random level and then get a random key below this level.'''
        level = self.weightedRandomLevel
        value = random.randint(0, self.columns-1)
        digits = map(lambda x: self.digits[x] if x<level else (value if x == level else random.randint(0, self.columns-1)), xrange(0, self.rows))
        return self.digits2guid(digits)
    
    @property 
    def weightedRandomValue(self):
        '''Get a weighted random key whose first few digits are same as ours, followed by one digit same as
        routing table value and followed by remaining random digits.'''
        choices = []
        for d in xrange(0, self.highestLevel+1):
            for v in xrange(0, self.columns):
                if self[d][v]: choices.append((d, v))
        if not choices: return None
        level, value = random.choice(choices)
        digits = map(lambda x: self.digits[x] if x<level else(value if x == level else random.randint(0, self.columns-1)), xrange(0, self.rows))
        return self.digits2guid(digits)

    def matching(self, guid):
        '''Return the matching digits with this node's guid.'''
        return self.firstdiff(self.guid2digits(guid))

    def nextHop(self, guid, ignore=None):
        '''Get the next hop node for the destination guid, ignoring the nodes in the ignore set.'''
        dest = self.guid2digits(guid)
        first = self.firstdiff(dest)
        if first == self.rows: return self.node
        ret = self.primary(first, dest[first])
        if ignore and find(lambda x: x == ret, ignore)>=0: # found in ignore
            ret = None
        return ret;
    
    @property
    def list(self):
        '''A list (array) representation of routing table.'''
        ret = []
        for row in self:
            for col in row:
                if col and col != self.entry:
                    ret.append(col.node)
        return ret

    def guid2digits(self, guid):
        return int2dig(guid, self.bitsPerDigit, self.rows)

    def digits2guid(self, digits):
        return dig2int(digits, self.bitsPerDigit, self.rows)

    def firstdiff(self, digits):
        '''Return the first difference with the other digits array.'''
        first = 0
        while first < self.rows and self.digits[first] == digits[first]:
            first = first + 1
        return first

def _testRoutingTable():  
    rt = []
    for port in xrange(0, 100):
        rt.append(RoutingTable(node=Node(ip='0.0.0.0',port=port,type=socket.SOCK_DGRAM,guid=H('0.0.0.0:'+str(port)))))
    for i in xrange(1, 100):
        #print 'adding', i
        rt[0].add(rt[i].node, 0.0)
    #print rt[0]

#------------------------------------------------------------------------------ 
# LeafSet
#------------------------------------------------------------------------------ 
class LeafSet(object):
    '''This is a one dimensional container with index from -len to +len, where len is
    the length of one side of the leaf-set. The 0'th element is the self node, and i'th element
    is the i'th successor for i>0 and i'th predecessor for i<0, i=1,2,...length.
    
    >>> node = Node(ip='0.0.0.0', port=0, type=socket.SOCK_DGRAM, guid=H('0.0.0.0:0'))
    >>> ls = LeafSet(node=node)
    >>> for port in xrange(1, 100): 
    ...    ignore = ls.add(Node(ip='0.0.0.0', port=port, type=socket.SOCK_DGRAM, guid=H('0.0.0.0:'+str(port))))
    >>> print ls
    <LeafSet <node ip='0.0.0.0' port=25 type=2 guid=332553500505024118139453427259589985268347006514L>
        <node ip='0.0.0.0' port=76 type=2 guid=344256270334124892387775982735564292838031798975L>
        <node ip='0.0.0.0' port=95 type=2 guid=345064513834135878542882879036800526214322188981L>
        <node ip='0.0.0.0' port=75 type=2 guid=384537642324149417382945675086589485089817610081L>
        <node ip='0.0.0.0' port=0 type=2 guid=386487918899427893147283785174226450560216948519L>
        <node ip='0.0.0.0' port=48 type=2 guid=393644250941402407785204206553305568458866605816L>
        <node ip='0.0.0.0' port=58 type=2 guid=415748779641751273361359367594880519561321642612L>
        <node ip='0.0.0.0' port=84 type=2 guid=420350901529310083152176181882612694359107974252L>
        <node ip='0.0.0.0' port=82 type=2 guid=447023377445164417508254939667924928525196135428L>>
    >>> print len(ls), ls.maxsize
    4 4
    >>> print ls['low'].guid < ls[0].guid < ls['high'].guid
    True
    >>> print (ls['high'].guid-1 in ls), (ls['high'].guid+1) in ls
    True False
    >>> print ls.closest(ls[-2].guid+10).guid == ls[-2].guid
    True
    >>> print ls.replicas(ls[-2].guid+10, 4) == set([ls[0], ls[-1], ls[-2]])
    True
    >>> print ls.intermediates(ls[-2].guid) == [ls[-1]]
    True
    >>> print (ls.random in ls)
    True
    ''' 
    def __init__(self, node, maxsize=4):
        self.node, self.maxsize = node, maxsize
        self._preds, self._succs, self.overlap = list(), list(), False
        self._set = self._list = None # set and list returns by to set and list properties
        self._updateOverlap()

    def __len__(self):
        '''Return the current length of the leaf-set, which is length of preds or succes. 
        The actual number of elements are 2*len+1 that includes len predecessors, len successors 
        and self node.'''
#        TODO see comment in remove() on why this assertion is wrong?
#        if len(self._preds) != len(self._succs):
#            raise AssertionError, 'length of self._preds[%d] != self._succs[%d]\npreds=%s\nsuccs=%s'%(len(self._preds),len(self._succs),' '.join(map(repr, self._preds)),' '.join(map(repr, self._succs))) 
        return len(self._preds)
    
    def __getitem__(self, index):
        '''Get the i'th item in the leaf-set. Special index such as 'low' and 'high' are recognized to
        return the lowest or highest element from leaf set including self node.'''
        if index == 0: return self.node
        elif index == 'low': return self._preds[-1] if len(self._preds) > 0 else self.node
        elif index == 'high': return self._succs[-1] if len(self._succs) > 0 else self.node
        elif index>0: return index <= len(self._succs) and self._succs[index-1] or None
        elif index<0: return -index <= len(self._preds) and self._preds[-index-1] or None

    def __contains__(self, item):
        '''If item is Node, then return True if it exists in the leaf set, else if item is int
        return True if it belongs to our range of leaf-set, else return False.'''
        if isinstance(item, Node): return find(lambda x: x.guid==item.guid, self._preds+self._succs)>=0 if self.node.guid != item.guid else False
        else: return inrange(self['low'].guid, self.node.guid, item) or inrange(self.node.guid, self['high'].guid, item)
    
    @property
    def random(self):
        '''Return a random element from the leaf-set, not including the self node.'''
        if len(self._preds)==0: return None
        index = random.randint(0, len(self._preds)+len(self._succs)-1)
        return index < len(self) and self._preds[index] or self._succs[index-len(self._preds)]

    @property
    def list(self):
        '''Return a list (array) representation of the leaf set.'''
        if self._list == None: self._list = self._preds + self._succs
        return self._list

    @property
    def set(self):
        '''Return the set representation of the leaf set.'''
        if self._set == None: self._set = set(self._preds + self._succs)
        return self._set

    @property
    def sorted(self):
        '''Return a sorted list (array) representation with preds, self node and succs.'''
        return [x for x in reversed(self._preds)] + [self.node] + self._succs

    def __repr__(self):
        '''Printable representation of the leaf set.'''
        return '<LeafSet %s>'%('\n    '.join(map(repr, self.sorted)) if len(self._preds)>0 else 'empty')

    def closest(self, guid, ignore=()):
        '''Return closest node to the given guid, ignoring elements in ignore (set).'''
        mn, md = self.node, distance(self.node.guid, guid) # result node and distance
        for n in filter(lambda x: x not in ignore, (self._preds + self._succs)):
            d = distance(n.guid, guid) # distance with node n, check if it smaller than md.
            if d<md or d==md and n!=mn and inrange(mn.guid, n.guid, guid) and not inrange(n.guid, mn.guid, guid):
                mn, md = n, d # a better match found, update result
        return mn
    
    def intermediates(self, guid):
        '''Return a list of nodes from self node to the given guid in our leaf set, or None if empty list.'''
        p = find(lambda x: x.guid == guid, self._preds)  # the guid is found in leaf set
        s = find(lambda x: x.guid == guid, self._succs)  # the guid is found in leaf set
        result = (filter(lambda x: inrange(guid, self.node.guid, x.guid), self._preds[0:p]) if p>=0 else []) + \
                 (filter(lambda x: inrange(self.node.guid, guid, x.guid), self._succs[0:s]) if s>=0 else [])
        return result if len(result)>0 else None

    def replicas(self, guid, desired):
        '''Return a set of nodes that should have replicas for the given guid.'''
        desired, result = min(desired, len(self._preds) + len(self._succs)), set() # result is set of nodes
        assert desired % 2 == 0 # must be even number since preds and succs are equal lengths
        if len(self._preds) == 0: result.add(self.node) # self node is a must
        else: # get the closest node in pred and succ and add all between those and us.
            m = distance(self.node.guid, guid)
            m, closest, ignore = reduce(lambda a,b: (b,a[2]-1,a[2]-1) if b<a[0] else (a[0],a[1],a[2]-1), map(lambda x: distance(x.guid, guid), self._preds), (m, 0, 0))
            m, closest, ignore = reduce(lambda a,b: (b,a[2]+1,a[2]+1) if b<a[0] else (a[0],a[1],a[2]+1), map(lambda x: distance(x.guid, guid), self._succs), (m, closest, 0))
            half = desired / 2
            start = 0
            if self.overlap or (0-closest != len(self._preds)) and (closest != len(self._succs)):
                if closest == 0: start = (closest - half) if inrange(self._preds[0].guid, self.node.guid, guid) else (closest - half + 1)
                elif closest < 0: start = (closest - half + 1) if inrange(self._preds[-1*closest-1].guid, self.node.guid, guid) else (closest - half)
                else: start = (closest - half) if inrange(self.node.guid, self._succs[closest-1].guid, guid) else (closest - half + 1)
                stop = start + desired
                for index in xrange(start, stop):
                    if index == 0: result.add(self.node)
                    elif index < 0 and 1-index < len(self._preds): result.add(self._preds[-index-1])
                    elif index > 0 and index-1 < len(self._succs): result.add(self._succs[index-1])
        return result
    
    def promising(self, node):
        '''Is the given node a promising candidate for this leaf set?'''
        if node.guid == self.node.guid: return False
        if len(self._preds) == 0: return True # everything is promising in empty list
        if find(lambda x: x.guid == node.guid, self._preds+self._succs)>=0: return False # exists
        if len(self._preds)<self.maxsize or len(self._succs)<self.maxsize: return True # can always accomodate until max size is reached
        return find(lambda x: inrange(x.guid, self.node.guid, node.guid), self._preds)>=0 or \
               find(lambda x: inrange(self.node.guid, x.guid, node.guid), self._succs)>=0

    def add(self, node):
        '''Add a node in the leaf set if possible. It returns None if node is not added, and returns
        self node if node is added without replacing, and returns old node if the old node is replaced
        by the newly added node.'''
        assert node.ip != None and node.port != 0 # just a sanity check
        self._set = self._list = None # reset to recalculate on next access
        if self.node.guid == node.guid: return None
        if len(self._preds)==0:
            self._preds.append(node); self._succs.append(node); self.overlap = True # preds and succs overlap
            return self.node
        ret = None
        
        if findNode(node.guid, self._preds)<0: # not found in preds
            for i in xrange(0, len(self._preds)+1):
                if i<len(self._preds) and inrange(self._preds[i].guid, self.node.guid, node.guid) or i==len(self._preds)<self.maxsize:
                    self._preds.insert(i, node)
                    ret = len(self._preds)>self.maxsize and self._preds.pop() or self.node
                    break
        if findNode(node.guid, self._succs)<0: # not found in preds
            for i in xrange(0, len(self._succs)+1):
                if i<len(self._succs) and inrange(self.node.guid, self._succs[i].guid, node.guid) or i==len(self._succs)<self.maxsize:
                    self._succs.insert(i, node)
                    ret = len(self._succs)>self.maxsize and self._succs.pop() or self.node
                    break
        if ret is not None: # leaf set changed
#            if len(self._preds) != len(self._succs): # ideally this should never happen
#                self._adjustLength()
            self._updateOverlap()
        assert len(self._preds) == len(self._succs)
        return ret

    def remove(self, node):
        '''Remove a node from the leaf set, and returns type as one of 'none', 'pred', 'succ', 
        'both' depending on whether the node was removed or not, and what type.'''
        p, s = find(lambda x: x.guid == node.guid, self._preds), find(lambda x: x.guid == node.guid, self._succs)
        if p>=0: del self._preds[p]
        if s>=0: del self._succs[s]
        if _debug: print 'LeafSet.remove p=%d, s=%d, node=%r, len=%d'%(p,s,node,len(self._preds))
        if p>=0 or s>=0:
            self._set = self._list = None
            if len(self._preds) != len(self._succs):
                if _debug: print 'LeafSet.remove adjusting lengths', len(self._preds), len(self._succs)
                self.overlap = True
            else:
                self._updateOverlap()
            if self.overlap: # overlaps then add all succs and preds to mutual lists
                for n in self._preds+self._succs: 
                    if hasattr(self, '_origadd'): self._origadd(n)
                    else: self.add(n)
            assert len(self._preds) == len(self._succs)
            return p>=0 and s>=0 and 'both' or p>=0 and 'pred' or 'succ'
        else: 
            return 'none'

    def _adjustLength(self):
        '''If preds and succs are of different lengths, then copy elements from succs to preds.'''
        if _debug: print 'LeafSet.add adjusting lengths', len(self._preds), len(self._succs)
        index = len(self._preds) - len(self._succs)
        i = 0
        while len(self._preds) != len(self._succs):
            if index < 0: self._preds.append(self._succs[-i]) # preds < succs. Copy succs to preds
            else: self._succs.append(self._preds[-i])
            i = i + 1
            self.overlap = True
            
    def _updateOverlap(self):
        '''Update the overlap field depending on whether the succs and preds overlap or not?'''
        if len(self._preds) == 0 or len(self._succs) == 0: 
            self.overlap = True
        else:
            self.overlap = False
            for p in self._preds:
                for s in self._succs:
                    if p.guid == s.guid:
                        self.overlap = True
                        return
                    
    def coversAll(self, replicas):
        '''Return true if there is an overlap in the leaf set and it covers all range for given
        replica size.'''
        size = min(len(self), replicas/2)
        for i in xrange(0, size):
            if self._preds[i] == self._succs[size-1]:
                return True
        return False

#------------------------------------------------------------------------------ 
# NodeCache
#------------------------------------------------------------------------------ 
class NodeCache(object):
    '''A one-dimensional container that provides host cache for Node objects with two abstractions:
    sorted for nodes sorted using guid, and recent for recently used nodes.
    
    >>> cache = NodeCache(maxsize=4)
    >>> for port in range(0, cache.maxsize): # until the cache is full
    ...    cache.add(Node(ip='0.0.0.0', port=port, type=socket.SOCK_DGRAM, guid=H('0.0.0.0:'+str(port))))
    >>> print cache
    <NodeCache len=4
        sorted='[386487918899427893147283785174226450560216948519L, 696085870186638593551070967803585453548489714879L, 852739581864525514108676383126943539373951595004L, 1270878719196245987460471235562079865445211503331L]'
        recent='[696085870186638593551070967803585453548489714879L, 852739581864525514108676383126943539373951595004L, 1270878719196245987460471235562079865445211503331L, 386487918899427893147283785174226450560216948519L]'>
    >>> for port in range(cache.maxsize, 2*cache.maxsize): # add additional 4 so that previous ones are replaced
    ...    cache.add(Node(ip='0.0.0.0', port=port, type=socket.SOCK_DGRAM, guid=H('0.0.0.0:'+str(port))))
    >>> print cache
    <NodeCache len=4
        sorted='[252478387135709829778192334194629447386561244062L, 893097759797013506484723759710183999272836968151L, 910908089409371729128886584183916560096870579416L, 1321123319433667090818861432786256425521662391362L]'
        recent='[893097759797013506484723759710183999272836968151L, 252478387135709829778192334194629447386561244062L, 910908089409371729128886584183916560096870579416L, 1321123319433667090818861432786256425521662391362L]'>
    >>> for port in range(cache.maxsize, 2*cache.maxsize): # repeated entries, cache remains the same
    ...    cache.add(Node(ip='0.0.0.0', port=port, type=socket.SOCK_DGRAM, guid=H('0.0.0.0:'+str(port))))
    >>> print cache
    <NodeCache len=4
        sorted='[252478387135709829778192334194629447386561244062L, 893097759797013506484723759710183999272836968151L, 910908089409371729128886584183916560096870579416L, 1321123319433667090818861432786256425521662391362L]'
        recent='[893097759797013506484723759710183999272836968151L, 252478387135709829778192334194629447386561244062L, 910908089409371729128886584183916560096870579416L, 1321123319433667090818861432786256425521662391362L]'>
    '''
    def __init__(self, maxsize=20):
        '''Create a cache with specified maxsize, defaults to 20.'''
        self.maxsize = maxsize
        self.sorted = []   # sorted list of Node
        self.recent = []   # recently used list of Node
        self.dict = dict() # index from guid to Node
    
    def __len__(self):
        '''Length of the node cache.'''
        return len(self.dict)
    
    def __contains__(self, elem):
        '''Check whether the cache contains the given elem which can be a Node or a guid.'''
        if isinstance(elem, Node): return (elem.guid in self.dict)
        else: return (elem in self.dict)
    
    def add(self, elem):
        '''Add to modify the index in sorted and recent.'''
        if self.maxsize>0:
            if elem.guid in self.dict: # exists, just update the recent list by moving elem to front.
                elem0 = self.dict[elem.guid] # this is the elem present in sorted or recent
                s, r = self.sorted.index(elem0), self.recent.index(elem0) # index in sorted and recent lists
                del self.recent[r] # move it to front of recent
                self.sorted[s] = elem # just in case elem0 is different from elem
            else: # need to add to self set, and sorted and recent lists.
                if len(self.dict) >= self.maxsize: # need to make room by discarding the least recently recent elem
                    self.remove(self.recent[-1]) # this will remove from all lists and set
                s = find(lambda x: elem.guid < x.guid, self.sorted) # insert in sorted list
                self.sorted.insert(s if s>=0 else len(self.sorted), elem)
        self.dict[elem.guid] = elem          # just in case, override previous elem0
        self.recent.insert(0, elem)          # add as most recently used item
        assert len(self.sorted) == len(self.recent) == len(self)

    def remove(self, elem):
        '''Remove method to modify the sorted and recent lists.'''
        if elem.guid in self.dict:
            elem = self.dict[elem.guid] # this is the object that is present in sorted or recent
            s, r = self.sorted.index(elem), self.recent.index(elem)
            del self.sorted[s]
            del self.recent[r]
            del self.dict[elem.guid]
        assert len(self.sorted) == len(self.recent) == len(self)

    def clear(self):
        '''Override the base class's clear method to clear the sorted and recent lists.'''
        self.sorted.clear()
        self.recent.clear()
        self.dict.clear()
    
    def closest(self, guid):
        '''Return the node that has guid closest to the given guid in this cache, or None if cache is empty.'''
        if len(self)>0:
            if guid in self.dict: return self.sorted[self.dict[guid][0]] # found an exact match, return it
            first = self.sorted[0]
            last =  self.sorted[-1]
            if guid<first.guid or guid>last.guid: # not in range, return either first or last
                return distance(guid, first.guid)<distance(guid, last.guid) and first or last
            else:
                for a in xrange(0, len(self.sorted)-1):
                    first, last = self.sorted[a], self.sorted[a+1]
                    if first.guid<guid<last.guid: # found the containing range, return one of the endpoint of the range
                        return distance(guid, first.guid)<distance(guid,last.guid) and first or last
        return None
    
    def __repr__(self): # print out a printable representation
        return '<NodeCache len=%r\n    sorted=%r\n    recent=%r>'%(len(self), repr(map(lambda x: x.guid, self.sorted)), repr(map(lambda x: x.guid, self.recent)))

#------------------------------------------------------------------------------ 
# Other data structures for router
#------------------------------------------------------------------------------ 
class LatencyTable(dict):
    '''Hash table from Node to a tuple (latency, last-activity-time). It uses the guid of the node
    as the index in the table.'''
    def __init__(self):
        dict.__init__(self)
    def add(self, node, latency, time):
        self[node] = (latency, time)
    def remove(self, node):
        if node in self: del self[node]
    def get(self, node):
        return dict.get(self, node, (-1.0, 0.0))
    def isActive(self, node, validity=5.0):
        return (self[node][1]-time.time()<validity) if (node in self) else False 
    def getLatency(self, node):
        return self[node][0] if (node in self) else -1.0

class DownSet(set):
    '''Set of down nodes with a cap on maxsize. A special property, random, returns a
    random element from the set.'''
    def __init__(self, maxsize=20):
        self.maxsize = maxsize
        set.__init__(self)
    def add(self, item):
        if len(self)>=self.maxsize: self.pop() # discard an arbitrary element
        set.add(self, item)
    def remove(self, item):
        set.discard(self, item) # always call discard to disable exception if not found
    @property
    def random(self):
        if len(self) == 0: return None
        index = random.randint(0, len(self)-1)
        for item in self:
            if index == 0: return item
            index = index - 1
        return None

class PossiblyDownSet(set):
    '''Set of possibly down nodes.'''
    def __init__(self):
        set.__init__(self)
    def remove(self, item):
        set.discard(self, item) # use discard so that it doesn't throw an error
        
class ReverseRoutingTable(set):
    '''Set of nodes for which we are in their routing table.'''
    def __init__(self):
        set.__init__(self)
    def remove(self, item):
        set.discard(self, item) # use discard so that it doesn't throw an error
        
def randomsleep(timeout):
    '''Sleep for a random amound of seconds in range [0.5*timeout, 1.5*timeout].'''
    # if _debug: print 'sleeping for random T=', timeout
    yield multitask.sleep((random.random()+0.5)*timeout)

#------------------------------------------------------------------------------ 
# The main Router class to control the router logic.
#------------------------------------------------------------------------------ 
class Router(object):
    '''The router for a DHT. The application should start a router as follows.
    Once started it starts listening for specific router related messages and
    handles them. 
    
    router = Router(net).start() # net is a pre-initialized network module
    
    Once started it listens for messages such as Route:Message, Neighbor:Indication, etc
    and handles them.
    '''
    count = 0 # just to name each router with Router[count]
    
    def __init__(self, net, **kwargs):
        '''Construct a Router module for the given network net. Optionally, other properties
        such as rt, rrt, ls, cache, down, pdown, lt and bs can be supplied as keyword arguments.'''
        Router.count = Router.count + 1; self.name  = 'Router[%d]'%(Router.count)
        self.starttime = time.time() # start time of the router module
        self.initialized = False # updated when router is joined the DHT
        self.node, self.net = net.node, net
        self.rt    = kwargs.get('rt',    RoutingTable(node=self.node)) # routing table
        self.rrt   = kwargs.get('rrt',   ReverseRoutingTable()) # reverse routing table is actually a set
        self.ls    = kwargs.get('ls',    LeafSet(node=self.node)) # leaf set
        self.cache = kwargs.get('cache', NodeCache()) # node cache
        self.down  = kwargs.get('down',  DownSet())  # set of Node that are down
        self.pdown = kwargs.get('pdown', PossiblyDownSet())   # set of Node that are possibly down
        self.lt    = kwargs.get('lt',    LatencyTable())  # table with index Node and value (latency, last-activity-time)
        self.bs    = kwargs.get('bs',    list())  # list of bootstrap Node objects
        self._pings  = set() # nodes that are currently being pinged using Ping:Request or some other.
        self._queue = multitask.SmartQueue() # queue for receiving message delivered to this node
        self._gens = []      # currently active generators, started on start or later, closed on stop.
        self._ignore= set()  # the set that needs to be ignored in nextHop. Use value as self.pdown if needed.
        
        # modify the add/remove of rt, ls, pdown, lt to local methods, which pings before adding or does additional processing.
        if not hasattr(self.rt, '_origadd'): self.rt._origadd = self.rt.add
        self.rt.add = self.rtadd #new.instancemethod(rtadd, self.rt, RoutingTable)
        if not hasattr(self.ls, '_origadd'): self.ls._origadd = self.ls.add
        self.ls.add = self.lsadd #new.instancemethod(lsadd, self.ls, LeafSet)
        if not hasattr(self.ls, '_origremove'): self.ls._origremove = self.ls.remove
        self.ls.remove = self.lsremove #new.instancemethod(lsremove, self.ls, LeafSet)
        if not hasattr(self.pdown, '_origadd'): self.pdown._origadd = self.pdown.add
        self.pdown.add = self.pdownadd 
        if not hasattr(self.lt, '_origadd'): self.lt._origadd = self.lt.add
        self.lt.add = self.ltadd 
    
    def __repr__(self):
        return '<Router node=%r\n  rt=%r\n  ls=%r>'%(self.node, self.rt, self.ls)
    
    def start(self): # start the periodic ping and join tasks
        for gen in [self.handler(), self.periodicping(), self.periodicjoin()]: 
            self._gens.append(gen)
            multitask.add(gen)
        return self

    def stop(self):
        for gen in self._gens: gen.close()
        self._gens[:] = []
        return self
    
    def initialize(self): # router has joined the DHT. start other tasks.
        # TODO: send pending messages if any.
        for gen in [self.updateleafset(), self.partitioncheck(), self.updatetablenear(), self.updatetablefar()]:
            self._gens.append(gen)
            multitask.add(gen)
        return self
    
    def handler(self):
        '''Handle incoming requests for the router.'''
        supported = ['Route:Request', 'Neighbor:Indication', 'Ping:Request', 'RoutingTable:Request', 'LeafSet:Request', 'Join:Request', 'Lookup:Request', 'LeafSet:Indication']
        while True: # schedule process message, but don't wait to start new before processing previous
            msg = yield self.net.get(lambda x: x.name in supported)
            if _debug: print 'router.handler name=', msg.name
            if   msg.name == 'Route:Request':       multitask.add(self.routehandler(msg))
            elif msg.name == 'Neighbor:Indication': multitask.add(self.neighborhandler(msg))
            elif msg.name == 'RoutingTable:Request':multitask.add(self.rthandler(msg))
            elif msg.name == 'LeafSet:Indication':  multitask.add(self.leafsethandler(msg))
            elif msg.name == 'Join:Request':        multitask.add(self.joinhandler(msg))
            elif msg.name == 'Lookup:Request':      multitask.add(self.lookuphandler(msg))
            elif msg.name != 'Ping:Request' and _debug: print 'invalid message name', msg.name
    
    def ping(self, node, second=False, timeout=5):
        '''Send a Ping:Request to the given node, and wait for response. '''
        msg = Message(name='Ping:Request')
        yield self.send(msg, node=node, timeout=timeout)
    
    def send(self, msg, node, timeout=None, ping=False):
        '''Send a message to node, and also handle the success or failure response.'''
        pinging = (node in self._pings) # alreadying pinging this
        if pinging and msg.name == 'Ping:Request':
            if _debug: print 'not sending %s as already pinging'%(msg.name,) 
            return # no need to send another ping if one is in flight
        if not pinging and (timeout or ping): 
            if _debug: print 'adding node to pinging', node.guid
            self._pings.add(node) # start pinging
            pinging = True
            timeout = timeout or 5.0 # default 5 seconds
        result = yield self.net.send(msg, node=node, timeout=timeout)
        if pinging: # process the response only when timeout is specified.
            self._pings.discard(node) # remove from pinging
            if _debug: print 'ping result is', result
            if result:
                self.pdown.remove(node)
                self.down.remove(node)
                self.lt.add(node) # check if we can add it to our data structures
            elif not msg.second: # failed to send first ping
                self.cache.remove(node)
                self.lt.remove(node)
                multitask.add(self.pdown.add(node)) # in background perform second ping, and on confirmation remove the node.
    
    def periodicping(self, timeout=180):
        '''Periodically ping with a random element from routing table, reverse routing table or leaf set.
        The validity argument represents the interval in seconds, if a node is already pinged within that 
        time, it is not pinged again.'''
        while True:
            yield randomsleep(timeout)
            now = time.time()
            all = self.rt.list + list(self.rrt) + self.ls.list
            all = set(filter(lambda x: x not in self._pings and x not in self.pdown, all)) # remove those that are down or we recently pinged
            msg = Message(name='Ping:Request')
            for node in all:
                yield self.send(msg, node=node, timeout=5)
    
    def rtadd(self, node, *args, **kwargs):
        rt = self.rt
        if node not in rt:
            if node not in self.lt: # no information about the node, ping it.
                multitask.add(self.ping(node))
                node = None
            else:
                result = rt._origadd(node, *args, **kwargs)
                if result: 
                    if self.node != result: multitask.add(self.net.send(Message(name='Neighbor:Indication', node=self.node, add=False), node=result))
                    multitask.add(self.net.send(Message(name='Neighbor:Indication', node=self.node, add=True), node=node))
                node = result
        return node
        
    def lsadd(self, node): 
        if node not in self.ls:
            if node not in self.lt:
                multitask.add(self.ping(node))
                node = None
            else:
                node = self.ls._origadd(node)
        return node
        
    def lsremove(self, node):
        result = self.ls._origremove(node)
        if result != 'none':
            if len(self.ls) == 0:
                rt = self.rt
                for row in xrange(rt.rows):
                    for col in xrange(rt.columns):
                        if rt[row][col] and rt.node != rt[row][col].node and node != rt[row][col]:
                            self.ls._origadd(rt[row][col].node) 
            # TODO: how do we inform listeners (storage) that leaf set is changed?
        return result
    
    def pdownadd(self, node):
        '''Add to the possibly down nodes set.'''
        if (node not in self.pdown) and ((node in self.rt) or (node in self.ls) or (node in self.rrt)): # otherwise we don't care
            self.pdown._origadd(node)
            msg = Message(name='Ping:Request', second=True)
            result = yield self.net.send(msg, timeout=60, node=node) 
            if not result: # node is down, remove from data structures
                if _debug: print 'Router.pdownadd() node is down %r'%(node)
                self.down.add(node)
                for ds in (self.lt, self.rt, self.ls, self.rrt): # must remove from rt before ls, because ls.remove may add into ls from rt if ls is empty
                    ds.remove(node)
            else: # surprisingly, the retry worked.
                self.pdown.remove(node)
                self.down.remove(node)
                self.lt.add(node)
            raise StopIteration(not result and node or None)
        raise StopIteration(None)

    def ltadd(self, node, latency=0.0):
        '''Add to latency map, and also to other data structures if needed.'''
        self.lt._origadd(node, latency, time.time())
        self.rt.add(node)
        self.ls.add(node)
        self.cache.add(node)
        if node not in self.ls and node not in self.rt and node not in self.rrt:
            self.lt.remove(node)
        
    def join(self, bs, cached=True, timeout=30):
        '''Send a Join:Request to remote bootstrap (ns) node, and wait for response. The response is True
        for success and False or error or timeout. Internal data structures are updated on response'''
        yield self.net.send(Message(name='Join:Request', returnaddr=self.node, path=[]), node=bs)
        msg = yield self.net.get(lambda x: x.name == 'Join:Response', timeout=timeout)
        if msg and len(msg.path)>0:
            root = msg.path[-1] # last node in the path is the root for this node's guid
            self.cache.add(root) 
            for node in [root]+msg.leafset:
                if node != self.node: 
                    self.ls.add(node) # update our leafset
                    if not self.initialized: self.rt.add(node) # and routing table
            if not self.initialized:
                for node in msg.path: # add all elements in path in routing table if needed
                    if node != self.node: self.rt.add(node)
            if not self.initialized: 
                self.initialized = True # router is now initialized
                self.initialize()
        raise StopIteration(msg and True or False)
    
    def joinhandler(self, msg):
        '''Process a Join:Request msg, and either send a Join:Response, or further propagate the request.
        It updates local datastructures (rt and ls).'''
        if findNode(self.node.guid, msg.path)>=0: return  # check if we have a routing loop, then don't process.
        next = self.nextHop(msg.returnaddr.guid, useCache=False) # find next hop for source node; don't use node cache.
        if not next or next == self.node or next == msg.returnaddr: # invalid next or matches local; send response.
            old = list(self.ls.set)                # old set before updating it
            self.rt.add(msg.returnaddr)
            self.ls.add(msg.returnaddr)  # update local datastructures
            yield self.net.send(Message(name='Join:Response', path=msg.path+[self.node], leafset=old), node=msg.returnaddr)
        else:
            del msg['remote']
            msg.path.append(self.node); msg['inbound'] = False # add this node in the path
            result = yield self.net.send(msg, node=next, timeout=5)# and proxy the message to next hop
            if result: self.down.remove(next)  # request was sent successfully, remove next from down nodes.
    
    def partitioncheck(self, timeout=600, jointimeout=10):
        '''Periodically check for partition. This must be invoked only after join() is successful.
        It periodically pings the down (list) nodes, and updates our ls and cache if they respond. 
        The jointimeout is used to wait for join response, and timeout is randomized for periodicity.'''
        while True:
            yield randomsleep(timeout)
            if len(self.down)>0:
                node = self.down.random()
                result = yield self.join(bs=node, timeout=jointimeout)
                if result: self.down.remove(node)
        
    def periodicjoin(self):
        '''Periodically join using one of the bootstrap nodes.'''
        while True:
            yield randomsleep(120)
            if len(self.bs)>0 and not self.initialized:
                node = random.choice(self.bs)
                if node:
                    self.bs.remove(node)
                    self.bs.append(node)
                    result = yield self.join(node)
                    if not result:
                        self.bs.remove(node)
                        if len(self.bs)==0: self.initialized = False # no more connected to bootstrap
        
    def nextHop(self, guid, useCache=False):
        '''Return the next hop Node based on routing-table, leaf-set and optionally cache.'''
        if guid in self.ls: # guid is in leaf-set range, find the closest node in leaf set
            return self.ls.closest(guid, self._ignore)
        else:
            node = self.rt.nextHop(guid, self._ignore)
            if not node: node = self.ls.closest(guid, self._ignore)
            cached = useCache and self.cache.closest(guid) or None
            if cached and distance(cached.guid, guid)<distance(node.guid, guid): node = cached
            return node
    
    def route(self, guid, payload):
        '''Route the given msg to the destination guid using the underlying network net, based on
        the nextHop result for guid. If the next hop if local node, just delivers it to the queue of net.'''
        next = self.nextHop(guid, useCache=True)
        if not next or next == self.node: # deliver to this node
            yield self.net.put(payload)
            result = True
        else: # proxy recursively to next hop
            msg = Message(name='Route:Request', src=self.node.guid, dest=guid, payload=payload)
            result = yield self.send(msg, node=next, timeout=5)
        raise StopIteration(result)
    
    def routehandler(self, msg):
        '''Handle an incoming Route:Request.'''
        if msg.remote: self.cache.add(msg.remote)
        next = self.nextHop(guid=msg.dest, useCache=True)
        if not next or next == self.node:
            yield self.net.put(msg.payload)
        else:
            if 'remote' in msg: del msg['remote'] # remove additional parameter that was added by network
            yield self.send(msg, node=next, timeout=5)
        
    def neighborhandler(self, msg):
        '''Handle a Neighbor:Indication message by updating our reverse routing table.'''
        if msg.add == True: self.rrt.add(msg.remote)
        else: self.rrt.remove(msg.remote)
        yield 
    
    def leafsethandler(self, msg):
        '''Respond to an incoming LeafSet:Indication by optionally sending a LeafSet:Indication, 
        and performing any leaf set updates.'''
        self.cache.add(msg.remote)
        for node in msg.leafset:
            if self.ls.promising(node): 
                self.ls.add(node) # add to ls in background
        if self.ls.promising(msg.remote):
            self.ls.add(msg.remote) # add in background
        if msg.wantreply and msg.remote != self.node:
            yield self.send(Message(name='LeafSet:Indication', node=self.node, leafset=list(self.ls.set)), node=msg.remote, timeout=5, ping=True)
        yield

    def updateleafset(self, timeout=40):
        '''Periodically update the leaf set.'''
        while True:
            yield randomsleep(timeout)
            node = self.ls.random
            if node and node not in self.pdown:
                yield self.send(Message(name='LeafSet:Indication', node=self.node, leafset=list(self.ls.set), wantreply=True), node=node, timeout=5, ping=True)
        
    def rthandler(self, msg):
        '''Handle an incoming RoutingTable:Request message.'''
        if msg.level >= self.rt.rows: return # level was too high 
        node, rt = msg.remote, self.rt
        self.cache.add(node)
        nodes = []
        for col in xrange(0, rt.columns):
            if rt[msg.level][col] and self.node != rt[msg.level][col].node:
                nodes.append(rt[msg.level][col].node)
        msg = Message(name='RoutingTable:Response', node=self.node, neighbors=nodes)
        if node in self.ls or node in self.rt or node in self.rrt:
            yield self.send(msg, node=node, timeout=5)
        else:
            yield self.send(msg, node=node) # no need to wait for ack
        
    def updatetablenear(self, timeout=100):
        '''Periodically update near routing table.'''
        while True:
            yield randomsleep(timeout)
            node = self.rt.weightedRandomNode
            if len(self.rt)>0 and node and node not in self.pdown:
                yield self.send(Message(name='RoutingTable:Request', level=self.rt.weightedRandomLevel), node=node, timeout=5, ping=True)
                msg = yield self.net.get(lambda x: x.name=='RoutingTable:Response', timeout=5)
                if msg:
                    self.cache.add(node)
                    nodes = filter(lambda x: x.guid < Hmod and x != self.node and x not in self.ls and x not in self.rt, msg.neighbors)
                    if nodes: 
                        notadded = []
                        for x in nodes:
                            if self.rt.fillsHole(x):
                                self.rt.add(x)
                            else:
                                notadded.append(x)
                        if notadded:
                            x = random.choice(notadded)
                            self.rt.add(x)
                            if node != x: # do a ping to random entry so that we may discover a better node
                                yield self.send(Message(name='Ping:Request'), node=x, timeout=5)
        
    def lookuphandler(self, msg):
        '''Handle an incoming lookup message.'''
        node = msg.returnaddr
        self.cache.add(node)
        yield self.net.send(Message(name='Lookup:Response', guid=msg.guid, node=self.node), node=node)
        
    def updatetablefar(self, timeout=200):
        while True:
            yield randomsleep(timeout)
            guid = self.rt.weightedRandomKey
            if guid:
                yield self.route(guid=guid, payload=Message(name='Lookup:Request', guid=guid, returnaddr=self.node))
                msg = yield self.net.get(lambda x: x.name=='Lookup:Response', timeout=5)
                if msg: 
                    self.cache.add(msg.node)
                    yield self.rt.add(msg.node)
    
def testRouter():
    multitask.completed = False
    def jointest():
        try:
            n = [Network().start() for x in xrange(0, 10)]
            r = [Router(x).start() for x in n] 
            for ri in r[1:]:
                ri.bs = [n[0].node]
                yield ri.join(bs=n[0].node)
                yield multitask.sleep(5)
        except:
            print 'testRouter.jointest() didnot pass'
            traceback.print_exc()
        yield multitask.sleep(600) # check if all updates go fine?
        multitask.completed = True
        
    multitask.add(jointest())
    while not multitask.completed: 
        multitask.get_default_task_manager().run_next()

#===============================================================================
# The Storage logic for in-memory database. It uses a simple data synchronization
# algorithm for replication. 
#===============================================================================

class Key(object):
    def __init__(self, **kwargs):
        _fmt = '!LLLLB%ds%ds%ds%ds'%(Hsize, Hsize, Hsize, Hsize)
        _fmtindex = '!%ds%ds%ds%ds'%(Hsize, Hsize, Hsize, Hsize) 
        if 'value' in kwargs: # need to parse
            self.str = kwargs.get('value')
            t1, t2, e1, e2, put, guid, hash, nonce, owner = struct.unpack(_fmt, self.str)
            self.time, self.expires = long(t1*(2**32)+t2), long(e1*(2**32)+e2)
            self.put = (put != 0)
            self.guid, self.hash, self.nonce, self.owner = bin2int(guid), bin2int(hash), bin2int(nonce), bin2int(owner)
        else: # need to construct from individual fields
            for n in ('time', 'expires', 'put', 'guid', 'hash', 'nonce', 'owner', 'client'):
                exec 'self.%s = kwargs.get("%s", None)'%(n,n)
            self.time = long(self.time); self.expires = long(self.expires)
            t1, t2, e1, e2 = int(self.time/(2**32)), int(self.time%(2**32)), int(self.expires/(2**32)), int(self.expires%(2**32))
            put = (self.put and 1 or 0)
            guid, hash, nonce, owner = int2bin(self.guid), int2bin(self.hash), int2bin(self.nonce), int2bin(self.owner)
            self.str = struct.pack(_fmt, t1, t2, e1, e2, put, guid, hash, nonce, owner)
            if len(self.str) != 97: raise ValueError, 'invalid length of the key %d'%(len(self.str))
        self.index = struct.pack(_fmtindex, int2bin(self.guid), int2bin(self.hash), int2bin(self.nonce), int2bin(self.owner))
    def __repr__(self): 
        return '<Key time=%r expires=%r put=%r guid=%r hash=%r nonce=%r owner=%r>'%(self.time, self.expires, self.put, self.guid, self.hash, self.nonce, self.owner)
    def __str__(self): return self.str
    def __cmp__(self, other): return 0 if id(self) == id(other) else cmp(self.str, other.str)
    def __hash__(self): return self.str.__hash__()
     
class Value(object):
    def __init__(self, **kwargs):
        if 'raw' in kwargs:
            raw = kwargs.get('raw')
            l, = struct.unpack('!H', raw[:2]); self.value, raw = raw[2:2+l], raw[2+l:]
            l, = struct.unpack('!H', raw[:2]); self.hash, raw = bin2int(raw[2:2+l]), raw[2+l:]
            l, = struct.unpack('!H', raw[:2]); self.Kp, raw = PublicKey(value=raw[2:2+l]), raw[2+l:]
            l, = struct.unpack('!H', raw[:2]); self.sigma, raw = raw[2:2+l], raw[2+l:]
        else:
            for n in ('value', 'hash', 'Kp', 'sigma'):
                exec 'self.%s = kwargs.get("%s", None)'%(n,n)
        if isinstance(self.value, long): print 'Incorrect Value(value=%r)'%(self.value)
    def __repr__(self): return '<value value-len=%d hash=%r Kp=%r sigma=%r, value=%r>'%(len(self.value) if self.value else 0, self.hash, self.Kp, self.sigma, self.value)
    def __len__(self): return len(str(self))
    def __str__(self):
        value, hash, Kp, sigma = str(self.value), int2bin(self.hash), str(self.Kp), str(self.sigma)
        return struct.pack('!H', len(value)) + value + struct.pack('!H', len(hash)) + hash + struct.pack('!H', len(Kp)) + Kp + struct.pack('!H', len(sigma)) + sigma 

# TODO: see TODO.txt on why I didn't use sqlite3 for now.
class Database(object):
    '''A database abstraction using python sqlite3.'''
    def __init__(self):
        self._data, self._guid, self._uniq = dict(), dict(), dict()
    def __del__(self):
        del self._data, self._guid, self._uniq
    def __repr__(self):
        return '<Database count=%d>'%(len(self._data))
    
    def clear(self):
        self._data.clear(); self._guid.clear(); self._uniq.clear()
        
    def put(self, key, value):
        '''Put a key, value pair.'''
        if key in self._data: return (None, None, None, None) # successful
        self._cleanup(key.guid)
        toput, result = self._remove(key, value)
        if toput: 
            self._data[key] = value
            self._put(key, value)
        if _debug: print 'db.put(key=%r,value=%r) returns %r'%(key, value, result)
        return result

    def _cleanup(self, guid):
        if guid not in self._guid: return
        now, o, oc = time.time(), self._guid[guid], 0
        for oi in o.keys():
            v, vc = o[oi], 0
            for vi in v.keys():
                i = v.get(vi, None)
                d = self._data[i] if (i is not None and i in self._data) else None
                if d is not None and i.expires<now:
                    del self._data[i]
                    del v[vi]
                else: vc = vc + 1
            if vc == 0: del o[oi]
            else: oc = oc + 1
        if oc == 0: del self._guid[guid]
       
    def _remove(self, key, value):
        if key.index not in self._uniq: return (True, (None, None, None, None))
        i = self._uniq[key.index]
        v = self._data[i]
        if v is None: del self._uniq[key.index]; return (True, (None, None, None, None))
        oldkey, oldvalue = i, v
        toput = True
        toremove = not True
        if key == oldkey: toput = False; result=(None, None, None, None)
        else:
            if key.put and oldkey.put: 
                if key.expires <= oldkey.expires: toput = False; result = (key, value, None, None)
                else: toremove = True; result = (oldkey, oldvalue, None, None)
            elif not key.put and not oldkey.put:
                if key.expires <= oldkey.expires: toput = False; result = (None, None, key, value)
                else: toremove = True; result = (None, None, oldkey, oldvalue)
            elif key.put and not oldkey.put: toput = False; result = (key, value, None, None)
            elif not key.put and oldkey.put: toremove = True;  result = (oldkey, oldvalue, None, None)
        if toremove:
            del self._data[i]
            del self._uniq[key.index]
        return (toput, result)
    
    def _put(self, key, value):
        self._uniq[key.index] = key
        if key.guid in self._guid: o = self._guid[key.guid]
        else: o = self._guid[key.guid] = dict()
        owner = key.owner or randomNonce()
        if owner in o: v = o[owner]
        else: v = o[owner] = dict()
        i = int2bin(key.hash) + int2bin(key.nonce)
        if i in v and v[i] != key and v[i] in self._data: del self._data[v[i]]
        v[i] = key

    def get(self, guid, owner=None, maxvalues=32):
        '''Get all the key-values for the guid, optionally for the given owner, with a cap of maxvalues.'''
        self._cleanup(guid)
        result = []
        if guid not in self._guid: return result
        o = self._guid[guid]
        if owner is None: v = set(sum(map(lambda x: x.values(), o.values()), []))
        else: v = set(sum(o[owner].values(), [])) if owner in o else set()
        result = map(lambda y: (y, self._data[y]), filter(lambda x: x in self._data and x.put, v))
        if _debug: print 'db.get(guid=%r,owner=%r,maxvalues=%r) returns %r'%(guid, owner, maxvalues, result)
        return result
    
    def getkeys(self, low, high):
        '''Get all the keys in the range [low, high).'''
        if low<=high: guids = sorted(filter(lambda x: low<=x<=high, self._guid.keys()))
        else: guids = sorted(filter(lambda x: x>=low, self._guid.keys())) + sorted(filter(lambda x: x<=high, self._guid.keys()))
        now = time.time()
        return filter(lambda y: y.expires>=now, sum(map(lambda z: sum(map(lambda w: w.values(), self._guid[z].values()), []), guids), []))
        
    def getvalue(self, key):
        '''Get the value for the specific key.'''
        return self._data.get(key, None)
    def discard(self, key):
        '''Remove the specific key.'''
        if key in self._data: del self._data[key]

def _testDatabase():
    db = Database()
    k1 = Key(time=time.time(), expires=time.time()+60, put=True, guid=10, hash=10, nonce=10, owner=10)
    v1 = Value(value='kundan', Kp='empty', sigma='empty')
    k2 = Key(time=time.time(), expires=time.time()+60, put=True, guid=10, hash=10, nonce=11, owner=10)
    v2 = Value(value='kundan2', Kp='empty', sigma='empty')
    assert db.put(k1, v1) == (None, None, None, None)
    assert db.put(k1, v1) == (None, None, None, None) # duplicate put
    k11 = Key(time=time.time(), expires=time.time()+120, put=True, guid=10, hash=10, nonce=10, owner=10)
    assert db.put(k11, v1) == (k1, v1, None, None) # override expired
    assert db.put(k2, v2) == (None, None, None, None) # add new value
    assert sorted(db.get(k1.guid)) == sorted([v1, v2])
    assert db.getvalue(k11) == v1
    assert sorted(db.getkeys(low=0, high=20)) == sorted([k11, k2])

class Range(object):
    '''A range object that also stores the nodes with which we have synchronized.'''
    def __init__(self, low, high):
        if low is None or high is None: raise ValueError('Invalid Range[%r, %r]'%(low, high))
        self.low, self.high = low, high
        self._str = '%d-%d'%(low, high)
        self.sync = dict() # hash table with key as Node and value as last sync or expiration time.
        self.hash = 0L     # hash of all keys in range
        self.keys = []     # list of all keys in range
    def __cmp__(self, other):
        if id(self) == id(other): return 0 # a shortcut to compare identical objects
        else: return cmp(self.low, other.low) or cmp(self.high, other.high)
    def __hash__(self): return self._str.__hash__()
    def __repr__(self): return self._str

class Ranges(dict):
    '''A set of range objects. The values are mutable, hence a get(key) method can be used to
    get the original range in the set where key is a Range.'''
    def __init__(self):
        dict.__init__(self)   # base class stores the set representation
        self.sorted = []      # sorted list of Range
    def add(self, range): 
        if range not in self:
            self[range] = range
            s = find(lambda x: range.low < x.low or (range.low==x.low and range.high<x.high), self.sorted) # insert in sorted list
            self.sorted.insert(s if s>=0 else len(self.sorted), range)
        else:
            s = self.sorted.index(self[range])
            self.sorted[s] = self[range] = range # update the value with new range
    def remove(self, range):
        if range in self:
            self.sorted.remove(self[range])
            del self[range]
    def clear(self):
        self.sorted.clear()
        dict.clear(self)

    def synched(self, guid, node, ls):
        s = find(lambda x: x.low<=guid<=x.high, self.sorted)
        if node: return (s>=0) and (node in self.sorted[s].sync) or False
        elif not ls or len(ls)==0: return True # always synced if no leafset
        else: return (s>=0) and (len(self.sorted[s].sync)>len(ls)) or False # return true if we synched with more than half of leaf set
    
    def update(self, ls):
        '''Update the ranges by removing those which are not in leaf-set.'''
        sorted, ranges = ls.sorted, set()
        if sorted:
            for i in xrange(0, len(sorted)-1):
                a, b = sorted[i], sorted[i+1]
                ranges.add((a.guid, (b.guid+Hmod-1)%Hmod))
        toremove = filter(lambda x: (x.low, x.high) not in ranges, self.sorted)
        for r in toremove: self.remove(r)

    def invalidate(self, guid):
        '''Invalidate all the ranges which covers the guid.'''
        try:
            for range in filter(lambda x: inrange(x.low, x.high, guid), self.sorted):
                range.hash = None
        except:
            print 'invalidate exception. guid=%r'%(guid) 
            traceback and traceback.print_exc()
             
class Storage(object):
    '''A Storage controller that performs replication as well as interfacing with backend database.'''
    def __init__(self, net, router, replicas=8, required=5):
        '''Construct a storage using the given network and router. The router object is required 
        because the storage needs to perform periodic discard of data to remote peers and keep track
        of change in router's leafset.'''
        self.node, self.net, self.router, self.ls = net.node, net, router, router.ls
        self.replicas, self.required = (replicas/2)*2, required # make it even
        self.low, self.high, self.ranges = 0L, (Hmod-1), Ranges()
        self._gens, self.db = [], Database()
        
    def __repr__(self):
        return '<Storage node=%r\n  data=%r>'%(self.node, self.db)
    
    def start(self):
        for gen in [self.handler(), self.periodicantropy(), self.periodicdiscard()]:
            self._gens.append(gen)
            multitask.add(gen)
        return self
    
    def stop(self):
        for gen in self._gens: gen.close()
        self._gens[:] = []
        self.db.clear()
        return self
    
    def handler(self):
        supported = ['Put:Request', 'Get:Request', 'Replicate:Request', 'ReplicaSet:Request', 'Hash:Request', 'Keys:Request', 'Data:Request']
        while True:
            msg = yield self.net.get(lambda x: x.name in supported)
            if _debug: print 'storage.handler name=', msg.name
            if msg.name == 'Put:Request': multitask.add(self.puthandler(msg))
            elif msg.name == 'Get:Request': multitask.add(self.gethandler(msg))
            elif msg.name == 'Replicate:Request': multitask.add(self.replicatehandler(msg))
            elif msg.name == 'Hash:Request': multitask.add(self.hashhandler(msg))
            elif msg.name == 'Keys:Request': multitask.add(self.keyshandler(msg))
            elif msg.name == 'Data:Request': multitask.add(self.datahandler(msg))
            elif msg.name == 'ReplicaSet:Request': multitask.add(self.rshandler(msg))
            elif _debug: print 'invalid message', msg.name

    def puthandler(self, msg, timeout=60, defaultTTL=600):
        '''Handle a put request with items time, seq, guid, value or hash, nonce, expires, put, 
        Kp and sigma. On completion put a Put:Response message with result=True or False.
        '''
        try:
            start = time.time()
            value, hash = msg.value, msg.hash
            if value is not None and hash is not None and hash != H(str(value)):
                raise ValueError, 'invalid hash for the value'
            if value is None and hash is None:
                raise ValueError, 'value and hash are both missing'
            if hash is None and value is not None:
                hash = H(str(value))
            owner = msg.Kp and H(str(msg.Kp)) or 0 # owner's identity

            replicas = self.replicaNodes(msg.dest)
            if not msg.time: msg['time'] = start
            if not msg.expires: msg['expires'] =  msg.time + defaultTTL
            
            key = Key(time=msg.time, expires=msg.expires, put=msg.put, guid=msg.dest, hash=hash, nonce=msg.nonce, owner=owner)
            value = Value(value=value, hash=hash, Kp=msg.Kp, sigma=msg.sigma)
            self.ranges.invalidate(key.guid)
            p, q, r, s = (yield self.db.put(key, value))[:4]
            if p: self.ranges.invalidate(p.guid)
            if r: self.ranges.invalidate(r.guid)
        
            if not replicas:
                raise ValueError, 'no replica node available'
            msg, seq = msg.dup(), msg.seq
            msg.name = 'Replicate:Request'
            msg['guid'] = msg.dest  # TODO: this was added because guid was needed in replicate request
            global _seq; _seq = _seq + 1; msg.seq = _seq
            if _debug: print 'replicate as %r'%(msg)
            for node in replicas:
                yield self.net.send(msg, node=node)
            while len(replicas)>(self.replicas-self.required): # wait for more responses
                resp = yield self.net.get(lambda x: x.name=='Replicate:Response' and x.seq==msg.seq, timeout=(timeout-(time.time()-start)))
                if not resp: # timed out waiting for response
                    raise ValueError, 'timedout waiting for replication'
                elif resp.remote in replicas:
                    replicas.remove(resp.remote)
                    
            # response is sent directly to the source
            yield self.net.send(Message(name='Put:Response', seq=seq, result=True), node=msg.src) 
        
        except ValueError, E:
            if _debug: print 'puthandler exception', E
            try: yield self.net.send(Message(name='Put:Response', seq=msg.seq, result=False, error=str(E)), node=msg.src)
            except: pass
        except: traceback and traceback.print_exc()
    
    def replicatehandler(self, msg):
        '''Handle a Replicate:Request message.'''
        try:
            start = time.time()
            value, hash, Kp, sigma = msg.value, msg.hash, msg.Kp, msg.sigma
            if value is not None and hash is not None and hash != H(str(value)):
                raise ValueError, 'invalid hash for the value'
            if value is None and hash is None:
                raise ValueError, 'value and hash are both missing'
            if hash is None and value is not None:
                hash = H(str(value))
            owner = Kp and H(str(Kp)) or None # owner's identity

            key = Key(time=msg.time, expires=msg.expires, guid=msg.guid, hash=hash, nonce=msg.nonce, owner=owner)
            value = Value(value=value, hash=hash, Kp=Kp, sigma=sigma)
            self.ranges.invalidate(key.guid)
            p, r = (yield self.db.put(key, value))[:2]
            if p: self.ranges.invalidate(p.guid)
            if r: self.ranges.invalidate(r.guid)
            
            yield self.net.send(Message(name='Replicate:Response', seq=msg.seq), node=msg.remote)
        
        except ValueError, E:
            if _debug: print 'replicatehandler exception', E
            try: yield self.net.send(Message(name='Replicate:Error', seq=msg.seq, error=str(E)), node=msg.remote)
            except: pass
        except: traceback and traceback.print_exc()

    def gethandler(self, msg):
        '''Handle a Get:Request with items seq, guid, and optional owner.'''
        keyvals = yield self.db.get(guid=msg.dest, owner=msg.owner, maxvalues=msg.maxvalues)
        vals = [v for k, v in keyvals]
        keyss = [k for k, v in keyvals]
        yield self.net.send(Message(name='Get:Response', seq=msg.seq, guid=msg.dest, vals=vals, keyss=keyss), node=msg.src) # send response directly to the source
    
    def leafsetchanged(self):
        '''The routers' leafset changed, hence the replicas for data also changed.'''
        ls = self.router.ls
        if len(ls) == 0:
            self.low, self.high = 0, (Hmod-1)
            self.ranges.clear()
            return
        if ls.coversAll(self.replicas):
            self.low, self.high = 0, (Hmod-1)
            self.ranges.clear()
        else:
            size = min(len(ls), self.replicas/2)
            self.low, self.high = ls._preds[size-1].guid, (ls._succs[size-1].guid-1)
            if self.high == -1: self.high = (Hmod-1)
            self.ranges.update(ls=self.ls)

    def periodicantropy(self, timeout=3, reset=30):
        global _seq 
        while True:
            yield randomsleep(timeout)
            start = time.time()
            node = self.ls.random
            if not node: continue   # no leaf set node
            ranges = self.getSharedRanges(node.guid)
            if not ranges: continue # no shared range
            range = random.choice(ranges.keys())
            keys = yield self.db.getkeys(low=range.low, high=range.high)
            hash = H(''.join(map(str, keys))) # hash of all the keys in the range
            seq = _seq = _seq + 1
            yield self.net.send(Message(name='Hash:Request', seq=seq, low=range.low, high=range.high, hash=hash), node=node)
            msg = yield self.net.get(lambda x: x.name=='Hash:Response' and x.seq==seq, timeout=(reset-time.time()+start))
            if not msg: # timedout
                self.unsynched(range=range, node=node)
                continue
            if msg.hash == hash: # we are in sync
                self.synched(range=range, node=node)
                continue
            else:
                seq = _seq = _seq+1
                yield self.net.send(Message(name='Keys:Request', seq=seq, low=range.low, high=range.high), node=node)
                msg = yield self.net.get(lambda x: x.name=='Keys:Response' and x.seq==seq, timeout=(reset-time.time()+start))
                if not msg or not msg.keyss:
                    self.unsynched(range=range, node=node)
                    continue
                try:
                    remotekeys = filter(lambda y: find(lambda x: str(x)==str(y), keys)<0, msg.keyss) # all keys in msg which are not in local keys
                except: 
                    if _debug: print 'msg.keys=', msg.keyss, 'keys=', keys
                    raise 
                for key in remotekeys: # for each unmatched key, synchronize the data.
                    seq = _seq = _seq + 1
                    yield self.net.send(Message(name='Data:Request', seq=seq, key=key), node=node)
                    msg = yield self.net.get(lambda x: x.name=='Data:Response' and x.seq==seq, timeout=(reset-time.time()+start))
                    if msg and msg.key.expires > time.time(): # not yet expired key
                        valid = True 
                        if not msg.key.put: # a remove record
                            hash = H(str(msg.value))
                            if hash != msg.key.hash: valid = False
                        if valid:
                            self.unsynched(range=range, node=node)
                            ranges.invalidate(msg.key.guid)
                            if msg.key.put: value = Value(value=msg.value, Kp=msg.Kp, sigma=msg.sigma)
                            else: value = Value(hash=msg.hash, Kp=msg.Kp, sigma=msg.sigma)
                            yield self.db.put(msg.key, value)
    
    def synched(self, range, node):
        '''The data in this range is synchronized with the given node.'''
        if range not in self.ranges: self.ranges.add(range)
        else: range = self.ranges.get(range)
        size = len(self.ls)
        n = 4*size*size*3
        t = math.ceil(n*math.log(n)/math.log(2))
        range.sync[node] = time.time() + t
        # yield multitask.sleep(t) # TODO: check why this is needed, and then uncomment
        # if node in range.sync and time.time()>=range[node]:
        #    del range.sync[node.hostport]
            
    def unsynched(self, range, node):
        '''The data in this range is not synchronized with the given node.'''
        if range in self.ranges:
            try: del self.ranges.get(range).sync[node]
            except KeyError: pass # ignore if not found.
            
    def getSharedRanges(self, guid):
        ret = Ranges()
        ls = self.ls
        if ls.coversAll(self.replicas):
            ret.add(Range(0, Hmod-1))
            return ret
        low = high = 0L
        for i in xrange(0, len(ls)):
            if guid == ls._succs[i].guid:
                low, high = (0 if (i==len(ls)-1) else (-len(ls)+i+1)), len(ls)
                break
            elif guid == ls._preds[i].guid:
                low, high = -len(ls), (0 if (i==len(ls)-1) else (len(ls)-i-1))

        guid = self.node.guid
        for j,k in map(lambda x: (x, x+1), xrange(low, high)):
            a = guid if j==0 else (ls._preds[-j-1].guid if j<0 else ls._succs[j-1].guid)
            b = guid if k==0 else (ls._preds[-k-1].guid if k<0 else ls._succs[k-1].guid)
            b = b-1
            if b==-1: b = (Hmod-1)
            ret.add(Range(a,b))
        return ret
    
    def hashhandler(self, msg):
        node, range = msg.remote, Range(low=msg.low, high=msg.high)
        ranges = self.getSharedRanges(node.guid)
        if len(self.ls)==0 or len(ranges)==0 or (range not in ranges): # not a valid range with this node
            yield self.net.send(Message(name='Hash:Response', seq=msg.seq, error='invalid range'), node=node)
            return
        keys = yield self.db.getkeys(low=range.low, high=range.high)
        if range not in self.ranges: self.ranges.add(range)
        else: range = self.ranges.get(range)
        hash = H(''.join(map(str, keys)))
        yield self.net.send(Message(name='Hash:Response', seq=msg.seq, hash=hash), node=node)
    
    def keyshandler(self, msg):
        node = msg.remote
        range = Range(low=msg.low, high=msg.high)
        if range in self.ranges:
            range = self.ranges.get(range)
            keys = yield self.db.getkeys(low=range.low, high=range.high)
            # TODO: send response in multiple messages with a cap of number of keys per response.
            yield self.net.send(Message(name='Keys:Response', seq=msg.seq, keyss=keys), node=node)
        else:
            yield self.net.send(Message(name='Keys:Response', seq=msg.seq, error='invalid range'), node=node)

    def datahandler(self, msg):
        node = msg.remote
        value = yield self.db.getvalue(key=msg.key)
        if value.value is not None: 
            yield self.net.send(Message(name='Data:Response', seq=msg.seq, key=msg.key, value=value), node=node)

    def periodicdiscard(self, timeout=5):
        global _seq
        while True:
            yield randomsleep(timeout)
            if self.ls.coversAll(self.replicas): continue # no need to discard if we cover all
            keys = yield self.db.getkeys(low=self.ls['high'].guid, high=self.ls['low'].guid) # get keys in inverse range
            keys = filter(lambda x: not inrange(self.low, self.high, x.guid), keys)
            for key in keys:
                seq = _seq = _seq + 1
                yield self.route(guid=key.guid, payload=Message(name='ReplicaSet:Request', seq=seq, src=self.node.guid, dest=key.guid))
                msg = yield self.net.get(lambda x: x.name=='ReplicaSet:Response' and x.seq==seq, timeout=timeout)
                replicas = msg.nodes
                if replicas:
                    node = random.choice(replicas)
                    value = yield self.db.getvalue(key=key)
                    seq = _seq = _seq + 1
                    yield self.net.send(Message(name='Replicate:Request', time=key.time, seq=seq, guid=key.guid, value=value.value, hash=key.hash, nonce=key.nonce, expires=key.expires, put=key.put, owner=key.owner, Kp=value.Kp, sigma=value.sigma), node=node)
                    msg = yield self.net.get(lambda x: x.name=='Replicate:Response' and x.seq==seq)
                    if msg: # received a response
                        yield self.db.discard(key=key)

    def rshandler(self, msg):
        replicas = [self.node] + list(self.replicaNodes(msg.dest))
        yield self.route(guid=msg.src, payload=Message(name='ReplicaSet:Response', seq=msg.seq, nodes=replicas))


    def replicaNodes(self, guid):
        ls, size, replicas = self.ls, len(self.ls), set()
        if size>0:
            if _debug: print 'replicaNodes', ls._preds[0].guid, self.node.guid, guid
            for i in xrange((size-1) if inrange(ls._preds[0].guid, self.node.guid, guid) else (size-2), -1, -1):
                replicas.add(ls._preds[i])
            for i in xrange((size-1) if inrange(ls._succs[0].guid, self.node.guid, guid) else (size-2), -1, -1):
                replicas.add(ls._succs[i])
        return replicas
    
#===============================================================================
# High level DHT (hash table) API such as put and get. The remove is done using
# the put function with argument put=False.
#===============================================================================

def put(net, guid, value, nonce, expires, Ks=None, put=True, timeout=30, retry=7):
    '''Put the given (guid, value) pair with given expiration and for owner represented
    by the private key Ks. The nonce identifies this instance of put value, and is used
    in removing or replacing this value.
    If the put argument is False, it removes the given (guid, value) pair which was 
    originally written by owner with private key Ks and with specified nonce. The 
    expires should be greater than or equal to the expires of the corresponding put value.
    
    result = yield put()
    '''
    global _seq
    seq = _seq = _seq + 1
    request = Message(name='Put:Request', date=time.time(), seq=seq, src=net.node, dest=guid, nonce=nonce, expires=expires, put=put, \
                value=str(value), hash=H(str(value)), Kp=Ks and extractPublicKey(Ks) or None, \
                sigma=sign(Ks, H(str(guid) + str(value) + str(nonce) + str(expires))) if Ks else None) 

    while retry>0:
        yield net.put(Message(name='Route:Request', src=net.node, dest=guid, payload=request), timeout=5)
        response = yield net.get(timeout=timeout, criteria=lambda x: x.seq==seq and x.name=='Put:Response') # wait for response
        if response: raise StopIteration(response.result)
        else: retry = retry - 1
    raise StopIteration(False) # exhausted all retries

def remove(net, guid, value, nonce, expires, Ks=None, timeout=30, retry=7):
    '''A convinience method that just invokes put(..., put=False,...).'''
    result = yield put(net, guid, value, nonce, expires, Ks, False, timeout, retry)
    raise StopIteration(result)

def get(net, guid, maxvalues=16, Kp=None, timeout=5):
    '''This is an function that returns all the values for the given guid. 
    A maximum of maxvalues values are returned, defaults to 16. If Kp is specified
    then only values by the owner with public key Kp are fectched.
    
    results = yield get(H(key))
    for value, nonce, Kp, expires in results:
        do something
    '''
    global _seq
    seq = _seq = _seq + 1
    request = Message(name='Get:Request', seq=seq, src=net.node, dest=guid, maxvalues=maxvalues, hash=Kp and H(str(Kp)) or None)
    
    retry = 1 # we don't do retries for get, hence set this to 1.
    while retry>0:
        yield net.put(Message(name='Route:Request', src=net.node, dest=guid, payload=request), timeout=5)
        response = yield net.get(timeout=timeout, criteria=lambda x: x.seq == seq and x.name =='Get:Response') # wait for response
        if response:
            result = [(v.value, k.nonce, v.Kp, k.expires) for k, v in zip(response.get('keyss', [None]*len(response['vals'])), response['vals'])]
            raise StopIteration(result) # don't use response.values as it is a built-in method of base class dict of Message.
        else: retry = retry - 1
    raise StopIteration([]) # exhausted all retries

def _testDHT():
    n1, n2 = Network().start(), Network().start()
    Storage(n1, Router(n1).start()).start()
    yield put(net=n1, guid=H('kundan'), value='Kundan Singh', nonce=randomNonce(), expires=time.time()+60, Ks=PrivateKey())
    data = yield get(net=n1, guid=H('kundan'))
    print 'got value=', data


import linecache, random, sys

def traceit(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals["__file__"]
        if filename == "<stdin>":
            filename = "dht.py"
        #if lineno > 288 and filename.find('rfc3261')>=0:
        if lineno >= 1405 and lineno <= 1465 and filename.find('dht.py')>=0:
            if (filename.endswith(".pyc") or
                filename.endswith(".pyo")):
                filename = filename[:-1]
            name = frame.f_globals["__name__"]
            line = linecache.getline(filename, lineno)
            print "%s:%s: %s" % (name, lineno, line.rstrip())
    return traceit

#sys.settrace(traceit)
#multitask.add(_testDHT())
#multitask.run()
#exit()
        
#--------------------------------------- Testing --------------------------

_apps = dict()
def start(app=None, options=None):
    '''Start the module.'''
    global _apps
    if app in _apps: raise IndexError, 'dht already started'
    n = Network().start()
    r = Router(n).start()
    s = Storage(n, r).start()
    _apps[app] = (n, r, s)
    return n # return the network so that application can call get/put on that.
    
def stop(app=None):
    '''Stop the module.'''
    global _apps
    if app not in _apps: raise IndexError, 'dht not started'
    n, r, s = _apps[app]
    del _apps[app]
    s.stop(); r.stop(); n.stop()
    
if __name__ == '__main__':
    import doctest
    doctest.testmod()    # first run doctest,
    for f in dir():      # then run all _test* functions
        if str(f).find('_test') == 0 and callable(eval(f)):
            exec f + '()'
    
'''
    start()
    try:
        multitask.run()
    except KeyboardInterrupt:
        pass
    stop()
    sys.exit()
'''
