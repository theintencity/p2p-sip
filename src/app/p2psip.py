# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.

'''
Implements a P2P-SIP adaptor and related components. The basic idea is derived from my earlier
work on SIPpeer and P2P-SIP as documented in the following papers, however the software is
completely independent:

[1] K.Singh and H.Schulzrinne, Peer-to-peer Internet telephony using SIP, NOSSDAV, 2005
    http://www1.cs.columbia.edu/~kns10/publication/sip-p2p-short.pdf
[2] K.Singh and H.Schulzrinne, SIPpeer: a session initiation protocol (SIP)-based peer-to-peer 
    Internet telephony client adaptor, Columbia University Implementation Report 2004, 
    http://www1.cs.columbia.edu/~kns10/publication/sip-p2p-design.pdf
[3] K.Singh and H.Schulzrinne, Using an external DHT as a SIP location service, Columbia University
    Technical Report, 2006. http://mice.cs.columbia.edu/getTechreport.php?techreportID=388
[4] K.Singh, Hello2web: a web-based Internet telephony client, a class project done in 2000.
    http://www1.cs.columbia.edu/~kns10/software/helloweb/
    
The high-level overview is as follows: the adaptor acts as a SIP-to-SIP gateway, and allows 
you to use your favorite SIP user agent to connect to the locally running adaptor. The adaptor
then uses P2P module to perform lookup and storage of contact information, along with other
information such as cryptographic credentials. An incoming REGISTER request from your UA
is translated into a P2P put operation that stores your contact information. Any other SIP request
from your UA is translated into a P2P get (lookup) operation for the destination, and then the
request is routed to that destination.

The implementation takes care of any NAT and firewall traversal issues in the signaling and
media path. In particular, it uses existing P2P nodes as relays if needed and performs a 
combination of various NAT traversal protocols such as STUN, TURN and ICE.

For security reasons, the default implementation can accept local user agent only from localhost
i.e., IP address of 127.0.0.1. The implementation allows both TCP and UDP for the local user agent
but uses only UDP on the Internet side. This is to facilitate easy NAT traversal on the Internet.
The implementation also allows a broken SIP message from the local user agent. This allows writing
simple clients, e.g., from web, without involving the complete SIP stack. The simplification
is as follows:

If the local user agent connects to the adaptor over TCP, then the user agent does not need to do 
any request retransmission. The TCP connection can remain persistent for the duration of the
registration. All request and response are exchanged on this TCP connection. If there is no
Expires header in the REGISTER request, then the adaptor assumes the registration
to be valid as long as the TCP connection is valid. If there is no Contact header in the 
REGISTER request, then the adaptor picks one based on local IP, else it may acts as a stateless
or stateful SIP proxy. 

If the local user agent connects to the adaptor using UDP, then the user agent does need to do
request retransmissions as per SIP. However, the adaptor performs periodic keep-alive using
OPTIONS to check the status of the user agent, and unregisters the user if the user agent
is found to be not alive, unless the original REGISTER was done with Expires of a day or more,
in which case the registration is assumed to be persistent for that duration.

Because of the design, the adaptor can be readily used as a P2P-SIP proxy as described in my
paper [1]. However, you must remove the restriction of only local user agent connection to allow
it to be a general purpose proxy used in a server farm.
'''

from __future__ import with_statement
import os, sys, socket, time, traceback, types

if __name__ == '__main__': # hack to add other libraries in the sys.path
    f = os.path.dirname(sys.path.pop(0))
    sys.path.append(f)
    sys.path.append(os.path.join(f, 'external'))

import multitask
from contextlib import closing
from std import rfc3261
from app import p2p, dht
from std.rfc2396 import Address
from std.rfc3261 import Stack, Message, Header, UserAgent, Proxy, TransportInfo
from std.rfc2617 import createAuthenticate
from std.kutil import getlocaladdr, Timer
from app.p2p import ServerSocket, H

_debug = False

class AbstractAgent(object):
    '''This is an abstract base class to connect SIP and location lookup. In particular, it creates listening
    SIP ports, and uses a location dictionary to store user contacts. The actual sub-class must override the
    self.location property to modify the storage layer (to P2P or database) and the onREGISTER, onINVITE,
    onRequest methods to modify the call routing.'''
    def __init__(self, sipaddr=('127.0.0.1', 5062), stack=Stack):
        '''Construct a new Agent. sipaddr argument indicates the listening address for incoming 
        local SIP connections and messages on both UDP and TCP. It initializes the local members.'''
        if _debug: print 'starting agent on', sipaddr
        self.conn = dict() # table indexed by (host, port) and value as connected TCP socket.
        self.location = dict() # table indexed by str(uri) and value as list of Contact Header objects.
        sock = socket.socket(type=socket.SOCK_DGRAM); sock.bind(sipaddr)
        self.udp = stack(self, TransportInfo(sock)); self.udp.sock = sock
        sock = socket.socket(type=socket.SOCK_STREAM); sock.bind(sipaddr); sock.listen(5)
        self.tcp = stack(self, TransportInfo(sock)); self.tcp.sock = sock
        
        self._gens = []
    
    def __del__(self):
        '''Delete the object and internal member references.'''
        try: 
            self.udp.sock.close(); self.tcp.sock.close();
            del self.p2p, self.udp, self.tcp, self._gens
        except: pass
            
    def start(self):
        '''Start the agent.'''
        for gen in [self._sipreceiver(self.udp), self._sipreceiver(self.tcp)]: self._gens.append(gen); multitask.add(gen)
        return self
    
    def stop(self):
        '''Stop the agent.'''
        for gen in self._gens: gen.close();
        self._gens[:] = []
        return self
    
    def _sipreceiver(self, stack, maxsize=16386):
        '''Handle the messages or connections on the given SIP stack's socket, and pass it to the stack
        so that stack can invoke appropriate callback on this object such as receivedRequest.'''
        sock = stack.sock
        def tcpreceiver(sock, remote): # handle the messages on the given TCP connection.
            while True:
                data = yield multitask.recv(sock, maxsize)
                if _debug: print '%r=>%r on type=%r\n%s'%(remote, sock.getsockname(), sock.type, data)
                if data: stack.received(data, remote)
        while True:
            if sock.type == socket.SOCK_DGRAM:
                data, remote = yield multitask.recvfrom(sock, maxsize)
                if _debug: print '%r=>%r on type=%r\n%s'%(remote, sock.getsockname(), sock.type, data)
                if data: stack.received(data, remote)
            elif sock.type == socket.SOCK_STREAM:
                conn, remote = yield multitask.accept(sock)
                if conn:
                    self.conn[remote] = conn
                    multitask.add(tcpreceiver(conn, remote))
            else: raise ValueError, 'invalid socket type'
    
    # following callbacks are invoked by the SIP stack
    def send(self, data, remote, stack):
        '''Send a given data to remote for the SIP stack.'''
        def _send(self, data, remote, stack): # a generator function that does the sending
            if _debug: print '%r=>%r on type=%r\n%s'%(stack.sock.getsockname(), remote, stack.sock.type, data)
            if stack.sock.type == socket.SOCK_STREAM: # for TCP send only if a connection exists to the remote.
                if remote in self.conn: 
                    yield multitask.send(self.conn[remote], data) # and send using that connected TCP socket.
            else: # for UDP send using the stack's UDP socket.
                yield multitask.sendto(stack.sock, data, remote)
        multitask.add(_send(self, data, remote, stack))
        
    def createServer(self, request, uri, stack): 
        '''Create a Proxy UAS for all requests except CANCEL.'''
        return (request.method != 'CANCEL') and Proxy(stack, request) or None
    
    def sending(self, ua, message, stack): pass # ignored
    def receivedRequest(self, ua, request, stack): 
        if _debug: print 'received request from stack', request.method
        handlerName = 'on' + request.method
        try:
            if hasattr(self, handlerName) and callable(eval('self.' + handlerName)): # user has defined onINVITE, onREGISTER, etc
                result = getattr(self, handlerName)(ua, request, stack)
            else:
                result = self.onRequest(ua, request, stack)
            if result is not None and type(result) == types.GeneratorType:
                if _debug: print 'result type', type(result)
                multitask.add(result)
        except:
            if _debug: print 'exception in', handlerName
            traceback and traceback.print_exc()
            ua.sendResponse(500, 'Internal server error')
    
    def receivedResponse(self, ua, response, stack): pass
    def cancelled(self, ua, request, stack): pass
    def dialogCreated(self, dialog, ua, stack): pass
    def authenticate(self, ua, header, stack): return True
    def createTimer(self, app, stack): return Timer(app)
    
    # following application level callbacks are invoked by this AbstractAgent
    def onREGISTER(self, ua, request, stack): # incoming registration
        if request.To.value.uri != request.From.value.uri:
            ua.sendResponse(400, 'Third-party registration not supported')
            return
        auth = self.authorize(request) # validate user's password.
        if auth == 200:
            saved = yield self.save(msg=request, uri=str(request.To.value.uri).lower())
            if _debug: print 'saved=', saved
            if not saved:
                ua.sendResponse(500, 'Internal server error')
            else:
                response = ua.createResponse(200, 'OK'); 
                locations = yield self.locate(str(request.To.value.uri))
                for h in map(lambda x: Header(str(x), 'Contact'), locations): 
                    response.insert(h, append=True)
                response.Expires = request.Expires if request.Expires else Header('3600', 'Expires')
                ua.sendResponse(response)
        elif auth == 404: # not found
            ua.sendResponse(404, 'Not found')
        else:
            response = ua.createResponse(401, 'Unauthorized')
            response.insert(Header(createAuthenticate(realm='localhost', domain=str(request.uri), stale=('FALSE' if auth==401 else 'TRUE')), 'WWW-Authenticate'), append=True)
            ua.sendResponse(response)
    
    def onPUBLISH(self, ua, request, stack): # incoming publish is handled as register
        return self.onREGISTER(ua, request, stack)
    
    def onRequest(self, ua, request, stack): # any other request
        if request.Route: # if route header is present unconditionally proxy the request
            proxied = ua.createRequest(request.method, dest=request.uri, recordRoute=(request.method=='INVITE'))
            ua.sendRequest(proxied)
            return
        if request.had_lr and not ua.isLocal(request.uri):
            if _debug: print 'proxying routed non-local request', request.uri
            proxied = ua.createRequest(request.method, dest=request.uri)
            ua.sendRequest(proxied)
            return
        dest = yield self.locate(str(request.uri))
        if _debug: print 'locations=', dest
        if dest: 
            if self.isProxy(request):
                for c in dest: # proxy using record-route
                    ua.sendRequest(ua.createRequest(request.method, c.value.uri, recordRoute=True))
            else:
                response = ua.createResponse(302, 'Moved Temporarily')
                for c in dest: response.insert(c, append=True)
                ua.sendResponse(response)
        else:
            ua.sendResponse(480, 'Temporarily unavailable') # or 404 not found?
        
    def isProxy(self, request): # return True to proxy, False to redirect
        return request['user-agent'] and request['user-agent'].value.find('X-Lite') >= 0
        
    def authorize(self, request, realm='localhost'):
        '''Server side of authentication. Returns 200 on success, 401 on failure, 0 if missing or invalid
        nonce, and 404 if no password/user information available.'''
        auths = filter(lambda x: x['realm']==realm, request.all('Authorization', 'Proxy-Authorization')) # search all our authenticate headers
        if not auths: return 0 # missing authenticate header
        # TODO: check for valid nonce. for now just assume all nonce to be valid.
        uri = request.From.value.uri
        return 200
    
    def save(self, msg, uri, defaultExpires=3600):
        '''Save the contacts from REGISTER or PUBLISH msg.'''
        expires = int(msg.Expires.value if msg.Expires else defaultExpires)
        if uri in self.location: existing = self.location[uri]
        else: existing = self.location[uri] = [] # initialize that user's contacts list
        if msg.Contact and msg.first('Contact').value == '*': # single contact: * header
            if msg.Expires and msg.Expires.value == '0': # unregistration msg
                del self.location[uri] # unregister by removing the contacts
        else: # handle individual contact headers in the msg
            now = time.time()
            for c in msg.all('Contact'): # for all contacts in the new msg
                e = now + (expires if 'expires' not in c else int(c.expires)) # expiration for this contact.
                existing[:] = filter(lambda x: x[0].value.uri!=c.value.uri, existing) # remove matching contacts
                existing.insert(0, (c, e)) # insert the new contact in begining
            existing[:] = filter(lambda x: x[1]>now, existing) # filter out expired contacts
            if not existing: # no more contacts
                del self.location[uri] # remove from the table as well
        if _debug: print 'save', self.location, 'returning True'
        yield # for some reason this is required for multitask.add() to work
        raise StopIteration(True)
    
    def locate(self, uri):
        '''Return all saved contacts for the given uri.'''
        if _debug: print 'locate', uri, self.location
        existing = self.location.get(str(uri), [])
        now = time.time()
        existing[:] = filter(lambda x: x[1]>now, existing) # remove expired headers
        for c in existing: c[0]['expires'] = str(int(c[1]-now)) # update the expires header with relative seconds
        result = map(lambda x: x[0], existing) # return the contact headers
        yield # for some reason this is required for multitask.add() to work
        raise StopIteration(result)
    
class Agent(AbstractAgent):
    '''An adaptor for P2P-SIP, that maps between local SIP user agent and Internet SIP network,
    and uses P2P module for lookup and storage. This is based on the data mode. A similar class
    can be implemented that does service mode, with advanced features such as presence aggregation
    and dynamic call routing.'''
    def __init__(self, server=False, sipaddr=('127.0.0.1', 5062), port=0):
        '''Initialize the P2P-SIP agent'''
        AbstractAgent.__init__(self, sipaddr=sipaddr)
        self.p2p = ServerSocket(server=server, port=port) # for initial testing start as bootstrap server
        self.location = None # to prevent accidental access to location dictionary
    def start(self, servers=None):
        '''Start the Agent'''
        self.p2p.start(servers=servers); AbstractAgent.start(self); return self
    def stop(self):
        '''Stop the Agent'''
        AbstractAgent.stop(self); self.p2p.stop(); return self
    def p2preceiver(self, p2p):
        '''Receive packets or connections from p2p socket server.'''
        def p2phandler(self, sock): # Handle the messages on the given P2P connection.
            while True: 
                data = yield sock.recv()
        while True:
            sock = yield p2p.accept()
            if hasattr(self, 'identity') and self.identity: multitask.add(p2phandler(sock))
            
    def save(self, msg, uri, defaultExpires=3600):
        '''Save the contacts from REGISTER or PUBLISH msg to P2P storage.'''
        expires = int(msg.Expires.value if msg.Expires else defaultExpires)
        
        existing = yield self.p2p.get(H(uri))
        if msg.Contact and msg.first('Contact').value == '*': # single contact: * header
            if msg.Expires and msg.Expires.value == '0': # unregistration msg
                if existing:
                    for value, nonce, Kp, expires in existing:
                        yield self.p2p.remove(H(uri), value, nonce, expires+1)
                existing = []
        else: # handle individual contact headers in the msg
            existing = dict([(str(Header(str(x[0]), 'Contact').value.uri), x) for x in existing])
            now, remove, update = time.time(), [], []
            for c in msg.all('Contact'): # for all contacts in the new msg
                e = now + (expires if 'expires' not in c else int(c.expires)) # expiration for this contact.
                if e<=now: remove.append(c)
                else: update.insert(0, (c, e))
            for c in remove:
                if c.value.uri in existing:
                    value, nonce, Kp, expires = existing[c.value.uri]
                    yield self.p2p.remove(H(uri), value, nonce, expires+1)
            for c, e in update:
                if c.value.uri in existing:
                    value, nonce, Kp, expires = existing[c.value.uri]
                    yield self.p2p.put(H(uri), value, nonce, now+e)
                else:
                    yield self.p2p.put(H(uri), str(c.value), dht.randomNonce(), now+e)
        if _debug: print 'save', self.location, 'returning True'
        raise StopIteration(True)
    
    def locate(self, uri):
        '''Return all saved contacts for the given uri from P2P storage.'''
        existing = yield self.p2p.get(H(uri))
        now = time.time()
        result = []
        for value, nonce, Kp, expires in existing:
            c = Header(value, 'Contact')
            c['expires'] = str(int(expires - now))
            result.append(c)
        if _debug: print 'locate', uri, result
        raise StopIteration(result)
            
#------------------------------------------- Testing ----------------------
_apps = dict()
def start(app=None, options=None):
    global _apps
    if app not in _apps:
        agent = _apps[app] = Agent().start()
def stop(app=None):
    global _apps
    if app in _apps:
        _apps[app].stop(); del _apps[app]
        
if __name__ == '__main__':
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-d', '--verbose', dest='verbose', default=False, action='store_true', help='enable debug trace')
    parser.add_option('-s', '--server',  dest='server',  default=False, action="store_true", help='start as bootstrap node')
    parser.add_option('-p', '--sip-port',dest='sip_port', default=5062, type="int", help='SIP port number to listen. default is 5062.')
    parser.add_option('-P', '--p2p-port',dest='p2p_port', default=0, type="int", help='Preferred P2P port number to listen. If supplied, disables multicast.')
    parser.add_option('-S', '--servers', dest='servers', default=None, help='list of bootstrap nodes as "ip:port,ip:port,..."')
    (options, args) = parser.parse_args()
    
    _debug = p2p._debug = rfc3261._debug = options.verbose
    
    servers = [(x.split(':', 1)[0], int(x.split(':', 1)[1])) for x in options.servers.split(',')] if options.servers else None
    
    agent = Agent(server=options.server, sipaddr=('0.0.0.0', options.sip_port), port=options.p2p_port).start(servers)
    try: multitask.run()
    except KeyboardInterrupt: pass
    agent.stop()
