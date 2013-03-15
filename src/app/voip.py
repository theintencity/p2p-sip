# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.

'''
Implementation of VoIP related applications such as SIP user agent. The main classes are as
follows: User, Session, Presence and Conf. 

A User represents a local user that is listening for SIP messages and is bound to a single
address-of-record. A Session is a SIP INVITE based session that is created implicitly
by the library when User.connect or User.accept is invoked for outbound or inbound calls.
A Presence object is used to represent the user's presence status and is created implicitly
by the library when User.watch or User.approve is invoked for watching a remote user or 
approving presence subscription from remote user. A Conf object is created by the application
either for a new conference for inviting new participants in the conference or for accepting
an incoming invitation in a conference. A Conf, Session or Presence object is associated with
one local User object which supplies the local credentials and local address-of-record for
various SIP messages.

There are some simplifications in the API design. In particular, a single listening socket
is associated with a single User, hence can do only one outbound registration. An instant 
message can be part of an established Session for a session-based IM or can be dispatched
independently by the User object for a paging-mode IM.

There is some analogy between the UNIX socket API and this API. I use semantics of socket
functions such as bind, accept, recv, send, connect and close.

User
----
The application first starts a User object, and starts the main listening loop so that incoming
SIP messages can be received. The socket for listening is supplied by the application, hence
additional considerations such as port number configuration or socket type are outside the 
library.

    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 5060)) 
    myself = User(sock).start()

Once a User object is created it can be bound to an address-of-record by doing SIP registration.
The optional username and password can be supplied for authentication, if the server demands
authentication. Additionally, the refresh argument can be supplied to automatically perform
registration refresh before the registration expires. The return value from bind method is a
tuple (result, reason) where result is 'success' or 'failed' and reason is None or a text
reason for failure.

    result, reason = (yield myself.bind('"Kundan Singh" <sip:kundansingh99@iptel.org>', 
                        username='kundansingh99', password='mypass', refresh=True))
    if result == 'failed':
        print 'bind failed', reason

The user can be unregistered by invoking the close() method on a bound user. If for some
reason the registration refresh fails, the recv method on user object will throw an exception.

   yield myself.close()

A communication such as a multimedia call involves two parties. Usually, you use myself
as one end and some other contact as the other end. The connect method is used on the user
object to place an outbound call to a destination contact. The additional socket is supplied
so that the session can be negotiated for this socket. The connect method is a generator
which eventually returns a Session object for connected session or a reason for failure.

    msock = socket.socket(type=socket.SOCK_DGRAM)
    msock.bind(('0.0.0.0', 0))
    yourcall, reason = (yield myself.connect('sanjayc77@iptel.org', msock))
    if not yourcall:
        print 'connect failed', reason
        
If the application requires that it should be able to cancel a pending outbound invitation
it should use the generator explicitly as follows:

    gen = myself.connect('sanjayc77@iptel.org', msock)
    try:
        yourcall, reason = (yield gen)
        if not yourcall:
            print 'connect failed', reason
    except GeneratorExit:
        # outgoing connect is cancelled by calling gen.close() in another task

To watch the presence status of a remote contact you can do the following:

    yourpresence, reason = yield myself.watch('sip:sanjayc77@iptel.org', refresh=True)
    if not yourpresence:
        print 'watch failed', reason

The application can send a paging-mode instant message using the send method as follows:

    result, reason = yield myself.sendIM('sip:sanjayc77@iptel.org', 'How are you doing?')
    if result == 'failed':
       print 'send failed', reason

The recv method can be used on the user object to receive incoming notifications for new 
connect, paging-mode instant message or watch request. The application can invoke the accept
or reject method to accept or reject a call, or the approve or block method to accept or
reject a watch request.  

    while True:
        cmd, arg = (yield myself.recv())
        if cmd == 'connect':                  # incoming connect request
            yourcall, = (yield myself.accept(arg, msock))
        elif cmd == 'close':                  # incoming connect is cancelled
            ...
        elif cmd == 'watch':                  # incoming watch request
            yourpresence, = (yield myself.approve(arg)
        elif cmd == 'send':                   # paging-mode instant message
            print 'received from sender=', arg[0], 'message=', arg[1]

Session and Presence
--------------------
Once a Session or Presence object is created, subsequent events for that session or presence
is dispatched to that object. The appliction does a processing loop to receive events from
the object as follows:

    while True:
        cmd, arg = (yield yourcall.recv())
        if cmd == 'send': 
            print 'received session-based instant message', arg
        elif cmd == 'close':
            print 'session closed by remote'

    while True:
        cmd, arg = (yield yourpresence.recv())
        if cmd == 'status':
            print 'presence status changed to', arg
        elif cmd == 'close':
            print 'watch request cancelled'

The application can change the presence status on the user object so that all the approved
remote watchers receive the update of status. 

    myself.status = 'online'
    
The media processing loop is outside this module. In particular, the application should
do something like the following to send and receive media on the msock. This is external so that
the library does not have to deal with sending and receiving media on an established session.

    while True:
        ... # receive my_data from device (mic or camera) and encode
        yield multitask.send(msock, my_data)
        
    while True:
       your_data = (yield multitask.recv(msock, 1500))
       ... # decode your_data and play to device (speaker or display)
       
Conf
----
A conference object can be constructed from the conference name, id and local
User object as follows:

    conf = Conf(name='sip:conf@example.net', id='72186356347283', user=myself)
    
The id is a unique identifier used in the Conf-ID header of the decentralized conference
signaling. 

Once a Conf object is created it can be treated by a User object except that it allows only
a session and among multiple remote contacts. In particular you can use the connect and accept
method on Conf to invite a contact in the conference, or accept an incoming connect request
in a conference.

    yourcall1, reason = (yield conf.connect('sip:sanjayc77@iptel.org', msock1)
    yourcall2, reason = (yield conf.connect('sip:kundan@iptel.org', msock2)
    ...
    while True:
        cmd, arg = (yield myself.recv())
        ...
        elif cmd == 'confconnect' or cmd == 'confinvite:    
            ...                       # similar to connect but for conference
            conf = find(arg)          # find an existing Conf or create one
            yourcall, = (yield conf.accept(arg))

The difference between confinvite and confconnect is that a confinvite is sent for 
a new conference invitation, which may require the application to create a Conf before
calling accept, whereas a confconnect is to indicate that some member A invited
another member B and that other member A is re-connecting with us, so we should immediately
invoke accept on the conf, and let the library take care of membership checks.

You can not remove a participant from the conference, but watch the status of the 
conference membership as follows:

    cmd, contact = (yield conf.recv())
    if cmd == 'connect': 
        # added the contact in the conference
    elif cmd == 'close':
        # the contact left the conference
        
To leave a conference just invoke the close method on the conference. In turn it closes
all the associated sessions for this conference.

    yield conf.close()
    
Note that once you have created a Conf object and started a conference with some member,
those members can admit new other members without your consent. This is a simplified version
of decentralized (full-mesh) conference with no conference or floor control.

Pitfalls to avoid
-----------------
The way generator functions operate in the multitask context is tricky. I define most of the
methods as generators, so that the semantics is like a blocking function call, but internally
it uses co-operative multitasking. For example,

   yourcall, reason = (yield myself.connect(...))

There are other alternative designs for API, e.g., event and callback oriented, provider 
and listener based, etc. Almost every other SIP API is usually in callback or listener design. I chose
the synchronous generator style with co-operative multitasking because it reduces the overhead
in terms of state maintenance and understanding different scattered parts of the source code.

There is one pitfall to avoid when using this API. If the generator method is called, you should
be careful to use 'yield'. If you use 'yield' the method's final return value is returned from
the yield statement. If you don't use 'yield' then it returns a generator which can later be
used to get all intermediate values as well as final values. This is also useful to cancel the
generator function by calling a close() on it. A general practice could be to always use 'yield' 
for simple applications.
'''

from __future__ import with_statement
from contextlib import closing
from std.kutil import Timer, getlocaladdr, getintfaddr
from std.rfc2396 import URI, Address
from std.rfc4566 import SDP, attrs as format
from std.rfc3550 import Network as RTPNetwork, Session as RTPSession
import std.rfc3261 as sip, std.rfc3264 as rfc3264, std.rfc3550 as rfc3550
import std.rfc3489bis as stun
import sys, traceback, socket, multitask, random

_debug = False  # set this to True to display all the debug messages.

class User(object):
    '''The User object provides a layer between the application and the SIP stack.'''
    def __init__(self, sock, start=False, nat=True):
        '''Construct a new User on given bound socket for SIP signaling. Starts listening for messages if start is set. Also assumes this
        User is behind NAT if nat is True (default) and performs NAT checks.'''
        self.sock, self.sockaddr, self.nat = sock, getlocaladdr(sock), nat
        self.nattype = self.mapping = self.filtering = self.external = None # NAT properties
        self._listenergen = self._natcheckgen = self._queue = None
        self.address = self.username = self.password = self.proxy = None
        self.transport = sip.TransportInfo(self.sock)
        self.stack = sip.Stack(self, self.transport) # create a SIP stack instance
        self.reg = None   # registration UAC
        
        if _debug: print 'User created on listening=', sock.getsockname(), 'advertised=', self.sockaddr
        if start:
            self.start()
            
    def __del__(self):
        '''Destroy other internal references to Stack, etc.'''
        self.stop()
        self.reg = None
        if self.stack: self.stack.app = None # TODO: since self.stack has a reference to this, __del__will never get called. 
        self.sock = self.stack = None
    
    #----------------------------- start/stop daemon ---------------------- 
       
    def start(self, maxsize=1500, interval=180):
        '''Start the listener, if not already started.'''
        if not self._listenergen:
            self._listenergen  = self._listener(maxsize=maxsize, interval=interval)
            multitask.add(self._listenergen) # start the transport listening task
        if self.nat and not self._natcheckgen:
            self._natcheckgen = self._natcheck(interval=interval)
            multitask.add(self._natcheckgen) # start the task that periodically checks the nat type
        return self
    
    def stop(self):
        '''Stop the listener, if already present'''
        if self._listenergen: 
            self._listenergen.close()
        if self._natcheckgen: 
            self._natcheckgen.close()
        self._listenergen = self._natcheckgen = None
        return self
    
    def _listener(self, maxsize, interval):
        '''Listen for transport messages on the signaling socket. The default maximum 
        packet size to receive is 1500 bytes. The interval argument specifies how
        often should the sock be checked for close, default is 180 s.
        This is a generator function and should be invoked as multitask.add(u._listener()).'''
        try:
            while self.sock and self.stack:
                try:
                    data, remote = (yield multitask.recvfrom(self.sock, maxsize, timeout=interval))
                    if _debug: print 'received[%d] from %s\n%s'%(len(data),remote,data)
                    self.stack.received(data, remote)
                except multitask.Timeout: pass
        except GeneratorExit: pass
        except: print 'User._listener exception', (sys and sys.exc_info() or None); traceback.print_exc(); raise
        if _debug: print 'terminating User._listener()'
    
    def _natcheck(self, interval):
        '''Periodically discover the NAT behavior. Default interval is every 3 min (180s).
        This is a generator function and should be invoked as multitask.add(u._natcheck())'''
        try:
            while self.sock:
                self.nattype, self.mapping, self.filtering, self.external = yield stun.discoverBehavior()
                if _debug: print 'nattype=', self.nattype, 'external=', self.external
                yield multitask.sleep(interval)
        except GeneratorExit: pass
        except: print 'User._natcheck exception', (sys and sys.exc_info() or None)
        if _debug: print 'terminating User._natcheck()'

    #-------------------- binding related ---------------------------------
    
    def bind(self, address, username=None, password=None, interval=180, refresh=False, update=False): 
        '''Register the local address with the server to receive incoming requests.
        This is a generator function, and returns either ('success', None) for successful
        registration or ('failed', 'reason') for a failure. The username and password 
        arguments are used to authenticate the registration. The interval argument 
        controls how long the registration is valid, and refresh if set to True causes 
        automatic refresh of registration before it expires. 
        If update is set to True then also update the self.transport.host with local address.uri.host.'''
        
        if self.reg: 
            raise StopIteration(('failed', 'Already bound'))
        
        address = self.address = Address(str(address))
        if not address.uri.scheme: address.uri.scheme = 'sip' # default scheme
        self.username, self.password = username or self.username or address.uri.user, password or self.password

        if update: self.transport.host = getintfaddr(address.uri.host)
        reg = self.reg = self.createClient(setProxyUser=False)
        reg.queue = multitask.Queue()
        result, reason = (yield self._bind(interval=interval, refresh=refresh, wait=False))
        if _debug: print 'received response', result
        if result == 'failed': self.reg = None
        raise StopIteration((result, reason))
                    
    def close(self):
        '''Close the binding by unregistering with the SIP server.'''
        if not self.reg:
            raise StopIteration(('failed', 'not bound'))
        reg = self.reg
        if reg.gen: reg.gen.close(); reg.gen = None
        result, reason = (yield self._bind(interval=0, refresh=False, wait=False))
        raise StopIteration((result, reason))
            
    def _bind(self, interval, refresh, wait):
        '''Internal function to perform bind and wait for response, and schedule refresh.'''
        try:
            if wait:
                yield multitask.sleep(interval - min(interval*0.05, 5)) # refresh about 5 seconds before expiry
            reg = self.reg
            reg.sendRequest(self._createRegister(interval))
            while True:
                response = (yield reg.queue.get())
                if response.CSeq.method == 'REGISTER':
                    if response.is2xx:   # success
                        if refresh:        # install automatic refresh
                            if response.Expires:
                                interval = int(response.Expires.value)
                            if interval > 0:
                                reg.gen = self._bind(interval, refresh, True) # generator for refresh
                                multitask.add(reg.gen)
                        raise StopIteration(('success', None))
                    elif response.isfinal: # failed
                        self.reg.gen = None; self.reg = None
                        raise StopIteration(('failed', str(response.response) + ' ' + response.responsetext))
        except GeneratorExit:
            raise StopIteration(('failed', 'Generator closed'))

    def _createRegister(self, interval):
        '''Create a REGISTER Message and populate the Expires and Contact headers. It assumes
        that self.reg is valid.'''
        if self.reg:
            ua = self.reg
            m = ua.createRegister(ua.localParty)
            m.Contact = sip.Header(str(self.stack.uri), 'Contact')
            m.Contact.value.uri.user = ua.localParty.uri.user
            m.Expires = sip.Header(str(interval), 'Expires')
            return m
        else: return None
    
    #-------------------------- Session related methods -------------------
    def connect(self, dest, mediasock=None, sdp=None, provisional=False):
        '''Invite a remote destination to a session. This is a generator function, which 
        returns a (session, None) for successful connection and (None, reason) for failure.
        Either mediasock or sdp must be present. If mediasock is present, then session is negotiated 
        for that mediasock socket, without SDP. Otherwise, the given sdp (rfc4566.SDP) is used 
        to negotiate the session. On success the returned Session object has mysdp and yoursdp
        properties storing rfc4566.SDP objects in the offer and answer, respectively.'''
        if self.nattype == 'blocked': 
            raise StopIteration((None, 'udp blocking network')) 
        else:
            dest = Address(str(dest))
            if not dest.uri:
                raise StopIteration((None, 'invalid dest URI'))
            ua = self.createClient(dest)
            ua.queue = multitask.Queue() # to receive responses
            m = ua.createRequest('INVITE')
            
            if mediasock is not None:
                local = yield self._getLocalCandidates(mediasock) # populate the media candidates
                for c in local: # add proprietary SIP header - Candidate
                    m.insert(sip.Header(c[0] + ':' + str(c[1]), 'Candidate'), True)
            elif sdp is not None:
                m.body, local = str(sdp), None
                m['Content-Type'] = sip.Header('application/sdp', 'Content-Type')
            else:
                raise StopIteration((None, 'either mediasock or sdp must be supplied'))

            ua.sendRequest(m)
            session, reason = yield self.continueConnect((ua, dest, mediasock, sdp, local), provisional=provisional)
            raise StopIteration(session, reason)
                    
    def continueConnect(self, context, provisional):
        ua, dest, mediasock, sdp, local = context
        while True:
            try:
                response = yield ua.queue.get()
            except GeneratorExit: # connect was cancelled
                ua.sendCancel()
                raise
            if response.response == 180 or response.response == 183: # ringing or early media event
                context = (ua, dest, mediasock, sdp, local)
                raise StopIteration((context, "%d %s"%(response.response, response.responsetext)))
            if response.is2xx: # success
                session = Session(user=self, dest=dest)
                session.ua, session.mediasock = hasattr(ua, 'dialog') and ua.dialog or ua, mediasock
                session.mysdp, session.yoursdp, session.local = sdp, None, local
                session.remote= [(x.value.split(':')[0], int(x.value.split(':')[1])) for x in response.all('Candidate')] # store remote candidates if available 
                
                if response.body and response['Content-Type'] and response['Content-Type'].value.lower() == 'application/sdp':
                    session.yoursdp = SDP(response.body)
                
                yield session.start(True)
                raise StopIteration((session, None))
            elif response.isfinal: # some failure
                raise StopIteration((None, str(response.response) + ' ' + response.responsetext))
    
    def accept(self, arg, mediasock=None, sdp=None):
        '''Accept a incoming connection from given arg (dest, ua). The arg is what is supplied
        in the 'connect' notification from recv() method's return value.'''
        dest, ua = arg
        m = ua.createResponse(200, 'OK')
        ua.queue = multitask.Queue()
        
        if mediasock is not None:
            local = yield self._getLocalCandidates(mediasock)
            for c in local: # add proprietary SIP header - Candidate
                m.insert(sip.Header(c[0] + ':' + str(c[1]), 'Candidate'), True)
        elif sdp is not None:
            m.body, local = str(sdp), None
            m['Content-Type'] = sip.Header('application/sdp', 'Content-Type')
        else:
            raise StopIteration((None, 'either mediasock or sdp must be supplied'))
            
        ua.sendResponse(m)
        
        try:
            while True:

                request = yield ua.queue.get(timeout=5) # wait for 5 seconds for ACK
                if request.method == 'ACK':
                    ''' hack: force terminating the transaction because Stack._receivedRequest
                    is unable to find it due to branch names being different'''
                    ua.transaction.timeout('H', 0)
                    session, incoming = Session(user=self, dest=dest), ua.request
                    session.ua, session.mediasock = hasattr(ua, 'dialog') and ua.dialog or ua, mediasock
                    session.mysdp, session.yoursdp, session.local = sdp, None, local
                    session.remote= [(x.value.split(':')[0], int(x.value.split(':')[1])) for x in incoming.all('Candidate')] # store remote candidates 
                    
                    if incoming.body and incoming['Content-Type'] and incoming['Content-Type'].value.lower() == 'application/sdp':
                        session.yoursdp = SDP(incoming.body)
                    
                    yield session.start(False)
                    raise StopIteration((session, None))
        except multitask.Timeout: pass
        except GeneratorExit: pass
        
        raise StopIteration((None, 'didnot receive ACK'))
    
    def reject(self, arg, reason='486 Busy here', headers=None):
        code, sep, phrase = reason.partition(' ')
        try: code = int(code) if code else ''
        except: pass
        if not isinstance(code, int): code, phrase = 603, reason # decline
        response = arg[1].createResponse(code, phrase)
        if headers: [response.insert(h, append=True) for h in headers] 
        arg[1].sendResponse(response)
        
    def _getLocalCandidates(self, mediasock):
        local = [getlocaladdr(mediasock)] # first element is local-addr
        if _debug: print 'getting local candidates for nattype=', self.nattype
        if self.nattype == 'good' or self.nattype == 'bad' or self.nat and (self.nattype is None): # get STUN address for media
            response, external = yield stun.request(mediasock)
            local.append(external)
        raise StopIteration(local)

    #-------------------------- presence and IM related methods------------
    def watch(self, dest):
        '''Watch for the presence status of the remote destination.'''
        raise StopIteration((None, 'Not implemented'))
    
    def approve(self, arg):
        '''Approve the remote watcher to know our presence status.'''
        raise StopIteration((None, 'Not implemented'))
    
    def block(self, arg):
        '''Block the remote watcher to know our presence status.'''
        raise StopIteration((None, 'Not implemented'))
    
    def sendIM(self, dest, message):
        '''Send a paging-mode instant message to the destination and return ('success', None)
        or ('failed', 'reason')'''
        ua = self.createClient(dest)
        ua.queue = multitask.Queue() # to receive responses
        m = ua.createRequest('MESSAGE')
        m['Content-Type'] = sip.Header('text/plain', 'Content-Type')
        m.body = str(message)
        ua.sendRequest(m)
        while True:
            response = yield ua.queue.get()
            if response.is2xx:
                raise StopIteration(('success', None))
            elif response.isfinal:
                raise StopIteration(('failed', str(response.response) + ' ' + response.responsetext))
    
    #-------------------------- generic event receive ---------------------
    def recv(self, timeout=None):
        if self._queue is None: self._queue = multitask.Queue()
        return self._queue.get(timeout=timeout)
    
    #-------------------------- Interaction with SIP stack ----------------
    # Callbacks invoked by SIP Stack
    def createServer(self, request, uri, stack): 
        '''Create a UAS if the method is acceptable. If yes, it also adds additional attributes
        queue and gen in the UAS.'''
        ua = request.method in ['INVITE', 'BYE', 'ACK', 'SUBSCRIBE', 'MESSAGE', 'NOTIFY'] and sip.UserAgent(self.stack, request) or None
        if ua: ua.queue = ua.gen = None
        if _debug: print 'createServer', ua
        return ua
    
    def createClient(self, dest=None, setProxyUser=True):
        '''Create a UAC and add additional attributes: queue and gen.'''
        ua = sip.UserAgent(self.stack)
        ua.queue = ua.gen = None
        ua.localParty  = self.address and self.address.dup() or None
        ua.remoteParty = dest and dest.dup() or self.address and self.address.dup() or None
        ua.remoteTarget= dest and dest.uri.dup() or self.address and self.address.uri.dup() or None
        ua.routeSet    = self.proxy and [sip.Header(str(self.proxy), 'Route')] or None
        if setProxyUser and ua.routeSet and not ua.routeSet[0].value.uri.user: ua.routeSet[0].value.uri.user = ua.remoteParty.uri.user
        if _debug: print 'createClient', ua
        return ua

    def sending(self, ua, message, stack): 
        pass
    
    def receivedRequest(self, ua, request, stack):
        '''Callback when received an incoming request.'''
        def _receivedRequest(self, ua, request): # a generator version
            if _debug: print 'receivedRequest method=', request.method, 'ua=', ua, ' for ua', (ua.queue is not None and 'with queue' or 'without queue') 
            if hasattr(ua, 'queue') and ua.queue is not None:
                yield ua.queue.put(request)
            elif request.method == 'INVITE':    # a new invitation
                if self._queue is not None:
                    if not request['Conf-ID']: # regular call invitation
                        yield self._queue.put(('connect', (str(request.From.value), ua)))
                    else: # conference invitation
                        if request['Invited-By']:
                            yield self._queue.put(('confconnect', (str(request.From.value), ua)))
                        else:
                            yield self._queue.put(('confinvite', (str(request.From.value), ua)))
                else:
                    ua.sendResponse(405, 'Method not allowed')
            elif request.method == 'SUBSCRIBE': # a new watch request
                if self._queue:
                    yield self._queue.put(('watch', (str(request.From.value), ua)))
                else:
                    ua.sendResponse(405, 'Method not allowed')
            elif request.method == 'MESSAGE':   # a paging-mode instant message
                if request.body and self._queue:
                    ua.sendResponse(200, 'OK')      # blindly accept the message
                    yield self._queue.put(('send', (str(request.From.value), request.body)))
                else:
                    ua.sendResponse(405, 'Method not allowed')
            elif request.method == 'CANCEL':   
                # TODO: non-dialog CANCEL comes here. need to fix rfc3261 so that it goes to cancelled() callback.
                if ua.request.method == 'INVITE': # only INVITE is allowed to be cancelled.
                    yield self._queue.put(('close', (str(request.From.value), ua)))
            else:
                ua.sendResponse(405, 'Method not allowed')
        multitask.add(_receivedRequest(self, ua, request))

    def receivedResponse(self, ua, response, stack):
        '''Callback when received an incoming response.'''
        def _receivedResponse(self, ua, response): # a generator version
            if _debug: print 'receivedResponse response=', response.response, ' for ua', (ua.queue is not None and 'with queue' or 'without queue') 
            if hasattr(ua, 'queue') and ua.queue is not None: # enqueue it to the ua's queue
                yield ua.queue.put(response)
                if _debug: print 'response put in the ua queue'
            else:
                if _debug: print 'ignoring response', response.response
        multitask.add(_receivedResponse(self, ua, response))
        
    def cancelled(self, ua, request, stack): 
        '''Callback when given original request has been cancelled by remote.'''
        def _cancelled(self, ua, request): # a generator version
            if hasattr(ua, 'queue') and ua.queue is not None:
                yield ua.queue.put(request)
            elif self._queue is not None and ua.request.method == 'INVITE': # only INVITE is allowed to be cancelled.
                yield self._queue.put(('close', (str(request.From.value), ua)))
        multitask.add(_cancelled(self, ua, request))
        
    def dialogCreated(self, dialog, ua, stack):
        dialog.queue = ua.queue
        dialog.gen   = ua.gen 
        ua.dialog = dialog
        if _debug: print 'dialogCreated from', ua, 'to', dialog
        # else ignore this since I don't manage any dialog related ua in user
        
    def authenticate(self, ua, obj, stack):
        '''Provide authentication information to the UAC or Dialog.'''
        obj.username, obj.password = self.username, self.password 
        return obj.username and obj.password and True or False

    def createTimer(self, app, stack):
        '''Callback to create a timer object.'''
        return Timer(app)
    
    # rfc3261.Transport related methods
    def send(self, data, addr, stack):
        '''Send data to the remote addr.'''
        def _send(self, data, addr): # generator version
            if _debug: print 'sending[%d] to %s\n%s'%(len(data), addr, data)
            if self.sock:
                if self.sock.type == socket.SOCK_STREAM:
                    try: 
                        remote = self.sock.getpeername()
                        if remote != addr:
                            if _debug: print 'connected to wrong addr', remote, 'but sending to', addr
                    except socket.error: # not connected, try connecting
                        try:
                            self.sock.connect(addr)
                        except socket.error:
                            if _debug: print 'failed to connect to', addr
                    try:
                        yield self.sock.send(data)
                    except socket.error:
                        if _debug: print 'socket error in send'
                elif self.sock.type == socket.SOCK_DGRAM:
                    try: 
                        yield self.sock.sendto(data, addr)
                    except socket.error:
                        if _debug: print 'socket error in sendto' 
                else:
                    if _debug: print 'invalid socket type', self.sock.type
        multitask.add(_send(self, data, addr))

#-------------------- Media Session ---------------------------------------

class MediaSession(object):
    '''A MediaSession object wraps the RTP's Network, RTP's Session and SDP's offer/answer mode.
    Application using audio/video should use one MediaSession associated with one Session.'''
    def __init__(self, app, streams, request=None, yoursdp=None, listen_ip='0.0.0.0', NetworkClass=RTPNetwork):
        '''app receives call back for incoming RTP, streams is supplied list of supported SDP.media,
        and request is a SIP message containing SDP offer if this is an incoming call.'''
        if len(streams) == 0: raise ValueError('must supply at least one stream')
        self.app, self.streams = app, streams
        self.is_hold = False
        self.mysdp = self.yoursdp = None; self.rtp, self.net, self._types = [], [], []
        if not request and not yoursdp: # this is for outgoing call, build an offer SDP as mysdp.
            net = [NetworkClass(app=None, src=(listen_ip, 0)) for i in xrange(len(streams))] # first create as many RTP network objects as streams.
            for m, n in zip(streams, net): m.port = n.src[1]           # update port numbers in streams. TODO: need to add RTCP port if different than RTP+1
            offer = rfc3264.createOffer(streams)                       # create the offered SDP now
            ip = map(lambda n: n.src[0] if n.src[0] != '0.0.0.0' else getlocaladdr(n.rtp)[0], net) # get all IP addresses in network
            if len(set(ip)) == 1: offer['c'] = SDP.connection(address=ip[0]) # unique IP, should set c= line in global level of SDP
            else:  # no unique IP. Must add ip/c= in all media lines
                for m, i in zip(offer['m'], ip): m['c'] = SDP.connection(address=i)
            self.mysdp, self.net[:] = offer, net
        elif yoursdp or request.body and request['Content-Type'] and request['Content-Type'].value.lower() == 'application/sdp': # this is for incoming call, build an answer SDP as mysdp based on offer SDP from request
            offer = yoursdp or SDP(request.body) 
            net = [NetworkClass(app=None, src=(listen_ip, 0)) for i in xrange(len(streams))] # create as many network objects as we have streams
            for m, n in zip(streams, net): m.port = n.src[1]           # update port numbers in streams. TODO: need to add RTCP port if different than RTP+1
            netoffer = dict(map(lambda x: (x.src[1], x), net))           # create a table of RTP port=>network
            answer = rfc3264.createAnswer(streams, offer)              # create the answered SDP now
            if not answer or not answer['m']:
                if _debug: print 'create answer failed to create an answer'
                for n in net: n.close()
            else:
                net1 = map(lambda m: netoffer[m.port] if m.port > 0 else None, answer['m']) # include networks which are successfully answered
                netanswer = dict(map(lambda x: (x.src[1], x), filter(lambda y: y is not None, net1)))
                for n in filter(lambda y: y.src[1] not in netanswer, net): n.close() # close the networks that were not used
                netoffer.clear(); netanswer.clear()
                netvalid = filter(lambda x: x is not None, net) # only non-None values
                ip = map(lambda n: n.src[0] if n.src[0] != '0.0.0.0' else getlocaladdr(n.rtp)[0], netvalid) # get all IP addresses in network
                if len(set(ip)) > 0: answer['c'] = SDP.connection(address=ip[0]) # TODO: we don't support different IPs in this case
                self.mysdp, self.net[:] = answer, net1
                self.setRemote(offer) # set the remote SDP which also sets the dest ip:port in net
        else:
            if _debug: print 'request does not have SDP body'
            
    def hold(self, value): # enable/disable hold mode.
        ip = []
        for i in self.net:
            if i is None:
                ip.append(i)
            elif i.src and i.src[0] != '0.0.0.0':
                ip.append(i.src[0])
            else:
                ip.append(getlocaladdr(i.rtp)[0])
        if self.mysdp['c']: self.mysdp['c'].address = ip[0] if not value else '0.0.0.0'
        self.mysdp['a'] = ['sendrecv'] if not value else ['sendonly']
        for m, i in zip(self.mysdp['m'], ip):
            if m['c']: m['c'].address = i if not value else '0.0.0.0'
        self.is_hold = value
        
    def setRemote(self, sdp):
        '''Update the RTP network's destination ip:port based on remote SDP. It also creates RTP Session if 
        needed. This is implicitly invoked in constructor for incoming call, since remote SDP is already 
        known. The application invokes this explicitly for outgoing call when 200 OK is received. Also, it
        is invoked when Session receives an incoming re-INVITE or different SDP in 200 OK of outbound re-INVITE'''
        self.yoursdp, net = sdp, self.net
        if sdp['m']:
            ip = sdp['c'].address if sdp['c'] else ('0.0.0.0')
            if len(net) == len(sdp['m']): # assume that answer's m= order matches offer's
                for m, n in zip(sdp['m'], net):
                    if n is not None:
                        ip0 = m['c'].address if m['c'] else ip
                        n.dest, n.destRTCP = (ip0, m.port), (ip0, m.port+1 if m.port > 0 else 0) # TODO: should use different RTCP ports
            else:
                for m1 in sdp['m']:
                    found = False
                    for i, m2 in enumerate(self.mysdp['m']):
                        if m1.media == m2.media and i <= len(net):
                            ip0, n, found = m1['c'].address if m1['c'] else ip, net[i], True
                            n.dest, n.destRTCP = (ip0, m1.port), (ip0, m1.port+1 if m1.port > 0 else 0)
                    if not found:
                        if _debug: print 'invalid m= line in answer', m1
        else:
            if _debug: print 'missing m= line in remote SDP'
        for my in filter(lambda m: m.port > 0, self.mysdp['m'] if self.mysdp else []): # update _types based on mysdp and yoursdp
            for your in filter(lambda m: m.port > 0 and m.media == my.media, self.yoursdp['m'] if self.yoursdp else []): self._types.append(my.media)
        netvalid = filter(lambda x: x is not None, net)
        if len(self.rtp) != len(netvalid):
            for rtp in self.rtp: rtp.net = None; rtp.stop() # clean previous RTP session
            self.rtp[:] = map(lambda n: RTPSession(app=self), netvalid)
            for r, n in zip(self.rtp, netvalid): r.net = n; n.app = r; r.start() # attach net with session
        
    def close(self):
        '''Clean up the media session. This must be called to clean up sockets, tasks, etc.'''
        for rtp in self.rtp: rtp.net = None; rtp.stop()
        for net in filter(lambda x: x is not None, self.net): net.app = None; net.close() 
        self.rtp[:], self.net[:] = [], []

    def hasType(self, type):
        '''Whether the media with the given type exists in both mysdp and yoursdp? Type can be 'audio' or 'video'.'''
        return type.lower() in self._types 
        
    def createTimer(self, app): # Callback to create a timer object.
        return Timer(app)
    
    def received(self, member, packet): # an RTP packet is received. Hand over to sip_data.
        if self.app and hasattr(self.app, 'received') and callable(self.app.received) and not self.is_hold:
            self.app.received(media=self, fmt=self._getMyFormat(packet.pt), packet=packet)
    
    def send(self, payload, ts, marker, fmt):
        fy, rtp = self._getYourFormat(fmt)
        if rtp and fy: rtp.send(payload=payload, ts=ts, marker=marker, pt=int(fy.pt))
        elif _debug: print 'could not find RTP session for fmt=%r/%r'%(fmt.name, fmt.rate)
        
    def _getMyFormat(self, pt): # returns matching fmt for this pt in mysdp
        if self.mysdp: 
            for m in self.mysdp['m']:
                for f in m.fmt:
                    if str(f.pt) == str(pt): return f
        if _debug: print 'format not found for pt=', pt
        return None

    def _getYourFormat(self, fmt): # returns (fmt, rtp) where fmt is matching format in yoursdp, and rtp is the associated session
        if self.yoursdp:
            for m in filter(lambda x: x.port > 0, self.yoursdp['m']):
                rtp = filter(lambda r: r.net and r.net.dest and r.net.dest[1] == m.port, self.rtp) # find matching RTP session
                fy = filter(lambda f:str(f.name).lower() == str(fmt.name).lower() and f.rate == fmt.rate and f.count == fmt.count
                            or fmt.pt >= 0 and fmt.pt < 96 and fmt.pt == f.pt, m.fmt)
                if fy: return (fy[0], rtp[0] if rtp else None)
        return (None, None)
        
    def hasYourFormat(self, fmt): # check whether the fmt is available in yoursdp
        if self.yoursdp:
            for m in filter(lambda x: x.port > 0, self.yoursdp['m']):
                fy = filter(lambda f:str(f.name).lower() == str(fmt.name).lower() and f.rate == fmt.rate and f.count == fmt.count
                            or fmt.pt >= 0 and fmt.pt < 96 and fmt.pt == f.pt, m.fmt)
                if fy: return True
        return False
        
#-------------------------- Session ---------------------------------------

class Session(object):
    '''The Session object represents a single session or call between local User and remote
    dest (Address).'''
    def __init__(self, user, dest):
        self.user, self.dest = user, dest
        self.ua = self.mediasock = self.local = self.remote = self.gen = self.remotemediaaddr = self.media = None
        self._queue = multitask.Queue()
        
    def start(self, outgoing):
        '''A generator function to initiate the connectivity check and then start the run
        method to receive messages on this ua.'''
        if self.mediasock and self.user.nat:
            yield self._checkconnectivity(outgoing)
        self.gen = self._run()
        multitask.add(self.gen)
        
    def send(self, message):
        if self.ua:
            ua = self.ua
            m = ua.createRequest('MESSAGE')
            m['Content-Type'] = sip.Header('text/plain', 'Content-Type')
            m.body = str(message)
            ua.sendRequest(m)
        yield # I don't wait for response 
    
    def recv(self, timeout=None):
        cmd, arg = yield self._queue.get(timeout=timeout)
        raise StopIteration((cmd, arg))
    
    def close(self, outgoing=True):
        '''Close the call and terminate any generators.'''
        self.mediasock = self.local = self.remote = self.media = None
        if self.gen: # close the generator
            self.gen.close()
            self.gen = None
        if self.ua:
            ua = self.ua
            if outgoing:
                ua.sendRequest(ua.createRequest('BYE'))
                try: response = yield ua.queue.get(timeout=5) # wait for atmost 5 seconds for BYE response
                except multitask.Timeout: pass # ignore the no response for BYE
            self.ua.queue = None
            self.ua.close()  # this will remove dialog if needed
            self.ua = None
    
    def _run(self):
        '''Thread method for this multitask task.'''
        try:
            while True:
                message = yield self.ua.queue.get()
                if message.method: # request
                    yield self._receivedRequest(message)
                else: # response
                    yield self._receivedResponse(message)
        except GeneratorExit: 
            self.gen = None
            self.ua.queue = multitask.Queue() # this is needed because the queue gets corrupted when generator is closed
           
    def _receivedRequest(self, request):
        '''Callback when received an incoming request.'''
        if _debug: print 'session receivedRequest', request.method, 'ua=', self.ua
        ua = self.ua
        if request.method == 'INVITE': yield self._receivedReInvite(request)
        elif request.method == 'BYE': # remote terminated the session
            ua.sendResponse(200, 'OK')
            yield self.close(outgoing=False)
            yield self._queue.put(('close', None))
        elif request.method == 'MESSAGE': # session based instant message
            ua.sendResponse(200, 'OK')
            message = request.body
            yield self._queue.put(('send', message))
        elif request.method not in ['ACK', 'CANCEL']:
            m = ua.createResponse(405, 'Method not allowed in session')
            m.Allow = sip.Header('INVITE, ACK, CANCEL, BYE', 'Allow')
            ua.sendResponse(m)
    
    def _receivedResponse(self, response):
        '''Callback when received an incoming response.'''
        if _debug: print 'session receivedResponse', response.response, 'ua=', self.ua
        method = response.CSeq.method
        if _debug: print 'Ignoring response ', response.response, 'of', method
    
    def _checkconnectivity(self, outgoing):
        '''Check media connectivity using ICE-style checks on mediasock. After it is done
        it returns 'connected' from register()'''
        if _debug: print 'check connectivity, local=', self.local, 'remote=', self.remote
        try:
            retry = 7 # retry count
            while retry>0:
                if not self.remote:
                    break
                for dest in self.remote: # send a ping to all remote candidates
                    if _debug: print 'sending connectivity request from', self.mediasock.getsockname(), 'to', dest
                    try: self.mediasock.sendto('request', dest)
                    except: pass # ignore any ICMP error.
                try:
                    while True:
                        response, remote = yield multitask.recvfrom(self.mediasock, 1500, timeout=1) # TODO: is the timeout too small?
                        if len(response) > 10: # probably a pending stun response from stun server
                            if _debug: print 'ignoring a late stun response, len=', len(response), 'remote=', remote
                            continue
                        break
                except multitask.Timeout:
                    retry = retry-1
                    continue
                
                if _debug: print 'received from', remote, 'response=', response
                #talk.mediasock.connect(remote) # connect the UDP socket to that address
                if response == 'request':
                    self.mediasock.sendto('response', remote)
                if _debug: print 'connected to peer', remote
                self.remotemediaaddr = remote
                break # connectivity check is completed
        except:
            if _debug: print '_checkconnectivity() exception', (sys and sys.exc_info() or None)
            
    def _receivedReInvite(self, request): # only accept re-invite if no new media stream.
        if not self.media or not hasattr(self.media, 'mysdp') or not hasattr(self.media, 'yoursdp') or not hasattr(self.media, 'setRemote'):
            self.ua.sendResponse(501, 'Re-INVITE Not Supported')
        elif not (request.body and request['Content-Type'] and request['Content-Type'].value.lower() == 'application/sdp'):
            self.ua.sendResponse(488, 'Must Supply SDP in Request Body')
        else:
            oldsdp, newsdp = self.yoursdp, SDP(request.body)
            if oldsdp and newsdp and len(oldsdp['m']) != len(newsdp['m']): # don't accept change in m= lines count
                self.ua.sendResponse(488, 'Change Not Acceptable Here')
            else:
                self.media.setRemote(newsdp)
                mysdp, yoursdp, m = self.media.mysdp, self.media.yoursdp, self.ua.createResponse(200, 'OK')
                m.body, m['Content-Type'] = str(mysdp), sip.Header('application/sdp', 'Content-Type')
                self.ua.sendResponse(m)
                yield self._queue.put(('change', yoursdp))

    def hold(self, value): # send re-INVITE with SDP ip=0.0.0.0
        if self.media and hasattr(self.media, 'hold') and hasattr(self.media, 'mysdp'):
            self.media.hold(value); 
            self.change(self.media.mysdp)
        else: raise ValueError('No media attribute found')
        
    def change(self, mysdp):
        if self.ua:
            m = self.ua.createRequest('INVITE')
            m['Content-Type'] = sip.Header('application/sdp', 'Content-Type')
            m.body = str(mysdp)
            self.ua.sendRequest(m)
        
class Presence(object):
    '''The Presence object represents a single subscribe dialog between local user and remote
    contact.'''
    def __init__(self, user, dest):
        self.user, self.dest = user, dest
        self.ua = self.gen = None
        self._queue = multitask.Queue()
        
    def start(self, outgoing):
        '''A generator function to initiate the connectivity check and then start the run
        method to receive messages on this ua.'''
        self.gen = self._run()
        multitask.add(self.gen)
        yield 
    
    def status(self, status):
        '''Update my presence status to the remote.'''
        if self.ua:
            ua = self.ua
            m = ua.createRequest('MESSAGE')
            m['Content-Type'] = sip.Header('text/plain', 'Content-Type')
            m.body = str(status) # TODO: update this to send NOTIFY or PUBLISH
            ua.sendRequest(m)
        yield # I don't wait for response 
    
    def recv(self, timeout=None):
        cmd, arg = yield self._queue.get(timeout=timeout)
        raise StopIteration((cmd, arg))
    
    def close(self, outgoing=True):
        '''Close the call and terminate any generators.'''
        self.local = self.remote = None # do not clear mediasock yet
        if self.gen: # close the generator
            self.gen.close()
            self.gen = None
        if self.ua:
            if outgoing:
                self.ua.sendRequest(self.ua.createRequest('BYE'))
                try: response = yield self.ua.queue.get(timeout=5) # wait for atmost 5 seconds for BYE response
                except: pass # ignore the timeout error
            self.ua.queue = None
            self.ua.close()  # this will remove dialog if needed
            self.ua = None
    
    def _run(self):
        '''Thread method for this multitask task.'''
        try:
            while True:
                message = yield self.ua.queue.get()
                if message.method: # request
                    yield self._receivedRequest(message)
                else: # response
                    yield self._receivedResponse(message)
        except GeneratorExit: 
            self.gen = None
            self.ua.queue = multitask.Queue()
            
    def _receivedRequest(self, request):
        '''Callback when received an incoming request.'''
        ua = self.ua
        if request.method == 'INVITE':
            ua.sendResponse(501, 're-INVITE not implemented')
        elif request.method == 'BYE': # remote terminated the session
            yield self.close(outgoing=False)
            yield self._queue.put(('close', None))
        elif request.method == 'MESSAGE': # session based instant message
            message = request.body
            yield self._queue.put(('send', message))
        elif request.method not in ['ACK', 'CANCEL']:
            m = ua.createResponse(405, 'Method not allowed in session')
            m.Allow = sip.Header('INVITE, ACK, CANCEL, BYE', 'Allow')
            ua.sendResponse(m)
    
    def _receivedResponse(self, response):
        '''Callback when received an incoming response.'''
        method = response.CSeq.method
        if _debug: print 'Ignoring response ', response.response, 'of', method
    
#------------------------------ Conf --------------------------------------

'''
The Conf class implements decentralized conferencing based on Jonathan Lennox's 
PhD thesis found at http://www1.cs.columbia.edu/~lennox/thesis.pdf
The model is that of full-mesh conference, where there is a signaling and media
relationship between every pair of participants. Any existing participant can
invite another participant. Every participant maintains its own list of membership
which eventual converges, even in the case of simultaneous join and leave.
Since the media stream is point-to-point between every pair of participants,
every participant is responsible for mixing or displaying multiple streams, one
from each active participant. This scheme works well for small 2-5 party conferences
assuming enough network bandwidth at each participant's network.

Each participant maintains the following conference state:
- id which uniquely identifies the named conference and is usually derived randomly by originator.
  For well-known conferences, one can use a pre-defined id, e.g., 'meetkundan'.
- originator is the Member which invited this participant in the conference. This is used in
  the Invited-By header in SIP INVITE to connect with existing participants. 
- name is a user understandable conference name such as 'my private meeting'.
- tag which identifies this participant's membership to this conference. 
- membership information as a list of Member where each Member has
  SIP address, tag, and state (pending or established).

To invite a new participant in the conference, 
  the participant sends a SIP INVITE message with Conf-ID and local tag

When a participant receives a INVITE
  if the target has a tag but doesnot match our tag,
    then reject the call
  else if the source is already a established Member in our conf state
    then reject the call
  else if the source is a pending Member in our conf state
    use a tie breaker to decide which direction of invitation is used.
    if our address.uri (user@domain) is less than source's address.uri in string comparision
      then reject the call. The source will do similar logic and accept the call.
  
  if there is no Invited-By header in INVITE request
    then treat this as a new call invitation and let the application decide whether to accept.
    when the application accepts, then send the 200 OK response, else send a failure response
  else this is for an existing conference
    if the Invited-By is correct and a Member in our conf state
      then accept the invitation as a new Member
    else
      reject the invitation saying this Invited-By does not belong to existing conf state
      
  When generating a 200 OK response to INVITE
    include one or more Conf-Member header with information about each established Member
    in particular, the address and tag of the Member

When a participant receives a 200 OK or a ACK message
  As per SIP spec generate ACK for a 200 OK response
    The ACK has a Conf-Member header with information about each established Member's
    address and tag
  if the message has Conf-Member header(s)
    for each member in Conf-Member
      if member is not a Member in our conf state
        then send INVITE to that member with Invited-By header set to the originator 
        of our conf state
  if message is ACK and our list of established Member is different than list of members in Conf-Member
    send INVITE with latest Conf-Member information to the source

Each Member in the conf-state is like a Session, where the pending or established state is
determined based on whether we received a 200 OK or ACK or not.

SIP headers
-----------
Examples of new SIP headers that are included are as follows:
The Conf-ID header's value is the id of the conf state. The additional parameter 'from' contains
the tag of the originator of the message (hence response's from will be the tag of the participant
that is generating the 200 OK response; thus header cannot be blindly copied from request to
response when generating a 200 OK.). The optional 'to' parameter contains the tag of the 
intended receiver of the message, if the local conf state's Member has known tag for that
participant. This is used by the receiver to know if the message is indeed intended for it or
some other instance of the participant's membership.
 
    Conf-ID: 727818273;from=88273747;to=415256273
    
The Invited-By header's value contains the address of the Member who is the originator of the
conference in this participant's conf state. It is used only in INVITE that is sent to connect
with existing participant after accepting a conference invitation. The tag parameter is 
mandatory stores the tag of the originator. The receiver usually can ignore the value, but
use only the tag for sanity checks.

    Invited-By: "Kundan Singh" <sip:kundan@iptel.org>;tag=88273747
    
The Conf-Member header can appear zero or more times in 200 OK and ACK messages. Each
such header contains information about an existing known participant's established Member 
information such as address and tag. A pending Member is not used in constructing Conf-Member
header.

    Conf-Member: "Sanjay Chouksey" <sip:sanjayc77@iptel.org>;tag=415256273
'''

class Member(object):
    def __init__(self, address, tag=None, state='pending'):
        self.address, self.tag, self.state, self.session = address, tag, state, None
        
class Conf(object):
    '''A conference object that is used for communication between a User and one or more
    Contact.'''
    def __init__(self, name, id, user):
        self.name, self.id, self.user, self.address = name, id, user, user.address
        self.originator = None
        self.tag = str(random.randint(0, 2**32))
        self.members = [] # TODO: use a better data structure like set or map indexed by tag as well as address
        
    def __repr__(self):
        print '<Conf name=%s id=%s user=%s members=%d>'%(self.name, self.id, self.user.address, len(self.members))
        
    def find(self, addrortag):
        '''Find a Member with the given address or tag.'''
        if isinstance(addrortag, Address):
            for member in self.members:
                if member.address.uri == addrortag.uri:
                    return member
        else:
            for member in self.members:
                if member.tag == addrortag:
                    return member
        return None
    
    def invite(self, dest):
        '''Invite a destination user in the conference. The method is similar to User.connect.'''
        dest, user = Address(str(dest)), self.user
        
        if self.find(dest): # if it is already a member, don't invite again
            raise StopIteration((None, '400 Already a conference member'))
        
        member = Member(address=dest)
        self.members.append(member)
        
        ua = user.createClient(dest)
        ua.queue = multitask.Queue() # to receive responses
        m = ua.createRequest('INVITE')
        
        #local = yield self._getLocalCandidates(mediasock) # populate the media candidates
        #for c in local: # add proprietary SIP header - Candidate
        #    m.insert(sip.Header(c[0] + ':' + str(c[1]), 'Candidate'), True)
        m['Conf-ID'] = sip.Header(str(self.id), 'Conf-ID')
        m['Conf-ID']['from'] = self.tag
 
        ua.autoack = False
        ua.sendRequest(m)
        
        while True:
            response = yield ua.queue.get()
            if response.is2xx: # success
                ua = hasattr(ua, 'dialog') and ua.dialog or ua # update ua if needed
                    
                session = Session(user=self, dest=dest)
                session.ua = ua
                #session.mediasock = mediasock
                #session.local = local
                #session.remote= [(x.value.split(':')[0], int(x.value.split(':')[1])) for x in response.all('Candidate')] # store remote candidates 
                
                if response['Conf-ID']:  # remote supports conference
                    member.tag = response['Conf-ID']['from']
                    member.state = 'established'
                    
                m = ua.createRequest('ACK') # send a ACK
                self._populateMessage(m, member.tag)
                ua.sendRequest(m) # send the request
                
                toinvite = self.remaining(response)
                if toinvite:
                    multitask.add(self.connect(toinvite)) # connect to those members if needed
                
                yield session.start(True)
                member.session = session
                raise StopIteration((member, None))
            elif response.isfinal: # some failure
                self.members.remove(member)
                raise StopIteration((None, str(response.response) + ' ' + response.responsetext))
        
    def connect(self, members):
        for member in members:
            if member.address.uri != self.address.uri and member.tag != self.tag and not self.find(member.tag) and member.state == 'pending':
                self.members.append(member)
                
                ua = self.user.createClient(member.address)
                ua.queue = multitask.Queue() # to receive responses
                m = ua.createRequest('INVITE')
                
                #local = yield self._getLocalCandidates(mediasock) # populate the media candidates
                #for c in local: # add proprietary SIP header - Candidate
                #    m.insert(sip.Header(c[0] + ':' + str(c[1]), 'Candidate'), True)
                m['Conf-ID'] = sip.Header(str(self.id), 'Conf-ID')
                m['Conf-ID']['from'] = self.tag
                m['Invited-By'] = sip.Header(self.originator and str(self.originator.address) or str(self.address), 'Invited-By')
                m['Invited-By']['tag'] = self.originator and self.originator.tag or self.tag
         
                ua.autoack = False
                ua.sendRequest(m)
                
                while True:
                    response = yield ua.queue.get()
                    if response.is2xx: # success
                        ua = hasattr(ua, 'dialog') and ua.dialog or ua # update ua if needed
                            
                        session = Session(user=self, dest=member.address)
                        session.ua = ua
                        #session.mediasock = mediasock
                        #session.local = local
                        #session.remote= [(x.value.split(':')[0], int(x.value.split(':')[1])) for x in response.all('Candidate')] # store remote candidates 
                        
                        if response['Conf-ID']:  # remote supports conference
                            member.tag = response['Conf-ID']['from']
                            member.state = 'established'
                            
                        m = ua.createRequest('ACK') # send a ACK
                        self._populateMessage(m, member.tag)
                        ua.sendRequest(m) # send the request

                        toinvite = self.remaining(response)
                        if toinvite:
                            multitask.add(self.connect(toinvite)) # connect to those members if needed
                        
                        yield session.start(True)
                        member.session = session
                        raise StopIteration((member, None))
                    elif response.isfinal: # some failure
                        self.members.remove(member)
                        raise StopIteration((None, str(response.response) + ' ' + response.responsetext))
                        
    def remaining(self, response):
        toinvite = []
        for mem in response.all('Conf-Member'): # for each Conf-Member in response
            if ('state' not in mem or mem['state'] == 'established') and not self.find(mem.tag):
                toinvite.append(Member(address=Address(mem.value), tag=mem.tag))  
        return toinvite
    
    def _populateMessage(self, m, desttag=None): 
        '''Populate the message with local headers.'''
        m['Conf-ID'] = sip.Header(str(self.id), 'Conf-ID')
        m['Conf-ID']['from'] = self.tag
        if desttag: m['Conf-ID']['to'] = desttag
        for mem in self.members: # add Conf-Member
            if mem.state == 'established':
                hdr = sip.Header(str(mem.address), 'Conf-Member')
                hdr['tag'] = mem.tag
                m.insert(hdr, append=True)
        return m
    
    def accept(self, arg):
        '''Accept an incoming invitation (dest, ua) or connect in this conference.'''
        try:
            dest, ua = arg
            request = ua.request # the original incoming request
            if request['Conf-ID']['to'] and request['Conf-ID']['to'] != self.tag:
                raise StopIteration((None, '400 Invalid to parameter in Conf-ID'))
            elif not request['Conf-ID']['from']:
                raise StopIteration((None, '400 Missing from parameter in Conf-ID'))
    
            tag = request['Conf-ID']['from']
            member = self.find(tag)
            if not member: # not already found by tag
                member = self.find(request.From.value)
                if member: # found by name
                    if member.state == 'established': # accept without problem
                        member.tag = tag
                        raise StopIteration((member, 'Already accepted'))
                    else:
                        raise StopIteration((None, '400 Simultaneous invitations'))
            else: # member exists
                if member.state == 'established':
                    raise StopIteration((None, 'Already a member'))
                elif member.state == 'pending' and self.address.uri < member.address.uri:
                    raise StopIteration((None, '400 Simultaneous invitations'))
                
            if request['Invited-By']: # a connect
                if not self.find(request['Invited-By']['tag']): # not found
                    raise StopIteration((None, '400 Invalid Invited-By header'))
            if not member:
                member = Member(address=request.From.value, tag=request['Conf-ID']['from'])
                self.originator = member
                self.members.append(member)
            raise StopIteration((member, None))
            
        except StopIteration, E: # send response and receive ACK before re-raising
            if E[0][0]:  # member is present, accept
                member = E[0][0]
                if isinstance(member, Member):
                    if _debug: print 'NOT A MEMBER', type(member)
                     
                m = ua.createResponse(200, 'OK')
                ua.queue = multitask.Queue()
                
                #local = yield self._getLocalCandidates(mediasock)
                #for c in local: # add proprietary SIP header - Candidate
                #    m.insert(sip.Header(c[0] + ':' + str(c[1]), 'Candidate'), True)
                    
                self._populateMessage(m, member.tag)
                ua.sendResponse(m)
                ua = hasattr(ua, 'dialog') and ua.dialog or ua
                
                try:
                    while True:
                        request = yield ua.queue.get(timeout=5) # wait for 5 seconds for ACK
                        if request.method == 'ACK':
                            session = Session(user=self, dest=dest)
                            session.ua = ua
                            #session.mediasock = mediasock
                            #session.local = local
                            #session.remote= [(x.value.split(':')[0], int(x.value.split(':')[1])) for x in ua.request.all('Candidate')] # store remote candidates 
                            
                            yield session.start(False)
                            if member.state == 'pending': member.state = 'established'
                            member.session = session
                            
                            toinvite = self.remaining(request)
                            if toinvite:
                                multitask.add(self.connect(toinvite)) # connect to those members if needed
                                
                            raise StopIteration((member, None))
                except multitask.Timeout: pass
                except GeneratorExit: pass
                
                self.members.remove(member)
                raise StopIteration((None, 'didnot receive ACK'))
            
            else: # failure response
                code, sep, rest = E[0][1] and E[0][1].partition(' ') or (200, '', 'OK')
                code = int(code)
                ua.sendResponse(ua.createResponse(code, rest))
                raise # re-raise Stop iteration exception for failure
        
    def recv(self):
        '''Receive any membership change events.'''
        
    def close(self):
        '''Close the conference by sending BYE to all the active members.'''
        for member in self.members:
            if member.state == 'established' and member.session:
                session = member.session
                yield session.close()
                member.session = None
                member.state = 'closed'
        self.members[:] = [] # clear the members
                
#------------------------- Unit test --------------------------------------

def testRegister():
    sock = socket.socket(type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 5062)) # use port 5062 for kundansingh99@iptel.org

    user = User(sock).start()
    result, reason = yield user.bind('"Kundan Singh" <sip:kundansingh99@iptel.org>', username='kundansingh99', password='mypass')
    print 'user.bind() returned', result, reason
    result, reason = yield user.close()
    print 'user.close() returned', result, reason
    user.stop()
    sock.close()

def testOutgoing(user, dest):
    msock = socket.socket(type=socket.SOCK_DGRAM)
    msock.bind(('0.0.0.0', 0))
    yourself, reason = (yield user.connect(dest, msock))
    if yourself:
        print 'call established'
        for x in range(0,3):
            yield multitask.sleep(1)
            msock.sendto('test media data', yourself.remotemediaaddr)
        print 'sending IM'
        yield yourself.send('example IM')
        yield multitask.sleep(5) # wait before closing the call
        print 'closing the call'
        yield yourself.close()
        print 'done'
        yield multitask.sleep(3) # wait before exiting
    else:
        print 'call failed', reason
        
def testIncoming(user):
    while True:
        cmd, arg = (yield user.recv())
        if cmd == 'connect':
            print 'incoming call from', arg
            msock = socket.socket(type=socket.SOCK_DGRAM)
            msock.bind(('0.0.0.0', 0))
            yourself, arg = yield user.accept(arg, msock)
            if not yourself:
                print 'cannot accept call', arg
                
            while True:
                try:
                    data, remote = yield multitask.recvfrom(msock, 1500, timeout=3)
                    print 'remote data is', data
                except:
                    break
            while True:
                cmd, arg = yield yourself.recv()
                print 'received command', cmd, arg
                if cmd == 'close':
                    break
        elif cmd == 'close':
            print 'incoming call cancelled by', arg
        elif cmd == 'send':
            print 'paging-mode IM received', arg

def testCall():
    sock1 = socket.socket(type=socket.SOCK_DGRAM)
    sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock1.bind(('0.0.0.0', 5062)) # use port 5062 for kundansingh99@iptel.org
    
    sock2 = socket.socket(type=socket.SOCK_DGRAM)
    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock2.bind(('0.0.0.0', 5060)) # use port 5060 for kundan@iptel.org
    
    user1 = User(sock1).start()
    user1.address = Address('"Kundan Singh" <sip:kundansingh99@iptel.org>')
    user1.username, user1.password = 'kundansingh99', 'mypass'
    result, reason = yield user1.bind(user1.address) 
    
    user2 = User(sock2).start()
    user2.address = Address('"Kundan" <sip:kundan@iptel.org>')
    user2.username, user2.password = 'kundan', 'mypass'
    
    multitask.add(testIncoming(user1))
    yield multitask.sleep(2)

    yield testOutgoing(user2, 'sip:kundansingh99@iptel.org')

    yield user1.stop()
    yield user2.stop()
    
def testConf():
    data = [(5060, '"User1" <sip:user1@localhost:5060>', 'user1', 'passwd1'), \
            (5062, '"User2" <sip:user2@localhost:5062>', 'user2', 'passwd2'), \
            (5064, '"User3" <sip:user3@localhost:5064>', 'user3', 'passwd3')]
    users = []
    for port,aor,u,p in data:
        sock = socket.socket(type=socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
        user = User(sock).start()
        user.address = Address(aor)
        user.username, user.password = u, p
        users.append(user)

    for user in users: # install listener for participants
        def listener(self):
            def sessionlistener(session):
                while True:
                    cmd, arg = yield session.recv()
                    if cmd == 'close': # closed the call
                        print 'call closed'
                        break
            conf = None
            while True:
                cmd, arg = yield self.recv()
                if cmd == 'confinvite':
                    conf = Conf(name=arg[0], id=arg[1], user=user)
                    member, reason = yield conf.accept(arg) # accept the invitation in a conference
                    if member:
                        multitask.add(sessionlistener(member.session))
                elif cmd == 'confconnect':
                    if conf:
                        member, reason = yield conf.accept(arg) 
                        if member:
                            multitask.add(sessionlistener(member.session))
                        
                    
        multitask.add(listener(user))
        
    conf = Conf(name='sip:conf@iptel.org', id=str(random.randint(0, 2**32)), user=users[0]) # first user hosts the conference
    for user in users[1:]: # and invites other users
        yield multitask.sleep(2) # wait before inviting a participant
        yield conf.invite(str(user.address))

    yield multitask.sleep(5) # wait while conf is active

    yield conf.close()
    yield multitask.sleep(2)

    for user in users:
        user.stop()

if __name__ == '__main__':
    #multitask.add(testRegister())
    multitask.add(testCall())
    #multitask.add(testConf())
    try:
        multitask.run()
    except KeyboardInterrupt:
        pass
    
