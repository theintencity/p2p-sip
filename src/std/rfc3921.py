# Copyright (c) 2007-2008, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3921 (XMPP IM and presence for client)
# This is still incomplete

import time, sys, select, multitask, traceback
if __name__ == '__main__': sys.path.append('../external'); sys.path.append('../std')
from simplexml import XML, XMLList
from rfc3920 import Connection, JID, Stanza, bind, authenticate

#------------------------------------------------------------------------------
# Private utility definitions
#------------------------------------------------------------------------------

_debug = True
def Property(func): return property(doc=func.__doc__, **func()) # This is used as decorator to define a property.
def respond(*args): raise StopIteration, tuple(args) if len(args) != 1 else args # a generator function calls respond to return a response
F = lambda x: x and x[0] or None # return first of a list or None if empty

def child(tag): # define a python attribute as an XML child tag.
    def func():
        def fget(self): return F(self(tag))
        def fset(self, value):
            if value is None: fdel(self) # None is treated as delete
            else:
                elem = isinstance(value, XML) and value or XML(tag=tag, children=[unicode(value)])
                self.children |= elem
            return elem
        def fdel(self): del self.children[tag]
        return dict(fget=fget, fset=fset, fdel=fdel)
    func = property(**func())
    return func
        
#------------------------------------------------------------------------------
# Data Structures        
#------------------------------------------------------------------------------

class Message(Stanza):
    '''A single instant message is represented using Message object'''
    types = ('chat', 'error', 'groupchat', 'headline', 'normal', None) 
    subject, thread, body = child('subject'), child('thread'), child('body')
    def __init__(self, value=None, **kwargs):
        super(Message, self).__init__(value=value, **kwargs); self.tag = 'message'
        self.direction, self.time = None, time.time() # these are not XML attributes
        for k,v in kwargs.iteritems(): self.__setattr__(k, str(v)) # should include type, to, frm, subject, thread, body
        
class Presence(Stanza):
    '''A single presence request.'''
    types = ('unavailable', 'subscribe', 'subscribed', 'unsubscribe', 'unsubscribed', 'probe', 'error', None)
    shows = ('away', 'chat', 'dnd', 'xa', None)
    show, status, priority = child('show'), child('status'), child('priority')
    def __init__(self, **kwargs):
        Stanza.__init__(self, tag='presence')
        for k,v in kwargs.iteritems(): 
            if v is not None: self.__setattr__(k, str(v)) # should include type, to, frm, show, status, priority

class Contact(XML):
    '''Maintain the contact information in XML'''
    subscriptions = ('none', 'from', 'to', 'both')
    asks = ('subscribe', 'unsubscribe')
    group = child('group')
    def __init__(self, value=None, tag='item', jid=None, name=None, subscription=None, ask=None, **kwargs):
        super(Contact, self).__init__(value=value, tag=tag, **kwargs)
        if not value:
            for a in ('jid', 'name', 'subscription', 'ask'):
                if locals()[a]: self.attrs[a] = locals()[a]
    def __getattribute__(self, key):
        if key in ('jid'): return JID(self.attrs.get(key))
        else: return XML.__getattribute__(self, key)

class Query(XML):
    '''A roster extension 'query' tag in jabber:iq:roster namespace. children can be a list of Contact/XML.'''
    def __init__(self, value=None, tag='query', type='get', xmlns='jabber:iq:roster', **kwargs):
        super(Query, self).__init__(value=value, tag=tag, xmlns=xmlns, **kwargs)
        if not value and type: self._.type = type

#------------------------------------------------------------------------------
# Low level control as event listener        
#------------------------------------------------------------------------------

class Connector(XMLList):
    '''A connector that uses a Connection and processes certain subset of events.'''
    def __init__(self, **kwargs):  # jid
        self.__dict__.update(kwargs)
        self._init, self._filter = False, None
    def __getattr__(self, key): return None # override method to prevent exceptions on attribute read
    
    def connected(self, old, new): pass # should be overridden by sub-class
    def process(self, data): pass       # should be overridden by sub-class
    
    @Property
    def connection():
        def fget(self): return self._connection
        def fset(self, value):
            if value != self._connection:
                if not isinstance(value, Connection): raise ValueError('Invalid connection property')
                old, self._connection = self._connection, value
                if self._filter is not None and old is not None:
                    old.detach(self._filter, self.process)
                if self._filter is not None and value is not None:
                    value.attach(self._filter, self.process)
                self.connected(old, value); 
        return locals()
    
    @Property
    def filter():
        def fget(self): return self._filter
        def fset(self, value):
            if value != self._filter:
                if not callable(value): raise ValueError('Invalid filter: must be function')
                old, self._filter = self._filter, value
                if self._connection is not None and old is not None:
                    self._connection.detach(self._filter, self.process)
                if self._connection is not None and value is not None:
                    self._connection.attach(self._filter, self.process)
        return locals()
    
#------------------------------------------------------------------------------
# Instant Message Management
#------------------------------------------------------------------------------
            
class History(Connector):
    '''Message history is used to maintain the conversation history in a group or one-to-one'''
    def __init__(self, **kwargs):  # type, to, frm
        super(History, self).__init__(**kwargs)
        self._init, self._queue = False, multitask.SmartQueue()
    
    def __repr__(self): return u'<History to="%s" from="%s" type="%s" len="%d" />'%(self.to, self.frm, self.type, len(self)) # override method to return concise information
    # adding a new history item should initialize if needed, hence override these methods
    def __setitem__(self, key, value): result = super(History, self).__setitem__(key, value); self._initialize(); return result
    def append(self, item): super(History, self).append(item); self._initialize()
    def extend(self, list): super(History, self).extend(list); self._initialize()
    
    def send(self, msg, **kwargs):
        if not self.connection: raise IOError, 'history.connection is not set before send'
        if not isinstance(msg, Message): msg = Message(); Message.__init__(msg)
        for x in ('to', 'type'): exec 'if not msg.%s and self.%s: msg.%s = self.%s'%(x,x,x,x)
        yield self.connection.put(msg)
        result = Message(value=str(msg), direction='send') # construct a new
        self.append(result)
        respond(result)
    
    def recv(self, **kwargs):
        result = yield self._queue.get(**kwargs)
        respond(result)
    
    def connected(self, old, new):
        if new is not None:
            def filter(data): # filter out the instant messages
                if data.tag != 'message': return False
                to, frm, type = self.to, self.frm, self.type
                return (not frm or frm == data.attrs['to']) and (not to or to == data.attrs['from']) and (not type or type == data.attrs['type'])
            self.filter = filter
        else: self.filter = None
        
    def process(self, data): # process incoming message
        if not isinstance(data, Message): data = Message(str(data))
        self.append(data)
        def add(self, data): 
            if self._queue is not None: yield self._queue.put(data)
        multitask.add(add(self, data))
        
    def _initialize(self): # configure this history if not already initialized
        if not self._init and len(self) > 0:
            if _debug: print 'history initialized'
            self._init = True
            item = super(History, self).__getitem__(0)
            if item.direction == 'send': self.to, self.frm, self.type = item.to, item.frm, item.type
            else: self.to, self.frm, self.type = item.frm, item.to, item.type
    
#------------------------------------------------------------------------------
# Roster Management        
#------------------------------------------------------------------------------

class Roster(Connector):
    '''User's contact list is maintained as an XMLList (list) of Contact objects.'''
    def __init__(self, **kwargs):
        super(Roster, self).__init__(**kwargs)
        self.presence = None
    def __repr__(self): return u'<Roster jid="%s" len="%d" />'%(self.jid, len(self)) # override method to return concise information
    
    @property
    def jid(self):
        return self.connection is not None and self.connection.jid or JID()
    
    @Property
    def presence():
        '''Represents local user's presence as a read-write attribute.'''
        def fget(self): return self._presence
        def fset(self, value): 
            self._presence = value
            if self.connection is not None and value is not None:
                def sendPresence(value): 
                    if self.connection is not None: yield self.connection.put(msg=value)
                multitask.add(sendPresence(value))
        return locals()

    def fetch(self):
        '''Fetch the roster on startup. This is called when connected.'''
        type, result = yield self.connection.iq(type='get', msg=XML(tag='query', xmlns='jabber:iq:roster'))
        if type == 'error': respond()
        else: 
            self[:] = result() if result else [] # update is called with XMLList of query
            if _debug: 'roster fetched=', self
    
    def addItem(self, item):
        '''Add or update an item (Contact) to the roster. Returns True or False.'''
        type, result = yield self.connection.iq(type='set', msg=Query(children=[item]))
        respond(type == 'result')
        
    def deleteItem(self, item):
        '''Delete an item (Contact) from the roster. Returns True or False.'''
        item = Contact(subscription='remove', jid=item.jid)
        
        type, reult = yield self.connection.iq(type='set', msg=Query(children=[item]))
        respond(type = 'result')
    
    # define additional methods for subscribe, subscribed, unsubscribe and unsubscribed
    for func in ('subscribe', 'subscribed', 'unsubscribe', 'unsubscribed'):
        exec "def %s(self, jid): yield self.connection.put(Presence(to=JID(jid).bareJID, type='%s'))"%(func, func)
    
    def connected(self, old, new): # connection or disconnection callback
        if new is not None: 
            def filter(data):
                if data.tag == 'presence': return True
                elif data.tag == 'iq' and data.type == 'set': query = F(data('query')); return query and query.xmlns == 'jabber:iq:roster'
                else: return False
            self.filter = filter
            multitask.add(self.fetch()) # when connected, install the onRosterSet listener and fetch the roster
            self.presence = Presence()
        else:
            self.filter = None
            self.presence = None
            self.clear()
        
    def process(self, data): # callback to process a incoming event
        if data.tag == 'presence': 
            if _debug: print 'presence update=', data
            data = Presence(value=data)
            if not data.type: pass # available
            elif data.type == 'unavailable': pass # not available
            elif data.type == 'subscribe': pass # incoming subscription
            elif data.type == 'subscribed': pass # outgoing subscription successful
            elif data.type == 'unsubscribe': pass # incoming unsubscription
            elif data.type == 'unsubscribed': pass # outgoing unsubscription completed
        elif data is not None:
            if _debug: print 'roster update=', type(data), data
            # TODO: first reply with a success
            for item in data('item'):
                if item.subscription == 'remove': del self[lambda x: x.jid == item.jid] # remove
                else: self[lambda x: x.jid == item.jid] = item # replace or add
            if _debug: print 'roster update=', self

#------------------------------------------------------------------------------
# High level User class        
#------------------------------------------------------------------------------

class User(Connection):
    '''A User object represents a single local user with methods, login, logout, etc.'''
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        self.roster, self._chat = Roster(), {}
    
    def login(self):
        if not self.username or not self.server or not self.password: respond(None, 'missing username, server or password')
        result, error = yield self.connect()
        if error: yield self.disconnect(); respond(result, error)
        result, error = yield self.authenticate()
        if error: yield self.disconnect(); respond(result, error)
        result, error = yield self.bind()
        if error: yield self.disconnect(); respond(result, error)
        
        self.attach(lambda x: not x or x.tag == 'message', self.process)
        
        self.roster = Roster()
        self.roster.connection = self
        
        respond(self.status, None)
        
    def logout(self):
        if self.connected:
            self.roster.clear() 
            yield self.disconnect()
        self._chat.clear()
    
    def chat(self, to):
        if to not in self._chat:
            history = History(frm=self.jid, to=to)
            history.connection = self
            self._chat[to] = history 
        return self._chat[to]
    
    def process(self, data):
        if not data: multitask.add(self.logout())
        # TODO: check if a chat exists for this user? otherwise add one
    
#------------------------------------------------------------------------------
# TESTING        
#------------------------------------------------------------------------------

def _testData():
    c = Contact(jid='kundan10@gmail.com', name='Kundan Singh')
    q = Query(type='set');
    q.children += c
    print q
    yield

def testMessage():
    m1 = Message(type='chat', to='kundan10@gmail.com', frm='kundansingh99@gmail.com', subject='Hello', direction='recv')
    print 'm1=', m1
    h1 = History()
    h1 += m1
    print 'h1+=m1=', h1
    h1.connection = Connection()
    m2 = Message(body='Hi')
    m3 = yield h1.send(m2)
    print 'm3=', m3
    print 'h1+=m3=', h1
    yield

def testIM(): # TODO: rename this with prefix _ to enable testing
    '''Test the IM sending part of this module'''
    # TODO: change the following to your account and password
    conn = Connection(server='gmail.com', username='kundansingh99', password='mypass')
    type, error = yield conn.connect() 
    if error:  print 'error=', error; respond()
    mechanism, error = yield authenticate(conn)
    if error: print 'error=', error; respond()
    jid, error = yield bind(conn)
    if error: print 'error=', error; respond()
    
    h1 = History(); h1.connection = conn
    m1 = yield h1.send(Message(type='chat', to='kundan10@gmail.com', body='Hello'))
    print 'history=', h1
    
    yield conn.disconnect()
    print 'testIM exiting'

def testPresence(): # TODO: rename this with prefix _ to enable testing
    # TODO: change the following to your account and password
    u1 = User(server='gmail.com', username='kundansingh99', password='mypass')
    result, error = yield u1.login()
    
    yield multitask.sleep(1)
    u1.roster.presence = Presence(show='dnd', status='Online')

    h1 = u1.chat('kundan10@gmail.com')
    yield h1.send(Message(body='Hello How are you?'))

    count = 5
    for i in xrange(5):
        try:
            msg = yield h1.recv(timeout=120)
            print msg
            print '%s: %s'%(msg.frm, msg.body.cdata)
            yield h1.send(Message(body='You said "%s"'%(msg.body.cdata)))
        except Exception, e:
            print str(type(e)), e
            break
        
    yield u1.logout()
    print 'testPresence exiting'

def testClose(): yield multitask.sleep(25); exit()

if __name__ == '__main__':
    import doctest; doctest.testmod()    # first run doctest,
    for f in dir():      # then run all _test* functions
        if str(f).find('_test') == 0 and callable(eval(f)):
            multitask.add(globals()[f]())
    try: multitask.run()
    except KeyboardInterrupt: pass
    except select.error: print 'select error'; pass
    sys.exit()
