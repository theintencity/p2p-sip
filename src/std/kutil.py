'''
Implement common utilities that are needed in more than one standards or RFCs, e.g.,
Timer and getlocaladdr.
'''

import socket

class Timer(object):
    '''Timer (multitask version) object used by SIP (rfc3261.Stack) and RTP (rfc3550.Session) among others.'''
    def __init__(self, app):
        self.app = app
        self.delay, self.running, self.gen = 0, False, None 
    def start(self, delay=None):
        import multitask
        if self.running: self.stop() # stop previous one first.
        if delay is not None: self.delay = delay # set the new delay
        self.running = True
        self.gen = self.run()
        multitask.add(self.gen)
    def stop(self):
        if self.running: self.running = False
        if self.gen: 
            try: self.gen.close()
            except: pass
            self.gen = None
    def run(self):
        try:
            import multitask
            yield multitask.sleep(self.delay / 1000.0)
            if self.running: self.app.timedout(self)
        except: pass # probably stopped before timeout

class gevent_Timer(object):
    '''Timer (gevent version) object used by SIP (rfc3261.Stack) and RTP (rfc3550.Session) among others.'''
    def __init__(self, app):
        self.app = app
        self.delay, self.running, self.gen = 0, False, None 
    def start(self, delay=None):
        import gevent
        if self.running: self.stop() # stop previous one first.
        if delay is not None: 
            self.delay = delay # set the new delay
        self.running = True
        self.gen = gevent.spawn_later(self.delay / 1000.0, self.app.timedout, self)
    def stop(self):
        if self.running: 
            self.running = False
        if self.gen: 
            try: self.gen.kill()
            except: pass
            self.gen = None

_local_ip = None # if set, then use this when needed in getlocaladdr

def getlocaladdr(sock=None):
    '''Get the local ('addr', port) for the given socket. It uses the
    getsockname() to get the local IP and port. If the local IP is '0.0.0.0'
    then it uses gethostbyname(gethostname()) to get the local IP. The
    returned object's repr gives 'ip:port' string. If the sock is absent, then
    just gets the local IP and sets the port part as 0.
    '''
    global _local_ip
    # TODO: use a better mechanism to get the address such as getifaddr
    addr = sock and sock.getsockname() or ('0.0.0.0', 0)
    if addr and addr[0] == '0.0.0.0': 
        addr = (_local_ip if _local_ip else socket.gethostbyname(socket.gethostname()), addr[1])
    return addr

def setlocaladdr(ip):
    global _local_ip
    _local_ip = ip
    
import traceback
def getintfaddr(dest):
    '''Get the local address that is used to connect to the given destination address.'''
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dest, 5060))
        result = s.getsockname()[0]
        return result
    except: return None
    finally: s.close()

from threading import Condition, Lock
import time

class MessageCore():
    '''The message core that handles message transfer among different objects. In particular,
    it provides put and get methods to dispatch and (blocked) receive of messages. A message
    is a dict and get can specify criteria to match for incoming message. There is only
    one global Core in this module.
    
    Caution: This uses Condition and Lock, hence must not be used along with multitask's single
    threaded co-operative multitasking framework. MessageCore is meant only for multi-threaded
    applications.'''
    def __init__(self):
        self.pending = [] # pending list. item is (elem, expiry)
        self.waiting = 0  # number of waiting get() calls; don't need a semaphore for single threaded application.
        self.cond    = Condition(Lock())

    def put(self, elem, timeout=10.):
        '''Put a given elem in the queue, and signal one get that is waiting
        on this elem properties. An optional timeout can specify how long to keep the elem
        in the queue if no get is done on the elem, default is 10 seconds.'''
        # TODO: need to change this to allow signaling all waiting get(), but not multiple times.
        self.cond.acquire()
        now = time.time()
        self.pending = filter(lambda x: x[1]<=now, self.pending) # remove expired ones
        self.pending.append((elem, now+timeout))
        self.cond.notifyAll()
        self.cond.release()
        
    def get(self, timeout=None, criteria=None):
        '''Get an elem from the queue that matches the properties specified using the criteria
        which is a function that gets invoked on every element. An optional timeout keyword 
        argument can specify how long to wait on the result. It returns None if a timeout 
        occurs'''
        result, start = None, time.time()
        self.cond.acquire()                                      # get the lock
        now, remaining = time.time(), (timeout or 0)-(time.time()-start)# in case we took long time to acquire the lock
        
        while timeout is None or remaining>=0:
            self.pending = filter(lambda x: x[1]<=now, self.pending) # remove expired ones
            found = filter(lambda x: criteria(x[0]), self.pending)   # check any matching criteria
            if found: # found in pending, return it.
                self.pending.remove(found[0]) # first remove that item
                self.cond.release()
                return found[0]
            self.cond.wait(timeout=remaining)
            remaining = (timeout or 0)-(time.time()-start)

        self.cond.release() # not found and timedout
        return None
    
import weakref

class Dispatcher(object):
    '''A event dispatcher. Should be used very very carefully, because all references are
    strong references and must be explictly removed for cleanup.'''
    #'''A event dispatcher. Should be used very very carefully, because all references are
    #weak references and be removed automatically when the event handler is removed.'''
    def __init__(self): self._handler = {}
    def __del__(self): self._handler.clear()
    
    def attach(self, event, func):
        '''Attach an event which is a lambda function taking one argument, to the event handler func.'''
        if event in self._handler.iterkeys(): 
            if func not in self._handler[event]: self._handler[event].append(func)
        else: self._handler[event] = [func]
    def detach(self, event, func):
        '''Detach the event handler func from the event (or all events if None)'''
        if event is not None:
            if event in self._handler and func in self._handler[event]: self._handler[event].remove(func)
            if len(self._handler[event]) == 0: del self._handler[event]
        else:
            for event in self._handler:
                if func in self._handler[event][:]:
                    self._handler[event].remove(func)
                    if len(self._handler[event]) == 0: del self._handler[event]
    def dispatch(self, data):
        '''Dispatch a given data to event handlers if the event lambda function returns true.'''
        for f in sum([y[1] for y in filter(lambda x: x[0](data), self._handler.iteritems())], []): 
            f(data)
            # TODO: ignore the exception 
                

#------------------------------- Testing ----------------------------------

if __name__ == '__main__':
    # A simple test that starts two timers, t1=4000 and t2=4000ms. When t2 expires,
    # t1 is stopped, and t2 is restarted with 3000ms. The output should print with delay: 
    # timedout 2000
    # stopping timer 4000
    # timedout 3000
    class App(object):
        def timedout(self, timer):
            print 'timedout', timer.delay
            if timer == self.t2 and self.t1 is not None:
                print 'stopping timer', self.t1.delay
                self.t1.stop()
                self.t1 = None
                timer.start(3000)
    app = App()
    t1 = Timer(app)
    t1.start(4000)
    t2 = Timer(app)
    t2.start(2000)
    app.t1 = t1
    app.t2 = t2
    
    import multitask
    multitask.run()
