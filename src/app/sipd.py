# Copyright (c) 2008, Kundan Singh. All rights reserved. See LICENSING for details.

'''
Implements a comprehensive SIP service platform including the following functions:
1. SIP registration, proxy and redirect server
2. Two-stage scalable SIP server farm
3. Master-slave reliable SIP server farm

In future I will implement the following as well:
4. Multiparty conferencing using SIP
5. Unified messaging using SIP
6. Media storage and playback using SIP/RTSP
7. Interactive voice response using SIP/VoiceXML
8. Scalable cache using a DHT
9. Presence agent/server for SIP/SIMPLE
10.Web based configuration using XML-RPC and HTTP
11.Web support using Flash server
12.Backend database for storing configuration and profile
13.Media relay using TURN and STUN. (no ICE).

This is just the controller module which invokes individual functions from other modules
based on the configuration. All configuration is done using web and stored in the database.
Multiple instances of the application interact with each other and share the signaling and
media responsibility as needed.

The high level script in this module controls the behavior of an incoming call.
'''

import os, sys, sqlite3

if __name__ == '__main__': # hack to add other libraries in the sys.path
    f = os.path.dirname(sys.path.pop(0))
    sys.path += [f, os.path.join(f, 'external')]

import multitask
from app import p2psip

_debug = True

HP = lambda x: (x.partition(':')[0], int(x.partition(':')[2]))

class ServerSIP(p2psip.AbstractAgent):
    '''The SIP server component of the system.'''
    def __init__(self, sipaddr=('0.0.0.0', 5060), primary=[], secondary=[], **kwargs):
        if _debug: print 'sipaddr=', sipaddr, 'primary=', primary, 'secondary=', secondary
        p2psip.AbstractAgent.__init__(self, sipaddr)
        self.primary, self.secondary, self.index = primary, secondary, 0
        local = sipaddr if sipaddr[0] != '0.0.0.0' else ('localhost', sipaddr[1])
        if primary and local in primary: self.index = primary.index(local)+1 if local in primary else 0
        elif secondary and local in secondary: self.index = -secondary.index(local)-1 if local in secondary else 0
        elif primary or secondary: raise ValueError('sipaddr argument must exist in primary or secondary if primary or secondary are specified')
        self.location = dict()
    def onRequest(self, ua, request, stack): # any other request
        if request.Route: # if route header is present unconditionally proxy the request
            proxied = ua.createRequest(request.method, dest=request.uri, recordRoute=(request.method=='INVITE'))
            ua.sendRequest(proxied)
            return
        if self.index > 0 and request.uri.user is not None: # if we are first stage proxy, proxy to second stage if needed
            if len(self.primary) > 1 and (hash(request.uri.user) % len(self.primary)+1) != self.index: # in the two-stage server farm, not for us
                proxied = ua.createRequest(request.method, dest=self.primary[hash(request.uri.user) % len(self.primary)], recordRoute=False)
                ua.sendRequest(proxied)
                return
        dest = self.locate(request.uri) # proxy based on location
        if _debug: print 'locations=', dest
        if dest: 
            for d in dest:
                proxied = ua.createRequest(request.method, dest=d, recordRoute=True)
                ua.sendRequest(proxied)
        else:
            ua.sendResponse(480, 'Temporarily unavailable') # or 404 not found?
        
class Agent(object):
    '''The service agent creates various ports for incoming connections/messages. When a message is received
    it invokes the appropriate service entity to handle the message. There are three main service agents: SIP,
    web and Flash with default port numbers as 5062, 80 and 1935, respectively. If the application is not running
    as root/admin, then it uses port 8080 for web instead of restricted port 80.'''
    def __init__(self, **kwargs):
        self.sip = ServerSIP(**kwargs)
    def start(self):
        self.sip.start()
        return self
    def stop(self):
        self.sip.stop()
    
#------------------------------------------- Testing ----------------------
_apps = dict()
def start(app=None, **kwargs):
    global _apps
    if app not in _apps:
        agent = _apps[app] = Agent(**kwargs).start()
def stop(app=None):
    global _apps
    if app in _apps:
        _apps[app].stop(); del _apps[app]
        
if __name__ == '__main__':
    from optparse import OptionParser, OptionGroup
    parser = OptionParser()
    parser.add_option('-d', '--verbose',   dest='verbose', default=False, action='store_true', help='enable debug for all modules')
    parser.add_option('-l', '--local',     dest='local',   default='0.0.0.0:5060', metavar='HOST:PORT', help='local listening HOST:PORT. Default is "0.0.0.0:5062"')
    group = OptionGroup(parser, 'Failover and Load Sharing', 'Use these options to specify multiple primary and secondary SIP servers, by using multiple -p and -s options. The server farm automatically uses two-stage architecture if there are multiple primary servers. Each instance of the server in the farm must use the same ordered list of server options.')
    group.add_option('-p', '--primary',   dest='primary', default=[], action="append", metavar='HOST:PORT',  help='primary server HOST:PORT. This option can appear multiple times.')
    group.add_option('-s', '--secondary', dest='secondary',default=[], action="append",metavar='HOST:PORT',  help='secondary server HOST:PORT. This option can appear multiple times.')
    parser.add_option_group(group)
    (options, args) = parser.parse_args()
    
    if options.verbose: 
        from app import p2psip
        from std import rfc3261
        _debug = p2psip._debug = rfc3261._debug = True 

    start(sipaddr=HP(options.local), primary=[HP(x) for x in options.primary], secondary=[HP(x) for x in options.secondary])
    try: multitask.run()
    except KeyboardInterrupt: pass
    stop()
