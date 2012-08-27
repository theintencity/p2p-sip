# Copyright (c) 2008, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3263 (Locating SIP servers)

'''
Uses DNS to resolve a domain name into SIP servers using NAPTR, SRV and A/AAAA records.
TODO: (1) need to make it multitask compatible or have a separate thread, (3) need to return priority and weight.

>>> print resolve('sip:192.1.2.3')                    # with numeric IP
[('192.1.2.3', 5060, 'udp'), ('192.1.2.3', 5060, 'tcp'), ('192.1.2.3', 5061, 'tls')]
>>> print resolve('sip:192.1.2.3;maddr=192.3.3.3')    #    and maddr param
[('192.3.3.3', 5060, 'udp'), ('192.3.3.3', 5060, 'tcp'), ('192.3.3.3', 5061, 'tls')]
>>> print resolve('sip:192.1.2.3:5062;transport=tcp') #    and port, transport param
[('192.1.2.3', 5062, 'tcp')]
>>> print resolve('sips:192.1.2.3')                   #    and sips
[('192.1.2.3', 5061, 'tls')]
>>> print resolve('sips:192.1.2.3:5062')              #    and sips, port
[('192.1.2.3', 5062, 'tls')]
>>> print resolve('sip:39peers.net')                  # with non-numeric without NAPTR/SRV
[('74.220.215.84', 5060, 'udp'), ('74.220.215.84', 5060, 'tcp'), ('74.220.215.84', 5061, 'tls')]
>>> print resolve('sip:39peers.net:5062')             #    and port  
[('74.220.215.84', 5062, 'udp'), ('74.220.215.84', 5062, 'tcp'), ('74.220.215.84', 5062, 'tls')]
>>> print resolve('sip:39peers.net;transport=tcp')    #    and transport  
[('74.220.215.84', 5060, 'tcp')]
>>> print resolve('sips:39peers.net')                 #    and sips  
[('74.220.215.84', 5061, 'tls')]
>>> print resolve('sip:iptel.org')                    # with no NAPTR but has SRV records
[('217.9.36.145', 5060, 'udp'), ('217.9.36.145', 5060, 'tcp')]
>>> print resolve('sips:iptel.org')                   #    and sips
[('217.9.36.145', 5061, 'tls')]
>>> print resolve('sip:columbia.edu')                 # with one NAPTR and two SRV records
[('128.59.59.229', 5060, 'udp'), ('128.59.59.208', 5060, 'udp')]
>>> print resolve('sips:columbia.edu')                #    and sips (no NAPTR for sips)
[('128.59.48.24', 5061, 'tls')]
>>> print resolve('sip:adobe.com')                    # with multiple NAPTR and multiple SRV
[('192.150.12.115', 5060, 'udp')]
>>> print resolve('sip:adobe.com', supported=('tcp', 'tls')) # if udp is not supported
[('192.150.12.115', 5060, 'tcp')]
>>> print resolve('sips:adobe.com')                    # with multiple NAPTR and multiple SRV
[('192.150.12.115', 5061, 'tls')]
>>> try: resolve('sip:twilio.com')                     # with incorrectly configured SRV
... except: print 'error'
error
'''

import sys, os, time, random
if __name__ == '__main__': # hack to add other libraries in the sys.path
    f = os.path.dirname(sys.path.pop(0))
    sys.path.append(os.path.join(f, 'external'))
if os.name == 'nt': # on windows import w32util and use RegistryResolve
    import w32util
    _nameservers = w32util.RegistryResolve()
else: _nameservers = None

import dns
from std.rfc2396 import URI, isIPv4

_debug = False; # enable debug trace or not
_resolver, _cache = None, {} # Name servers, resolver and DNS cache (plus negative cache)
_proto = {'udp': ('sip+d2u', 5060), 'tcp': ('sip+d2t', 5060), 'tls': ('sips+d2t', 5061), 'sctp': ('sip+d2s', 5060)} # map from transport to details
_rproto = dict([(x[1][0], x[0]) for x in _proto.iteritems()]) # reverse mapping {'sip+d2u': 'udp', ...} 
_xproto = dict([(x[0], '_%s._%s'%(x[1][0].split('+')[0], x[0] if x[0] != 'tls' else 'tcp')) for x in _proto.iteritems()]) # mapping {'udp' : '_sip._udp', ...}
_rxproto = dict([(x[1], x[0]) for x in _xproto.iteritems()]) # mapping { '_sips._tcp': 'tls', ...} 
_zxproto = dict([(x[0], _proto[x[1]]) for x in _rxproto.iteritems()]) # mapping { '_sips._tcp': ('sip+d2t, 5061), ...}
_group = lambda x: sorted(x, lambda a,b: a[1]-b[1]) # sort a list of tuples based on priority

def _query(key, negTimeout=60): # key is (target, type)
    '''Perform a single DNS query, and return the ANSWER section. Uses internal cache to avoid repeating the queries. 
    The timeout of the cache entry is determined by TTL obtained in the results. It always returns a list, even if empty.'''
    global _resolver; resolver = _resolver or dns.Resolver(_nameservers)
    if key in _cache and _cache[key][1] < time.time(): return random.shuffle(_cache[key][0]) and _cache[key][0]
    try:
        raw = resolver.Raw(key[0], key[1], dns.C_IN, recursion=True, proto=None)
        if raw and raw['HEADER']['OPCODES']['TC']: # if truncated, try with TCP
            raw = resolver.Raw(key[0], key[1], dns.C_IN, recursion=False, proto='tcp')
        answer = raw and raw['HEADER']['ANCOUNT'] > 0 and raw['ANSWER'] or []; random.shuffle(answer)
    except Exception, e:
        if _debug: print '_query(', key, ') exception=', e 
        answer = []
    _cache[key] = (answer, time.time() + min([(x['TTL'] if 'TTL' in x else negTimeout) for x in answer] + [negTimeout]))
    return answer
 
# @implements RFC3263 P1L27-P1L32
def resolve(uri, supported=('udp', 'tcp', 'tls'), secproto=('tls',)):
    '''Resolve a URI using RFC3263 to list of (IP address, port) tuples each with its order, preference, transport and 
    TTL information. The application can supply a list of supported protocols if needed.'''
    if not isinstance(uri, URI): uri = URI(uri)
    transport = uri.param['transport'] if 'transport' in uri.param else None
    target = uri.param['maddr'] if 'maddr' in uri.param else uri.host
    numeric, port, naptr, srv, result = isIPv4(target), uri.port, None, None, None
    if uri.secure: supported = secproto # only support secproto for "sips"
    #@implements rfc3263 P6L10-P8L32
    if transport: transports = (transport,) if transport in supported else () # only the given transport is used
    elif numeric or port is not None: transports = supported
    else:
        naptr = _query((target, dns.T_NAPTR))
        if naptr: # find the first that is supported
            ordered = filter(lambda r: r[1] in supported, sorted(map(lambda r: (r['RDATA']['ORDER'], _rproto.get(r['RDATA']['SERVICE'].lower(), ''), r), naptr), lambda a,b: a[0]-b[0])) # filter out unsupported transports
            if ordered:
                selected = filter(lambda r: r[0] == ordered[0][0], ordered) # keep only top-ordered values, ignore rest
                transports, naptr = map(lambda r: r[1], selected), map(lambda r: r[2], selected) # unzip to transports and naptr values
            else: transports, naptr = supported, None # assume failure if not found; clear the naptr response
        if not naptr: # do not use "else", because naptr may be cleared in "if"
            srv = filter(lambda r: r[1], map(lambda p: (_rxproto.get(p, ''), _query(('%s.%s'%(p, target), dns.T_SRV))), map(lambda t: _xproto[t], supported)))
            if srv: transports = map(lambda s: s[0], srv)
            else: transports = supported
    #@implements rfc3263 P8L34-P9L31
    if numeric: result = map(lambda t: (target, port or _proto[t][1], t), transports)
    elif port: result = sum(map(lambda t: map(lambda r: (r['RDATA'], port, t), _query((target, dns.T_A))), transports), [])
    else:
        service = None
        if naptr: service = sorted(map(lambda x: (x['RDATA']['REPLACEMENT'].lower(), x['RDATA']['ORDER'], x['RDATA']['PREFERENCE'], x['RDATA']['SERVICE'].lower()), naptr), lambda a,b: a[1]-b[1])
        elif transport: service = [('%s.%s'%(_xproto[transport], target), 0, 0, _proto[transport][0])]
        if not srv: 
            srv = filter(lambda y: y[1], map(lambda s: (_rproto[s[3].lower()], _query((s[0], dns.T_SRV))), service)) if service else []
        if srv:
            out = list(sorted(sum(map(lambda s: map(lambda r: (r['RDATA']['DOMAIN'].lower(), r['RDATA']['PRIORITY'], r['RDATA']['WEIGHT'], r['RDATA']['PORT'], s[0]), s[1]), srv), []),  lambda a,b: a[1]-b[1]))
            result = sum(map(lambda x: map(lambda y: (y['RDATA'], x[1], x[2]), (_query((x[0], dns.T_A)) or [])), map(lambda r: (r[0], r[3], r[4]), out)), [])
    return result or map(lambda x: (x[0], port or _proto[x[1]][1], x[1]), sum(map(lambda b: map(lambda a: (a, b), map(lambda x: x['RDATA'], _query((target, dns.T_A)))), transports), [])) # finally do A record on target, if nothing else worked

if __name__ == '__main__': # Unit test of this module
    import doctest; doctest.testmod()
