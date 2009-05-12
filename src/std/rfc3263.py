# Copyright (c) 2008, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3263 (Locating SIP servers)

'''
Uses DNS to resolve a domain name into SIP servers using NAPTR, SRV and A/AAAA records.
TODO: (1) need to make it multitask compatible or have a separate thread, (3) need to return priority and weight.

>>> print resolve('sip:192.1.2.3')                    # with numeric IP
[('192.1.2.3', 5060, 'udp'), ('192.1.2.3', 5060, 'tcp'), ('192.1.2.3', 5060, 'sctp')]
>>> print resolve('sip:192.1.2.3;maddr=192.3.3.3')    #    and maddr param
[('192.3.3.3', 5060, 'udp'), ('192.3.3.3', 5060, 'tcp'), ('192.3.3.3', 5060, 'sctp')]
>>> print resolve('sip:192.1.2.3:5062;transport=tcp') #    and port, transport param
[('192.1.2.3', 5062, 'tcp')]
>>> print resolve('sips:192.1.2.3')                   #    and sips
[('192.1.2.3', 5061, 'tls')]
>>> print resolve('sips:192.1.2.3:5062')              #    and sips, port
[('192.1.2.3', 5062, 'tls')]
>>> print resolve('sip:39peers.net')                  # with non-numeric without NAPTR/SRV
[('74.220.215.84', 5060, 'udp'), ('74.220.215.84', 5060, 'tcp'), ('74.220.215.84', 5060, 'sctp')]
>>> print resolve('sip:39peers.net:5062')             #    and port  
[('74.220.215.84', 5062, 'udp'), ('74.220.215.84', 5062, 'tcp'), ('74.220.215.84', 5062, 'sctp')]
>>> print resolve('sip:39peers.net;transport=tcp')    #    and transport  
[('74.220.215.84', 5060, 'tcp')]
>>> print resolve('sips:39peers.net')                 #    and sips  
[('74.220.215.84', 5061, 'tls')]
>>> print resolve('sip:iptel.org')                    # with no NAPTR but has SRV records
[('213.192.59.75', 5060, '_sip._udp'), ('213.192.59.75', 5060, '_sip._tcp')]
>>> print resolve('sips:iptel.org')                   #    and sips
[('213.192.59.75', 5061, 'tls')]
>>> print sorted(resolve('sip:columbia.edu'))         # with one NAPTR and two SRV records
[('128.59.59.199', 5060, 'udp'), ('128.59.59.79', 5060, 'udp')]
>>> print sorted(resolve('sips:columbia.edu'))        #    and sips (no NAPTR for sips)
[('128.59.48.24', 5061, 'tls')]
>>> print sorted(resolve('sip:yale.edu'))             # with NAPTR and SRV, but no A. uses A for domain.
[('130.132.51.8', 5060, 'tcp'), ('130.132.51.8', 5060, 'udp')]
>>> print sorted(resolve('sip:adobe.com'))            # with multiple NAPTR and multiple SRV
[('192.150.12.115', 5060, 'tcp'), ('192.150.12.115', 5060, 'udp'), ('192.150.12.115', 5061, 'tls')]
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
_resolver, _cache, _secproto, _unsecproto = None, {}, ('tls', ), ('udp', 'tcp', 'sctp') # Name servers and supported transports, resolver and DNS cache (plus negative cache)
_supported = _secproto + _unsecproto # list of supported protocols 
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
        raw = resolver.Raw(key[0], key[1], dns.C_IN, True)
        answer = raw and raw['HEADER']['ANCOUNT'] > 0 and raw['ANSWER'] or []; random.shuffle(answer)
    except Exception, e:
        if _debug: print '_query(', key, ') exception=', e 
        answer = []
    _cache[key] = (answer, time.time() + min([(x['TTL'] if 'TTL' in x else negTimeout) for x in answer] + [negTimeout]))
    return answer
 
# @implements RFC3263 P1L27-P1L32
def resolve(uri):
    '''Resolve a URI using RFC3263 to list of (IP address, port) tuples each with its order, preference, transport and 
    TTL information. The application can supply a list of supported protocols if needed.'''
    if not isinstance(uri, URI): uri = URI(uri)
    transport, target = uri.param['transport'] if 'transport' in uri.param else None, uri.param['maddr'] if 'maddr' in uri.param else uri.host
    numeric, port, result, naptr, srv, result = isIPv4(target), uri.port, None, None, None, None
    #@implements rfc3263 P6L10-P8L32
    if transport: transports = [transport] # only the given transport is used
    elif numeric or port is not None: transports = [x for x in (_secproto if uri.secure else _unsecproto)]
    else:
        naptr = _query((target, dns.T_NAPTR))
        if naptr:
            transports = map(lambda y: _rproto[y[1].lower()], sorted(map(lambda x: (x['RDATA']['ORDER'], x['RDATA']['SERVICE']), naptr), lambda a,b: a[0]-b[0]))
            if uri.secure: 
                transports = filter(lambda x: x in _secproto, transports)
                if not transports: transports, naptr = _secproto, None # assume tls if not found; clear the naptr response
        else:
            srv = filter(lambda x: x[1], [(p, _query(('%s.%s'%(p, target), dns.T_SRV))) for p in [_xproto[x] for x in (_secproto if uri.secure else _unsecproto)]])
            transports = [_rxproto[y[0]] for y in srv] or uri.secure and list(_secproto) or list(_unsecproto)
    #@implements rfc3263 P8L34-P9L31
    if numeric: result = [(target, port or _proto[x][1], x) for x in transports]
    elif port is None:
        service = None
        if naptr: service = sorted(map(lambda x: (x['RDATA']['REPLACEMENT'].lower(), x['RDATA']['ORDER'], x['RDATA']['PREFERENCE'], x['RDATA']['SERVICE'].lower()), naptr), lambda a,b: a[1]-b[1])
        elif transport: service = [('%s.%s'%(_xproto[transport], target), 0, 0, _proto[transport][0])]
        if not srv: srv = filter(lambda y: y[1], [(_rproto[a[3].lower()], _query((a[0], dns.T_SRV))) for a in service]) if service else []
        if srv:
            out = sum([[sorted([(y['RDATA']['DOMAIN'].lower(), y['RDATA']['PRIORITY'], y['RDATA']['WEIGHT'], y['RDATA']['PORT'], x[0])],  lambda a,b: a[1]-b[1]) for y in x[1]] for x in srv], [])
            result = sum([[(y['RDATA'], x[1], x[2]) for y in (_query((x[0], dns.T_A)) or [])] for x in [(x[0], x[3], x[4]) for x in sum(out, [])]], [])
    return result or [(x[0], port or _proto[x[1]][1], x[1]) for x in sum([[(a, b) for a in [x['RDATA'] for x in _query((target, dns.T_A))] ] for b in transports], [])] # finally do A record on target, if nothing else worked

if __name__ == '__main__': # Unit test of this module
    import doctest; doctest.testmod()