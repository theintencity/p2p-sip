# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
'''
OpenDHT API borrowed from http://www.opendht.org.
The put, get and remove functions are generators so that we don't block the
main multitask thread while doing XML-RPC.
'''
import hashlib, multitask
from xmlrpclib import ServerProxy, Binary

_gateway = 'http://opendht.nyuld.net:5851/'
#_gateway = 'http://planetlab3.ucsd.edu:5851/' # an alternative gateway

def put(key, value, secret='', ttl=180, gateway=_gateway):
    '''Invoke XML-RPC put(H(key), value, H(secret), ttl) on the OpenDHT gateway.
    Return True on success and False otherwise.'''
    pxy = ServerProxy(gateway)
    key = Binary(hashlib.sha1(key).digest())
    value = Binary(value)
    shash = Binary(hashlib.sha1(secret).digest())
    if not secret:
        result = pxy.put(key, value, ttl, 'put.py') 
    else:
        result = pxy.put_removable(key, value, 'SHA', shash, ttl, 'put.py')
    return (result == 0)

def remove(key, value, secret, ttl=180, gateway=_gateway):
    '''Invoke XML-RPC rm(H(key), H(value), secret, ttl) on the OpenDHT gateway.
    Return True on success and False otherwise.'''
    pxy = ServerProxy(gateway)
    key = Binary(hashlib.sha1(key).digest())
    valueHash = Binary(hashlib.sha1(value).digest())
    secret = Binary(secret)
    return (pxy.rm(key, valueHash, 'SHA', secret, ttl, 'rm.py') != 0)

def get(key, maxvals=10, gateway=_gateway):
    '''Invoke XML-RPC get_details(H(key), maxvals) on the OpenDHT gateway.
    Return a list of tuple(value, remaining-ttl, hash-algorithm, H(secret))
    where remaining-ttl is int, hash-algorithm is string and H(secret) is lower-case
    hex of hash of secret starting with 0x.'''
    pxy = ServerProxy(gateway)
    pm = Binary('')
    key = Binary(hashlib.sha1(key).digest())
    result = []
    while True:
        vals, pm = pxy.get_details(key, maxvals, pm, 'get.py')
        for v in vals:
            # hex = '0x' + ''.join(['%02x'%ord(x) for x in v[3].data[:4]])
            result.append([v[0].data, v[1], v[2], v[3].data])
        if not pm.data: break
    return result

def lookup(service, maxvals=10, gateway=_gateway):
    '''TODO: Need to implement the ReDiR interface, but for now use get.'''
    return get(service, maxvals, gateway)

def advertise(key, value, ttl=180, gateway=_gateway):
    '''TODO: Need to implement the ReDiR interface, but for now use put.'''
    return put(key, value, secret='', ttl=ttl, gateway=gateway)

class Connector(object):
    '''A Connector object implements the put, get and remove methods
    and also provides failover by connecting to multiple gateways.'''
    # TODO: implement this for robustness.

if __name__ == '__main__':
    print put('kundan', 'Kundan Singh')
    print get('kundan')
    print put('kundan', 'Munna', 'donttell')
    print get('kundan')
    print remove('kundan', 'Munna', 'donttell')
    print get('kundan')
