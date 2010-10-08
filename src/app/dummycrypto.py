# Copyright (c) 2009, Kundan Singh. All rights reserved. See LICENSING for details.

'''
A dummy module to act as a stub for crypto.
'''

import os, struct, pickle

class PublicKey(object): 
    __slots__ = ('n', 'e', '_data', '_bits')
    def __init__(self, data=None, **kwargs):
        if data: kwargs = pickle.loads(data)
        [setattr(self, k, kwargs.get(k, None)) for k in PublicKey.__slots__]
    def __str__(self):
        return pickle.dumps(dict([(k, getattr(self, k)) for k in PublicKey.__slots__]))
    
class PrivateKey(object): 
    __slots__ = ('n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'iqmp', '_data', '_bits') 
    def __init__(self, data=None, **kwargs):
        if data: kwargs = pickle.loads(data)
        [setattr(self, k, kwargs.get(k, None)) for k in PrivateKey.__slots__]
    def __str__(self):
        return pickle.dumps(dict([(k, getattr(self, k)) for k in PrivateKey.__slots__]))
    
def generateRSA(bits=1024): Ks = PrivateKey(n=10,e=10,d=10,p=10,q=10,dmp1=10,dmq1=10,iqmp=10,_data=10,_bits=bits); return (Ks, extractPublicKey(Ks))
def extractPublicKey(Ks): return PublicKey(n=Ks.n,e=Ks.e,_data=Ks._data,_bits=Ks._bits)
def sign(Ks, hash): return str(hash)
def verify(Kp, hash, signature): return str(hash) == signature
