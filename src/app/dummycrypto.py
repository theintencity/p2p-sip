# Copyright (c) 2009, Kundan Singh. All rights reserved. See LICENSING for details.

'''
A dummy module to act as a stub for crypto.
'''

import os, struct

class PublicKey(object): 
    __slots__ = ('n', 'e', '_data', '_bits')
    def __init__(self, data=None, **kwargs):
        pass
    
class PrivateKey(object): 
    __slots__ = ('n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'iqmp', '_data', '_bits') 
    def __init__(self, data=None, **kwargs):
        pass
    
def generateRSA(bits=1024): return (PrivateKey(), PublicKey())
def extractPublicKey(Ks): return PublicKey()
def sign(Ks, hash): return str(hash)
def verify(Kp, hash, signature): return str(hash) == signature
