# Copyright (c) 2007-2009, Kundan Singh. All rights reserved. See LICENSING for details.

'''
Crypto utilities such as RSA public/private key, X509 certificates, RC4 encryption, random number generator.
This used the OpenSSL module internally.
'''

import os, struct
from string import atoi
try: from OpenSSL.crypto import *
except: print 'WARNING: cannot import OpenSSL.crypto'

#===============================================================================
# Generic methods such as ASN.1 minimal parsing and utility functions
#===============================================================================

# following two definitions are reused from dht.py
bin2int = lambda x: long(''.join('%02x'%(ord(a)) for a in x), 16)
def int2bin(x, signByte=True): # if signByte is True (default), prepend '\x00' if first byte is >= '\x80'
    result = ''
    while x != 0: result, x = struct.pack('>B', x % 256)+result, x / 256
    if len(result) == 0: return '\x00'
    elif not signByte: return result
    else: return (result if struct.unpack('>B', result[:1])[0] < 0x80 else '\x00' + result) if len(result) else '\x00'

class ASN1(object):
    '''The parser and formatter for basic ASN1 DER as needed for PEM encoding of public key and private key.
    >>> Ks = load('data/kundansingh_99@yahoo.com.key')
    >>> encoded = dump_privatekey(FILETYPE_ASN1, Ks._data)
    >>> print ASN1.encode(ASN1.decode(encoded)[0]) == encoded
    True
    '''
    _classes = ['universal', 'application', 'context-specific', 'private']
    _types   = ['primitive', 'constructed']
    def __init__(self):
        self._type, self._class, self._tag, self._len, self._value = 0, 0, 0, 0, []
    def __repr__(self):
        return '<ASN1 class=%s type=%s tag=%d len=%d>%s</ASN1>'%(ASN1._classes[self._class], ASN1._types[self._type], self._tag, self._len, \
                (''.join(repr(x) for x in self._value) if isinstance(self._value, list) else repr(self._value)))
        
    def __len__(self): return len(self._value)
    def __getitem__(self, index): return self._value[index]
    @property
    def value(self): return self._value;
    
    @staticmethod
    def decode(value, off=0): # decode a single ASN1 tag. Returns (ASN1, off)
        asn = ASN1()
        if value:
            orig_off = off
            asn._class, asn._type, asn._tag, off = ASN1._decodeType(value, off)
            asn._len, off  = ASN1._decodeLen(value, off)
            if asn._type == 0:
                if asn._tag == 2: # integer
                    asn._value = bin2int(value[off:off+asn._len])
                    off += asn._len
                else: raise ValueError('ASN1 parsing only supports integer as primitive type')
            elif asn._type == 1:
                if asn._tag == 16:
                    orig_val = value[off:]
                    while off < len(value):
                        asn0, off = ASN1.decode(value, off)
                        asn._value.append(asn0)
                else: raise ValueError('ASN1 parsing only supports sequence as constructed type')
            if off == orig_off: raise ValueError('cannot parse ASN.1 at offset %d'%(off))
        return (asn, off)
    
    @staticmethod
    def encode(asn): # encode a ASN1 value into string.
        if asn is None: return ''
        if asn._type == 0 and asn._tag == 2:
            val = int2bin(asn._value)
        elif asn._type == 1 and asn._tag == 16:
            val = ''.join(ASN1.encode(x) for x in asn._value)
        else: raise ValueError('ASN1 formatting only supports integer and sequence')
        return ASN1._encodeType(asn) + ASN1._encodeLen(val) + val

    @staticmethod
    def _decodeType(value, off):
        val = ord(value[off]); off = off + 1
        _class, _type, val = ((val & 0xc0) >> 6), ((val & 0x20) >> 5), (val & 0x1f)
        if val < 0x1f: _tag = val
        else:
            v=ord(value[off]); off = off + 1
            while (v & 0x80) != 0:
                val, v, off = val * 128 + (v & 0x7f), ord(value[off]), off + 1
            _tag = val
        return (_class, _type, _tag, off)
    @staticmethod
    def _encodeType(asn):
        first = (asn._class << 6) | (asn._type << 5)
        if asn._tag < 0x1f: return struct.pack('>B', first | asn._tag)
        else: 
            result, tag = struct.pack('>B', first | 0x1f), asn._tag
            while tag != 0:
                result, tag = struct.pack('>B', tag if tag < 0x80 else (0x80 | (tag % 128)))+result, tag / 128
            return result
    @staticmethod
    def _decodeLen(value, off):
        val = ord(value[off]); off = off + 1
        if (val & 0x80) == 0: _len = val & 0x7f
        else: 
            _llen = val & 0x7f
            _len = bin2int(value[off:off+_llen])
            off = off + _llen
        return (_len, off)
    @staticmethod
    def _encodeLen(data):
        size = len(data)
        if size < 0x80: return struct.pack('>B', size)
        else: sstr = int2bin(size, False); return struct.pack('>B', 0x80 | len(sstr)) + sstr
        
#===============================================================================
# High-level PublicKey and PrivateKey classes
#===============================================================================

class PublicKey(object): 
    '''This is RSA public key. The _data property may be a PKey or X509 or ASN1 object'''
    __slots__ = ('n', 'e', '_data', '_bits')
    def __init__(self, data=None, **kwargs):
        self.n = self.e = self._data = self._bits = None
        if data: self._load(data)
    def __repr__(self): return '<PublicKey[%r] n=%r e=%r/>'%(self._bits, self.n, self.e)
    def __str__(self): return save(self)
    def _load(self, data): # load from X509 or PKey data
        self._data = data
        raw = dump_privatekey(FILETYPE_ASN1, data.get_pubkey()) if type(data)==type(X509()) else dump_privatekey(FILETYPE_ASN1, data)
        self._bits = data.get_pubkey().bits() if type(data)==type(X509()) else data.bits()
        asn, ignore = ASN1.decode(raw)
        self.n, self.e = asn[1].value, asn[2].value
    
class PrivateKey(object): 
    '''This is RSA private key. The _data property is a PKey object'''
    __slots__ = ('n', 'e', 'd', 'p', 'q', 'dmp1', 'dmq1', 'iqmp', '_data', '_bits') 
    def __init__(self, data=None, **kwargs):
        self.n = self.e = self.d = self.p = self.q = self.dmp1 = self.dmq1 = self.iqmp = self._data = self._bits = None
        if data: self._load(data)
    def __repr__(self):
        return '<PrivateKey[%r] n=%r\n e=%r\n d=%r\n p=%r\n q=%r\n dmp1=%r\n dmq1=%r\n iqmp=%r/>'%(self._bits, self.n, self.e, self.d, self.p, self.q, self.dmp1, self.dmq1, self.iqmp)
    def __str__(self): return save(self)
    def _load(self, data): # load from PKey data
        self._data = data
        raw = dump_privatekey(FILETYPE_ASN1, data)
        self._bits = data.bits()
        asn, ignore = ASN1.decode(raw)
        self.n, self.e, self.d, self.p, self.q, self.dmp1, self.dmq1, self.iqmp = (asn[x].value for x in xrange(1,9))
    
def generateRSA(bits=1024):
    '''Generate a RSA key pair: Ks, Kp.'''
    pkey = PKey()
    pkey.generate_key(TYPE_RSA, bits)
    Ks = PrivateKey(pkey)
    Kp = extractPublicKey(Ks)
    return (Ks, Kp)

def extractPublicKey(Ks):
    '''Extract publickey from a private key.'''
    Kp = PublicKey()
    Kp.n, Kp.e, Kp._bits = Ks.n if hasattr(Ks, 'n') else None, Ks.e if hasattr(Ks, 'e') else None, Ks._bits
    if Ks._data:
        asn = ASN1.decode(dump_privatekey(FILETYPE_ASN1, Ks._data))[0]
        asn._len, asn._value = 3, asn._value[0:3] # ignore private key components form the value list
        Kp._data = asn
    return Kp

def load(file, passphrase=''):
    '''Load a file for private key, public key or certificate. It takes care of PEM and ASN1 formats.
    @param file either a file name or a string buffer built from the content of the input file.
    @return either PublicKey or PrivateKey objects.
    >>> Ks = load('data/kundansingh_99@yahoo.com.key')
    >>> Kp = load('data/kundansingh_99@yahoo.com.pem')
    '''
    if file.find('\x00') < 0 and  os.path.isfile(file): file = open(file, 'r').read() # read this as a file
    type = FILETYPE_PEM if file.startswith('-----') else FILETYPE_ASN1
    try: result = PrivateKey(load_privatekey(type, file, passphrase))
    except Error, e:
        try: error = e[0][0][2]
        except: error = str(e)
        if error == 'field missing':
            asn = ASN1.decode(file)[0]
            asn._len, asn._value = 3, asn._value[0:3] # ignore private key components form the value list
            result = PublicKey()
            result._data, result.n, result.e = asn, asn[1].value, asn[2].value
        else:
            if error != 'no start line' and error != 'not enough data': raise ValueError('Cannot read input: %s'%(str(e)))
            try: result = PublicKey(load_certificate(type, file))
            except Error, e: raise ValueError('Cannot load input: %s'%(str(e)))
    return result

def save(key, asPEM=False):
    '''Dump the key into returned string, either as PEM if asPEM is True or as binary ASN1 (default).'''
    filetype = FILETYPE_PEM if asPEM else FILETYPE_ASN1
    if isinstance(key, PrivateKey): return dump_privatekey(filetype, key._data)
    elif isinstance(key, PublicKey): 
        if type(key._data)==type(X509()): return dump_certificate(filetype, key._data)
        elif isinstance(key._data, ASN1) and filetype == FILETYPE_ASN1: return ASN1.encode(key._data)
        else: return dump_privatekey(filetype, key._data)
    else: raise ValueError('key is neither PublicKey nor PrivateKey object') 
    
#===============================================================================
# Various encryption and decryption such as RSA and RC4
#===============================================================================

# following is reused from http://www.amk.ca/python/writing/crypto-curiosa
def rsa(data, n, e=0x10001, d=None, bits=1024):
    '''Create a generator to perform encryption or decryption operation.
    >>> print rsa(rsa('kund', n=0x1967cb529, e=0x10001, bits=40).next(), n=0x1967cb529, d=0xac363601, bits=40).next()
    kund
    '''
    if not d: o, inb = bits/8, bits/8-1   # encryption
    else: e, o, inb = d, bits/8-1, bits/8 # decryption
    while data:
        if len(data)>inb: raise ValueError, 'length of data is more than modulus bits'
        result = ''.join(map(lambda i, b=pow(reduce(lambda x,y: (x<<8L)+y, map(ord, data)), e, n):
                             chr(b>>8*i&255), range(o-1,-1,-1)))
        data = yield result

def arc4(data, key):
    '''Create a generator for alleged RC4 encryption or decryption.
    >>> print arc4(data=arc4(data="kundan", key='666f6f').next(), key='666f6f').next()
    kundan
    '''
    t,x,y,j,a=range(256),0,0,0,key
    k=(map(lambda b:atoi(a[b:b+2],16), range(0,len(a),2))*256)[:256]
    for i in t[:]:j=(k[i]+t[i]+j)%256;t[i],t[j]=t[j],t[i]
    while data:
        result = ''
        for byte in data:
            l,x=len(byte),(x+1)%256
            y,c=(y+t[x])%256,l and ord(byte)
            t[x],t[y]=t[y],t[x]
            result += chr(c^t[(t[x]+t[y])%256])[:l]
        data = yield result
    
    
#===============================================================================
# Signature and verification using RSA
#===============================================================================

def sign(Ks, hash):
    '''Sign a hash using the given private key. Throws an exception if size of hash is more than
    the modulus of the private key. It returns the signature.'''
    # TODO: why should I use bits as bits+8? It doesn't work otherwise
    return rsa(data=str(hash), n=Ks.n, d=Ks.d, bits=Ks._bits+8).next()

def verify(Kp, hash, signature):
    '''Verify that the signature is a valid signature of hash using the private key that was 
    associated with this public key Kp. Returns True on success and False otherwise.
    
    >>> Ks, Kp = generateRSA(); 
    >>> print verify(Kp, 'somehash', sign(Ks, 'somehash'))
    True
    '''
    _hash = rsa(data=signature, n=Kp.n, e=Kp.e, bits=Kp._bits+8).next()
    return bin2int(_hash) == bin2int(str(hash)) 


# test routine for unit testing

if __name__ == '__main__':
    import doctest
    doctest.testmod()
