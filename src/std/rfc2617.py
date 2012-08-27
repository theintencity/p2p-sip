# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC2617 (HTTP auth)

'''
The HTTP basic and digest access authentication as per RFC 2617.
'''

from random import randint
from hashlib import md5
from base64 import b64encode
import time

# @implements RFC2617 P3L16-P3L25
_quote   = lambda s: '"' + s + '"' if not s or s[0] != '"' != s[-1] else s
_unquote = lambda s: s[1:-1] if s and s[0] == '"' == s[-1] else s

def createAuthenticate(authMethod='Digest', **kwargs):
    '''Build the WWW-Authenticate header's value.
    >>> print createAuthenticate('Basic', realm='iptel.org')
    Basic realm="iptel.org"
    >>> print createAuthenticate('Digest', realm='iptel.org', domain='sip:iptel.org', nonce='somenonce')
    Digest realm="iptel.org", domain="sip:iptel.org", qop="auth", nonce="somenonce", opaque="", stale=FALSE, algorithm=MD5
    '''
    if authMethod.lower() == 'basic':
        return 'Basic realm=%s'%(_quote(kwargs.get('realm', '')))
    elif authMethod.lower() == 'digest':
        predef = ('realm', 'domain', 'qop', 'nonce', 'opaque', 'stale', 'algorithm')
        unquoted = ('stale', 'algorithm')
        now = time.time(); nonce = kwargs.get('nonce', b64encode('%d %s'%(now, md5('%d:%d'%(now, id(createAuthenticate))))))
        default = dict(realm='', domain='', opaque='', stale='FALSE', algorithm='MD5', qop='auth', nonce=nonce)
        kv = map(lambda x: (x, kwargs.get(x, default[x])), predef) + filter(lambda x: x[0] not in predef, kwargs.items()) # put predef attributes in order before non predef attributes
        return 'Digest ' + ', '.join(map(lambda y: '%s=%s'%(y[0], _quote(y[1]) if y[0] not in unquoted else y[1]), kv))
    else: raise ValueError, 'invalid authMethod%s'%(authMethod)
    
# @implements RFC2617 P3L27-P3L36
# @implements RFC2617 P4L14-P4L29
def createAuthorization(challenge, username, password, uri=None, method=None, entityBody=None, context=None):
    '''Build the Authorization header for this challenge. The challenge represents the
    WWW-Authenticate header's value and the function returns the Authorization
    header's value. The context (dict) is used to save cnonce and nonceCount
    if available. The uri represents the request URI str, and method the request
    method. The result contains the properties in alphabetical order of property name.
    
    >>> context = {'cnonce':'0a4f113b', 'nc': 0}
    >>> print createAuthorization('Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"', 'Mufasa', 'Circle Of Life', '/dir/index.html', 'GET', None, context)
    Digest cnonce="0a4f113b",nc=00000001,nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",opaque="5ccc069c403ebaf9f0171e9517f40e41",qop=auth,realm="testrealm@host.com",response="6629fae49393a05397450978507c4ef1",uri="/dir/index.html",username="Mufasa"
    >>> print createAuthorization('Basic realm="WallyWorld"', 'Aladdin', 'open sesame')
    Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    '''
    authMethod, sep, rest = challenge.strip().partition(' ')
    ch, cr = dict(), dict() # challenge and credentials
    cr['password']   = password
    cr['username']   = username
    
    # @implements RFC2617 P5L20-P5L41
    if authMethod.lower() == 'basic':
        return authMethod + ' ' + basic(cr)
    # @implements RFC2617 P6L46-P7L5
    elif authMethod.lower() == 'digest':
        for n,v in map(lambda x: x.strip().split('='), rest.split(',') if rest else []):
            ch[n.lower().strip()] = _unquote(v.strip())
        # TODO: doesn't work if embedded ',' in value, e.g., qop="auth,auth-int"
        # @implements RFC2617 P8L3-P8L25
        for y in filter(lambda x: x in ch, ['username', 'realm', 'nonce', 'opaque', 'algorithm']):
            cr[y] = ch[y]
        cr['uri']        = uri
        cr['httpMethod'] = method
        if 'qop' in ch:
            if context and 'cnonce' in context:
                cnonce, nc = context['cnonce'], context['nc'] + 1
            else:
                cnonce, nc = H(str(randint(0, 2**31))), 1
            if context:
                context['cnonce'], context['nc'] = cnonce, nc
            cr['qop'], cr['cnonce'], cr['nc'] = 'auth', cnonce, '%08x'% nc
    
        # @implements RFC2617 P11L11-P11L30
        cr['response'] = digest(cr)
        items = sorted(filter(lambda x: x not in ['name', 'authMethod', 'value', 'httpMethod', 'entityBody', 'password'], cr))
        return authMethod + ' ' + ','.join(map(lambda y: '%s=%s'%(y, (cr[y] if y == 'qop' or y == 'nc' else _quote(cr[y]))), items))
    else:
        raise ValueError, 'Invalid auth method -- ' + authMethod


# @implements RFC2617 P10L19-P10L33
H = lambda d: md5(d).hexdigest()
KD = lambda s, d: H(s + ':' + d)

# @implements RFC2617 P18L34-P19L9
def digest(cr):
    '''Create a digest response for the credentials.
    
    >>> input = {'httpMethod':'GET', 'username':'Mufasa', 'password': 'Circle Of Life', 'realm':'testrealm@host.com', 'algorithm':'md5', 'nonce':'dcd98b7102dd2f0e8b11d0f600bfb0c093', 'uri':'/dir/index.html', 'qop':'auth', 'nc': '00000001', 'cnonce':'0a4f113b', 'opaque':'5ccc069c403ebaf9f0171e9517f40e41'}
    >>> print digest(input)
    "6629fae49393a05397450978507c4ef1"
    '''
    algorithm, username, realm, password, nonce, cnonce, nc, qop, httpMethod, uri, entityBody \
      = map(lambda x: cr[x] if x in cr else None, ['algorithm', 'username', 'realm', 'password', 'nonce', 'cnonce', 'nc', 'qop', 'httpMethod', 'uri', 'entityBody'])
      
    # @implements RFC2617 P13L26-P13L45
    if algorithm and algorithm.lower() == 'md5-sess':
        A1 = H(username + ':' + realm + ':' + password) + ':' + nonce + ':' + cnonce
    else:
        A1 = username + ':' + realm + ':' + password
    # @implements RFC2617 P14L10-P14L17
    if not qop or qop == 'auth':
        A2 = httpMethod + ':' + str(uri)
    else:
        A2 = httpMethod + ':' + str(uri) + ':' + H(str(entityBody))

    # @implements RFC2617 P13L6-P13L20
    if qop and (qop == 'auth' or qop == 'auth-int'):
        return _quote(KD(H(A1), nonce + ':' + str(nc) + ':' + cnonce + ':' + qop + ':' + H(A2)))
    else:
        return _quote(KD(H(A1), nonce + ':' + H(A2)))


# @implements RFC2617 P6L8-P6L11
def basic(cr):
    '''Create a basic response for the credentials.
    
    >>> print basic({'username':'Aladdin', 'password':'open sesame'})
    QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    '''
    # @implements RFC2617 P5L43-P6L6
    return b64encode(cr['username'] + ':' + cr['password'])


if __name__ == '__main__':
    import doctest
    doctest.testmod()