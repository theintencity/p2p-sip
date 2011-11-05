#
# DNS.py: DNS client implementation.
# Obtained from http://www.linuxproducts.org/dnspy-04-214.html
#
# Copyright (C) 2007 Vladimir Popov <jumbo@narod.ru>
#
# Distributed under Python License, see http://www.python.org/psf/license/
#

__version__ = '0.4'

import random
import select
import socket
import string
import struct
import types

_EnableDebug = False

#
# DNS types as defined in various RFC.
# All DNS types which do not fit these types are mapped to T_UNKNOWN.
#
T_UNKNOWN = 0x00     # For unrecognized types
T_A       = 0x01     # RFC-1035 # IPv4 host address
T_NS      = 0x02     # RFC-1035 # Authoritative name server
T_MD      = 0x03     # RFC-1035 # Mail destination (obsolete, use MX)
T_MF      = 0x04     # RFC-1035 # Mail forwarder (obsolete, use MX)
T_CNAME   = 0x05     # RFC-1035 # Canonical name for an alias
T_SOA     = 0x06     # RFC-1035 # Start of a zone of authority
T_MB      = 0x07     # RFC-1035 # Mailbox domain name (EXPERIMENTAL)
T_MG      = 0x08     # RFC-1035 # Mail group member (EXPERIMENTAL)
T_MR      = 0x09     # RFC-1035 # Mail rename domain name (EXPERIMENTAL)
T_NULL    = 0x0A     # RFC-1035 # Null RR (EXPERIMENTAL)
T_WKS     = 0x0B     # RFC-1035 # Well Known Service destination
T_PTR     = 0x0C     # RFC-1035 # Domain name pointer
T_HINFO   = 0x0D     # RFC-1035 # Host information
T_MINFO   = 0x0E     # RFC-1035 # Mailbox or mail list information
T_MX      = 0x0F     # RFC-1035 # Mail Exchange
T_TXT     = 0x10     # RFC-1035 # Text strings
T_RP      = 0x11     # RFC-1183 # Responsible Person
T_AFSDB   = 0x12     # RFC-1183 # AFS database location
T_X25     = 0x13     # RFC-1183 # X.25 PSDN address
T_ISDN    = 0x14     # RFC-1183 # ISDN phone number
T_RT      = 0x15     # RFC-1183 # Route Through
#T_NSAP    = 0x16     # RFC-1706 # NSAP style A record
#T_NSAPPTR = 0x17     # RFC-1706 # NSAP style PTR record
#T_SIG     = 0x18     # RFC-2335 # Security signature
#T_KEY     = 0x19     # RFC-2335 # Security key
T_PX      = 0x1A     # RFC-2163 # X.400 mail mapping information
T_GPOS    = 0x1B     # RFC-1712 # Geographical position
T_AAAA    = 0x1C     # RFC-3596 # IPv6 host address
T_LOC     = 0x1D     # RFC-1876 # Location information
#T_NXT     = 0x1E     # RFC-2535 # Next domain (Obsolete, RFC-3755)
#T_EID     = 0x1F     # Patton # Endpoint Identifier
#T_NIMLOC  = 0x20     # Patton # Nimrod Locator
T_SRV     = 0x21     # RFC-2782 # Location of services
#T_ATMA    = 0x22     # Dobrowski # ATM Address
T_NAPTR   = 0x23     # RFC-2915 # Naming Authority Pointer
T_KX      = 0x24     # RFC-2230 # Key Exchanger
#T_CERT    = 0x25     # RFC-2538 # Certificate or CRL
#T_A6      = 0x26     # RFC-2874 # A6, RFC-3226
#T_DNAME   = 0x27     # RFC-2672 # DNAME
#T_SINK    = 0x28     # Eastlake # SINK
#T_OPT     = 0x29     # RFC-2671 # OPT
T_APL     = 0x2A     # RFC-3123 # Address prefix list
#T_DS      = 0x2B     # RFC-4034 # Delegation Signer
#T_SSHFP   = 0x2C     # RFC-4255 # SSH Key Fingerprint
#T_IPSECKEY= 0x2D     # RFC-4025 # IPSECKEY
#T_RRSIG   = 0x2E     # RFC-4034 # DNS RRsets signature
#T_NSEC    = 0x2F     # RFC-4034 # DNS NSEC
#T_DNSKEY  = 0x30     # RFC-4034 # DNS RRsets public key
#T_DHCID   = 0x31     # RFC-4701 # DHCP Id
#T_SPF     = 0x63     # RFC-4408 # SPF
#T_TKEY    = 0xF9     # RFC-2930 # Transaction key
#T_TSIG    = 0xFA     # RFC-2845 # Transaction signature
T_IXFR    = 0xFB     # RFC-1995 # Incremental zone transfer
T_AXFR    = 0xFC     # RFC-1035 # Entire zone transfer
T_MAILB   = 0xFD     # RFC-1035 # Mailbox related records (MB, MG or MR)
T_MAILA   = 0xFE     # RFC-1035 # Mail agent RRs (Obsolete - see MX)
T_ANY     = 0xFF     # RFC-1035 # Request for all records
DNS_TYPE = {
    T_UNKNOWN: 'UNKNOWN',
    T_A      : 'A',
    T_NS     : 'NS',
    T_MD     : 'MD',
    T_MF     : 'MF',
    T_CNAME  : 'CNAME',
    T_SOA    : 'SOA',
    T_MB     : 'MB',
    T_MG     : 'MG',
    T_MR     : 'MR',
    T_NULL   : 'NULL',
    T_WKS    : 'WKS',
    T_PTR    : 'PTR',
    T_HINFO  : 'HINFO',
    T_MINFO  : 'MINFO',
    T_MX     : 'MX',
    T_TXT    : 'TXT',
    T_RP     : 'RP',
    T_AFSDB  : 'AFSDB',
    T_X25    : 'X25',
    T_ISDN   : 'ISDN',
    T_RT     : 'RT',
    T_PX     : 'PX',
    T_GPOS   : 'GPOS',
    T_AAAA   : 'AAAA',
    T_LOC    : 'LOC',
    T_SRV    : 'SRV',
    T_NAPTR  : 'NAPTR',
    T_KX     : 'KX',
    T_APL    : 'APL',
    T_IXFR   : 'IXFR',
    T_AXFR   : 'AXFR',
    T_MAILB  : 'MAILB',
    T_MAILA  : 'MAILA',
    T_ANY    : 'ANY',
}

#
# DNS classes
#
C_RSV  = 0x00 # Reserved
C_IN   = 0x01 # The Internet
C_CS   = 0x02 # CSNET class (obsolete)
C_CH   = 0x03 # CHAOS class
C_HS   = 0x04 # Hesiod [Dyer 87]
C_NONE = 0xFE # None, RFC-2136
C_ANY  = 0xFF # Any
DNS_CLASS = {
    C_RSV : 'RESERVED',   # 'Reserved',
    C_IN  : 'IN',         # 'Internet',
    C_CS  : 'CS',         # 'CSNET',
    C_CH  : 'CH',         # 'CHAOS',
    C_HS  : 'HS',         # 'Hesiod [Dyer 87]',
    C_NONE: 'NONE',       # 'None',
    C_ANY : 'ANY',        # 'Any',
}

# DNS request/response constants
_HDR_REQUEST       = 0x0000 # 0 << 15 # This is request
_HDR_RESPONSE      = 0x8000 # 1 << 15 # This is response

_HDR_OPCODE_MASK   = 0x7800
_HDR_OPCODE_QUERY  = 0x0000 # 0 << 11 # RFC-1035 # Simple query
_HDR_OPCODE_IQUERY = 0x0800 # 1 << 11 # RFC-3425 # Inverse query, Opcode retired
_HDR_OPCODE_STATUS = 0x1000 # 2 << 11 # RFC-1035 # Status query
_HDR_OPCODE_RSV    = 0x1800 # 3 << 11 # Reserved
_HDR_OPCODE_NOTIFY = 0x2000 # 4 << 11 # RFC-1996 # Notify
_HDR_OPCODE_UPDATE = 0x2800 # 5 << 11 # RFC-2136 # Update

_HDR_AUTH_ANSWER   = 0x0400 # 1 << 10 # Authoritative answer
_HDR_TRUNCATION    = 0x0200 # 1 << 9  # Truncation
_HDR_REC_DESIRED   = 0x0100 # 1 << 8  # Recursion desired
_HDR_REC_AVAIL     = 0x0080 # 1 << 7  # Recursion available

_HDR_RESERVED_MASK = 0x0070 # 7 << 4  # Reserved bits

# DNS response error codes
_HDR_RCODE_MASK    = 0x000F
HDR_RCODE_NOERROR  = 0x0 # RFC-1035
HDR_RCODE_FORMERR  = 0x1 # RFC-1035
HDR_RCODE_SERVFAIL = 0x2 # RFC-1035
HDR_RCODE_NXDOMAIN = 0x3 # RFC-1035
HDR_RCODE_NOTIMP   = 0x4 # RFC-1035
HDR_RCODE_REFUSED  = 0x5 # RFC-1035
HDR_RCODE_YXDOMAIN = 0x6 # RFC-2136
HDR_RCODE_YXRRSET  = 0x7 # RFC-2136
HDR_RCODE_NXRRSET  = 0x8 # RFC-2136
HDR_RCODE_NOTAUTH  = 0x9 # RFC-2136
HDR_RCODE_NOTZONE  = 0xA # RFC-2136
HDR_RCODE = {
    HDR_RCODE_NOERROR : ['Success', 'No error codition'],
    HDR_RCODE_FORMERR : ['Format Error', 'Format Error - The name server was unable to interpret the query.'],
    HDR_RCODE_SERVFAIL: ['Server Failure', 'Server failure - The name server was unable to process this query due to a problem with the name server'],
    HDR_RCODE_NXDOMAIN: ['Non-Existent Domain', 'Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.'],
    HDR_RCODE_NOTIMP  : ['Not Implemented', 'Not Implemented - The name server does not support the requested kind of query.'],
    HDR_RCODE_REFUSED : ['Refused', 'Refused - The name server refuses to perform the specified operation for policy reasons.'],
    HDR_RCODE_YXDOMAIN: ['Name Exists when it should not', 'Some name that ought not to exist, does exist.'],
    HDR_RCODE_YXRRSET : ['RR Set Exists when it should not', 'Some RRset that ought not to exist, does exist.'],
    HDR_RCODE_NXRRSET : ['RR Set that should exist does not', 'Some RRset that ought to exist, does not exist.'],
    HDR_RCODE_NOTAUTH : ['Server Not Authoritative for zone', 'The server is not authoritative for the zone named in the Zone Section.'],
    HDR_RCODE_NOTZONE : ['Name not contained in zone', 'A name used in the Prerequisite or Update Section is not within the zone denoted by the Zone Section.']
}

def _unique(lst):
    res = []
    for elem in lst:
        # Try to preserve order
        if not elem in res:
            res.append(elem)
    return res


#
# Debug class. Used to print stamps on function enter/exit and
# arbitrary debug messages when _EnableDebug is set to True.
#
class _debug:
    def __init__(self, name):
        self._name = name
        if _EnableDebug:
            print "%s.py: %s <<" % (__name__, self._name)
    def msg(self, message):
        if _EnableDebug:
            print "%s.py: %s: %s" % (__name__, self._name, message)
    def __del__(self):
        if _EnableDebug:
            print "%s.py: %s >>" % (__name__, self._name)


class QueryError(Exception):
    """
    Exception raised during DNS query compilation
    """
    pass

class AnswerError(Exception):
    """
    Exception raised during DNS answer parsing
    """
    pass

class IncompleteAnswerError(AnswerError):
    """
    Exception raised if DNS answer is incomplete
    """
    pass

class ResolverError(Exception):
    """
    Exception raised during DNS resolution
    """
    pass

class ConnectionError(ResolverError):
    """
    Exception raised when communicating with name server
    """
    pass

class ServerError(ResolverError):
    """
    Exception raised by non-zero RCODE field
    """
    pass


#
# _dnsquery: Class for composing DNS query
#
_QRY_NAME  = 0
_QRY_TYPE  = 1
_QRY_CLASS = 2
class _dnsquery:
    def __init__(self, query, sections=None, recursion=False, id=None):
        dbg = _debug('_dnsquery::__init__')

        self._query = ()
        self._sections = {'AUTHORITY': [], 'ADDITIONAL': []}

        self.__sanity(query, sections)

        self._recursion = recursion
        self._id = id or self.__getID()

        dbg.msg('%u: %s' % (self._id, self._query))

    #
    # Check for input data sanity
    #
    def __sanity(self, query, sections):
        dbg = _debug('_dnsquery::__sanity')
        addr, qtype, qclass = query
        if not isinstance(addr, types.StringTypes):
            raise ValueError('Invalid name %s' % str(addr))
        if qtype == 0 or not DNS_TYPE.has_key(qtype):
            raise ValueError('Invalid type %u' % qtype)
        if qclass == 0 or not DNS_CLASS.has_key(qclass):
            raise ValueError('Invalid class %u' % qclass)
        self._query = query

        if not sections:
            return

        sections = self.__normalize(sections)
        for k in ['AUTHORITY', 'ADDITIONAL']:
            if sections.has_key(k):
                v = sections[k]
                if not (isinstance(v, types.ListType) or \
                        isinstance(v, types.TupleType)):
                    raise ValueError('%s format error' % k)
                self._sections[k] = v

    #
    # Check the_map and convert the keys into upper case if key is a string.
    #
    def __normalize(self, the_map):
        dbg = _debug('_dnsquery::__normalize')
        res = {}
        for key in the_map:
            if isinstance(key, types.StringTypes):
                res[key.upper()] = the_map[key]
        return res

    #
    # Create 2 octets from 16-bit unsinged int
    #
    def __pack16(self, value):
        dbg = _debug('_dnsquery::__pack16')
        # use big-endian explicitely
        return struct.pack('>H', value)

    #
    # Create 4 octets from 32-bit unsinged int
    #
    def __pack32(self, value):
        dbg = _debug('_dnsquery::__pack32')
        # use big-endian explicitely
        return struct.pack('>L', value)

    #
    # Get random number for request ID
    #
    def __getID(self):
        dbg = _debug('_dnsquery::__getID')
        return random.randrange(1, 0xFFFF)

    #
    # Create request header
    #
    def __mkqhead(self):
        dbg = _debug('_dnsquery::__mkqhead')
        qhead  = self.__pack16(self._id)                          # ID

        r = _HDR_REQUEST + _HDR_OPCODE_QUERY
        if self._recursion:
            r += _HDR_REC_DESIRED

        qhead += self.__pack16(r)                                 # OPCODES
        qhead += self.__pack16(0x1)                               # QDCOUNT
        qhead += self.__pack16(0)                                 # ANCOUNT
        qhead += self.__pack16(len(self._sections['AUTHORITY']))  # NSCOUNT
        qhead += self.__pack16(len(self._sections['ADDITIONAL'])) # ARCOUNT
        return qhead

    #
    # Prepare domain name for question section
    #
    def __mkqname(self, req):
        dbg = _debug('_dnsquery::__mkqname')
        res = ''
        tokens = req.split('.')
        for token in tokens:
            res += '%c' % len(token) + token
        return res + '\x00'

    #
    # Convert IPv4 address 'AAA.BBB.CCC.DDD' to 'DDD.CCC.BBB.AAA.in-addr.arpa'
    #
    def __arpadomain(self, ipaddress):
        dbg = _debug('_dnsquery::__arpadomain(%s)' % ipaddress)
        addrlist = ipaddress.split('.')
        if len(addrlist) != 4 or not self.__isipaddress(addrlist):
            return ipaddress
        addrlist.reverse()
        addrlist.append('in-addr')
        addrlist.append('arpa')
        return string.join(addrlist, '.')

    #
    # Check the list to be IPv4 address
    #
    def __isipaddress(self, ipaddrlist):
        for i in ipaddrlist:
            try:
                ipaddrblock = int(i)
            except:
                return False

            if ipaddrblock != ipaddrblock & 0xFF:
                return False
        return True

    def __SOA_RDATA(self, data):
        dbg = _debug('_dnsquery::__SOA_RDATA')
        rdata = ''
        # Mandatory keys MNAME, RNAME, SERIAL
        for name in ['MNAME', 'RNAME']:
            rdata += self.__mkqname(name)
        rdata += self.__pack32(data['SERIAL'])
        for key in ['REFRESH', 'RETRY', 'EXPIRE', 'MINIMUM']:
            if data.has_key(key):
                rdata += self.__pack32(data[key])
            else:
                rdata += self.__pack32(0L)
        return rdata
            

    def __mkqrdata(self, qtype, qclass, qrdata):
        dbg = _debug('_dnsquery::__mkqrdata')
        rdata = ''
        if   qtype == T_SOA:
            rdata = self.__SOA_RDATA(qrdata)
        else:
            raise QueryError('Unsupported TYPE %u' % qtype)
        return rdata

    def __mkqsection(self, sname):
        dbg = _debug('_dnsquery::__mkqsection')

        if not self._sections.has_key(sname):
            return ''

        sqry = ''
        for section in self._sections[sname]:
            qname = section['NAME']
            qtype = section['TYPE']
            qclass = section['CLASS']

            qttl = 0L
            if section.has_key('TTL'):
                qttl = section['TTL']

            if qtype == T_PTR:
                qname = self.__arpadomain(qname)
            sqry += self.__mkqname(qname)
            sqry += self.__pack16(qtype)
            sqry += self.__pack16(qclass)
            sqry += self.__pack32(qttl)
            rdata = self.__mkqrdata(qtype, qclass, section['RDATA'])
            sqry += self.__pack16(len(rdata))
            sqry += rdata
        return sqry

    #
    # Return binary octets of the query
    #
    def get(self, prefix=False):
        dbg = _debug('_dnsquery::get')
        qry  = self.__mkqhead()
        qname = self._query[_QRY_NAME]
        if self._query[_QRY_TYPE] == T_PTR:
            qname = self.__arpadomain(qname)
        dbg.msg('QNAME: %s' % qname)
        qry += self.__mkqname(qname)
        qry += self.__pack16(self._query[_QRY_TYPE])
        qry += self.__pack16(self._query[_QRY_CLASS])

        # Add sections
        qry += self.__mkqsection('AUTHORITY')
        qry += self.__mkqsection('ADDITIONAL')

        # Messages sent over TCP connections are prefixed
        # with a two byte length field which gives the message length,
        # excluding the two byte length field.
        if prefix:
            qry = self.__pack16(len(qry)) + qry

        return qry

    #
    # Returns id of this query
    #
    def id(self):
        return self._id

    def __str__(self):
        res  = 'ID: %u\n' % self._id
        res += 'Query: %s\n' % self._query[_QRY_NAME]
        res += 'Type : %s\n' % DNS_TYPE[self._query[_QRY_TYPE]]
        res += 'Class: %s\n' % DNS_CLASS[self._query[_QRY_CLASS]]
        return res


#
# _dnsanswer: Class for parsing DNS server answer
#

# Fields of _dnsanswer._status list
_PARSE_SECTION = 0
_PARSE_OFFSET = 1

# _PARSE_SECTION values
_PARSE_HEADER = 0
_PARSE_QUERY = 1
_PARSE_ANSWER = 2
_PARSE_AUTHORITY = 3
_PARSE_ADDITIONAL = 4
_PARSE_END = 5
class _dnsanswer:
    def __init__(self, answer=None, prefix=False):
        dbg = _debug('_dnsanswer::__init__')

        self._answer = ''

        # Messages sent over TCP connections are prefixed
        # with a two byte length field which gives the message length,
        # excluding the two byte length field.
        self._prefix = prefix
        self._size = 0

        self._dict = {}
        self._complete = False
        # _status has 2 elements
        # 0: Section that has to be parsed next
        # 1: Section start offset
        self._status = [_PARSE_HEADER, 0]

        if answer:
            self.add(answer)

    def __parse(self):
        dbg = _debug('_dnsanswer::__parse')
        try:
            self.__parseheader()
            self.__parsequery()
            self.__parsesections()
            if self._prefix and self._size != self._status[_PARSE_OFFSET]:
                raise IncompleteAnswerError()
            self._complete = True
        except IncompleteAnswerError:
            pass
        return

    def __parseheader(self):
        dbg = _debug('_dnsanswer::__parseheader')

        if self._status[_PARSE_SECTION] > _PARSE_HEADER:
            dbg.msg("HEADER already parsed")
            return

        assert self._status[_PARSE_OFFSET] == 0, "Inconsistent parse offset when parsing HEADER: %u" % self._status[_PARSE_OFFSET]

        self.__sentry(len(self._answer), 12)

        # Process header
        self._dict['HEADER'] = {}
        self._dict['HEADER']['ID'] = self.__unpack16(self._answer[0:2])
        self._dict['HEADER']['OPCODES'] = self.__opcodes(self._answer[2:4])

        offset = 4
        for i in ('QDCOUNT', 'ANCOUNT', 'NSCOUNT', 'ARCOUNT'):
            self._dict['HEADER'][i] = self.__unpack16(self._answer[offset:offset + 2])
            offset += 2

        self._status[_PARSE_SECTION] += 1
        self._status[_PARSE_OFFSET] = offset

        dbg.msg('HEADER: %s' % self._dict['HEADER'])

    def __parsequery(self):
        dbg = _debug('_dnsanswer::__parsequery')

        if self._status[_PARSE_SECTION] > _PARSE_QUERY:
            dbg.msg("QUERY already parsed")
            return

        assert self._status[_PARSE_SECTION] == _PARSE_QUERY, "Inconsistent parse section when parsing QUERY: %u" % self._status[_PARSE_SECTION]
        assert self._status[_PARSE_OFFSET] == 12, "Inconsistent parse offset when parsing QUERY: %u" % self._status[_PARSE_OFFSET]

        offset = self._status[_PARSE_OFFSET]

        # Process question section
        self._dict['QUERY'] = []
        for i in range(self._dict['HEADER']['QDCOUNT']):
            q, offset = self.__question(self._answer, offset)
            self._dict['QUERY'].append(q)

        self._status[_PARSE_SECTION] += 1
        self._status[_PARSE_OFFSET] = offset

    def __parsesections(self):
        dbg = _debug('_dnsanswer::__parsesections')

        # Process remaining sections
        assert self._status[_PARSE_SECTION] > _PARSE_QUERY, "Inconsistent parse section when parsing ANSWER: %u" % self._status[_PARSE_SECTION]

        idx = self._status[_PARSE_SECTION] - _PARSE_ANSWER
        offset = self._status[_PARSE_OFFSET]

        sections = (
                        ('ANCOUNT', 'ANSWER'),
                        ('NSCOUNT', 'AUTHORITY'),
                        ('ARCOUNT', 'ADDITIONAL'),
                   )
        for count, name in sections[idx:]:
            self._dict[name] = []
            for i in range(self._dict['HEADER'][count]):
                dbg.msg('Starting to read %s[%u] section...' % (name, i))
                section, offset = self.__section(self._answer, offset)
                self._dict[name].append(section)
            self._status[_PARSE_SECTION] += 1
            self._status[_PARSE_OFFSET] = offset

        dbg.msg('ANSWER: %s' % self._dict)

    #
    # Convert 2 octets to unsigned int
    #
    def __unpack16(self, value):
        dbg = _debug('_dnsanswer::__unpack16')
        # use big-endian explicitely
        return struct.unpack('>H', value)[0]

    #
    # Convert 4 octets to unsigned long int
    #
    def __unpack32(self, value):
        dbg = _debug('_dnsanswer::__unpack32')
        # use big-endian explicitely
        return struct.unpack('>L', value)[0]

    #
    # Parse entry of the question section of the DNS response
    #
    def __question(self, data, offset=12):
        dbg = _debug('_dnsanswer::__question')

        res = {}
        res['DOMAIN'], offset = self.__domain(data, offset)
        res['TYPE'], offset = self.__dnstype(data, offset)
        res['CLASS'], offset = self.__dnsclass(data, offset)

        dbg.msg("QUESTION: %s" % res)

        return (res, offset)

    #
    # Parse entry of any arbitrary non-question section starting
    # from the given offset.
    #
    def __section(self, data, offset):
        dbg = _debug('_dnsanswer::__section')
        res = {}

        res['DOMAIN'], offset = self.__domain(data, offset)
        res['TYPE'], offset = self.__dnstype(data, offset)
        res['CLASS'], offset = self.__dnsclass(data, offset)
        res['TTL'], offset = self.__ttl(data, offset)
        rdlen, offset = self.__rdlength(data, offset)
        res['RDATA'], offset = self.__rdata(data, offset, rdlen, res['TYPE'])

        dbg.msg('SECTION: %s' % res)

        return (res, offset)

    #
    # Raise exception if length of answer is shorter than required.
    #
    def __sentry(self, datalen, reqlen):
        if datalen < reqlen:
            raise IncompleteAnswerError('Answer is incomplete')

    #
    # Returns domain name, follow links where required
    #
    def __domain(self, data, offset):
        dbg = _debug('_dnsanswer::__domain')

        datalen = len(data)

        if datalen < offset + 2:
            return ('', offset)
        
        self.__sentry(datalen, offset + 2)

        # check whether the first element is a link
        anoffset = self.__islink(data, offset)
        if anoffset:
            token, anoffset = self.__domain(data, anoffset)
            return (token, offset + 2)

        tokenlist = []
        tokenlen = ord(data[offset])
        while tokenlen:
            self.__sentry(datalen, offset + tokenlen + 1)
            tokenlist.append(data[offset + 1:offset + tokenlen + 1])
            dbg.msg('Token found: %s' % tokenlist[-1])
            offset += tokenlen + 1

            # check whether the next element is a link
            self.__sentry(datalen, offset + 1)
            anoffset = self.__islink(data, offset)
            if anoffset:
                token, anoffset = self.__domain(data, anoffset)
                tokenlist.append(token)
                offset += 1
                break
            else:
                tokenlen = ord(data[offset])
        return (string.join(tokenlist, '.'), offset + 1,)

    #
    # Returns IPv4 address, dotted notation
    #
    def __IPv4(self, data, offset):
        dbg = _debug('_dnsanswer::__IPv4')

        self.__sentry(len(data), offset + 4)

        length = 4
        ipaddrlist = []
        while length:
            ipaddrlist.append(str(ord(data[offset])))
            offset += 1
            length -= 1
        return (string.join(ipaddrlist, '.'), offset,)

    #
    # Returns IPv6 address, dotted notation
    # FIXME: more testing
    #
    def __IPv6(self, data, offset, length):
        dbg = _debug('_dnsanswer::__IPv6')

        self.__sentry(len(data), offset + length)

        ret = ''
        prev_empty = False
        if ord(data[offset]) == 0:
            prev_empty = True
        else:
            ret = '%X' % ord(data[offset])
        ret += ':'
        length -= 1
        offset += 1
        while length:
            if ord(data[offset]) > 0:
                if prev_empty:
                    ret += ':'
                ret += '%X:' % ord(data[offset])
            else:
                prev_empty = True
            length -= 1
            offset += 1
        return (ret[:-1], offset)

    #
    # Returns string from the query
    #
    def __strval(self, data, offset):
        dbg = _debug('_dnsanswer::__strval')

        strlen = ord(data[offset])

        self.__sentry(len(data), offset + strlen + 1)

        offset += 1
        retstr = data[offset:offset + strlen]
        return (retstr, offset + strlen)

    #
    # Checks whether position at the offset is a link.
    # If yes, returns the target offset, False otherwise.
    #
    def __islink(self, data, offset):
        dbg = _debug('_dnsanswer::__islink')
        # In order to reduce the size of messages, the domain system
        # utilizes a compression scheme which eliminates the repetition
        # of domain names in a message. In this scheme, an entire domain
        # name or a list of labels at the end of a domain name is replaced
        # with a pointer to a prior occurance of the same name.
        #
        # The pointer takes the form of a two octet sequence:
        #
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        # | 1  1|                OFFSET                   |
        # +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        #
        if len(data[offset:]) < 2:
            dbg.msg('Last octet in sequence (%u)' % offset)
            return 0

        self.__sentry(len(data), offset + 2)

        word = self.__unpack16(data[offset:offset + 2])
        if word / 0x4000 == 0x3:
            dbg.msg('Following link from offset %u to offset %u' % (offset, word & 0x3FFF))
            return word & 0x3FFF
        dbg.msg('Not a link at offset %u' % offset)
        return 0

    #
    # Decode 2 octets at offset position and advance offset accordingly
    #
    def __twobytes(self, data, offset):
        offset_end = offset + 2
        self.__sentry(len(data), offset_end)
        ret = self.__unpack16(data[offset:offset_end])
        return (ret, offset_end)

    #
    # Decode 4 octets at offset position and advance offset accordingly
    #
    def __fourbytes(self, data, offset):
        offset_end = offset + 4
        self.__sentry(len(data), offset_end)
        ret = self.__unpack32(data[offset:offset_end])
        return (ret, offset_end)

    #
    # Returns DNS_CLASS found at the given offset
    #
    def __dnsclass(self, data, offset):
        dbg = _debug('_dnsanswer::__dnsclass')
        return self.__twobytes(data, offset)

    #
    # Returns DNS_TYPE found at the given offset
    #
    def __dnstype(self, data, offset):
        dbg = _debug('_dnsanswer::__dnstype')
        return self.__twobytes(data, offset)

    #
    # Returns TTL value found at the given offset
    #
    def __ttl(self, data, offset):
        dbg = _debug('_dnsanswer::__ttl')
        return self.__fourbytes(data, offset)

    #
    # Returns RDATA length found at the given offset
    #
    def __rdlength(self, data, offset):
        dbg = _debug('_dnsanswer::__rdlength')
        return self.__twobytes(data, offset)

    def __CNAME_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__CNAME_RDATA')
        return self.__domain(data, offset)

    def __HINFO_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__HINFO_RDATA')
        res = {}
        res['CPU'], offset = self.__strval(data, offset)
        res['OS'], offset = self.__strval(data, offset)
        return (res, offset)

    def __MB_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MB_RDATA')
        return self.__domain(data, offset)

    def __MD_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MD_RDATA')
        return self.__domain(data, offset)

    def __MF_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MF_RDATA')
        return self.__domain(data, offset)

    def __MG_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MG_RDATA')
        return self.__domain(data, offset)

    def __MINFO_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MINFO_RDATA')
        res = {}
        res['RMAILBX'], offset = self.__domain(data, offset)
        res['EMAILBX'], offset = self.__domain(data, offset)
        return (res, offset)

    def __MR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MR_RDATA')
        return self.__domain(data, offset)

    def __MX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__MX_RDATA')
        res = {}
        res['REFERENCE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __NULL_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NULL')
        return self.__UNKNOWN_RDATA(data, offset, length)

    def __NS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NS_RDATA')
        return self.__domain(data, offset)

    def __PTR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__PTR_RDATA')
        return self.__domain(data, offset)

    def __SOA_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__SOA_RDATA')
        res = {}
        res['MNAME'], offset = self.__domain(data, offset)
        res['RNAME'], offset = self.__domain(data, offset)
        res['SERIAL'], offset = self.__fourbytes(data, offset)
        res['REFRESH'], offset = self.__fourbytes(data, offset)
        res['RETRY'], offset = self.__fourbytes(data, offset)
        res['EXPIRE'], offset = self.__fourbytes(data, offset)
        res['MINIMUM'], offset = self.__fourbytes(data, offset)
        return (res, offset)

    def __TXT_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__TXT_RDATA')
        return self.__strval(data, offset)

    def __A_RDATA(self, data, offset, length=4):
        dbg = _debug('_dnsanswer::__A_RDATA')
        return self.__IPv4(data, offset)

    def __AAAA_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__AAAA_RDATA')
        return self.__IPv6(data, offset, length)

    def __AFSDB_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__AFSDB_RDATA')
        res = {}
        res['TYPE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __RP_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__RP_RDATA')
        res = {}
        res['MBOX'], offset = self.__domain(data, offset)
        res['TXT'], offset = self.__domain(data, offset)
        return (res, offset)

    def __X25_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__X25_RDATA')
        return self.__strval(data, offset)

    def __ISDN_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__ISDN_RDATA')
        res = {}
        res['ISDN'], offset = self.__strval(data, offset)
        if len(res['ISDN']) + 1 < length:
            res['SA'], offset = self.__strval(data, offset)
        return (res, offset)

    def __RT_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__RT_RDATA')
        res = {}
        res['REFERENCE'], offset = self.__twobytes(data, offset)
        res['ROUTE'], offset = self.__domain(data, offset)
        return (res, offset)

    def __GPOS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__GPOS_RDATA')
        res = {}
        res['LONGITUDE'], offset = self.__strval(data, offset)
        res['LATITUDE'], offset = self.__strval(data, offset)
        res['ALTITUDE'], offset = self.__strval(data, offset)
        return (res, offset)

    def __WKS_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__WKS_RDATA')

        assert length > 4, 'Inconsistent WKS RDATA length %u' % length

        self.__sentry(len(data), offset + length)

        res = {}
        res['ADDRESS'], offset = self.__IPv4(data, offset)
        res['PROTOCOL'] = ord(data[offset])
        offset += 1

        res['SERVICES'] = []
        octetno = 0
        for i in range(offset, offset + length - 5):
            val = ord(data[i])
            for j in range(7, 0, -1):
                if val & 1 << j:
                    res['SERVICES'].append((7 - j) + 8 * octetno)
            octetno += 1

        return (res, offset + octetno)

    def __SRV_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__SRV_RDATA')
        res = {}
        res['PRIORITY'], offset = self.__twobytes(data, offset)
        res['WEIGHT'], offset = self.__twobytes(data, offset)
        res['PORT'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    def __KX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__KX_RDATA')
        res = {}
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['DOMAIN'], offset = self.__domain(data, offset)
        return (res, offset)

    # FIXME: BIND fails to load zone with error: "unknown RR type 'APL'"
    def __APL_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__APL_RDATA')

        self.__sentry(len(data), offset + length)

        res = {}
        res['AF'], offset = self.__twobytes(data, offset)

        res['PREFIX'] = ord(data[offset])
        offset += 1

        tmpvar = ord(data[offset])
        res['NEGATION'] = False
        if tmpvar & 0x80:
            res['NEGATION'] = True
        afdlen = tmpvar & 0x7F
        offset += 1

        AF_INET = 1
        AF_INET6 = 2
        if res['AF'] == AF_INET:
            if res['PREFIX'] > 32:
                raise AnswerError('Wrong PREFIX %u in ARL RR' % res['PREFIX'])
            if afdlen > 4:
                raise AnswerError('Wrong AFDLENGTH %u for AF_INET' % afdlen)
            ipaddrlist = []
            while afdlen:
                ipaddrlist.append(str(ord(data[offset])))
                offset += 1
                afdlen -= 1
            res['AFD'] = string.join(ipaddrlist, '.')
        elif res['AF'] == AF_INET6:
            if res['PREFIX'] > 128:
                raise AnswerError('Wrong PREFIX %u in ARL RR' % res['PREFIX'])
            if afdlen > 16:
                raise AnswerError('Wrong AFDLENGTH %u for AF_INET6' % afdlen)
            res['AFD'], offset = self.__IPv6(data, offset, afdlen)
        else:
            raise AnswerError('Unknown Address Family %u' % res['AF'])

        return (res, offset)

    def __PX_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__PX_RDATA')
        res = {}
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['MAP822'], offset = self.__domain(data, offset)
        res['MAPX400'], offset = self.__domain(data, offset)
        return (res, offset)

    def __LOC_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__LOC_RDATA')

        self.__sentry(len(data), offset + length)

        res = {}
        res['VERSION'] = ord(data[offset])
        offset += 1
        res['SIZE'] = ord(data[offset])
        offset += 1
        res['HORIZ_PRE'] = ord(data[offset])
        offset += 1
        res['VERT_PRE'] = ord(data[offset])
        offset += 1
        res['LATITUDE'], offset = self.__fourbytes(data, offset)
        res['LONGITUDE'], offset = self.__fourbytes(data, offset)
        res['ALTITUDE'], offset = self.__fourbytes(data, offset)

        return (res, offset)

    def __NAPTR_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__NAPTR_RDATA')
        res = {}
        res['ORDER'], offset = self.__twobytes(data, offset)
        res['PREFERENCE'], offset = self.__twobytes(data, offset)
        res['FLAGS'], offset = self.__strval(data, offset)
        res['SERVICE'], offset = self.__strval(data, offset)
        res['REGEXP'], offset = self.__strval(data, offset)
        res['REPLACEMENT'], offset = self.__domain(data, offset)
        return (res, offset)

    def __UNKNOWN_RDATA(self, data, offset, length):
        dbg = _debug('_dnsanswer::__UNKNOWN_RDATA')
        self.__sentry(len(data), offset + length)
        res = "Unsupported TYPE: '%s'" % data[offset:offset + length]
        return (res, offset + length)

    def __rdata(self, data, offset, length, atype):
        dbg = _debug('_dnsanswer::__rdata')
        if   atype == T_A:
            return self.__A_RDATA(data, offset, length)
        elif atype == T_NS:
            return self.__NS_RDATA(data, offset, length)
        elif atype == T_MD:
            return self.__MD_RDATA(data, offset, length)
        elif atype == T_MF:
            return self.__MF_RDATA(data, offset, length)
        elif atype == T_CNAME:
            return self.__CNAME_RDATA(data, offset, length)
        elif atype == T_SOA:
            return self.__SOA_RDATA(data, offset, length)
        elif atype == T_MB:
            return self.__MB_RDATA(data, offset, length)
        elif atype == T_MG:
            return self.__MG_RDATA(data, offset, length)
        elif atype == T_MR:
            return self.__MR_RDATA(data, offset, length)
        elif atype == T_NULL:
            return self.__NULL_RDATA(data, offset, length)
        elif atype == T_WKS:
            return self.__WKS_RDATA(data, offset, length)
        elif atype == T_PTR:
            return self.__PTR_RDATA(data, offset, length)
        elif atype == T_HINFO:
            return self.__HINFO_RDATA(data, offset, length)
        elif atype == T_MINFO:
            return self.__MINFO_RDATA(data, offset, length)
        elif atype == T_MX:
            return self.__MX_RDATA(data, offset, length)
        elif atype == T_TXT:
            return self.__TXT_RDATA(data, offset, length)
        elif atype == T_AFSDB:
            return self.__AFSDB_RDATA(data, offset, length)
        elif atype == T_RP:
            return self.__RP_RDATA(data, offset, length)
        elif atype == T_X25:
            return self.__X25_RDATA(data, offset, length)
        elif atype == T_ISDN:
            return self.__ISDN_RDATA(data, offset, length)
        elif atype == T_RT:
            return self.__RT_RDATA(data, offset, length)
        elif atype == T_GPOS:
            return self.__GPOS_RDATA(data, offset, length)
        elif atype == T_AAAA:
            return self.__AAAA_RDATA(data, offset, length)
        elif atype == T_LOC:
            return self.__LOC_RDATA(data, offset, length)
        elif atype == T_SRV:
            return self.__SRV_RDATA(data, offset, length)
        elif atype == T_NAPTR:
            return self.__NAPTR_RDATA(data, offset, length)
        elif atype == T_KX:
            return self.__KX_RDATA(data, offset, length)
        elif atype == T_APL:
            return self.__APL_RDATA(data, offset, length)
        elif atype == T_PX:
            return self.__PX_RDATA(data, offset, length)

        print 'WARNING: Unsupported TYPE %u' % atype
        return self.__UNKNOWN_RDATA(data, offset, length)

    #
    # Parse 2 octets that follow ID octets
    #
    def __opcodes(self, value):
        dbg = _debug('_dnsanswer::__opcodes')
        opcodes = self.__unpack16(value)

        dict = {}

        # Reserved bits, always zero
        dict['Z'] = (opcodes & _HDR_RESERVED_MASK) / 16

        dict['QR'] = False
        if opcodes & _HDR_RESPONSE:
            dict['QR'] = True

        dict['OPCODE'] = (opcodes & _HDR_OPCODE_MASK) / 2048

        dict['AA'] = False
        if opcodes & _HDR_AUTH_ANSWER:
            dict['AA'] = True

        dict['TC'] = False
        if opcodes & _HDR_TRUNCATION:
            dict['TC'] = True

        dict['RD'] = False
        if opcodes & _HDR_REC_DESIRED:
            dict['RD'] = True
        dict['RA'] = False
        if opcodes & _HDR_REC_AVAIL:
            dict['RA'] = True

        dict['RCODE'] = opcodes & _HDR_RCODE_MASK

        dbg.msg("OPCODES: %s" % dict)
        return dict

    def __str__(self):
        if not self._complete:
            return 'Incomplete answer'
        res  = ''
        res += 'ID: %u\n' % self._dict['HEADER']['ID']
        res += 'OPCODES: %s\n' % self._dict['HEADER']['OPCODES']
        if self._dict['HEADER']['OPCODES']['RCODE']:
            try:
                res += 'ERROR: %s\n' % HDR_RCODE[self._dict['HEADER']['OPCODES']['RCODE']][0]
            except KeyError:
                res += 'ERROR: Unknown Error %u\n' % self._dict['HEADER']['OPCODES']['RCODE']
        res += 'QDCOUNT: %u\n' % self._dict['HEADER']['QDCOUNT']
        res += 'ANCOUNT: %u\n' % self._dict['HEADER']['ANCOUNT']
        res += 'NSCOUNT: %u\n' % self._dict['HEADER']['NSCOUNT']
        res += 'ARCOUNT: %u\n' % self._dict['HEADER']['ARCOUNT']
        res += 'QUERY: %s\n' % self._dict['QUERY']
        res += 'ANSWER: %s\n' % self._dict['ANSWER']
        res += 'AUTHORITY: %s\n' % self._dict['AUTHORITY']
        res += 'ADDITIONAL: %s\n' % self._dict['ADDITIONAL']
        return res

    def id(self):
        return self._dict['HEADER']['ID']

    def isComplete(self):
        dbg = _debug('_dnsanswer::isComplete(%s)' % self._complete)
        return self._complete

    #
    # Returns parsed server response as a dict
    #
    def get(self):
        return self._dict

    #
    # Adds new chunk of response to self._answer and resumes the parsing.
    #
    def add(self, chunk):
        dbg = _debug('_dnsanswer::add')
        self._answer += chunk

        #open('/tmp/dns.txt', 'w').write(self._answer)

        if self._prefix:
            if self._size == 0 and len(self._answer) > 2:
                self._size = self.__twobytes(self._answer, 0)[0]
                dbg.msg("TCP Message Length: %u" % self._size)
                assert self._size > 0, "Inconsistent length in TCP response"
                self._answer = self._answer[2:]
        else:
            dbg.msg("UDP Message Length: %u" % len(self._answer))

        self.__parse()

        if self._prefix:
            return self._size - len(self._answer)
        return 0

    #
    # Returns error code and string representation of the parsed response.
    #
    def error(self):
        errcode = self._dict['HEADER']['OPCODES']['RCODE']
        errstr = 'Unknown Error %u' % errcode
        if errcode:
            if HDR_RCODE.has_key(errcode):
                errstr = HDR_RCODE[errcode][0]
        else:
            errstr = 'No Error'
        return (errcode, errstr)

#
# Class to parse server string (proto:name:port)
#
_PROTOCOLS = {'udp': socket.SOCK_DGRAM, 'tcp': socket.SOCK_STREAM}
class _dnsserver:
    def __init__(self, host, defport=53, proto=None):
        self._serverport = defport
        self._serverproto = 'udp'

        hoststruct = host.split(':', 2)
        structlen = len(hoststruct)
        if structlen == 2:
            if _PROTOCOLS.has_key(hoststruct[0].lower()):
                self._serverproto = hoststruct[0].lower()
                self._servername = hoststruct[1]
            else:
                self._servername = hoststruct[0]
                self._serverport = int(hoststruct[1])
        elif structlen == 3:
            if not _PROTOCOLS.has_key(hoststruct[0].lower()):
                raise KeyError('Invalid connection protocol name: %s' % proto)
            self._serverproto = hoststruct[0].lower()
            self._servername = hoststruct[1]
            self._serverport = int(hoststruct[2])
        else:
            self._servername = hoststruct[0]

        #
        # Caller wants us to use this proto
        #
        if not proto is None:
            if _PROTOCOLS.has_key(proto):
                self._serverproto = proto
            else:
                raise KeyError('Invalid connection protocol name: %s' % proto)

    def proto(self):
        return _PROTOCOLS[self._serverproto]

    def name(self):
        return self._servername

    def port(self):
        return self._serverport

    def __str__(self):
        return '%s:%s:%u' % (self._serverproto, self._servername, self._serverport)

#
# This class handles connection to name server srv
#
class _dnsconnection:
    def __init__(self, srv=None, timeout=10):
        dbg = _debug("_dnsconnection::__init__")
        self._connected = False
        self._proto = srv.proto()
        self._name = srv.name()
        self._port = srv.port()
        self._timeout = timeout

        self._socket = socket.socket(socket.AF_INET, self._proto)
        self._fd = self._socket.fileno()

    def useprefix(self):
        if self._proto == socket.SOCK_STREAM:
            return True
        return False

    def connect(self):
        dbg = _debug("_dnsconnection::connect")
        self._socket.connect((self._name, self._port))
        self._connected = True

    def send(self, data):
        dbg = _debug("_dnsconnection::send")
        if not self._connected:
            dbg.msg('not connected')
            return
        self._socket.send(data)

    def __recv(self):
        dbg = _debug('_dnsconnection::__recv')

        if self._proto == socket.SOCK_STREAM:
            return self._socket.recv(0x200) # 512 bytes

        # Check whether the response came from the same name server
        answer, (host, port) = self._socket.recvfrom(0x40000) # 16 kb
        if not (host == self._name and port == self._port):
            raise ConnectionError('Request server %s:%u does not match response server %s:%u' % (self._name, self._port, host, port))
        return answer

    def recv(self, receiver):
        dbg = _debug("_dnsconnection::recv")

        if not self._connected:
            dbg.msg('not connected')
            return False

        togo = -1
        while togo:
            rl, wl, xl = select.select([self._fd,], [], [], self._timeout)
            if self._fd in rl:
                togo = receiver.add(self.__recv())
            else:
                return False

        return True

    def disconnect(self):
        dbg = _debug("_dnsconnection::disconnect")
        if not self._connected:
            dbg.msg('not connected')
            return
        self._socket.close()
        self._connected = False

    def __str__(self):
        s = '%s:%s:%s: ' % (self._proto, self._name, self._port)
        if not self._connected:
            s += 'not '
        s += 'connected'
        return s

class Resolver:
    """
    Resolver class is used to send, receive, and parse DNS requests.

    When instantiating this class you may specify list of nameservers
    to use, port these name servers use, and a timeout for waiting for
    the name server response.

    In case the name servers weren't supplied /etc/resolv.conf is used.
    If /etc/resolv.conf does not contain information on name servers
    (or the file is missing, or other error), it is assumed that DNS
    server resides on localhost, port 53.

    In case the port wasn't specified port 53 is used.

    Default value for timeout is 10 seconds.

    Typical usage of this class is as follows:

        resolver = DNS.Resolver() # use /etc/resolv.conf, port 53, 10 sec

        ipaddrlist = resolver.IPAddress('some.host.com')
        print ipaddrlist
        # resolver found 3 addresses associated with the hostname
        ('192.168.0.1', '192.168.0.2', '192.168.0.3')

        mxlist = resolver.MailExchange('domain.com')
        print mxlist
        # mail for this domain is handled by 2 mail servers
        (('domain.com',), ((10, '192.168.0.10'), (20, '192.168.0.20')),)

    For more comprehensive information use Raw() method.
    """

    def __init__(self, nameservers=None, port=53, timeout=0):
        dbg = _debug("Resolver::__init__")

        # Parse /etc/resolv.conf
        dnsservers, candidates, parsedtimeout = self.__resolv_conf()

        self._servers = nameservers or dnsservers or ['udp:127.0.0.1:53']
        self._port = port or 53
        self._timeout = timeout or parsedtimeout or 10 # Timeout for select
        self._candidates = candidates

    def __str__(self):
        fmt = 'Name servers: %s\nCandidate Domains: %s\nTimeout: %u sec'
        return fmt % (self._servers, self._candidates, self._timeout)

    #
    # Remove everything that was commented
    #
    def __stripcomment(self, line, comments):
        dbg = _debug("Resolver::__stripcomment")
        line = line.strip()
        for br in comments:
            c = line.find(br)
            if c != -1:
                line = line[:c].strip()
        return line

    #
    # Parse /etc/resolv.conf for nameserver entries.
    # Returns list of all found name servers.
    #
    def __resolv_conf(self):
        dbg = _debug("Resolver::__resolv_conf")
        nameservers = []
        candidatedomains = []
        primarydomain = ''
        timeout = 0

        try:
            rawlines = open('/etc/resolv.conf', 'r').readlines()
        except:
            return ((), (), 0)

        comments = [';', '#']
        for line in rawlines:
            sl = self.__stripcomment(line, comments)

            # Ignore empty lines and comments
            if not sl:
                continue

            l = sl.split(' ')
            if l:
                if l[0] == 'nameserver':
                    for ns in l[1:]:
                        if not ns in nameservers:
                            nameservers.append(ns)
                elif l[0] == 'domain':
                    primarydomain = l[1]
                elif l[0] == 'search':
                    for domain in l[1:]:
                        if not domain in candidatedomains:
                            candidatedomains.append(domain)
                elif l[0] == 'options':
                    for option in l[1:]:
                        if option.startswith('timeout'):
                            timeout = int(option.split(':', 1)[1])

        if primarydomain and not primarydomain in candidatedomains:
            candidatedomains.insert(0, primarydomain)
            candidatedomains = _unique(candidatedomains)

        return (tuple(nameservers), tuple(candidatedomains), timeout)

    #
    # Try to send DNS query to the list of name servers.
    # Exit on the first received response.
    #
    def __resolve(self, query, proto=None):
        dbg = _debug("Resolver::__resolve")

        for server in self._servers:

            srv = _dnsserver(server, self._port, proto)
            conn = _dnsconnection(srv, self._timeout)
            answer = _dnsanswer(prefix = conn.useprefix())

            dbg.msg("Connecting to %s" % srv)
            conn.connect()

            try:
                dbg.msg("Sending query...")
                conn.send(query.get(conn.useprefix()))
                dbg.msg("Waiting for response...")
                if not conn.recv(answer):
                    dbg.msg("Request timed out, giving up")
            finally:
                conn.disconnect()

            if answer.isComplete():
                dbg.msg("Answer received")
                return answer

            dbg.msg("No answer from %s" % srv)

        return None

    def ixfr(self, domain, serial, mname, rname, recursion=True, proto=None):
        """
        Returns tuple of incremental changes of the domain zone records
        since serial version.

        mname is the name of the name server that was the original or
        primary source of data for this zone.

        rname is the mailbox of the person responsible for this zone.
        """
        soa = {'NAME': domain, 'TYPE': T_SOA, 'CLASS': C_IN}
        soa['RDATA'] = {'MNAME': mname, 'RNAME': rname, 'SERIAL': serial}

        sections = {'AUTHORITY': [soa,]}

        res = self.Raw(domain, T_IXFR, C_IN, recursion, proto, sections)

        if res['HEADER']['ANCOUNT'] == 1:
            # UDP packet overflow, force TCP
            res = self.Raw(domain, T_IXFR, C_IN, recursion, 'tcp', sections)

        return tuple(res['ANSWER'])

    def CandidateDomains(self):
        """
        Returns possible domains of localhost
        """
        return tuple(self._candidates)

    def MailDomain(self, hostname, recursion=True, proto=None):
        """
        Returns possible mail domain the host belongs to.
        """
        dbg = _debug('Resolver::MailDomain')

        raw = self.Raw(hostname, T_MX, C_IN, recursion, proto, None)

        if raw['HEADER']['ANCOUNT'] > 0:
            # The hostname is the domain name itself
            return hostname

        # Check the AUTHORITY section for the domain names
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])
            hint = _unique(domains)
            hint.sort()
            return hint[0]
        return None

    def Hostname(self, ipaddress, recursion=True, proto=None):
        """
        Returns immutable list of the IP address hostnames
        """
        dbg = _debug('Resolver::Hostname')

        raw = self.Raw(ipaddress, T_PTR, C_IN, recursion, proto, None)

        res = ()
        if raw['HEADER']['ANCOUNT'] > 0:
            for answer in raw['ANSWER']:
                res += (answer['RDATA'],)
        return res

    def NameServer(self, domain, recursion=True, proto=None):
        """
        Find name servers that serve the domain.
        Returns immutable list consisting of two elements: hints section
        which comprises possible domains that should be queried on behalf
        of the initial domain, and list of the names of the name servers. 
        """
        dbg = _debug('Resolver::NameServer')

        raw = self.Raw(domain, T_NS, C_IN, recursion, proto, None)

        # Fill hint section
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])
            hint = _unique(domains)
            hint.sort()

        # Fill NS section
        ns = []
        if raw['HEADER']['ANCOUNT'] > 0:
            for nsrecord in raw['ANSWER']:
                ns.append(nsrecord['RDATA'])
        return (tuple(hint), tuple(ns))

    def MailExchange(self, domain, recursion=True, proto=None):
        """
        Find the domain mail servers, their preferences as well.
        Returned list consists of two elements - first comes the hint
        section comprised of possible domains that should be queried
        on behalf of the initial domain, the second one is list of
        found MX records for this domain.
        """
        dbg = _debug('Resolver::MailExchange')

        raw = self.Raw(domain, T_MX, C_IN, recursion, proto, None)

        # Fill hint section
        hint = []
        if raw['HEADER']['NSCOUNT'] > 0:
            domains = []
            for nsrecord in raw['AUTHORITY']:
                domains.append(nsrecord['DOMAIN'])
            hint = _unique(domains)
            hint.sort()

        # Fill MX section
        mx = []
        if raw['HEADER']['ANCOUNT'] > 0:
            for mxrecord in raw['ANSWER']:
                mx.append((
                        mxrecord['RDATA']['REFERENCE'],
                        mxrecord['RDATA']['DOMAIN']
                    ))
        return (tuple(hint), tuple(mx))

    def IPAddress(self, hostname, recursion=True, proto=None):
        """
        Find all IP addresses of the host by its name.
        Returns immutable list of the addresses.
        """
        dbg = _debug('Resolver::IPAddress')

        raw = self.Raw(hostname, T_A, C_IN, recursion, proto, None)

        res = ()
        if raw['HEADER']['ANCOUNT'] > 0:
            for answer in raw['ANSWER']:
                res += (answer['RDATA'],)
        return res

    #
    # Compose a DNS query, send to DNS servers, and return parsed answer.
    #
    def Raw(self, addr, qtype=T_A, qclass=C_IN, recursion=False, proto=None, sections=None):
        """
        Resolve given hostname/IP address, query type, and query class.
        All other Resolver class methods like IPAddress(), MailExchange(),
        etc internally use this function.

        The query will be recursive if the recursion is set to True.

        Caller may set proto to 'udp' or 'tcp' to enforce
        the communication protocol regardless of name servers
        configuration. Omit this argument to use server settings.

        Returns complete DNS server response as dictionary with following
        keys:
            HEADER: Placeholder of header information. Has a dictionary
                    with keys:
                ID: id of DNS request
                OPCODES: Dictionary of server response values. Keys are:
                    QR: boolean field that specifies whether this message
                        is a query (False), or a response (True).
                    OPCODE: integer field that specifies kind of query in
                            this message. This value is set by originator
                            of query and copied into response. The values
                            are:
                            0 - a standard query
                            1 - an inverse query
                            2 - a server status request
                    AA: Authoritative Answer - this boolean value is valid
                        in responses, and specifies that the responding
                        name server is an authority for the domain name in
                        question section.
                    TC: TrunCation - specifies that this message was
                        truncated due to length greater than that permitted
                        on the transmission channel.
                    RD: Recursion Desired - this boolean may be set in
                        a query and is copied into the response. If RD is
                        set, it directs the name server to pursue the query
                        recursively. Recursive query support is optional.
                    RA: Recursion Available - this bit is set or cleared in
                        a response, and denotes whether recursive query
                        support is available in the name server.
                    Z: Reserved for future use. Must be zero in all queries
                       and responses.
                    RCODE: Response code - this field is set as part of
                           responses, see DNS_RCODE values.
                QDCOUNT: number of entries in the question section.
                ANCOUNT: number of resource records in the answer section.
                NSCOUNT: number of name server resource records in the
                         authority records section.
                ARCOUNT: number of resource records in the additional
                         records section.
            QUERY: list of the question section entries. Each entry is a
                   dictionary with keys:
                        DOMAIN: string of the queried domain name
                        TYPE: query type, see DNS_TYPE constants
                        CLASS: query class, see DNS_CLASS constants
            ANSWER: list of the answer section entries. Each entry is a
                    dictionary which keys are
                        DOMAIN: an owner name, i.e., the name of the node
                                to which this resource record pertains.
                        TYPE: RR type, see DNS_TYPE constants
                        CLASS: RR class, see DNS_CLASS constants
                        TTL: a 32 bit signed integer that specifies the
                             time interval that the resource record may
                             be cached before the source of the
                             information should again be consulted. Zero
                             values are interpreted to mean that the RR
                             can only be used for the transaction in
                             progress, and should not be cached. For
                             example, SOA records are always distributed
                             with a zero TTL to prohibit caching. Zero
                             values can also be used for extremely
                             volatile data.
                        RDATA: a variable length string that describes the
                               resource.  The format of this information
                               varies according to the TYPE and CLASS of
                               the resource record.
            AUTHORITY: list of the authority records section entries. Each
                       entry is a dictionary which keys are DOMAIN, TYPE,
                       CLASS, TTL, and RDATA, see ANSWER section
                       description.
            ADDITIONAL: list of the additonal records section entries. Each
                        entry is a dictionary which keys are DOMAIN, TYPE,
                        CLASS, TTL, and RDATA, see ANSWER section
                        description.
        """
        dbg = _debug("Resolver::Raw")

        if qtype == '*':
            qtype = T_ANY
        if qclass == '*':
            qclass = C_ANY

        query = _dnsquery((addr, qtype, qclass), sections, recursion)
        answer = self.__resolve(query, proto)

        if answer is None:
            raise ResolverError('None of the servers responded')

        if answer.isComplete():
            if query.id() == answer.id():
                e, s = answer.error()
                if e:
                    raise ServerError(s)
                return answer.get()
            else:
                raise ResolverError("Query ID %u does not match answer ID %u" % (query.id(), answer.id()))
        else:
            raise ResolverError('Truncated answer')

#
# Revision history:
#
# Revision 0.4 ---- 2007/06/04 ---- pva
# * Change class/type constants names:
#     DNS_TYPE_*  => T_*
#     DNS_CLASS_* => C_*
# * Update list of RCODE constants
# * Support WKS, AFSDB, RP, X25, ISDN, RT, GPOS, KX, PX, LOC, NAPTR queries
# * Support incremental zone transfer, see Resolver.ixfr()
# * Add 'sections' arg to Raw(), to pass AUTHORITY and ADDITIONAL
#   to query builder. Format of the argument is the same as in
#   the corresponding sections of Raw() result.
# * Fix bug in parsing DNS server name, thanks to Chris Clark
#
# Revision 0.3 ---- 2007/05/28 ---- pva
# * Implement both UDP and TCP connections to name servers
# * Allow to specify communication protocol in server name as
#   'protocol:servername:port' (eg 'udp:localhost:53' or 'tcp:localhost:53')
# * Allow to enforce communication protocol (see proto arg)
# * Add support for types: SRV, AXFR, MAILA, MAILB, ANY
# * Use '*' as shortcut to DNS_CLASS_ANY, DNS_TYPE_ANY
# * Handle unsupported RDATA by _dnsanswer.__UNKNOWN_RDATA()
#   for later debugging.
#
# Revision 0.2 ---- 2007/05/21 ---- pva
# * Add CandidateDomains() which returns domains found in 'domain' and 'search'
#   options of /etc/resolve.conf ('domain' precedes).
# * Raise ServerError instead of ResolverError when RCODE is
#   not HDR_RCODE_NOERROR, for consistency
# * Parse more /etc/resolv.conf options ('domain', 'search', 'timeout')
# * Each nameserver may be specified as 'servername:port'
# * Raise IncompleteAnswerError when the received answer is truncated
# * Watch for the answer completeness
# * Minor bugfixes and improvements
#
# Revision 0.1 ---- 2007/05/14 ---- pva
#   Initial release
#

# vim:ts=4:sw=4:et:nowrap
