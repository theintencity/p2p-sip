# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3550 (RTP)

'''
This module implements the real-time transport protocol (RTP) and companion real-time
transport control protocol (RTCP) based on RFC 3550.

The RTP and RTCP classes define the packet format for RTP and RTCP.
The Session class defines the control behavior for an RTP session.
The Source class represents a member or source.
The Network class abstracts out the network behavior such as pair of sockets. 
'''

# @implements RFC3550 P1L31-P1L50

import os, sys, struct, random, math, time, socket, traceback
from kutil import getlocaladdr
try: import multitask
except: print 'could not import multitask from rfc3550'

_debug = False
_padding = False  # whether outbound RTP header contains padding or not?

'''
return the data as list string representing binary form of the characted in data.
>>> print binstr('\\x01\\x02\\x03\\x04\\x05\\x06\\x07')
00000001000000100000001100000100
000001010000011000000111--------
'''
#binary = lambda a, s=1: [''.join([('1' if (ord(x) & (1<<(7-y))) else '0') for y in range(0, 8)]) for x in a]
def binary(data, size=4):
    all = ''.join([''.join([('1' if (ord(x) & (1<<(7-y))) else '0') for y in range(0, 8)]) for x in data])
    result, size = [], size*8  # size to bits
    while len(all) >= size:
        result.append(all[:size])
        all = all[size:]
    if len(all)>0:
        result.append(all + '-'*(size-len(all)))
    return result
binstr = lambda x: '\n'.join(binary(x))

# @implements RFC3550 P8L41-P8L47
class RTP(object):
    '''A RTP packet.
    >>> p1 = RTP(pt=8, seq=12, ts=13, ssrc=14, csrcs=[15, 16], marker=True, extn=(17, '\\x18\\x19\\x1a\\x1b'), payload='\\x1c\\x1d\\x1e')
    >>> print ''.join(['%02x'%ord(x) for x in str(p1)])
    b288000c0000000d0000000e0000000f000000100011000118191a1b1c1d1e01
    >>> p2 = RTP(value=str(p1))
    >>> print p2.pt, p2.seq, p2.ts, p2.ssrc, p2.csrcs, p2.marker, p2.extn, repr(p2.payload)
    8 12 13 14 [15, 16] True (17, '\\x18\\x19\\x1a\\x1b') '\\x1c\\x1d\\x1e'
    >>> print '\\n'.join(binary(str(p2)))
    10110010100010000000000000001100
    00000000000000000000000000001101
    00000000000000000000000000001110
    00000000000000000000000000001111
    00000000000000000000000000010000
    00000000000100010000000000000001
    00011000000110010001101000011011
    00011100000111010001111000000001
    '''
    def __init__(self, value=None, pt=0, seq=0, ts=0, ssrc=0, csrcs=None, marker=False, extn=None, payload=''):
        '''Construct a RTP packet from individual components: pt a payload type [0, 128),
        seq a 16 bit unsigned sequence number, ts a 32 bit unsigned timestamp, ssrc a
        32 bit source identifier, csrcs a list of 32-bit contributing source identifiers
        with max size of 15, marker a boolean, extn a tuple of (type, value) for the header
        extension and payload is the RTP payload data. 
        Alternatively, if value is specified, then construct the RTP packet by parsing the 
        value.'''
        csrcs = csrcs or []
        if not value: # construct using components.
            self.pt, self.seq, self.ts, self.ssrc, self.csrcs, self.marker, self.extn, self.payload = \
            pt, seq, ts, ssrc, csrcs, marker, extn, payload
        else: # parse the packet.
            if len(value) < 12: raise ValueError, 'RTP packet must be at least 12 bytes'
            if ord(value[0]) & 0xC0 != 0x80: raise ValueError, 'RTP version must be 2'
            px, mpt, self.seq, self.ts, self.ssrc = struct.unpack('!BBHII', value[:12])
            self.marker, self.pt = (mpt & 0x80 and True or False), (mpt & 0x7f)
            self.csrcs, value = ([] if (px & 0x0f == 0) else list(struct.unpack('!'+'I'*(px&0x0f), value[12:12+(px&0x0f)*4]))), value[12+(px & 0x0f)*4:]
            if px & 0x10:
                xtype, xlen = struct.unpack('!HH', value[:4])
                self.extn, value = (xtype, value[4:4+xlen*4]), value[4+xlen*4:]
            else: self.extn = None
            self.payload = value if px & 0x20 == 0 else value[:len(value)-ord(value[-1])]
    def __repr__(self):
        global _padding
        return struct.pack('!BBHII', 0x80 | (_padding and (len(self.payload)%4 != 0) and 0x20 or 0x00) | (self.extn and 0x10 or 0x00) | (len(self.csrcs) > 15 and 15 or len(self.csrcs)), \
                           (self.pt & 0x7f) | (self.marker and 1 or 0) << 7, (self.seq & 0xffff), self.ts, self.ssrc) \
                + ''.join(struct.pack('!I', x) for x in self.csrcs[:16]) \
                + ('' if not self.extn else (struct.pack('!HH', self.extn[0] & 0xffff, len(self.extn[1])/4) + self.extn[1])) \
                + self.payload \
                + ('' if (not _padding or len(self.payload) % 4 == 0) else ('\x00'*(4-len(self.payload)%4-1) + struct.pack('!B', 4-len(self.payload)%4)))
        

# @implements RFC3550 P9L1-P9L7
class RTCP(list):
    '''A compound RTCP packet is a list of individual RTCP packets. A individual RTCP
    packet is of type RTCP.packet with attributes or items defined depending on the type
    of the packet.
    
    >>> sr = RTCP.packet(pt=RTCP.SR, ssrc=1, ntp=2, ts=3, pktcount=4, octcount=5, reports=[], extn=None)
    >>> r1 = RTCP.packet(ssrc=1, flost=2, clost=3, hseq=4, jitter=5, lsr=6, dlsr=7)
    >>> r2 = RTCP.packet(ssrc=8, flost=9, clost=10, hseq=11, jitter=12, lsr=13, dlsr=14)
    >>> rr = RTCP.packet(pt=RTCP.RR, ssrc=1, reports=[r1, r2])
    >>> item1 = (1, [(RTCP.CNAME, 'kundan@example.net'), (RTCP.NAME, 'Kundan Singh'), (RTCP.EMAIL, 'kundan@example.net'), (RTCP.PHONE, '9176216392')])
    >>> item2 = (2, [(RTCP.CNAME, 'sanjayc77@example.net'), ])
    >>> sdes = RTCP.packet(pt=RTCP.SDES, items=[item1, item2])
    >>> bye  = RTCP.packet(pt=RTCP.BYE, ssrcs=[1,2,3], reason='disconnecting') 
    >>> p1 = RTCP([sr, rr, sdes, bye])
    >>> p2 = RTCP(str(p1))
    >>> sr, rr, sdes, bye = tuple(p2)
    >>> print sr.pt, sr.ssrc, sr.ntp, sr.ts, sr.pktcount, sr.octcount
    200 1 2.0 3 4 5
    >>> print rr.pt, rr.ssrc, [(x.ssrc, x.flost, x.clost, x.hseq, x.jitter, x.lsr, x.dlsr) for x in rr.reports]
    201 1 [(1, 2, 3, 4, 5, 6, 7), (8, 9, 10, 11, 12, 13, 14)]
    >>> print sdes.pt
    202
    >>> for item in sdes.items:
    ...    print 'ssrc=', item[0]
    ...    for n,v in item[1]: print '',n,'=',v
    ssrc= 1
     1 = kundan@example.net
     2 = Kundan Singh
     3 = kundan@example.net
     4 = 9176216392
    ssrc= 2
     1 = sanjayc77@example.net
    >>> print bye.pt, bye.ssrcs, bye.reason
    203 [1, 2, 3] disconnecting
    '''
    SR, RR, SDES, BYE, APP = range(200, 205) # various packet types
    CNAME, NAME, EMAIL, PHONE, LOC, TOOL, NOTE, PRIV = range(1, 9)
    
    def __init__(self, value=None): # parse the compound RTCP packet.
        if isinstance(value, list):
            for v in value: self.append(v) # just append the list of packets
            return
        while value and len(value)>0:
            p = RTCP.packet() # individual RTCP packet
            px, p.pt, plen = struct.unpack('!BBH', value[:4])
            if px & 0xC0 != 0x80: raise ValueError, 'RTP version must be 2'
            if p.pt < 200 or p.pt >= 205: raise ValueError, 'Not an RTCP packet type %d'%(p.pt)
            data, value = value[4:4+plen*4], value[4+plen*4:] # data for this packet, value for next
            if px & 0x20: data = data[:len(data)-ord(data[-1])] # remove padding
            if p.pt == RTCP.SR or p.pt == RTCP.RR:
                if p.pt == RTCP.SR:
                    p.ssrc, ntp1, ntp2, p.ts, p.pktcount, p.octcount = struct.unpack('!IIIIII', data[:24])
                    p.ntp = ntp2time((ntp1, ntp2))
                    data = data[24:]
                else:
                    p.ssrc, = struct.unpack('!I', data[:4])
                    data = data[4:]
                p.reports = []
                for i in range(px&0x1f):
                    r = RTCP.packet()
                    r.ssrc, lost, r.hseq, r.jitter, r.lsr, r.dlsr = struct.unpack('!IIIIII', data[:24])
                    r.flost, r.clost = (lost >> 24) & 0x0ff, (lost & 0x0ffffff)
                    p.reports.append(r)
                    data = data[24:]
                p.extn = data if data else None
            elif p.pt == RTCP.SDES:
                p.items = []
                for i in range(0, px&0x1f):
                    ssrc, = struct.unpack('!I', data[:4])
                    items = []
                    data, count = data[4:], 0
                    while len(data)>0:
                        itype, ilen = struct.unpack('!BB', data[:2])
                        count += (2 + ilen)
                        ivalue, data = data[2:2+ilen], data[2+ilen:]
                        if itype == 0: break
                        items.append((itype, ivalue))
                    if count % 4 != 0: data = data[(4-count%4):] # ignore padding for the chunk
                    p.items.append((ssrc, items))
            elif p.pt == RTCP.BYE:
                p.ssrcs, p.reason = [], None
                for i in range(0, px & 0x01f):
                    ssrc, = struct.unpack('!I', data[:4])
                    p.ssrcs.append(ssrc)
                    data = data[4:]
                if data and len(data)>0:
                    rlen, = struct.unpack('!B', data[:1])
                    p.reason = data[1:1+rlen] # no need to ignore padding, it already gets ignored when we use next packet
            elif p.pt == RTCP.APP:
                p.subtype = px&0x1f
                p.ssrc, p.name = struct.unpack('!I4s', data[:8])
                p.data = data[8:]
                if not p.data: p.data = None
            else: # just store the raw data
                p.subtype = px&0x1f
                p.data = data[4:]
            self.append(p)

    def __str__(self):
        global _padding
        result = ''
        for p in self:
            count, value = 0, ''
            if p.pt == RTCP.SR or p.pt == RTCP.RR:
                if p.pt == RTCP.SR:
                    ntp1, ntp2 = time2ntp(p.ntp) 
                    value = struct.pack('!IIIIII', p.ssrc, ntp1, ntp2, p.ts, p.pktcount, p.octcount)
                else: value = struct.pack('!I', p.ssrc)
                count = len(p.reports)
                for r in p.reports:
                    value += struct.pack('!IIIIII', r.ssrc, (r.flost << 24) | (r.clost & 0x0ffffff), r.hseq, r.jitter, r.lsr, r.dlsr)
                if p.extn: value += p.extn
            elif p.pt == RTCP.SDES:
                count = len(p.items)
                for ssrc,items in p.items:
                    chunk = struct.pack('!I', ssrc)
                    for n,v in items:
                        chunk += struct.pack('!BB', n, len(v)>255 and 255 or len(v)) + v[:256]
                    chunk += struct.pack('!BB', 0, 0) # to indicate end of items.
                    if len(chunk)%4!=0: chunk += '\x00'*(4-len(chunk)%4)
                    value += chunk
            elif p.pt == RTCP.BYE:
                count = len(p.ssrcs)
                for ssrc in p.ssrcs: value += struct.pack('!I', ssrc)
                if p.reason and len(p.reason)>0: value += struct.pack('!B', len(p.reason)>255 and 255 or len(p.reason)) + p.reason[:256]
            elif p.pt == RTCP.APP:
                count = p.subtype
                value += struct.pack('!I4s', p.ssrc, p.name) + (p.data if p.data else '')
            else: # just add the raw data
                count = p.subtype
                value += p.data
            length = len(value)/4 + (1 if len(value)%4 != 0 else 0)
            result += struct.pack('!BBH', 0x80 | (_padding and len(value)%4 != 0 and 0x20 or 0x00) | (count & 0x1f), p.pt, length) \
                + value + ('' if (not _padding or len(value) % 4 == 0) else ('\x00'*(4-len(value)%4-1) + struct.pack('!B', 4-len(value)%4)))
        # TODO: we do padding in each packet, instead of only in last.
        return result

    class packet(object):
        '''A generic class for individual packet or report. It exposes both container and
        attribute interface.'''
        def __init__(self, **kwargs): 
            for n,v in kwargs.items(): self[n] = v 
        # attribute access: use container if not found
        def __getattr__(self, name): return self.__getitem__(name)
        # container access: use key in __dict__
        def __getitem__(self, name): return self.__dict__.get(name, None)
        def __setitem__(self, name, value): self.__dict__[name] = value
        def __contains__(self, name): return name in self.__dict__
    

# following definitions are borrowed from RFC 3550
RTP_SEQ_MOD    = (1<<16)
MAX_DROPOUT    = 3000
MAX_MISORDER   = 100
MIN_SEQUENTIAL = 2

# @implements RFC3550 P78L8-P78L23
class Source(object):
    '''A source in a RTP-based Session. This is used to represent both the local member
    as well as the remote members. The SSRC and SDES's CNAME must be unique in a session.
    '''
    def __init__(self, ssrc, items=[], address=None):
        '''Create a new member for the given SSRC.
        >>> m = Source(1, [(RTCP.CNAME, 'kundan@example.net'), (RTCP.NAME, 'Kundan Singh')], ('127.0.0.1', 8000))
        >>> print m
        <Source ssrc=1 items=[(1, 'kundan@example.net'), (2, 'Kundan Singh')] address=('127.0.0.1', 8000) lost=0 fraction=0 pktcount=0 octcount=0 maxseq=0 badseq=0 cycles=0 baseseq=0 probation=0 received=0 expectedprior=0 receivedprior=0 transit=0 jitter=0 lastts=None lastntp=None rtcpdelay=None>
        '''
        self.ssrc, self.items, self.address = ssrc, items, address
        self.lost = self.fraction = self.pktcount = self.octcount = self.timeout = 0
        self.maxseq = self.badseq = self.cycles = self.baseseq = self.probation = self.received = self.expectedprior = self.receivedprior = self.transit = self.jitter = 0 # based on RFC 3550's source structure
        self.lastts = self.lastntp = self.rtcpdelay = None
    
    def __repr__(self):
        props =  ('ssrc', 'items', 'address', 'lost', 'fraction', 'pktcount', 'octcount', \
                  'maxseq', 'badseq', 'cycles', 'baseseq', 'probation', 'received',      \
                  'expectedprior', 'receivedprior', 'transit', 'jitter', 'lastts',     \
                  'lastntp', 'rtcpdelay')
        return ('<Source ' + ' '.join([p+'=%r' for p in props]) + '>')%tuple([(eval('self.%s'%p)) for p in props])
        
    # @implements RFC3550 P80L17-P80L27
    def initseq(self, seq):
        '''Initialize the seq using the newly received seq of RTP packet.
        >>> print Source(ssrc=1).initseq(10)
        <Source ssrc=1 items=[] address=None lost=0 fraction=0 pktcount=0 octcount=0 maxseq=10 badseq=9 cycles=0 baseseq=10 probation=0 received=0 expectedprior=0 receivedprior=0 transit=0 jitter=0 lastts=None lastntp=None rtcpdelay=None>
        '''
        self.baseseq = self.maxseq = seq
        self.badseq = seq - 1
        self.cycles = self.received = self.receivedprior = self.expectedprior = 0
        return self
        
    # @implements RFC3550 P79L26-P79L38
    def newfound(self, seq):
        '''Indicate that this source is newly found and added to members table.
        >>> print Source(ssrc=1).newfound(10)
        <Source ssrc=1 items=[] address=None lost=0 fraction=0 pktcount=0 octcount=0 maxseq=9 badseq=9 cycles=0 baseseq=10 probation=2 received=0 expectedprior=0 receivedprior=0 transit=0 jitter=0 lastts=None lastntp=None rtcpdelay=None>
        '''
        self.initseq(seq)
        self.maxseq, self.probation = seq-1, MIN_SEQUENTIAL
        return self # return so that methods can be nested
    
    # @implements RFC3550 P80L29-P81L35
    def updateseq(self, seq):
        '''Update the source properties based on received RTP packet's seq.
        >>> print Source(1).newfound(10).updateseq(12).updateseq(13) # simulate loss of 11
        <Source ssrc=1 items=[] address=None lost=0 fraction=0 pktcount=0 octcount=0 maxseq=13 badseq=12 cycles=0 baseseq=13 probation=0 received=1 expectedprior=0 receivedprior=0 transit=0 jitter=0 lastts=None lastntp=None rtcpdelay=None>
        '''
        udelta = seq - self.maxseq
        if self.probation > 0:
            if seq == self.maxseq+1:
                self.probation, self.maxseq = self.probation - 1, seq
                if self.probation == 0:
                    self.initseq(seq)
                    self.received = self.received + 1
                    return self # True
            else:
                self.probation, self.maxseq = MIN_SEQUENTIAL-1, seq # at least next one packet should be in sequence
            return self # False
        elif udelta < MAX_DROPOUT: # in order, with permissible gap
            if seq < self.maxseq: self.cycles += RTP_SEQ_MOD
            self.maxseq = seq
        elif udelta <= RTP_SEQ_MOD - MAX_MISORDER: # the seq made a very large jump
            if seq == self.badseq: self.initseq(seq) # probably the other side reset the seq
            else: 
                self.badseq = (seq + 1) & (RTP_SEQ_MOD-1)
                return self # False
        self.received = self.received + 1
        return self # True

    # @implements RFC3550 P94L1-P94L34
    def updatejitter(self, ts, arrival):
        '''Update the jitter based on ts and arrival (in ts units). 
        >>> s = Source(1).newfound(10).updatejitter(1000, 0).updatejitter(1160, 160).updatejitter(1330, 320)
        >>> print s.transit, int(s.jitter)
        -1010 55
        '''
        transit = int(arrival - ts)
        d, self.transit = int(math.fabs(transit - self.transit)), transit
        self.jitter += (1/16.) * (d-self.jitter)
        return self
    
    # @implements RFC3550 P83L5-P83L48
    def updatelostandexpected(self):
        '''Update the number of packets expected and lost.
        >>> s = Source(1).newfound(10).updateseq(11).updateseq(12).updateseq(14).updatelostandexpected() # similar loss of 13
        >>> print s.lost, s.fraction, s.expectedprior, s.receivedprior
        1 85 3 2
        '''
        extendedmax = self.cycles + self.maxseq
        expected = extendedmax - self.baseseq + 1
        self.lost = expected - self.received
        expectedinterval = expected - self.expectedprior
        self.expectedprior = expected
        receivedinterval = self.received - self.receivedprior
        self.receivedprior = self.received
        lostinterval = expectedinterval - receivedinterval
        if expectedinterval == 0 or lostinterval <= 0: self.fraction = 0
        else: self.fraction = (lostinterval << 8) / expectedinterval
        return self
    
    def storereport(self, fraction, lost, jitter, delay):
        self.fraction, self.lost, self.jitter, self.rtcpdelay = fraction, lost, jitter, delay
        return self
        

def time2ntp(value):
    '''Convert from time.time() output to NTP (sec, frac).
    >>> print time2ntp(0.5)
    (2208988800L, 2147483648L)
    '''
    value = value + 2208988800
    return (int(value), int((value-int(value)) * 4294967296.))

def ntp2time(value):
    '''Convert from NTP (sec, frac) to time similar to time.time() output.
    >>> print ntp2time(time2ntp(10.5))
    10.5
    '''
    return (value[0] + value[1] / 4294967296.) - 2208988800
    
# @implements RFC3550 P9L31-P10L21
class Session(object):
    '''A RTP session.'''
    def __init__(self, app, **kwargs):
        '''Start an RTP session for the given network with additional optional keyword
        arguments such as pt, rate, bandwidth, fraction, member, ssrc, cname, seq0, ts0.
        
        @param pt: the optional payload type, default 96.
        @param rate: the optional sampling rate, default 8000.
        @param bandwidth: the optional total session bandwidth, default 64000.
        @param fraction: the optional fraction to use for RTCP, default 0.05.
        @param member: the optional Source object for this member, default constructs a new.
        @param ssrc: if member is absent, then optional SSRC for Source, default a random number.
        @param cname: if member is absent, then optional CNAME for Source, default is ssrc@hostname.
        @param seq0: the optional initial sequence number, default a random number.
        @param ts0: the optional initial timestamp, default a random number.
        '''
        self.app, self.net, self.pt, self.rate, self.bandwidth, self.fraction, self.member    = \
          app, None, kwargs.get('pt', 96), kwargs.get('rate', 8000), kwargs.get('bandwidth', 64000), kwargs.get('fraction', 0.05), kwargs.get('member', None)
        if not self.member:
            ssrc  = kwargs.get('ssrc', random.randint(0, 2**32))
            cname = kwargs.get('cname', '%d@%s'%(ssrc, getlocaladdr()))
            self.member = Source(ssrc=ssrc, items=[(RTCP.CNAME, cname)])
        self.seq0, self.ts0 = kwargs.get('seq0', self.randint(0, 2**16)), kwargs.get('ts0', self.randint(0, 2**32))
        self.seq = self.ts = self.ts1 = 0 # recent seq and ts. ts1 is base time.
        self.ntp = self.ntp1 = self.tc    # recent NTP time and base time.
        
        self.rtpsent = self.rtcpsent = self.byesent = self.running = False
        
        # @implements RFC3550 P29L1-P29L34
        self.tp = self.tn = 0 # tp=last RTCP transmit time, tc=current time, tn=next RTCP scheduled time
        self.members, self.senders = dict(), dict()  # TODO: this should be a smart set+map data structure
        self.pmembers = 0
        self.rtcpbw = self.bandwidth*self.fraction
        self.wesent, self.initial, self.avgrtcpsize = False, True, 200
        
    def randint(self, low=0, high=0x100000000):
        '''Return a random number between [low, high).'''
        return random.randint(low, high) # TODO: use the algorithm defined in RFC to implement this instead of using random
    
    @property
    def tc(self):
        '''The current time property in double.'''
        return time.time()
    
    @property
    def tsnow(self):
        '''The current RTP timestamp in ts unit based on current time.'''
        if self.ntp != self.ntp1: return int(self.ts + (self.tc - self.ntp)*((self.ts - self.ts1) / (self.ntp - self.ntp1))) & 0xffffffff
        else: return int(self.ts) & 0xffffffff
        
    def start(self):  
        '''Start the session, starts sending RTCP and RTP, as well as receiving them.'''
        if self.running: return # already running, don't run again.
        
        self.senders.clear(); self.members.clear(); # add ourself in members.
        self.pmembers = 1
        self.members[self.member.ssrc] = self.member
        self.wesent = self.rtcpsent = False

        delay = self.rtcpinterval(True) # compute first RTCP interval
        self.tp, self.tn = self.tc, self.tc + delay
        
        if hasattr(self.app, 'createTimer') and callable(self.app.createTimer):
            self.timer = timer = self.app.createTimer(self) # schedule a timer to send RTCP
            timer.start(delay*1000)
        else: # ignore RTCP sending if timer is not created
            self.timer = None
            if _debug: print 'exception in creating the timer.' 
        self.running = True
        
        if hasattr(self.app, 'starting') and callable(self.app.starting): self.app.starting(self) # ignore if starting() is not defined
        
    def stop(self, reason=''):
        '''Stop or close the session, hence stops sending or receiving packets.'''
        if not self.running: return # not running already. Don't bother.
        self.sendBYE(reason=reason)
        self.members.clear()
        self.senders.clear()
        self.pmembers = 0
        if self.timer: 
            self.timer.stop()
            self.timer = None
        self.running = False
        if hasattr(self.app, 'stopping') and callable(self.app.stopping): self.app.stopping(self) # ignore if stopping is not defined
        self.net = None
    
    def send(self, payload='', ts=0, marker=False, pt=None):
        '''Send a RTP packet using the given payload, timestamp and marker.'''
        member = self.member
        member.pktcount = member.pktcount + 1
        member.octcount = member.octcount + len(payload)
        self.ts, self.ntp = ts, self.tc
        if self.ts1 == 0: self.ts1 = ts
        self.rtpsent = self.wesent = True

        if pt is None: pt = self.pt
        pkt = RTP(pt=pt, marker=marker, seq=self.seq0+self.seq, ts=(self.ts0+ts) & 0xffffffff, ssrc=member.ssrc, payload=payload)
        data = str(pkt)
        if self.net is not None: self.net.sendRTP(data) # TODO: not a generator, multitask.add(self.net.sendRTP(data)) # invoke app or net to send the packet
        elif hasattr(self.app, 'sendRTP') and callable(self.app.sendRTP): self.app.sendRTP(self, data)
        elif _debug: print 'ignoring send RTP' 

        self.seq = self.seq + 1
        
    def receivedRTP(self, data, src, dest):
        '''Received an RTP packet on the network. Process it and invoke app.received() callback'''
        p = RTP(data)
        # @implements RFC3550 P31L7-P31L24
        member = None
        if p.ssrc not in self.members and self.running:  
            member = self.members[p.ssrc] = Source(ssrc=p.ssrc).newfound(p.seq)
        elif self.running: 
            member = self.members[p.ssrc]
        if p.ssrc not in self.senders and self.running:
            self.senders[p.ssrc] = self.members[p.ssrc]
        if member:
            member.received = member.received + 1
            member.timeout = 0
            member.address = src
            member.updateseq(p.seq)
            member.updatejitter(p.ts, self.tsnow)
            if hasattr(self.app, 'received') and callable(self.app.received): self.app.received(member, p)
            elif _debug: print 'ignoring received RTP'
        
    def receivedRTCP(self, data, src, dest):
        '''Received an RTCP packet on network. Process it locally.'''
        for p in RTCP(data):  # for each individual packet
            # @implements RFC3550 P92L22-P93L35
            if p.pt == RTCP.SR or p.pt == RTCP.RR:
                if p.ssrc not in self.members and self.running:
                    self.members[p.ssrc] = Source(ssrc=p.ssrc)
                member = self.members[p.ssrc] # identify the member
                if p.pt == RTCP.SR: 
                    member.lastts  = p.ts
                    member.lastntp = p.ntp
                member.timeout = 0
                for r in p.reports:
                    if r.ssrc == self.member.ssrc:
                        self.member.storereport(r.flost, r.clost, r.jitter, r.dlsr/65536.)
                        break
            elif p.pt == RTCP.SDES:
                for ssrc,items in p.items:
                    if ssrc not in self.members:
                        member = self.members[ssrc] = Source(ssrc=ssrc)
                    else:
                        member = self.members[ssrc]
                    member.items = items # override previous items list
            # @implements RFC3550 P31L26-P32L12
            elif p.pt == RTCP.BYE:
                for ssrc in p.ssrcs:
                    if ssrc in self.members:
                        del self.members[ssrc]
                    if ssrc in self.senders:
                        del self.senders[ssrc]
                    if self.running:
                        if self.timer: self.timer.stop()
                        self.tn = self.tc + (len(self.members)/self.pmembers) * (self.tn-self.tc)
                        self.tp = self.tc - (len(self.members)/self.pmembers) * (self.tc-self.tp)
                        if self.timer: self.timer.start((self.tn - self.tc) * 1000)
                        self.pmembers = len(self.members)
                    
        # @implements RFC3550 P31L19-P31L24
        self.avgrtcpsize = (1/16.)*len(data) + (15/16.)*self.avgrtcpsize
        
    # @implements RFC3550 P29L40-P30L39
    def rtcpinterval(self, initial=False):
        if len(self.senders) < 0.25*len(self.members): 
            if self.wesent: C, n = self.avgrtcpsize / (0.25*self.rtcpbw), len(self.senders)
            else: C, n = self.avgrtcpsize / (0.75*self.rtcpbw), len(self.members) - len(self.senders)
        else: C, n = self.avgrtcpsize / self.rtcpbw, len(self.members)
        return (min(initial and 2.5 or 5.0, n*C)) * (random.random() + 0.5) / 1.21828

    # @implements RFC3550 P90L43-P92L20
    def timedout(self, timer):
        '''Timeout invoked to send out an RTCP.'''
        if not self.running: # need to send BYE
            delay = self.rtcpinterval()
            self.tn = self.tp + delay
            if self.tn <= self.tc:
                self.sendBYE()
            else:
                self.timer.start((self.tn - self.tc) * 1000)
        else: # need to send report
            delay = self.rtcpinterval()
            self.tn = self.tp + delay
            if self.tn <= self.tc:
                size = self.sendRTCP()
                self.avgrtcpsize = (1/16.)*size + (15/16.)*self.avgrtcpsize
                self.tp = self.tc
                delay = self.rtcpinterval()
                self.initial = False
            else:
                delay = self.tn - self.tc
            self.pmembers = len(self.members)
            self.timer.start(delay*1000) # restart the timer
             
    def sendBYE(self, reason=''):    
        if self.rtpsent and self.rtcpsent:
            self.sendRTCP(True)
            
    def sendRTCP(self, sendbye=False):
        '''Send a RTCP packet with SR or RR and SDES, and optionally BYE if sendbye is True.
        It returns the size of the packet sent.'''
        reports = []
        toremove = []
        for member in self.members.values():
            if member.received > 0:
                ntp1, ntp2 = time2ntp(member.lastntp)
                lsr  = ((ntp1 & 0x0ffff) << 16) | ((ntp2 >> 16) & 0x0ffff)
                dlsr = int((self.tc - member.lastntp)*65536)
                member.updatelostandexpected()
                report = RTCP.packet(ssrc=member.ssrc, flost=member.fraction, clost=member.lost, hseq=member.cycles+member.maxseq, jitter=int(member.jitter), lsr=lsr, dlsr=dlsr)
                reports.append(report)
                member.received = 0
            if member.timeout == 5: # if no packet within five RTCP intervals
                toremove.append(member.ssrc) # schedule it to be removed
            else:
                member.timeout = member.timeout + 1
        if toremove: # remove all timedout members
            for ssrc in toremove: del self.members[ssrc]

        packet = RTCP()
        if self.wesent: # add a sender report
            p = RTCP.packet(pt=RTCP.SR, ntp=self.tc, ts=self.tsnow+self.ts0, pktcount=self.member.pktcount, octcount=self.member.octcount, reports=reports[:32])
            self.wesent = False
        else:
            p = RTCP.packet(pt=RTCP.RR, reports=reports[:32])
        packet.append(p)
        
        if len(reports)>=32: # add additional RR if needed
            reports = reports[32:]
            while reports:
                p, reports = RTCP.packet(pt=RTCP.RR, reports=reports[:32]), reports[32:]
                packet.append(p)
        
        p = RTCP.packet(pt=RTCP.SDES, items=self.member.items) # add SDES. Should add items only every few packets, except for CNAME which is added in every.
        packet.append(p)
        
        if sendbye: # add a BYE packet as well
            p = RTCP.packet(pt=RTCP.BYE, ssrcs=[self.member.ssrc]) # Need to add a reason as well
            packet.append(p)
            
        data = str(packet) # format for network data
        if self.net is not None: multitask.add(self.net.sendRTCP(data)) # invoke app or net to send the packet
        elif hasattr(self.app, 'sendRTCP') and callable(self.app.sendRTCP): self.app.sendRTCP(self, data)
        elif _debug: print 'ignoring send RTCP' 
        self.rtcpsent = True
        return len(data)
        
class Network(object):
    '''A network interface that can be implemented by the application for the session,
    in case of a simple consecutive (even,odd) UDP ports of RTP and RTCP. The useful properties
    are src and dest, which are tuple ('ip', port) representing source and destination
    addresses. There are also srcRTCP and destRTCP properties that explicitly allow
    setting RTCP ports different from RTP. Once created the src property can not be changed.
    One way to connect this Network object with Session is to assign session.net as this object, and
    assign network.app as Session object. This way the Session object invokes this Network's methods
    (using generator) to send packets, and Network invokes Session's methods to indicate incoming 
    packets.'''
    def __init__(self, app, **kwargs):
        '''Initialize the network.'''
        s1, s2 = self._initialize(app, **kwargs)
        
        if s1 and s2:
            self.rtp, self.rtcp = s1, s2
            self._rtpgen = self.receiveRTP(self.rtp)
            self._rtcpgen = self.receiveRTCP(self.rtcp)
            multitask.add(self._rtpgen)
            multitask.add(self._rtcpgen)
        else:
            raise ValueError, 'cannot allocate sockets'
        
    def _initialize(self, app, **kwargs):
        self.app    = app
        self.src    = kwargs.get('src', ('0.0.0.0', 0))
        self.dest   = kwargs.get('dest', None)
        self.srcRTCP= kwargs.get('srcRTCP', (self.src[0], self.src[1] and self.src[1]+1 or 0))
        self.destRTCP=kwargs.get('destRTCP', None)
        self.maxsize = kwargs.get('maxsize', 1500)
        self.rtp = self.rtcp = None

        if self.src[1] != 0:  # specified port
            try:
                s1 = socket.socket(type=socket.SOCK_DGRAM)
                s2 = socket.socket(type=socket.SOCK_DGRAM)
                if _debug: print 'created RTP/RTCP sockets', s1, s2
                s1.bind(self.src)
                s2.bind(self.srcRTCP)
            except:
                if _debug: print 'failed to bind. closing', s1, s2
                s1.close(); s2.close();
                s1 = s2 = None
        else:
            retry = kwargs.get('retry', 20)   # number of retries to do
            low   = kwargs.get('low', 10000)  # the range low-high for picking port number
            high  = kwargs.get('high', 65535)
            even  = kwargs.get('even', True)  # means by default use even port for RTP
            while retry>0:
                s1 = socket.socket(type=socket.SOCK_DGRAM)
                s2 = socket.socket(type=socket.SOCK_DGRAM)
                if _debug: print 'created RTP/RTCP sockets(2)', s1, s2
                # don't bind to any (port=0) to avoid collision in RTCP, where some OS will allocate same port for RTP for retries
                if even:
                    port = random.randint(low, high) & 0x0fffe # should not use high+1?
                else: 
                    port = random.randint(low, high) | 0x00001
                try:
                    s1.bind((self.src[0], port))
                    s2.bind((self.src[0], port+1))
                    self.src, self.srcRTCP = s1.getsockname(), s2.getsockname()
                    break
                except:
                    if _debug: print 'failed to bind. closing(2)', s1, s2
                    s1.close(); s2.close();
                    s1 = s2 = None
                retry = retry - 1
        return (s1, s2)

    def __del__(self):
        self.close()
    
    def close(self):
        if _debug: print 'cleaning up sockets', self.rtp, self.rtcp
        if self._rtpgen: self._rtpgen.close(); self._rtpgen = None
        if self._rtcpgen: self._rtcpgen.close(); self._rtcpgen = None
        if self.rtp: self.rtp.close(); self.rtp = None
        if self.rtcp: self.rtcp.close(); self.rtcp = None
        if self.app: self.app = None
        
    def receiveRTP(self, sock):
        try:
            fd = sock.fileno()
            while True:
                data, remote = yield multitask.recvfrom(sock, self.maxsize)
                if self.app: self.app.receivedRTP(data, remote, self.src)
        except GeneratorExit: pass # terminated
        except: print 'receive RTP exception', (sys and sys.exc_info()); traceback.print_exc()
        try: os.close(fd)
        except: pass
        
    def receiveRTCP(self, sock):
        try:
            fd = sock.fileno()
            while True:
                data, remote = yield multitask.recvfrom(sock, self.maxsize)
                if self.app: self.app.receivedRTCP(data, remote, self.srcRTCP)
        except GeneratorExit: pass # terminated
        except: print 'receive RTCP exception', (sys and sys.exc_info())
        try: os.close(fd)
        except: pass
        
    def sendRTP(self, data, dest=None): # unline sendRTCP this is not a generator
        if self.rtp:
            dest = dest or self.dest
            if dest and dest[1] > 0 and dest[0] != '0.0.0.0': 
                if _debug: print 'sending RTP %d to %r'%(len(data), dest)
                #yield multitask.sendto(self.rtp, data, dest)
                self.rtp.sendto(data, dest)
            elif _debug: print 'ignoring send RTP'
        
    def sendRTCP(self, data, dest=None):
        if self.rtcp:
            dest = dest or self.destRTCP
            if dest and dest[1] > 0 and dest[0] != '0.0.0.0':
                if _debug: print 'sending RTCP %d to %r'%(len(data), dest) 
                yield multitask.sendto(self.rtcp, data, dest)
            elif _debug: print 'ignoring send RTCP'

try: import gevent
except ImportError: gevent = None

class gevent_Network(Network):
    def __init__(self, app, **kwargs):
        '''Initialize the network.'''
        if not gevent: raise ValueError('must have gevent before instantiating gevent_Network')
        s1, s2 = self._initialize(app, **kwargs)
        if s1 and s2:
            self.rtp, self.rtcp = s1, s2
            self._rtpgen = gevent.spawn(self.receiveRTP, self.rtp)
            self._rtcpgen = gevent.spawn(self.receiveRTCP, self.rtcp)
        else:
            raise ValueError, 'cannot allocate sockets'

    def closeRTP(self):
        if self.rtp: self.rtp.close(); self.rtp = None

    def closeRTCP(self):
        if self.rtcp: self.rtcp.close(); self.rtcp = None
    
    def close(self):
        if _debug: print 'cleaning up sockets', self.rtp, self.rtcp
        if self._rtpgen is not None:
            status = bool(self._rtpgen)
            self._rtpgen.kill();
            if(status is False and self.rtp):#either not scheduled, or already closed
                self.closeRTP()
            self._rtpgen = None
        if self._rtcpgen is not None:
            status = bool(self._rtcpgen)
            self._rtcpgen.kill();
            if(status is False and self.rtcp):#either not scheduled, or already closed
                self.closeRTCP()
            self._rtcpgen = None
        if self.app: self.app = None
        
    def receiveRTP(self, sock):
        try:
            fd = sock.fileno()
            while True:
                data, remote = sock.recvfrom(self.maxsize)
                if self.app: self.app.receivedRTP(data, remote, self.src)
        except gevent.GreenletExit: pass # terminated
        except: print 'receive RTP exception', (sys and sys.exc_info()); traceback.print_exc()
        self.closeRTP()
        self._rtpgen = None
        try: os.close(fd)
        except: pass
        
    def receiveRTCP(self, sock):
        try:
            fd = sock.fileno()
            while True:
                data, remote = sock.recvfrom(self.maxsize)
                if self.app: self.app.receivedRTCP(data, remote, self.srcRTCP)
        except gevent.GreenletExit: pass # terminated
        except: print 'receive RTCP exception', (sys and sys.exc_info())
        self.closeRTCP()
        self._rtcpgen = None
        try: os.close(fd)
        except: pass
        
    def sendRTP(self, data, dest=None): # unline sendRTCP this is not a generator
        if self.rtp:
            dest = dest or self.dest
            if dest and dest[1] > 0 and dest[0] != '0.0.0.0': 
                if _debug: print 'sending RTP %d to %r'%(len(data), dest)
                self.rtp.sendto(data, dest)
            else: 
                if _debug: print 'ignoring send RTP as dest is not set'
        
    def sendRTCP(self, data, dest=None):
        if self.rtcp:
            dest = dest or self.destRTCP
            if dest and dest[1] > 0 and dest[0] != '0.0.0.0':
                if _debug: print 'sending RTCP %d to %r'%(len(data), dest) 
                self.rtcp.sendto(data, dest)
            else: 
                if _debug: 'ignoring send RTCP as dest is not set'

if __name__ == '__main__':
    import doctest
    doctest.testmod()
