# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC2198 (Redundant RTP payload)

'''
Implements RTP payload for redundant audio data as per RFC 2198.
'''

import struct

def createRedundant(packets):
    '''Create redundant payload using the individual RTP packets. The packets arg is assumed
    to be a list of tuples (pt, timestamp, payload). The first packet is assumed to be 
    primary, and is put the last. All other packets are put in the same order'''
    hdr, data = '', ''
    for p in packets[1:]:
        hdr += struct.pack('!BHB', 0x80 | p[0], p[1] - packets[0][1], len(p[2]))
        data += p[2]
    if packets:
        hdr += struct.pack('!BHB', packets[0][0], packets[0][1], len(packets[0][2]))
        data += packets[0][2]
    return hdr + data

def parseRedundant(packet, ts):
    '''Parse a redundant payload and return the individual payloads. The first in the result
    is the primary payload. Each payload is tuple (pt, timestamp, payload). The ts of the 
    original RTP packet should be supplied as well.'''
    all = []
    while packet:
        pt, = struct.unpack('!B', packet[:1])
        packet = packet[1:]
        if pt & 0x80: 
            all.insert(0, (pt))
        else:
            tsoffset, len = struct.unpack('!HB', packet[:3])
            packet = packet[3:]
            all.append((pt & 0x7f, tsoffset, len))
    result = []
    for a in all[1:]: # for all secondary data
        data = (a[0], ts+a[1], packet[:a[2]])
        packet = packet[a[2]:]
        result.append(data)
    if all:
        result.insert(0, (all[0][0], ts, packet)) # put remaining data as primary
    return result

