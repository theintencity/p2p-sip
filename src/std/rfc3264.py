# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3264 (offer-answer)
# implements only for unicast

'''
The SDP offer/answer model for unicast sessions.

Suppose the offerer wants to support PCMU and PCMA audio and H261 video, it can
use the following code to generate the offer SDP.

from std.rfc4566 import SDP, attrs as format
from std.rfc3264 import createOffer, createAnswer

>>> audio = SDP.media(media='audio', port='9000')
>>> audio.fmt = [format(pt=0, name='PCMU', rate=8000), format(pt=8, name='PCMA', rate=8000)]
>>> video = SDP.media(media='video', port='9002')
>>> video.fmt = [format(pt=31, name='H261', rate=90000)] 
>>> offer = createOffer([audio, video])
>>>
>>> offer.o.sessionid = offer.o.version = 1192000146 # so that testing doesn't depend on time
>>> offer.o.address = '192.168.1.66'                    # or IP address
>>> print str(offer).replace('\\r', '\\\\r').replace('\\n', '\\\\n')
v=0\\r\\no=- 1192000146 1192000146 IN IP4 192.168.1.66\\r\\ns=-\\r\\nt=0 0\\r\\nm=audio 9000 RTP/AVP 0 8\\r\\na=rtpmap:0 PCMU/8000\\r\\na=rtpmap:8 PCMA/8000\\r\\nm=video 9002 RTP/AVP 31\\r\\na=rtpmap:31 H261/90000\\r\\n

When the offer is received by the answerer, it can use the following code to generate
the answer. Suppose the answerer wants to support PCMU and GSM audio and no video.

from std.rfc4566 import SDP, attrs as format
from std.rfc3264 import createAnswer
>>> audio = SDP.media(media='audio', port='8020')
>>> audio.fmt = [format(pt=0), format(pt=3)]  # for known payload types, description is optional
>>> answer = createAnswer([audio], offer)
>>>
>>> answer.o.sessionid = answer.o.version = 1192000146 
>>> answer.o.address = '192.168.1.66'
>>> print str(answer).replace('\\r', '\\\\r').replace('\\n', '\\\\n')
v=0\\r\\no=- 1192000146 1192000146 IN IP4 192.168.1.66\\r\\ns=-\\r\\nt=0 0\\r\\nm=audio 8020 RTP/AVP 0\\r\\na=rtpmap:0 PCMU/8000\\r\\nm=video 0 RTP/AVP 31\\r\\na=rtpmap:31 H261/90000\\r\\n

Suppose the offerer wants to change the offer (e.g., using SIP re-INVITE) by removing
video from the offer; it should reuse the previous offer as follows:

newOffer = createOffer([audio], offer)
'''

# @implements RFC3264 P1L27-P1L36
# @implements RFC3264 P3L18-P3L21

from std.rfc4566 import SDP, attrs as format  # although RFC 3264 used old RFC 2327 for SDP definition, we use new RFC 4566

_debug = True

# @implements RFC3264 P4L1-P4L5
# A media stream is implemented by SDP.media class of std.rfc4566 module

# @implements RFC3264 P5L6-P5L41
def createOffer(streams, previous=None, **kwargs):
    '''Create an offer SDP using local (streams) list of media Stream objects.
    If a previous offer/answer SDP is specified then it creates a modified offer.
    Additionally, the optional keyword arguments such as e and p can be specified.'''
    s = SDP()
    s.v = '0'
    for a in "iep": # add optioanl e and p headers if present
        if a in kwargs: s[a] = kwargs[a]
    s.o = SDP.originator(previous and str(previous.o) or None)
    if previous: s.o.version = s.o.version + 1
    s.s = '-'
    s.t = ['0 0'] # because t= can appear multiple times, it is a list.
    s.m = streams
    return s

def createAnswer(streams, offer, **kwargs):
    '''Create an answer SDP for the remote offer SDP using local (streams) list of 
    media Stream objects.'''
    s = SDP()
    s.v = '0'
    for a in "iep": 
        if a in kwargs: s[a] = kwargs[a]
    s.o = SDP.originator()
    s.s = '-'
    s.t = offer.t
    s.m = []
    streams = list(streams) # so that original list is not modified
    for your in offer.m: # for each m= line in offer
        my, i   = None, 0      # answered stream
        while i < len(streams):
            if streams[i].media == your.media: # match the first stream in streams
                my = streams[i].dup() # found, hence
                del streams[i]  #  remove from streams so that we don't match again for another m=
                found = []
                for fy in your.fmt:  # all offered formats, find the matching pairs
                    for fm in my.fmt:# the preference order is from offer, hence do for fy, then for fm.
                        try: fmpt, fypt = int(fm.pt), int(fy.pt) # try using numeric payload type
                        except: fmpt = fypt = -1
                        if 0<=fmpt<32 and 0<=fypt<32 and fmpt == fypt \
                        or fmpt<0 and fypt<0 and fm.pt == fy.pt \
                        or str(fm.name).lower() == str(fy.name).lower() and fm.rate == fy.rate and fm.count == fy.count: # we don't match the params
                            found.append((fy, fm)); break
                if found: # we found some matching formats, put them in 
                    my.fmt = map(lambda x: x[0], found) # use remote's fy including fy.pt
                else:
                    my.fmt = [format(pt=0)] # no match in formats, but matched media, must put a format with payload type 0
                    my.port = 0             #   and reset the port.
                break
            else: 
                i = i + 1
        if not my: # did not match the stream, must put a stream with port = 0
            my = SDP.media(str(your))
            my.port = 0
        s.m.append(my) # append it to our media

    valid = False
    for my in s.m: # check if any valid matching stream is present with valid port
        if my.port != 0:
            valid = True
            break
        
    return valid and s or None  # if no valid matching stream found, return None


if __name__ == '__main__':
    import doctest
    doctest.testmod()
