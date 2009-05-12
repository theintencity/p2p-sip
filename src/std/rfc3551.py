# Copyright (c) 2007, Kundan Singh. All rights reserved. See LICENSING for details.
# @implements RFC3551 (RTP AVP)
'''
Define the RTP static payload types as per RFC 3551. type and desc are two main functions.

>>> print type('GSM/8000')
3
>>> print desc(3)
('GSM', 8000, 1, 3, 'GSM/8000')

>>> for x in range(0, len(_types)):
...    name, rate, count, pt, d = desc(x)
...    assert(pt == x)
...    if d: assert(x == type(d))
...    if d: print '%d=>%s'%(pt, d),     
0=>PCMU/8000 3=>GSM/8000 4=>G723/8000 5=>DVI4/8000 6=>DVI4/16000 7=>LPC/8000 8=>PCMA/8000 9=>G722/8000 10=>L16/44100/2 11=>L16/44100 12=>QCELP/8000 13=>CN/8000 14=>MPA/90000 15=>G728/8000 16=>DVI4/11025 17=>DVI4/22050 18=>G729/8000 25=>CelB/90000 26=>JPEG/90000 28=>nv/90000 31=>H261/90000 32=>MPV/90000 33=>MP2T/90000 34=>H263/90000
'''

# static types: arranged in rows 0-5, 6-10, 11-15, ...
_types = ["PCMU/8000/1", None, None, "GSM/8000/1", "G723/8000/1", "DVI4/8000/1", \
  "DVI4/16000/1", "LPC/8000/1", "PCMA/8000/1", "G722/8000/1", "L16/44100/2",     \
  "L16/44100/1", "QCELP/8000/1", "CN/8000/1", "MPA/90000/1", "G728/8000/1",      \
  "DVI4/11025/1", "DVI4/22050/1", "G729/8000/1", None, None,                     \
  None, None, None, None, "CelB/90000/1",                                        \
  "JPEG/90000/1",  None, "nv/90000/1", None, None,                               \
  "H261/90000/1", "MPV/90000/1", "MP2T/90000/1", "H263/90000/1"]

def _type2desc(t):
    if _types[t]:
        name, srate, scount = _types[t].split('/')
        return (name, int(srate), int(scount), t, name + '/' + srate + ('' if scount == '1' else '/' + scount))
    else:
        return (None, None, None, t, None)

_desc   = map(_type2desc, range(0, len(_types))) 
_lowers = [(x and x.lower() or None) for x in _types]

# return the type (int) for the description ('name/rate' or 'name/rate/count') or 
# -1 if not found.
type = lambda x:  _lowers.index(x.lower()) if x and (x.lower() in _lowers) \
          else ((_lowers.index(x.lower()+'/1') if x and ((x.lower()+'/1') in _lowers) else -1))

# return the description ('name', rate, count, pt, 'name/rate/count') for the type (int)) or 
# tuple (None, None, None, pt, None) if not found or not defined.
desc = lambda x: _desc[x] if x >=0 and x < len(_desc) else (None, None, None, x, None)

if __name__ == '__main__':
    import doctest
    doctest.testmod()