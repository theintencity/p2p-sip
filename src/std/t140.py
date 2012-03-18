# Copyright (c) 2011, Kundan Singh. All rights reserved. See LICENSING for details.
# implements ITU-T's T.140 standard

'''
Implements the codes of T.140 for real-time text.
'''

_names = 'BEL BS NEWLINE CRLF SOS ST ESC INT BOM' 
_codes = (u'\u0007', u'\u0008', u'\u2028', u'\u000D\u000A', u'\u0098', u'\u009C', u'\u001B', u'\u001B\u0061', u'\uFEFF')
names = dict([(k.encode('utf-8'), v) for k, v in zip(_codes, _names.split())])
codes = dict([(v, k) for k, v in names.iteritems()])
for code, name in names.iteritems(): exec('%s=%r'%(name, code)) 

if __name__ == '__main__':
    print '%r'%([BEL, BS, NEWLINE, CRLF, SOS, ST, ESC, INT, BOM])
