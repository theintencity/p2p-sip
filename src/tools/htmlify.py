# Generate the html documentation based on the code and specification.

import sys, os
# hack to add other libraries in the sys.path
f = os.path.dirname(sys.path.pop(0))
sys.path.append(os.path.join(f, 'external'))
srcdir  = os.path.join(f, 'std') 
f = os.path.dirname(f)
outdir  = os.path.join(os.path.join(f, 'doc'), 'html')
specdir = os.path.join(os.path.join(f, 'doc'), 'spec')

import mysilvercity as msc, StringIO, urllib

def openspec(name):
    '''Open the file for the given specification.'''            
    global specdir
    name = name.lower()
    filename = os.path.join(specdir, name)+'.txt'
    
    if not os.path.exists(filename):
        if name.startswith('rfc'):
            input = urllib.urlopen('http://www.ietf.org/rfc/' + name + '.txt')
        elif name.startswith('draft-'):
            input = urllib.urlopen('http://www.ietf.org/internet-drafts/' + name + '.txt')
        else:
            input = None
        if input:
            file = open(filename, 'w')
            pnum, lnum = 1, -3
            for line in input:
                lnum = lnum+1
                if lnum>0 and lnum<=48 or lnum>48 and len(line)>4 and line[-2]!=']':
                    file.write('P'+str(pnum)+'L'+str(lnum)+'\t'+line)
                if ord(line[0]) == 12: # line break in RFCs
                    pnum, lnum = pnum + 1, -3
            input.close()
            file.close()
    return os.path.exists(filename) and open(filename, 'rU') or None

import glob, re

implements = re.compile('#\s*@implements\s+(?P<ref>\S+)\s+(?:(?:\((?P<sec>[^\)]+)\))|(?P<lines>\S+))')
linere     = re.compile('^(?P<begin>\S+)-(?P<end>\S+)') 

quote = lambda s: s.replace('<', '&lt;').replace('>', '&gt;').replace('&','&amp;')

os.chdir(srcdir)
mhtml  = msc.MyPythonHTMLGenerator(msc.mypython_css)

for filename in glob.glob('*.py'): # change to *.py
    print 'filename=', filename
    file = open(filename, 'rU')
    html = open(os.path.join(outdir, filename + '.html'), 'w')

    print >> html, '''\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<HTML>
  <HEAD>
    <LINK href="default.css" rel="stylesheet" type="text/css">
  </HEAD>
  <BODY><PRE>'''

    block = '' # current block of python code
    for line in file:
        m = implements.search(line)
        if not m:
            block += line
        else:
            # output block so far
            if block:
                f = StringIO.StringIO() 
                mhtml.generate_html(f, block)
                print >> html, f.getvalue()
                f.close()
                block = ''
            
            # then replace the @ implements with its substitution  
            ref, sec, lines = m.group('ref'), m.group('sec'), m.group('lines')
            out = None
            if sec:
                out = '<b>' + quote('This file implements ' + ref + ' (' + sec + ')') + '</b>'
                file2 = openspec(ref)  # so that the file is fetched.
                if file2: file2.close()
            elif lines:
                m = linere.match(lines)
                if m: 
                    begin, end = m.group('begin'), m.group('end')
                    file2 = openspec(ref)
                    if file2:
                        state = 'before'
                        source = 'From '+ref + ' p.' + begin[1:].partition('L')[0] 
                        out = []
                        for line2 in file2:
                            num, sep, rest = line2.partition('\t')
                            rest = rest[:-1]
                            if state == 'before' and num == begin:
                                state = 'during'
                                out.append(rest)
                            elif state == 'during':
                                out.append(rest)
                                if num == end:
                                    state = 'after'
                                    break
                        out = source + '<pre>' + '\n'.join(quote(x) for x in out) + '</pre>'
                        file2.close()
            if out:
                print >> html, '</PRE><DIV class="commentbox">%s</DIV><PRE>'%(out)
    
    if block:
        f = StringIO.StringIO() 
        mhtml.generate_html(f, block)
        print >> html, f.getvalue()
        f.close()
    
    print >> html, '''
  </PRE></BODY>
</HTML>'''
    file.close()
    html.close()