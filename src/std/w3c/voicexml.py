# implements http://www.w3.org/TR/voicexml20/

'''
Interpreter Context (has Interpreter) and receives user input
Implementation Platform - transfers calls, receives call, disconnects, timers.

Dialog - form + menu
  each field can have a grammar. Form level grammar.
  sub-dialog is like function call.
Session 
Application
Grammar
Events
Links

Document has form, menu, meta, metadata, var, script, property, catch and link
'''

import sys, select, urllib2, traceback
if __name__ == '__main__': sys.path.append('../../external')
from simplexml import XML, XMLList, parser
import multitask

_debug = True

def F(x): return x[0] if x else None

#------------------------------------------------------------------------------
# HIGH LEVEL API        
#------------------------------------------------------------------------------

def interpret(url=None, **kwargs):
    '''A generator to process a given VoiceXML URL or Document.'''
    vxml = Document(url=url)
    yield vxml.run()

def _load(url):
    if str(url).startswith('http://'):
        return urllib2.urlopen(url).read()
    else:
        return open(url, 'rb').read()
    
#------------------------------------------------------------------------------
# Document        
#------------------------------------------------------------------------------

_elements = '''
assign audio block catch choice clear disconnect else elseif enumerate error exit field filled
form goto grammar help if initial link log menu meta metadata noinput nomatch object option
param prompt property record reprompt return script subdialog submit throw transfer value var vxml
'''.split()

class Document(object):
    def __init__(self, **kwargs):
        '''Construct (and load) the document and any applicable parent.'''
        self.url = url = kwargs.get('url', None)
        xml = kwargs.get('xml', _load(url))
        if not isinstance(xml, XML): xml = XML(xml)
        self.xml = xml
        if xml.tag != 'vxml' or xml.xmlns != 'http://www.w3.org/2001/vxml': raise ValueError, 'Not a VoiceXML document ' + str(xml.tag) + ', xmlns=' + str(xml.xmlns)
        if xml._.version != '2.0': raise ValueError, 'Unsupported version ' + str(xml._.version) 
        unknown = filter(lambda x: x.tag not in ('form', 'menu', 'meta', 'metadata', 'var', 'script', 'property', 'catch', 'link'), xml())
        if unknown: raise ValueError, 'Invalid tag in document: ' + ','.join(map(lambda x: x.tag, unknown))
        self.application = Document(url='/'.join(self.url.split('/')[:-1])+'/'+xml._.application) if xml._.application else None
        
        self.var, self.dialog, self.property, self.link = {}, [], {}, []
        for x in xml():
            if x.tag == 'var':
                self.var[x._.name] = eval(x._.expr, self.var.copy()) if x._.expr else None
            elif x.tag in ('form', 'menu'):
                self.dialog.append(x)
            elif x.tag == 'meta':
                self.property[x._.name] = x._.content
            elif x.tag == 'link':
                self.link.append(x)
                
    def run(self, id=None):
        '''Generator to execute the document.'''
        form = F(self.dialog) if not id else F(filter(lambda x: x._.id == id, self.dialog))
        if not form: raise StopIteration, 'exit'
        yield interpretForm(Form(form))
        
class Context(object):
    def __init__(self):
        self.variables, self.grammars, self.catch, self.scripts, self.properties = [], [], [], [], []

class Interpreter(object):
    def __init__(self):
        self.root = None # root Context

class Form(object):
    def __init__(self):
        self.inputItems, self.controlItems = [], []
        self.decl = []# non-form variables
        self.eventHandlers = []
        self.filledActions = []
        self.id = None
        self.scope = None

def createVarName():
    return 'varrand'

class FormItem(object):
    def __init__(self, xml):
        self.xml = xml;
        self.name = self.justFilled = self.var = self.counter = self.grammar = None
    @property
    def tag(self):
        return self.xml.tag
    
def interpretForm(form, grammar, utterance=None):
    '''Form interpretation algorithm'''
    items = []  # all the form items
    for child in form(): # for all elements in form
        item = FormItem(child)
        items.append(item)
        if item.tag == 'var':
            item.name = item.xml._.name
            item.var = item.xml._.expr or None
        elif item.tag == 'script': # not supported
            pass # evaluate the script
        elif item.tag in ('field', 'record', 'transfer', 'object', 'subdialog', 'block', 'initial'):
            item.name = item.xml._.name or '_var_'+str(len(items))
            item.var = item.xml._.expr or None
            if item.tag in ('field', 'record', 'transfer', 'object', 'subdialog', 'initial'):
                item.counter = 1
                
    def nextItem(items):
        return items[0]
    
    while True: # main loop
        if utterance is None:
            # select phase
            next = goto or nextItem(items)
            if not next:
                raise StopIteration, 'exit'
            
            # collect phase
            if not lastCatch or dialogChange:
                yield ('prompt', next.prompt)
                next.counter += 1
            if next.modal:
                activeGrammar = next.grammar
            else:
                activeGrammar = next.grammar + grammar
            yield ('grammar', activeGrammar)
        
            if next.tag in ('field', 'record', 'initial'):
                utterance = yield ('collect', next.tag)
            elif next.tag in ('object', 'subdialog'):
                next.var = execute(next.tag, next)
            elif next.tag == 'transfer':
                result = yield ('transfer', next)
                if next.xml._.wait == 'true':
                    next.var = result
            elif next.tag == 'block':
                next.var = True
                execute(next.tag, next)
                
        # Process phase
        lastResult = utterance
        match = utterance.grammar.parent
        if match.tag in ('link', 'choice'):
            next = match.xml._.next or match.xml._.expr
            if not next:
                event = match.xml._.event or match.xml._.eventexpr
        elif match not in items:
            yield ('transition', (match, utterance))
        
        filledAny = False
        for x in items: 
            x.justFilled = False
        if match.tag == 'field':
            if utterance.isStruct:
                match.var = utterance
            # TODO: more
            match.justFilled = filledAny = True
        else:
            itemDict = dict([(x.name, x) for x in items])
            for k, v in utterance:
                if k in itemDict:
                    itemDict[k].var = v
                    itemDict[k].justFilled = filledAny = True
        if filledAny:
            for x in items:
                if x.tag == 'initial':
                    x.var = True
        for x in filter(lambda x: x.tag == 'filled', items):
            pass # TODO: more
        
#------------------------------------------------------------------------------
# TESTING        
#------------------------------------------------------------------------------

def _testInterpret():
    try:
        yield interpret('example/goodbye1.vxml') # initial example
        yield interpret('example/goodbye2.vxml') # initial example
        yield interpret('example/leaf.vxml')     # multi-document
        yield interpret('example/app.vxml')      # subdialog
    
    except StopIteration: pass
    except Exception, e:
        print 'exception', type(e), e, traceback.print_exc()
    yield

def _testClose(): yield multitask.sleep(2); exit()

if __name__ == '__main__':
    import doctest; doctest.testmod()    # first run doctest,
    for f in dir():      # then run all _test* functions
        if str(f).find('_test') == 0 and callable(eval(f)):
            multitask.add(globals()[f]())
    try: multitask.run()
    except KeyboardInterrupt: pass
    except select.error: print 'select error'; pass
    sys.exit()
