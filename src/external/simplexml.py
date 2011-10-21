# Copyright (c) 2008, Kundan Singh. All rights reserved. See LICENSING for details.

'''
Simple XML handling. The existing xml.dom.minidom is too Java'ish, so simplexml is used to allow easier syntax
when processing XML. The basic API ideas are inspired from ActionScript's XML and XMLList data types.
XML is the main class which can be used as follows:

An XML string can be parsed using the constructor.
>>> a1 = XML(u'<people xmlns="private" type="contacts">start<contact>Kundan Singh</contact>end</people>')
>>> print a1
<people xmlns="private" type="contacts">start<contact>Kundan Singh</contact>end</people>

The XML element has attributes such as xmlns, tag and children. The XML attributes can be accessed using the
special attribute named '_' in the XML object. The XML attribute can also be read-accessed as a regular
Python attribute on the XML element assuming there is no conflict and the attribute name is simple.
>>> print a1.xmlns, a1.tag
private people
>>> print a1.type
contacts
>>> print a1.type == a1._['type'] == a1._.type == 'contacts'
True
>>> a1._.source='yahoo'; print a1
<people xmlns="private" source="yahoo" type="contacts">start<contact>Kundan Singh</contact>end</people>
>>> del a1._['source']; print a1
<people xmlns="private" type="contacts">start<contact>Kundan Singh</contact>end</people>

The children can be accessed using various ways. The children attribute returns the XMLList of children
which includes both elements and data objects.
>>> x1 = a1.children
>>> print len(x1)
3

An XMLList is derived from list, and each element contains individual XML element or data item.
>>> print x1
start<contact>Kundan Singh</contact>end
>>> print list(x1)
[u'start', <contact>Kundan Singh</contact>, u'end']
>>> print ', '.join(map(unicode, x1))
start, <contact>Kundan Singh</contact>, end
>>> print XML('<contact>Kundan Singh</contact>') in x1, u'start' in x1
True False

You can use the list semantics to access the children. The list methods such as append, extend, 
insert, pop, reverse, and operators such as del, slicing and indexing. The only catch is that
the slicing operation returns a regular list, instead of XMLList.
>>> x1.append(XML('<contact/>')); print x1
start<contact>Kundan Singh</contact>end<contact />
>>> x1.extend(['final']); print x1
start<contact>Kundan Singh</contact>end<contact />final
>>> x1.insert(1, 'begin'); print x1
startbegin<contact>Kundan Singh</contact>end<contact />final
>>> y = x1.pop(); print y, x1
final startbegin<contact>Kundan Singh</contact>end<contact />
>>> x1.reverse(); print x1
<contact />end<contact>Kundan Singh</contact>beginstart
>>> del x1[3]; print x1
<contact />end<contact>Kundan Singh</contact>start
>>> x1[1], x1[3] = x1[3], x1[1]; print x1
<contact />start<contact>Kundan Singh</contact>end
>>> print x1[0], isinstance(x1[0], XML), type(x1[1])
<contact /> True <type 'unicode'>
>>> print x1[0:2], type(x1) == XMLList, type(x1[0:2])
[<contact />, u'start'] True <type 'list'>
>>> print x1[:]
[<contact />, u'start', <contact>Kundan Singh</contact>, u'end']

You can also use the mapping semantics to access the children. It allows various filtering and
search method as well. There are some special index defined such as x1['*'] to return all the
elements with no data items of this XMLList, and x1('name') to return all the children elements
of the elements in XMLList with tag as 'name', and x1() to return all the children elements
of the elements in XMLList. Additionally the cdata and elems attributes fetch only the concatenated
CDATA string or list of elements, respectively.
>>> type(x1.contact) == XMLList
True
>>> print x1.contact
<contact /><contact>Kundan Singh</contact>
>>> print x1.contact == x1["contact"]
True
>>> print x1.contact == x1[lambda x: x.tag == 'contact']
True

>>> x = XML('<first><second><third a="1"/><third a="2"/><third2/></second></first>')
>>> x2 = x.children
>>> print x2("third")
<third a="1" /><third a="2" />
>>> print x2(lambda x: x.tag == 'third') == x2('third')
True
>>> print x2()
<third a="1" /><third a="2" /><third2 />
>>> print x2['*']
<second><third a="1" /><third a="2" /><third2 /></second>
>>> print x()('third')
<third a="1" /><third a="2" />
>>> print x() == x.children["*"]
True

>>> print 'contact' in x1, 'info' in x1
True False
>>> x1['info'] = XML('<info>contact list</info>'); print x1
<contact />start<contact>Kundan Singh</contact>end<info>contact list</info>
>>> del x1['info']; print x1
<contact />start<contact>Kundan Singh</contact>end
>>> x1['info'] = 'contact list'; print x1 # has same effect as earlier explict XML assignment
<contact />start<contact>Kundan Singh</contact>end<info>contact list</info>
>>> x1['info'] = None; print x1; # same effect as del x1['info']
<contact />start<contact>Kundan Singh</contact>end
>>> x1['contact'] = XMLList([XML('<contact>Kundan Singh</contact>'), XML('<contact>Mamta Singh</contact>')]); print x1
<contact>Kundan Singh</contact><contact>Mamta Singh</contact>startend
>>> x1['info'] = XMLList([XML('<info>contact list</info>')]); print x1
<contact>Kundan Singh</contact><contact>Mamta Singh</contact>startend<info>contact list</info>

>>> print x1.keys()
set([u'info', u'contact'])
>>> print map(unicode, x1.iterkeys())
[u'info', u'contact']

>>> print x1.values()
[<contact>Kundan Singh</contact>, <contact>Mamta Singh</contact>, u'start', u'end', <info>contact list</info>]
>>> print map(unicode, x1.itervalues())
[u'<contact>Kundan Singh</contact>', u'<contact>Mamta Singh</contact>', u'start', u'end', u'<info>contact list</info>']

>>> print x1.items()
[(u'contact', <contact>Kundan Singh</contact>), (u'contact', <contact>Mamta Singh</contact>), ('#text', u'start'), ('#text', u'end'), (u'info', <info>contact list</info>)]
>>> print map(unicode, x1.iteritems())
[u"(u'contact', <contact>Kundan Singh</contact>)", u"(u'contact', <contact>Mamta Singh</contact>)", u"('#text', u'start')", u"('#text', u'end')", u"(u'info', <info>contact list</info>)"]

>>> x2 = x1.copy(); print type(x2) == XMLList, x2 == x1
True True
>>> x2.clear(); print len(x2), len(x1)
0 5

>>> print x1.cdata
Kundan SinghMamta Singhstartendcontact list
>>> print x1.elems
[<contact>Kundan Singh</contact>, <contact>Mamta Singh</contact>, <info>contact list</info>]
>>> del x1[1:]; print x1
<contact>Kundan Singh</contact>

Additionally, the XMLList defines certain arithmetic style operations to manipulate the
data or list.
>>> print x1 + XML('<desc/>')
<contact>Kundan Singh</contact><desc />
>>> print x1 + x1
<contact>Kundan Singh</contact><contact>Kundan Singh</contact>
>>> print x1 + 'something'
<contact>Kundan Singh</contact>something

>>> x1 += XML('<desc/>'); print x1                        # append tag
<contact>Kundan Singh</contact><desc />
>>> x1 |= XML('<desc/>'); x1 |= XML('<desc type="1"/>'); x1 |= XML('<info/>'); print x1 # overwrite or append tag
<contact>Kundan Singh</contact><desc type="1" /><info />
>>> x1 -= XML('<info/>'); print x1                        # remove if tag is present
<contact>Kundan Singh</contact><desc type="1" />
>>> x1 ^= XML('<desc/>'); x1 ^= XML('<info/>'); print x1; # append if tag not already present, else don't overwrite
<contact>Kundan Singh</contact><desc type="1" /><info />
>>> x1 &= XML('<desc/>'); x1 &= XML('<info2/>'); print x1 # overwrite if tag already present, else don't append
<contact>Kundan Singh</contact><info /><desc />

The XML namespaces are handled using the xmlns property. The namespaces attribute of the top-level XML element
contains the list of namespace URI and their prefixes. The xmlns attribute is just the namespace URI. The namespace
declaration might get moved from parent to child or vice-versa during various XML operations.
>>> x2 = XML('<a:node xmlns:a="private" xmlns:b="public"><a:child/><b:child/></a:node>'); print x2
<node xmlns="private"><child /><child xmlns="public" /></node>
'''

from xml.parsers import expat

escape =lambda x: x.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;') # escape & < > " with appropriate XML entities

def ustr(value):
    '''Converts 'value' to utf-8 string using value's __str__ or unicode.
    >>> print type (ustr(u'kundan')) == unicode, ustr(u'kundan') == ustr('kundan')
    True True
    '''
    if isinstance(value, unicode): return value
    try: r = value.__str__()
    except AttributeError: r = str(value)
    return r if isinstance(r, unicode) else unicode(r, 'utf-8')

class parser(object):
    '''A parser using expat to parse XML string into XML object. Use the xml attribute to extract the parsed XML.'''
    def __init__(self, value=None, node=None):
        self._parser = expat.ParserCreate(namespace_separator=' ')
        for n in ('StartElementHandler', 'EndElementHandler', 'CharacterDataHandler', 'StartNamespaceDeclHandler'):
            exec 'self._parser.%s = self._%s'%(n, n) # TODO: should avoid calling exec
        self._current, self._depth, self._root = None, 0, node
        self.namespaces={'http://www.w3.org/XML/1998/namespace': 'xml:'}
        self.xmlns='http://www.w3.org/XML/1998/namespace'
        if value: 
            self._parser.Parse(value, 1)
            if self._depth != 0: raise ValueError, 'Invalid XML value ' + value
            
    def update(self, value): self._parser.Parse(value, 0) # add more data to be parsed

    @property
    def xml(self): return self._root # return the root XML node after parsing

    def _StartElementHandler(self, tag, attrs):
        xmlns, tag = tag.split(' ') if tag.find(' ') >= 0 else ('', tag)
        for n, v in filter(lambda x: x[0].rfind(' ') >= 0, attrs.items()):
            uri,ignore,prefix = n.partition(' ')
            attrs[self.namespaces[uri]+prefix] = v; del attrs[n]
        if self._depth == 0 and self._root is None: self._root = XML(tag=tag, xmlns=xmlns, attrs=attrs) # create new root element
        elif self._depth == 0: XML.__init__(self._root, tag=tag, xmlns=xmlns, attrs=attrs) # re-invoke the constructor
        else: self._current.children.append(XML(tag=tag, xmlns=xmlns, parent=self._current, attrs=attrs)) # append child element
        self._current = self._root if self._depth == 0 else self._current.children[-1] # current node is root or last child
        self._depth += 1

    def _EndElementHandler(self, tag):
        self._depth -= 1
        if self._depth > 0: self._current = self._current.parent

    def _CharacterDataHandler(self, data):
        if not self._current: return
        if self._current.children and isinstance(self._current.children[-1], XML): self._current.children.append(data)
        elif self._current.children: self._current.children[-1] += data
        else: self._current.children.append(data)

    def _StartNamespaceDeclHandler(self, prefix, uri):
        if prefix: self.namespaces[uri] = prefix + ':'
        else: self.xmlns = uri
        
class XMLList(list):
    '''List of XML or CDATA elements. Used for children in XML.'''
    def __init__(self, values=[]): list.__init__(self, values)
    def __repr__(self): return u''.join([str(x) for x in self])
    
    # private functions
    def _filter(self, func, recurse=False): # filter the elements in the sub-tree
        if recurse:
            result = XMLList()
            for x in filter(lambda y: isinstance(y, XML), self):
                if func(x): result.append(x)
                res = x.children._filter(func, recurse)
                if res: result.extend(res)
            return result
        else: return XMLList(filter(lambda x: isinstance(x, XML) and func(x), self))
        
    def _delete(self, func, recurse=False): # delete the elements in the sub-tree
        result = XMLList()
        remove = list()
        for x in filter(lambda y: isinstance(y, XML), self):
            if func(x): result.append(x); remove.append(x)
            elif recurse: 
                res = x.children._delete(func, recurse)
                if res: result.extend(res)
        for x in remove: self.remove(x)
        return result
    
    def _update(self, tag, values):
        remove = list()
        pos = -1
        for i in xrange(0, len(self)):
            x = self[i] if isinstance(self[i], XML) and self[i].tag == tag else None
            if x is not None:
                if pos < 0: pos = i
                remove.append(x)
        for x in remove: self.remove(x)
        if pos < 0: pos = len(self)
        if isinstance(values, XMLList): self[pos:pos] = values[:]
        elif isinstance(values, XML): self[pos:pos] = [values]
        elif isinstance(values, (str, unicode)): self[pos:pos] = [XML('<%s>%s</%s>'%(tag, values, tag))]
        elif values is None or not values:  pass # do nothing, already deleted
        else: raise ValueError, 'Invalid argument in XMLList._update ' + str(type(values))
    
    # attribute access for elements, and call semantics for accessing or filtering child elements
    def __getattr__(self, name): return self._filter(lambda x: x.tag == name)
    
    def __call__(self, name=None):
        f = (lambda x: x.tag == name or not name) if not callable(name) else name
        return XMLList(sum([[y for y in x.children._filter(f)] for x in self["*"]], []))

    # container access for elements as well as filtering elements
    def __contains__(self, item): # item is either XML, or tag name, or lambda function to test
        if isinstance(item, XML): return list.__contains__(self, item)
        elif isinstance(item, (str, unicode)): return self._filter(lambda x: x.tag == item)
        elif callable(item): return self._filter(item)
        else: return False
    
    def __getitem__(self, key): # key is either int, or "*", or tag name, or lambda function to test
        if isinstance(key, int): return list.__getitem__(self, key)
        elif key == u'*': return self._filter(lambda x: True)
        elif isinstance(key, (str, unicode)): return self._filter(lambda x: x.tag == key)
        elif callable(key): return self._filter(key)
        else: return None
    
    def __setitem__(self, key, value): # key is either int, or tag name.
        if isinstance(key, int): list.__setitem__(self, key, value); result = value
        elif key == u'*': self[:] = value if isinstance(value, XMLList) else [value]; result = self
        elif isinstance(key, (str, unicode)): self._update(key, value); result = value
        return result

    def __delitem__(self, key): # key is same as that in __getitem__ 
        if isinstance(key, int): list.__delitem__(self, key); return None
        elif key == u'*': result, self[:] = self[:], []; return result # make it empty
        elif isinstance(key, (str, unicode)): return self._delete(lambda x: x.tag == key)
        elif callable(key): return self._delete(key)
        else: return None
    
    # mapping related methods similar to container access for elements
    def keys(self): return set([x.tag for x in filter(lambda y: isinstance(y, XML), self)]) # returns a set of all tags
    def values(self): return self[:] # return all the XML and data elements in this list
    def items(self): return [(x.tag, x) if isinstance(x, XML) else ('#text', x) for x in self] # return list of tuples of (tag, XML)
    def has_key(self, key): # return true if the tag exists
        for y in filter(lambda x: isinstance(x, XML), self):
            if y.tag == key: return True
        return False
    def get(self, key, default=None): return self._filter(lambda x: x.tag == key) or default # return the value for the key, or default
    def clear(self): self[:] = [] # clear the list
    def iterkeys(self): return iter(self.keys()) # iterator for keys
    def itervalues(self): return iter(self) # iterator for values
    def iteritems(self): # iterator for items
        for x in self: yield (x.tag if isinstance(x, XML) else '#text', x)
    def copy(self): return XMLList(self[:])
    def update(self, arg): self[:] = arg # update self with the given list of XML
    #not implemented:  setdefault(), pop(), popitem()
        
    @property
    def cdata(self): return u''.join([(x.cdata if isinstance(x, XML) else x) for x in self])
    @property
    def elems(self): return filter(lambda x: isinstance(x, XML), self)

    # arithmetic manipulation or operations
    def __add__(self, other): # XMLList + XML, XMLList + XMLList, XMLList + list, XMLList + object
        if isinstance(other, list): return XMLList(self[:] + other)
        else: return XMLList(self[:] + [other if isinstance(other, XML) else unicode(other)])
    
    def __radd__(self, other): 
        if isinstance(other, list): return XMLList(other + self[:])
        else: return XMLList([other if isinstance(other, XML) else unicode(other)] + self[:])
    
    def __iadd__(self, other): # XMLList += XML, XMLList += XMLList, XMLList += list, XMLList += object
        if isinstance(other, list): self.extend(other)
        else: self.append(other if isinstance(other, XML) else unicode(other))
        return self
    
    def __isub__(self, other): # XMLList -= XML, XMLList -= XMLList, XMLList -= list, XMLList -= object
        if not isinstance(other, list): other = [other]
        self[:] = filter(lambda x: x not in other, self)
        return self
    
    def __ixor__(self, other): # XMLList ^= XML, XMLList ^= XMLList (add only if tag is not found, else don't overwrite)
        if not isinstance(other, list): other = [other]
        self.extend(filter(lambda x: x.tag not in self.keys(), other))
        return self
    
    def __ior__(self, other): # XMLList |= XML, XMLList |= XMLList (overwrite if tag is found else append)
        if not isinstance(other, list): other = [other]
        overwrite = filter(lambda x: x.tag in self.keys(), other)       # that needs to be overwritten
        overtags = map(lambda x: x.tag, overwrite)
        add = filter(lambda x: x.tag not in self.keys(), other)         # that needs to be added
        self[:] = filter(lambda x: x.tag not in overtags, self) # remove these for overwritting
        self.extend(overwrite + add)                             # append the overwritten and added elements
        return self
        
    def __iand__(self, other): # XMLList &= XML, XMLList &= XMLList (overwrite only if tag is found, else don't append)
        if not isinstance(other, list): other = [other]
        overwrite = filter(lambda x: x.tag in self.keys(), other)       # that needs to be overwritten
        overtags = map(lambda x: x.tag, overwrite)
        self[:] = filter(lambda x: x.tag not in overtags, self) # remove these for overwriting
        self.extend(overwrite)                                         # append the overwritten elements
        return self
    
class XML(object):
    '''A single XML element. Can be constructed either using raw string or individual fields.'''
    def __init__(self, value=None, tag='element', xmlns='', attrs={}, children=None, parent=None):
        if value and value[0] == '<': p = parser(value, self); return
        self.tag, self.xmlns, self.attrs, self.children, self.parent = tag, xmlns, attrs.copy() if attrs else {}, children if isinstance(children, XMLList) else XMLList(children) if children else XMLList(), parent
        if self.parent and not self.xmlns: self.xmlns = self.parent.xmlns
        if isinstance(self.children, (str, unicode)): self.children = [self.children]

    def __repr__(self):
        ns = [u'xmlns="%s"'%(self.xmlns,)] if self.xmlns and (not self.parent or self.xmlns != self.parent.xmlns) else []
        attrs = [u'%s="%s"'%(k, escape(ustr(v))) for k,v in self.attrs.iteritems()]
        intag = u' '.join([self.tag] + ns + attrs)
        inner = u''.join([unicode(x) if isinstance(x, XML) else escape(x) for x in self.children])
        return u'<%s>%s</%s>'%(intag, inner, self.tag) if inner else u'<%s />'%(intag)
    
    def toprettyxml(self, encoding='UTF-8', indent='  ', count=0): # similar but not same as xml.dom.minidom's toprettyxml
        ns = [u'xmlns="%s"'%(self.xmlns,)] if self.xmlns and (not self.parent or self.xmlns != self.parent.xmlns) else []
        attrs = [u'%s="%s"'%(k, escape(ustr(v))) for k,v in self.attrs.iteritems()]
        intag = u' '.join([self.tag] + ns + attrs)
        inner = (u'\n' + indent*(count+1)).join([x.toprettyxml(encoding=None, indent=indent, count=count+1) if isinstance(x, XML) else escape(x.strip()) for x in self.children if not isinstance(x, basestring) or x.strip()])
        return ('' if encoding is None else u'<?xml version="1.0"?>\n' if not encoding else u'<?xml version="1.0" encoding="%s"?>\n'%(encoding,)) + \
            (u'<%s>\n'%(intag,) + indent*(count+1) + inner + '\n' + indent*count + u'</%s>'%(self.tag,) if len(self.elems) \
             else (u'<%s>%s</%s>'%(intag, inner, self.tag) if inner else u'<%s />'%(intag,)))
        
    def __cmp__(self, other): return cmp(unicode(self), unicode(other))
    
    # XML attributes can be accessed using Python container semantics. Doesn't throw exception.
    def __getitem__(self, item): return self.attrs.get(item, None)
    def __setitem__(self, item, value): self.attrs[item] = value
    def __delitem__(self, item): del self.attrs[item]
    def __contains__(self, item): return item in self.attrs
    
    def __call__(self, name=None): return self.children[name if name else "*"]
    
    def __getattr__(self, name): # if Python attribute not found, then check XML attribute. Never throws exception for attribute error
        if name == '_':
            if name not in self.__dict__: self.__dict__[name] = _(self)
            return self.__dict__[name]
        elif name in self.__dict__['attrs']:
            return self.__dict__['attrs'].get(name)
        raise AttributeError, 'Invalid attribute access ' + name
    
    def clear(self): self.children.clear(); self.attrs.clear() # clear all children and attributes
    def copy(self): return XML(str(self)) # copy into another XML
    @property
    def cdata(self): return self.children.cdata
    @property
    def elems(self): return self.children.elems
    
class _(object):
    '''Allows accessing XML attributes by name using Python attribute semantics.'''
    def __init__(self, node): self.__dict__['_node'] = node
    def __getattr__(self, name): return self._node.attrs.get(name, None)
    def __setattr__(self, name, value): self._node.attrs[name] = value
    def __delattr__(self, name): del self._node.attrs[name]
    def __contains__(self, name): return name in self._node.attrs
    def __setitem__(self, name, value): self._node.attrs[name] = value
    def __getitem__(self, name): return self._node.attrs.get(name, None)
    def __delitem__(self, name): del self._node.attrs[name]
    def __call__(self, name): return self._node.attrs.get(name, None)

# unit testing of this module    
if __name__ == '__main__':
    import doctest
    doctest.testmod()
