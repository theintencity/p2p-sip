#!/usr/bin/env python
from __future__ import with_statement
import wx, time, random, sys, os
from math import degrees, radians, atan2, sin, cos, sqrt, pow

if __name__ == '__main__': # hack to add other libraries in the sys.path
    f = os.path.dirname(sys.path.pop(0))
    sys.path += [f, os.path.join(f, 'external'), os.path.join(f, 'app')]

import dht, p2p, dummycrypto as crypto
from std.rfc2396 import isMulticast, isIPv4

'''
A graphical display of the DHT logs for ring-based DHT algorithms. The module follows
the model-view-controller design pattern, where the Model and View classes are
defined in this module whereas the application should define a controller if needed
to act on the user input. 
'''

#===============================================================================
# general information about the software
#===============================================================================
_debug = False # change this to false for released code
_trace = False

p2p.BOOTSTRAP = None


import linecache

def traceit(frame, event, arg):
    if event == "line":
        lineno = frame.f_lineno
        filename = frame.f_globals["__file__"]
        if lineno>890 and filename.find('dht.py')>=0:
            if (filename.endswith(".pyc") or
                filename.endswith(".pyo")):
                filename = filename[:-1]
            name = frame.f_globals["__name__"]
            line = linecache.getline(filename, lineno)
            print "%s:%s: %s" % (name, lineno, line.rstrip())
    return traceit

#===============================================================================
# Main application for the user interface
#===============================================================================
class Model(object):
    '''The data model for the DHT based on the received log or constructed by simulator.
    It consists of list of nodes, and list of messages for the flow.'''
    index = 0
    
    def __init__(self, modulo=2**160, nodeExpiry=60, msgExpiry=2):
        '''Construct a new data model by specifying the modulo of the DHT number space,
        the expiration of how long the node and message be displayed after an activity.'''
        self.nodes = {}
        self.msgs  = []
        self.selected = None  # selected node which is highlighted
        self.modulo, self.nodeExpiry, self.msgExpiry = modulo, nodeExpiry, msgExpiry
        
    def addNode(self, guid, s=None, now=None):
        now = now or time.time()
        if guid not in self.nodes: 
            Model.index = Model.index + 1
            class Node: pass
            node = Node(); node.guid, node.angle, node.index, node.s, node.removed = guid, (360+90-guid*360/self.modulo)%360, Model.index, s, False 
            self.nodes[guid] = node
        node = self.nodes[guid]; node.expires = now + self.nodeExpiry
        return node
    
    def removeNode(self, node):
        self.selected = None
        node.removed = True
        node.s.stop() # stops the network and other modules of the DHT node
        
    def sendMessage(self, src, dst, msg, now=None):
        '''A message is sent from src (guid) to dst (guid).'''
        now = now or time.time()
        src = self.addNode(src, now=now); dst = self.addNode(dst, now=now)
        class Message: pass
        m = Message(); m.src, m.dst, m.msg, m.expires = src, dst, msg, now + self.msgExpiry
        self.msgs.append(m)
        
    def refresh(self):
        '''Remove any expired entries from nodes and msgs.'''
        now = time.time()
        for id in filter(lambda x: self.nodes[x].expires<now, self.nodes):
            if _debug: print 'removing expired node %r'%(self.nodes[id])
            del self.nodes[id] 
        self.msgs[:] = filter(lambda x: x.expires>=now, self.msgs) # filter away expired ones
        
class View(wx.Panel):
    '''Implementation of the view using a Panel that displays the ring-based DHT.'''
    def __init__(self, parent=None, size=(500, 600), model=None, control=None):
        wx.Panel.__init__(self, parent, size=size)
        wx.EVT_PAINT(self, self.OnPaint)
        wx.EVT_LEFT_DOWN(self, self.OnMouseDown)
        wx.EVT_SIZE(self, self.OnSize)
        self.model = model
        self.control = control
        self.brush = dict(glass=wx.Brush('white', style=wx.TRANSPARENT), blue=wx.Brush('#d0d0ff', style=wx.SOLID), grey=wx.Brush('#d0d0d0', style=wx.SOLID), red=wx.Brush('#ff0000', style=wx.SOLID), green=wx.Brush('#008000', style=wx.SOLID))
        self.pen   = dict(glass=wx.Pen('white', width=0, style=wx.TRANSPARENT), black=wx.Pen('black', 1, style=wx.SOLID), grey=wx.Pen('#d0d0d0', width=1, style=wx.SOLID), blue=wx.Pen('#d0d0ff', width=1, style=wx.SOLID), red=wx.Pen('red', width=2, style=wx.DOT), green=wx.Pen('#008000', width=2, style=wx.SOLID))

        self.key = wx.TextCtrl(self, pos=wx.Point(20, size[1]-60), size=wx.Size(70, 20), value='Key')
        self.value = wx.TextCtrl(self, pos=wx.Point(100, size[1]-60), size=wx.Size(70, 20), value='Value')
        self.put = wx.Button(self, pos=wx.Point(180, size[1]-60), size=wx.Size(40, 20), label='put')
        self.get = wx.Button(self, pos=wx.Point(230, size[1]-60), size=wx.Size(40, 20), label='get')
        self.remove = wx.Button(self, pos=wx.Point(280, size[1]-60), size=wx.Size(40, 20), label='rm')
        self.user = wx.TextCtrl(self, pos=wx.Point(20, size[1]-30), size=wx.Size(130, 20), value='node1@39peers.net')
        self.bind = wx.Button(self, pos=wx.Point(160, size[1]-30), size=wx.Size(80, 20), label='bind')
        self.conn = wx.Button(self, pos=wx.Point(250, size[1]-30), size=wx.Size(80, 20), label='connect')
        self.sendto = wx.Button(self, pos=wx.Point(340, size[1]-30), size=wx.Size(80, 20), label='sendto')
        self.put.Bind(wx.EVT_BUTTON, self.onUserButton)
        self.get.Bind(wx.EVT_BUTTON, self.onUserButton)
        self.remove.Bind(wx.EVT_BUTTON, self.onUserButton)
        self.bind.Bind(wx.EVT_BUTTON, self.onUserButton)
        self.conn.Bind(wx.EVT_BUTTON, self.onUserButton)
        self.sendto.Bind(wx.EVT_BUTTON, self.onUserButton)

    def onUserButton(self, event):
        global sock2, pending
        try:
            cmd = event.GetEventObject().GetLabel()
            node = self.model.selected
            now = time.time()
            if cmd == 'put':
                print 'put ' + self.key.GetValue() + ', ' + self.value.GetValue()
                pending.append((node.s.put, dict(guid=p2p.H(self.key.GetValue()), value=self.value.GetValue(), nonce=p2p.H(self.key.GetValue()), expires=now+60)))
            elif cmd == 'get':
                print 'get ' + self.key.GetValue()
                pending.append((node.s.get, dict(guid=p2p.H(self.key.GetValue()))))
            elif cmd == 'rm':
                print 'rm ' + self.key.GetValue() + ', ' + self.value.GetValue()
                pending.append((node.s.remove, dict(guid=p2p.H(self.key.GetValue()), value=self.value.GetValue(), nonce=p2p.H(self.key.GetValue()), expires=now+60)))
            elif cmd == 'bind':
                print 'bind ' + self.user.GetValue()
                import multitask
                def nodebind(sock, identity):
                    yield sock.bind(identity=identity)
                    def sockaccept(sock):
                        sock2 = yield sock.accept()
                        print 'accept sock=%r'%(sock2)
                    def sockrecv(sock):
                        remote, data = yield sock.recvfrom()
                        print 'recvfrom remote=%r, data=%r'%(remote, data)
                    multitask.add(sockaccept(sock))
                    multitask.add(sockrecv(sock))
                pending.append((nodebind, dict(sock=node.s, identity=self.user.GetValue())))
                #pending.append((node.s.bind, dict(identity=self.user.GetValue())))
            elif cmd == 'connect':
                print 'connect ' + self.user.GetValue()
                pending.append((node.s.connect, dict(identity=self.user.GetValue())))
            elif cmd == 'sendto':
                print 'sendto ' + self.user.GetValue() + ' ' + self.value.GetValue()
                pending.append((node.s.sendto, dict(identity=self.user.GetValue(), data=self.value.GetValue())))
            sock2.send('1') # signal the multitask thread to add a new node.
        except: print 'exception in onUserButton'
        
    def OnPaint(self, event):
        width, height = self.GetClientSizeTuple()
        buffer = wx.EmptyBitmap(width, height)
        dc = wx.BufferedPaintDC(self, buffer)
        dc.SetBackground(self.brush['glass'])
        dc.Clear()
        dc.SetBrush(self.brush['glass'])
        dc.SetPen(self.pen['blue'])
        radius = min(width, height) / 2
        dc.DrawCircle(radius, radius, radius - 20)
        
        if self.model is None: return # empty model, no need to draw any nodes.
        self.model.refresh()      # clean up expired ones
        
        # first display the message flow so that they don't appear above the nodes.
        for msg in self.model.msgs:
            a1, a2 = msg.src.angle, msg.dst.angle
            x1, y1 = radius + (radius-20)*cos(radians(a1)), radius + (radius-20)*sin(radians(a1))
            x2, y2 = radius + (radius-20)*cos(radians(a2)), radius + (radius-20)*sin(radians(a2))
            l = sqrt((x2-x1)**2 + (y2-y1)**2)  # length of the line
            if l>=20: # can't draw less than 20.
                x3, y3 = x2-20*(x2-x1)/l, y2-20*(y2-y1)/l # a point at distance 20 from (x2,y2)
                dc.SetPen(self.pen['grey'])
                dc.DrawLine(x1, y1, x3, y3)
                dc.SetPen(self.pen['black'])
                dc.DrawLine(x3, y3, x2, y2)
            
        # now display the nodes
        dc.SetMapMode(wx.MM_TEXT)
        # dc.SetFont(wx.Font(10, wx.MODERN, wx.NORMAL, wx.NORMAL))
        index = 1
        dc.SetPen(self.pen['glass'])
        for node in filter(lambda x: not x.removed, self.model.nodes.values()):
            angle = node.angle
            x, y = radius + (radius-20)*cos(radians(angle)), radius + (radius-20)*sin(radians(angle)) 
            server = hasattr(node, 's') and node.s is not None and node.s.router is not None
            dc.SetBrush(self.brush[server and 'blue' or 'grey'])
            dc.DrawCircle(x, y, 10)
            text = '%d'%(node.index)
            w, h = dc.GetTextExtent(text)
            dc.DrawText(text, x-w/2, y-h/2)
            
        # finally highlight the selected node and its leaf and table nodes, if any
        if self.model.selected is not None:
            dc.SetBrush(self.brush['glass'])
            dc.SetPen(self.pen['red'])
            node = self.model.selected; angle = node.angle 
            x, y = radius + (radius-20)*cos(radians(angle)), radius + (radius-20)*sin(radians(angle))
            dc.DrawCircle(x, y, 12)

            # draw the delete button
            x, y = radius + (radius-50)*cos(radians(angle)), radius + (radius-50)*sin(radians(angle))
            dc.SetBrush(self.brush['red'])
            dc.SetPen(self.pen['black'])
            dc.DrawCircle(x, y, 10)
            delta = 10.0/1.414
            dc.DrawLine(x-delta, y-delta, x+delta, y+delta)
            dc.DrawLine(x-delta, y+delta, x+delta, y-delta)
            
            # draw leaf set
            ls = hasattr(node, 's') and node.s is not None and node.s.router is not None and node.s.router.ls.list or []
            ls = map(lambda z: (z.index, z.angle), filter(lambda y: y is not None, map(lambda x: self.model.nodes.get(x.guid, None), ls)))
            dc.SetBrush(self.brush['glass'])
            dc.SetPen(self.pen['green'])
            for index, angle in ls:
                x, y = radius + (radius-20)*cos(radians(angle)), radius + (radius-20)*sin(radians(angle))
                dc.DrawCircle(x, y, 12)
            dc.DrawText('Node: ' + str(node.index) + ', LS:' + ','.join(map(lambda x: str(x[0]), ls)), 20, height-80)
            map(lambda x: x.Show(True), [self.key, self.value, self.put, self.get, self.remove, self.user, self.bind, self.conn, self.sendto])
        else:
            map(lambda x: x.Show(False), [self.key, self.value, self.put, self.get, self.remove, self.user, self.bind, self.conn, self.sendto])
            dc.SetBrush(self.brush['glass'])
            dc.SetPen(self.pen['blue'])
            dc.DrawText('Click near the center of the ring to create a new random DHT node.', 20, height-80)
            dc.DrawText('Create nodes slowly in the beginning and more frequently later.', 20, height-60)
            dc.DrawText('Click on a node to view leaf-set. Click on red to remove the node.', 20, height-40)
            
        # The buffer gets copied to the screen when the dc goes out of scope.
        
    def OnMouseDown(self, event):
        if self.control:
            point = event.GetPosition()
            width, height = self.GetClientSizeTuple()
            radius = min(width, height) / 2
            distance = sqrt(pow(point.y-radius, 2) + pow(point.x-radius, 2))
            #if distance < (radius-40) or distance > radius: 
            #    return
            angle = (360 + 90 - degrees(atan2(point.y-radius, point.x-radius))) % 360
            guid = ((2**160)/360) * long(angle)
            self.control.onClicked(guid, abs(distance - (radius-20)))

    def OnSize(self, event):
        self.Refresh()
        
#===============================================================================
# Main routine when this script is invoked as standalone script
#===============================================================================

class ControllerStub(object):
    '''A controller stub for generating random messages and adding nodes on mouse click.'''
    def __init__(self, model=None, view=None):
        self.model = model
        self.view = view
        self.guids = []
        self.timer = wx.Timer()
        self.timer.Bind(wx.EVT_TIMER, self.onTimer)
        self.timer.Start(2000)
        
    def onClicked(self, guid, distance=None):
        if distance<=20: # create only if clicked near the ring.
            if self.model:
                node = self.model.addNode(guid)
                if guid not in self.guids: 
                    self.guids.append(guid)
            if self.view: self.view.Refresh()
        
    def onTimer(self, event):
        if self.model and len(self.guids)>=2:
            src, dst = random.sample(self.guids, 2)
            self.model.sendMessage(src, dst, 'Something')
        if self.view: self.view.Refresh()

def testDisplay(frame):
    '''Just test the display routines using a ControllerStub.'''
    model = Model()
    control = ControllerStub(model)
    frame.panel = View(frame, model=model, control=control)
    control.view = frame.panel;

# a pair of connected sockets is used to signal multitask for a new event.
# TODO: can we use socket.socketpair
import socket
sock1, sock2 = socket.socket(type=socket.SOCK_DGRAM), socket.socket(type=socket.SOCK_DGRAM)
sock1.bind(('127.0.0.1', 0))
sock2.connect(('127.0.0.1', sock1.getsockname()[1]))
pending = []
active = []

class NetworkStub(p2p.Network):
    def __init__(self, Ks=None, cert=None, model=None, view=None):
        p2p.Network.__init__(self, Ks=Ks, cert=cert)
        self.model, self.view = model, view
        
    def send(self, msg, node, timeout=None):
        model, src, dst = self.model, self.node.guid, node.guid
        toSend = True
        if model is not None:
            if src in model.nodes and dst in model.nodes: 
                s, d = model.nodes[src], model.nodes[dst]
                sin, din = s.index, d.index
                if s.removed: 
                    toSend = False
                    if _debug: print 'Not sending', msg, ' because source is removed'
                elif msg.name not in ('Hash:Request', 'Hash:Response', 'Ack:Indication'):
                    if _debug: print '%d=>%s \t%s'%(sin, str(din) if not isMulticast(node.ip) else 'M', msg.name) 
            if toSend:  
                model.sendMessage(src, dst, msg.name)
        # if self.view is not None: self.view.Refresh() # TODO: use a timer instead, otherwise it flickers
        if toSend:
            return p2p.Network.send(self, msg, node, timeout=timeout)
        else:
            raise StopIteration, True
        
class ControllerDHT(object):
    def __init__(self, model=None, view=None):
        self.model, self.view = model, view
        self.timer = wx.Timer()
        self.timer.Bind(wx.EVT_TIMER, self.onTimer)
        self.timer.Start(1000)
        
    def onClicked(self, guid, distance=None):
        global pending, active
        if distance>40: # clicked far from the ring.
            if self.model:
                s = p2p.ServerSocket(Model.index==0)
                pending.append(s)
                sock2.send('1') # signal the multitask thread to add a new node.
            if self.view: self.view.Refresh() 
        else: # clicked near the ring.
            comp = lambda x, y: cmp(abs(x-guid), abs(y-guid))
            nodes = [self.model.nodes[x] for x in sorted(self.model.nodes.keys(), comp)]
            if nodes: 
                if _debug: print 'clicked near', nodes[0].index
                if nodes[0] == self.model.selected: # already selected, check if needs to be deleted?
                    if distance > 20:
                        if _debug: print 'removing node', nodes[0].index
                        try: active.remove(nodes[0].s)
                        except: print 'Error in removing from active nodes'
                        self.model.removeNode(nodes[0])
                else:
                    self.model.selected = nodes[0]
                if self.model.selected is not None:
                    for s in active:
                        if s.net.node.guid == nodes[0].guid:
                            r = s.router
                            if _debug: print 'Node%d'%(nodes[0].index)
                            if r is not None:
                                ns = self.model.nodes
                                if _debug: print '%r'%(r.ls)
                                if _debug: print ' LeafSet=', ','.join(map(lambda x: '%d'%(ns[x.guid].index), r.ls.sorted))
                                if _debug: print ' Table=', ','.join(map(lambda x: '%d'%(ns[x.guid].index), r.rt.list))
                if self.view: self.view.Refresh()
                
    def onTimer(self, event): # refresh the view
        if self.view: self.view.Refresh()
        
def testDHT(frame):
    model = Model()
    control = ControllerDHT(model)
    frame.panel = View(frame, model=model, control=control)
    control.view = frame.panel

    # start the multitask as a separate thread.
    import thread, traceback, multitask
    def threadproc(arg):
        global sock1, pending, active
        def execute(s):
            if isinstance(s, p2p.ServerSocket):
                n = NetworkStub(Ks=crypto.generateRSA()[0], cert=None, model=model, view=control.view)
                s.start(net=n)
                node = model.addNode(s.net.node.guid, s)
                s.net.node.index = node.index # so that dht.Node has the index.
                active.append(s)
            else:
                if _debug: print s[0], s[1]
                result = yield s[0](**s[1])
                if not isinstance(result, list):
                    print result
                else:
                    if _debug: print result
                    values = map(lambda x: x[0], result)
                    print '\n'.join(values) if values else 'None'
        def waitonsock(sock):
            global pending
            try:
                while True: 
                    yield multitask.recvfrom(sock, 10)
                    for s in pending:
                        multitask.add(execute(s))
                    pending[:] = []
            except StopIteration:
                raise
            except:
                print 'waitonsock', sys.exc_info(), traceback.print_exc()
        multitask.add(waitonsock(sock1)) # this will trigger multitask out of wait loop
         
        if _debug: print 'starting multitask.run()'
        if _trace: sys.settrace(traceit)
        try: multitask.run()
        except KeyboardInterrupt: interrupt_main()
        except: 
            if _debug: print 'exception in multitask.run()'; traceback.print_exc()
    thread.start_new_thread(threadproc, (None,))
    


if __name__ == '__main__':
    if sys.argv[-1] == '-d':
        _debug = dht._debug = p2p._debug = True
        #_trace = True
        
    app = wx.PySimpleApp()
    frame = wx.Frame(parent=None, id=wx.ID_ANY, title='DHT display')
    #testDisplay(frame)
    testDHT(frame)
    frame.Fit()
    frame.Show(True)
    app.MainLoop()
    sys.exit()
    