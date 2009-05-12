# This module contains windows specific utilities

import string
import _winreg

#------------------------------------------------------------------------------
# Python Cookbook: 
# http://my.safaribooksonline.com/0596001673/pythoncook-CHP-7-SECT-10
# Modified to accommodate DhcpNameServer for XP/Vista
#------------------------------------------------------------------------------

def binipdisplay(s):
    "convert a binary array of ip addresses to a python list"
    if len(s)%4!= 0:
        raise EnvironmentError # well ...
    ol=[]
    for i in range(len(s)/4):
        s1=s[:4]
        s=s[4:]
        ip=[]
        for j in s1:
            ip.append(str(ord(j)))
        ol.append(string.join(ip,'.'))
    return ol

def stringdisplay(s):
    'convert "d.d.d.d,d.d.d.d" to ["d.d.d.d","d.d.d.d"]'
    return string.split(s,",")

def RegistryResolve():
    """ Return the list of dotted-quads addresses of name servers found in
    the registry -- tested on NT4 Server SP6a, Win/2000 Pro SP2, XP, ME
    (each of which has a different registry layout for nameservers!) """

    nameservers=[]
    x=_winreg.ConnectRegistry(None,_winreg.HKEY_LOCAL_MACHINE)
    try:
        y= _winreg.OpenKey(x,
         r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters")
    except EnvironmentError: # so it isn't NT/2000/XP
        # Windows ME, perhaps?
        try: # for Windows ME
            y = _winreg.OpenKey(x,
              r"SYSTEM\CurrentControlSet\Services\VxD\MSTCP")
            nameserver, dummytype = _winreg.QueryValueEx(y,'NameServer')
            if nameserver and not (nameserver in nameservers):
                nameservers.extend(stringdisplay(nameserver))
        except EnvironmentError:
            pass # Must be another Windows dialect, so who knows?
        return nameservers

    nameserver = _winreg.QueryValueEx(y,"NameServer")[0]
    if nameserver:
        nameservers = [nameserver]
    _winreg.CloseKey(y)
    try: # for win2000
        y = _winreg.OpenKey(x, r"SYSTEM\CurrentControlSet\Services\Tcpip"
                               r"\Parameters\DNSRegisteredAdapters")
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y,i)
                z = _winreg.OpenKey(y,n)
                dnscount,dnscounttype = _winreg.QueryValueEx(z,
                    'DNSServerAddressCount')
                dnsvalues,dnsvaluestype = _winreg.QueryValueEx(z,
                    'DNSServerAddresses')
                nameservers.extend(binipdisplay(dnsvalues))
                _winreg.CloseKey(z)
            except EnvironmentError:
                break
        _winreg.CloseKey(y)
    except EnvironmentError:
        pass

    try: # for XP
        y = _winreg.OpenKey(x,
         r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces")
        for i in range(1000):
            try:
                n = _winreg.EnumKey(y,i)
                z = _winreg.OpenKey(y,n)
                try:
                    nameserver,dummytype = _winreg.QueryValueEx(z,'NameServer')
                    if nameserver and not (nameserver in nameservers):
                        nameservers.extend(stringdisplay(nameserver))
                    if not nameserver: # try DhcpNameServer
                        nameserver,dummytype = _winreg.QueryValueEx(z,'DhcpNameServer')
                        if nameserver and not (nameserver in nameservers):
                            nameservers.extend(stringdisplay(nameserver))
                except EnvironmentError:
                    pass
                _winreg.CloseKey(z)
            except EnvironmentError:
                break
        _winreg.CloseKey(y)
    except EnvironmentError:
        # Print "Key Interfaces not found, just do nothing"
        pass

    _winreg.CloseKey(x)
    return nameservers

if __name__=="__main__":
    print "Name servers:",RegistryResolve()
