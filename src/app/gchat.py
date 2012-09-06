'''
An example program that uses the XMPP modules (rfc3920 and rfc3921) to connect to
Google Chat and send messages.
'''
import sys, getpass, select
try: import readline
except: readline = None

import multitask
from std import rfc3920, rfc3921

def recv(h):
    while True:
        msg = yield h.recv()
        if msg.frm and msg.body:
            # msg.frm.partition('/')[0]
            print '< %s'%(msg.body.cdata,)
            if readline:
                readline.redisplay()

def send(h, u):
    while True:
        print '> ',
        sys.stdout.flush()
        input = yield multitask.read(sys.stdin.fileno(), 4096)
        if input == None or input.strip() == "exit":
            break
        yield h.send(rfc3921.Message(body=input.strip()))
    yield u.logout()
    sys.exit(0)
    

def main(username, password, targetname):
    user = rfc3921.User(server='gmail.com', username=username, password=password)
    result, error = yield user.login()
    
    yield multitask.sleep(1)
    user.roster.presence = rfc3921.Presence(show=None, status='Online')

    history = user.chat(targetname + '@gmail.com')

    multitask.add(recv(history))
    multitask.add(send(history, user))

if __name__ == '__main__':
    rfc3920._debug = rfc3921._debug = False
    if len(sys.argv) != 3:
        print 'usage: %s your-gmail-id target-gmail-id'%(sys.argv[0],)
        sys.exit(-1)
    
    username, targetname = sys.argv[1:3]
    password = getpass.getpass()

    multitask.add(main(username, password, targetname))
    try: multitask.run()
    except KeyboardInterrupt: pass
    except select.error: print 'select error'; pass
