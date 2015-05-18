# Using External Media Tools #

This page describes how you can use external media tools such as RAT and vic with SIP user agent of voip.py to write your own user agent.

## How are SIP and SDP connected? ##

In app/voip.py there is a User class with connect(..., sdp) and accept(..., sdp) methods. There is also a MediaSession class which has mysdp property and a setRemote(sdp) method. In rfc4566.py there is a SDP class which is used as sdp in above methods and properties. The MediaSession has mysdp (local party's SDP) and yoursdp (remote party's SDP) properties which can be assigned in any order depending on whether the call is incoming or outgoing. For example, for incoming call, you assign mysdp first, and when you received SIP successful response, you assign yoursdp using setRemote() method. For incoming call, you assign yoursdp based on the incoming SIP call invitation, and then ask for mysdp to send in the successful SIP response body. The voip.py module separates the SIP session from the media session. Some example of how SDP and MediaSession is used is shown in rtmp\_invite, rtmp\_accept and _incominghandler functions of:
http://code.google.com/p/rtmplite/source/browse/trunk/siprtmp.py_

## How can I use it for external tools? ##

Since the MediaSession class has a built-in RTP session, you should not use that when using RAT/vic, but instead create another class ExternalMediaSession which encapsulates the external tool process, mysdp and yoursdp properties. You can create the class which supports similar semantics of offer/answer of SDP as MediaSession and launch the external tool using Python's os.system or spawn functions. Let us looks at the core logic in more details:

On the caller side: first create any user object and do any registration if needed. You can see the example code fragments in voip.py or siprtmp.py modules.
```
user = User(...).start()
```
Then create your media session for the external tools, and any transport address, e.g., 224.2.3.4:2002.
```
media = ExternalMediaSession(apps=..., transport=...)
```
The media session should populate the local party's SDP which gets assigned to SIP outgoing session as follows. (dest is some destination SIP URI string)
```
session, reason = yield user.connect(dest=..., sdp=media.mysdp)
```
Once the SIP session is connected, you assign the remote party's SDP to your media session.
```
if session:
  media.setRemote(session.yoursdp)
```

On the receiving side, you will create a User object and do any registration as needed.
```
user = User.start()
```
Then you will wait for incoming events on the user object.
```
cmd, arg = yield user.recv()
```
The incoming call event is called "connect". when an incoming call is received you first create your media session, assign the remote party's SDP and then get the local party's SDP to set to the SIP session.
```
if cmd == 'connect':
  media = ExternalMediaSession(app=...)    
  media.setRemote(arg[1].request.body)
  if media.mysdp is None: 
    reason = '488 Incompatible Media'
  else:
    session, reason = yield user.accept(arg, sdp=media.mysdp)
    if session: # connected
       ...
```

You will need to implement the ExternalMediaSession class which creates mysdp and yoursdp and relates it local transport address and/or to offer/answer SDP from SIP session.