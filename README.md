# Open source peer-to-peer Internet telephony (P2P-SIP) software in Python #

> This project was migrated from <https://code.google.com/p/p2p-sip> on May 17, 2015  
> Keywords: *SIP*, *P2P*, *Python*, *p2psip*, *DHT*, *implementation*  
> Members: *kundan10* (owner, copyright holder), *theintencity* (owner, copyright holder), *rami.halloush*, *luke.weber*, *voipresearcher*, *juanantonio.ram*  
> Links: [Blog](http://p2p-sip.blogspot.com/), [39 peers](http://39peers.net/), [Implementing SIP telephony in Python](http://39peers.net/download/doc/report.pdf), [Student Projects](http://myprojectguide.org/), [Support](http://groups.google.com/group/myprojectguide)  
> License: [GNU GPL v3](http://www.gnu.org/licenses/gpl.html)  
> Others: starred by 36 users  

This project aims at implementing an open-source peer-to-peer Internet telephony software using the Session Initiation Protocol (P2P-SIP) in the Python programming language.

**New:** project description has been moved from the 39peers.net website to this page

Peer-to-peer systems inherently have high scalability, fault tolerance and robustness against catastrophic failures because there is no central server and the network self-organizes itself. Internet telephony can be an application of peer-to-peer architecture where the participants locate and communicate with each other without relying on expensive or managed service providers. This project is an attempt to provide an open source peer-to-peer software based on open standards.

This project is developed for student developers and researchers to experiment with new ideas. It is written in Python programming language. It supports open protocols such as IETF SIP and RTP. It is licensed under GNU/GPL license (an alternate commercial license is available as well). This project does not use the recommendation developed by the IETF P2P-SIP working group. I am looking for student volunteers to contribute in that regard.

## Quick Start ##

Please use the git clone to get the sources. Alternatively, you can download the latest tar/gzip archive from the [download](/downloads) page. Or you can browse the source code with documentation extracted from the corresponding specifications online here. The annotated source code for web view is generated using the included tool `htmlify.py`.

The downloaded archive will create the `p2p-sip/` directory containing the source code in Python. The sub-directory `src/` contains the source code packages `app`, `std`, `tools` and `external`.

The `std` package contains implementation of various IETF RFCs and Internet-drafts such as RFC 3261, RFC 3550, RFC 2617, etc. The `app` package contains the applications such as SIP client (`voip.py`), DHT using Bamboo (`dht.py`), etc. Some of the other modules are not yet completed.

You will need Python 2.5 or higher (but not Python 3.x) to run the software. Set your python path and test a couple of modules such as `voip` and `dhtgui` before modifying the source code for your needs.

You need to set the `PYTHONPATH` environment variable before testing these modules. For example, you can do the following to test the `voip` module. It performs certain SIP registration, call and instant message test with the `iptel.org` server.
```
bash$ tar -zxvf source-*.tgz
bash$ cd p2p-sip/src  
bash$ export PYTHONPATH=.:external:std:app 
bash$ python app/voip.py 
```

Each module comes with a simple test case to test that module. I will upload more example applications built using these basic modules as demanded. The following command launches a test user interface for the P2P module. It depends on `wxPython` for user interface functions.
```
bash$ python app/dhtgui.py
```
This launches a user interface with a DHT circle. You can click near the center of the circle to add a new node.

Alternatively, to launch the P2P-SIP node, use the `p2psip.py` module as follows. The first node should be launched with `-s` option to become a super-node, and all subsequent ones should be launched without `-s` to join this P2P network. The first node listens on SIP port 5062. If you use `-d` option then you can also see the P2P messages exchanged between these nodes. If you wish to run the P2P network across multiple IP networks, you will need to re-configure the boot-strap node because the multicast discovery typically works only within the same IP network.
```
bash$ python app/p2psip.py -s   # first node as boot strap server
bash$ python app/p2psip.py       # subsequent nodes on other terminals/machines 
```

If you wish to **test P2P-SIP using X-lite** please use the following X-lite v3 configuration. In preferences/options under "Account" tab, select "Domain proxy" and set the proxy address to be the boot strap server on port 5062, or one of the other server with correct port, e.g., `127.0.0.1:5062`. In "Voicemail" tab, uncheck everything to avoid sending unnecessary voicemail related messages to P2P-SIP nodes. In "Topology" tab, under "Firewall traversal", the "IP address" is set to "Use local IP address". "STUN server" is set to "Use specified server" and the address is left blank. Uncheck all other boxes and set "Use Xtunnels" to never. In "Presence" tab, the "Mode" is peer-to-peer. All other values are left as default. In "Advanced" tab, make sure to uncheck the "send SIP keep alive messages". In fact, the only checked box is the "use rport". All other values are left as default.

Beyond these examples, feel free to explore the source code and learn more about various modules.

## Contributing ##

If you have patch for a bug-fix or a feature, feel free to send me the patch to the [support group](https://groups.google.com/group/myprojectguide). If you plan to do significant contributions, please let me know and I will add you as a project member so that you can check in files using SVN. Please join the [support group](http://groups.google.com/group/myprojectguide) if you want to contribute or hear about the project announcements.

If you are a project student and would like to do a project in SIP, P2P or P2P-SIP, you are welcome to use this software. I will be happy to assist you in mentoring your project in my free time. One of the main objective of the project is to help the student developers understand the existing protocols for peer-to-peer and real-time communication. Thus we encourage developers to take a look at the source code and how it reflects the specifications of various protocols. The Python programming language allows us to write compact and concise software in a way that provides pseudo-code to validate the specifications. You can browse the source code with embedded comments from corresponding specifications later on this page.

All individual contributors who would like to add a feature, fix a bug or modify the source code in any way, are welcome! Please follow the programming style and send your modified source code to us, and we will add it after review. All submitted code must be released under GNU/GPL, but the original author retains the Copyright.

**Notice:** The past and current owner of this project is [Kundan Singh](http://kundansingh.com). The owners of the project reserve all the rights to source code. All the contributors and committers automatically and implicitly assign all the rights to the owners by contributing to this project. The rights assignment implies that the owners reserve all the rights to publish or distribute the sources or binaries elsewhere under another license for commercial or non-commercial use. Irrespective of the rights, this project will continue to remain open source.

## Programming guidelines ##

Please follow these high-level guidelines:

  1. Compact and concise style - we believe that Python is one of the best programming language that allows us to write clean and concise software unlike verbosity of other languages such as Java. In particular, if something can be done cleanly in ten lines, please do not write fifty lines for interfaces, getter and setters or solving the world problem!
  1. Extensive documentation - we believe documentation with examples is the best way to use a new API or software. Python doctest is one way to write examples and documentation for smaller routines. Python docstring and code comments should be used extensively in the source code.
  1. Reuse code and documentation - unless it hurts first point above, the existing code and documentation should be reused as much as possible. In particular, most standard protocols are documented in various IETF RFCs, and should be reused with reference. This may need you to modify the source code API to fit the specification. Please use the `htmlify.py` tool available in this software to beautify and decorate your RFC implementation.

Beyond these, you can use your own style and discretion to design your software.

## Browse Source Code ##

There are two parts in the software -- the standards and applications. The standards as specified in certain RFCs and Internet-drafts are implemented in the `std` package whereas the high-level applications are implemented in the `app` package. As mentioned earlier, one of the main advantage of building on this project is that the source code is much smaller in terms of lines of code.

The following table summarizes the `std` package content and allows your to browse the source code with embedded documentation extracted from the corresponding specifications.

| Module	| Description	| Lines |
|:-------|:------------|:------|
| [rfc2198](http://39peers.net/download/python/doc/html/rfc2198.py.html)	| Implements RTP payload type for redundant audio data.	| 45    |
| [rfc2396](http://39peers.net/download/python/doc/html/rfc2396.py.html)	| Implements various forms of addresses such as URI or SIP address	| 177   |
| [rfc2617](http://39peers.net/download/python/doc/html/rfc2617.py.html)	| Implements HTTP basic and digest authentication which is reused in SIP.	| 131   |
| [rfc2833](http://39peers.net/download/python/doc/html/rfc2833.py.html)	| Implements the DTMF touch-tone payload in a RTP packet. | 40    |
| [rfc3261](http://39peers.net/download/python/doc/html/rfc3261.py.html)	| Implements the user agent part of Session Initiation Protocol (SIP).	| 1558  |
| [rfc3263](http://39peers.net/download/python/doc/html/rfc3263.py.html) | Implements SIP server discovery using DNS NAPTR, SRV and A.  | 108   |
| [rfc3264](http://39peers.net/download/python/doc/html/rfc3264.py.html)	| Implements the SDP offer answer model for unicast session as used in SIP	| 120   |
| [rfc3489bis](http://39peers.net/download/python/doc/html/rfc3489bis.py.html)	| Implements basic NAT traversal technologies such as STUN, NAT discovery using STUN, and variation on TURN. | 693   |
| [rfc3550](http://39peers.net/download/python/doc/html/rfc3550.py.html)	| Implements the Real-time Transport Protocol (RTP) and its companion control protocol RTCP.	 | 687   |
| [rfc3551](http://39peers.net/download/python/doc/html/rfc3551.py.html) | 	Defines the static payload types for RTP. | 48    |
| [rfc3920](http://39peers.net/download/python/doc/html/rfc3920.py.html)	| Implements XMPP core for client.	| 435   |
| [rfc3921](http://39peers.net/download/python/doc/html/rfc3921.py.html)	| Implements IM and Presence of XMPP client (incomplete).	| 373   |
| [rfc4566](http://39peers.net/download/python/doc/html/rfc4566.py.html)	| Implements the session description protocol (SDP).	| 162   |

The high level application modules use some of these modules and build additional applications or libraries as summarized below:

| Module	| Description	| Lines |
|:-------|:------------|:------|
| [voip](http://39peers.net/download/python/doc/html/voip.py.html)	| Implements a SIP user agent library for registration, call, instant messaging and conferences.	 | 1261  |
| [dht](http://39peers.net/download/python/doc/html/dht.py.html) 	| Implements a variation of the Bamboo/Pastry distributed hash table algorithm  | 1983  |
| [opendht](http://39peers.net/download/python/doc/html/opendht.py.html) 	| Implements the client side library to connect to existing OpenDHT service.	 | 71    |
| p2p	   | Implements a peer-to-peer pipe abstraction between two peers using a DHT. (incomplete).	 | 642   |
| p2psip	| Implements various P2P-SIP application scenarios using p2p and voip modules. (incomplete).	 | 285   |
| crypto	| Implements an abstraction for cryptography algorithms to be used in dht or p2p. (incomplete).	 | 261   |
| dhtgui | Implements a test tool to launch p2p/dht module and display the nodes in a circle.	| 427   |
| sipd	  | Implements a very simple SIP registration and proxy server using rfc3261 module. (incomplete)	| 115   |

There are several supporting modules. Below are some of the important ones.

| Module	| Description	| Lines |
|:-------|:------------|:------|
| [simplexml](http://39peers.net/download/python/doc/html/simplexml.py.html)	| Implements a simple XML DOM with convenient methods and operators to work on XML and XMLList.	 | 420   |

You can also browse the sources but without the embedded documentation.

## Documentation ##

I have used several types of documentation in this project to assist the student developers understand the software.

  1. An extensive guide to implementing SIP in Python (still incomplete) is available in both [PDF](http://39peers.net/download/doc/report.pdf) and [HTML](http://39peers.net/download/doc/report.html) formats. I recommend this document if you want to walk through various modules in the implementation, or understand various design decisions and intricate details of why something is implemented in a certain way. The document takes you through pretty much every line of code in the implementation.
  1. The Python documentation either using the comments or docstring present in the source code itself.
  1. The documentation extracted from the corresponding specification in the htmlified source code. See the Browse Source Code section above.

## License ##

This project is free-for-all to use. The software that enables peer-to-peer protocol is released under GNU/GPL. All the content and data, are Copyright 2007-2014 by [Kundan Singh](http://kundansingh.com).

If you want to distribute, copy or modify this software, you are welcome to do so under the terms of the [GNU General Public License](http://www.gnu.org/copyleft/gpl.html#SEC1). If you are unfamiliar with this license, you might want to read [How To Apply These Terms To Your Program](http://www.gnu.org/copyleft/gpl.html#SEC4) and the [GNU General Public License FAQ](http://www.gnu.org/licenses/gpl-faq.html).

An alternative commercial license is available. Please [contact us](http://theintencity.com) by email.

## FAQ ##

### Why another P2P software? ###

There are a number of existing peer-to-peer (P2P) software applications. Most applications are targeted for file sharing that uses caching of popular content for efficiency. There are a few distributed hash table (DHT) based applications as well that are more suited for Internet telephony. However, many of these existing systems suffer from one or more of the following drawbacks:

  1. The implementation is proprietary even if the application executable is free to use. This means developers cannot use it for experimenting with new ideas.
  1. The implementation is too complex with too many files, modules and interaction among modules. Sometimes this is due to the choice of implementation language and other times due to complex design philosophies.
  1. The implementation is either not portable or requires significant effort to port on various platforms.
  1. The application does not use standard protocols such as IETF's SIP and RTP for real-time communication.
  1. The application does not do full peer-to-peer, i.e., only media path is end-to-end by solving the NAT traversal problem. A true peer-to-peer communication application should try to do both signaling and media as peer-to-peer. It should not rely on central authentication server for every login.

There are some remarkably great software applications that fill in part of the picture. For example Benny's pjsip.org provides a very fine high performance, small footprint library for SIP, RTP, media, NAT traversal, etc. JAIN NIST stack for SIP has been used extensively in several projects. Sean's Bamboo DHT provides a open source Java based DHT implementation. The project goals of these projects are different from ours. In particular, we advise you to not use our software if you are interested in high performance, embedded platform or well tested piece of engineering.

**Goals of this project:**

Our project is meant as experimental for developers (hint: project students) to quickly try out new ideas, without having to write thousands of lines of code or without spending a lot of time to see if a small variation in the existing algorithm works well.

Another main goal of the project is to help the developers understand the RFCs and drafts of various protocols and how they translate into source code. This helps developing more inter-operable software easily. Usually a developer has to translate the specification into object oriented design and pseudo-code, and then write the implementation. This project provides design of several specifications in Python which is a pseudo-code style language.

### Why Python? ###

Python encourages developers' efficiency because of very compact, concise (and beautiful!) software that one can write. Based on my experience the number of lines-of-code is 5 to 30 times less than the corresponding code in Java or C/C++.

I have written SIP stack four times now in four different languages. First was a modification of a C stack based on RFC 2543 in 1999-2000. Later I reworked the user agent API and the library to create a RFC 3261 based C++ stack in 2002, with some C code hanging around. After graduating and joining a company, I wrote another SIP stack in `ActionScript`, which is like `ECMAScript`, in 2006. And finally I wrote again for this project in Python end of 2007. The first time it took around 4-5 months to get things going in C, then around 3-4 months for C++, around one month in `ActionScript` and about a week in Python. Based on my experience, generally for every line of Python code there is about 3-10 lines of `ActionScript` code, 5-10 lines of Java code, and more than 20 lines in C.

The source code for RFC 3261 implementation in Python for user agents is about 1300 lines, whereas a similar library in C++ or Java extends to more than ten thousand lines of source code. For a significantly large project, if designed right, one can achieve a factor of improvement in lines-of-code. Clearly writing one line of Python code takes more time than writing one line of Java code, but reducing the overall lines-of-code has many fold advantages:

  1. Less number of lines means that one can write software much faster. Implementing a typical RFC takes a day or two, unless it is big like RFC 3261 (SIP) in which case it may take a week or so. On the other hand, a C++ or Java programmer will have to spend much longer to get things going.
  1. There is less garbage (syntactic sugar) in the source code, which means reading and understanding the code is easier. Syntax highlighting tools, and embedded docstring mechanism help in a number of ways.
  1. Less code means that the testing and review efforts are less. The embedded doctest style testing is pretty convenient for small routines. Lot of code is easily reviewed just by reading the code and the corresponding specification or documentation, unlike in C or Java where there could be too much of interdependencies among different classes, methods and functions.
  1. Less code means there would be less number of bugs.
  1. The improvement in programming efficiency has further effect on the programmer, as he gets more motivated to write more code, instead of getting stuck in dealing with lots of code. While I don't have the numbers, I would guess that the development and testing cost in terms of man-hours asymptotically grows faster than the number of lines of code.

I have written many large software pieces in many different programming languages, C, C++, Tcl, Perl, Java, `ActionScript` and Python. And I have come to a conclusion that Python is probably the best, and should be used for all applications if possible. Projects where Python may not be used are those which have specific constraints such as low level access or performance requirements (C/C++), or need to work within a browser (`JavaScript`) or server (PHP).

## Who uses this project? ##

This article lists other projects that use software pieces from this project. The list includes [SIP-RTMP gateway](https://github.com/theintencity/rtmplite) and the [Internet video city](https://github.com/theintencity/videocity). If you (plan to) use some pieces of this project, please let me know so that I can list your project on this page.

  * [SIP-RTMP gateway](https://github.com/theintencity/rtmplite): The goal of this project is to allow Flash to SIP calls and vice versa. The gateway implements translation of signaling as well as media between Flash Player's RTMP and standard SIP, SDP and RTP/RTCP. The client side API allows you or any third-party to build user interface of web-based audio and video phone that uses SIP in the back end. The implementation uses this project's software for the the SIP, SDP and RTP/RTCP components.
  * [The Internet Video City](https://github.com/theintencity/videocity): The project aims at providing open source and free software tools to developers and system engineers to support enterprise and consumer video conferencing using ubiquitous web based Flash Player platform. The video communication is abstracted out as a city, where you own a home with several rooms, decorate your rooms with your favorite photos and videos, invite your friends and family to visit a room by handing out visiting card, or visit other people's rooms to video chat with them or to leave a video message if they are not in their home. The implementation uses this project's software for the `crypto` module that implements publilc key cryptography.
