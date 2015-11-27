sshuttle: where transparent proxy meets VPN meets ssh
=====================================================

As far as I know, sshuttle is the only program that solves the following
common case:

- Your client machine (or router) is Linux, FreeBSD, or MacOS.

- You have access to a remote network via ssh.

- You don't necessarily have admin access on the remote network.

- The remote network has no VPN, or only stupid/complex VPN
  protocols (IPsec, PPTP, etc). Or maybe you *are* the
  admin and you just got frustrated with the awful state of
  VPN tools.

- You don't want to create an ssh port forward for every
  single host/port on the remote network.

- You hate openssh's port forwarding because it's randomly
  slow and/or stupid.

- You can't use openssh's PermitTunnel feature because
  it's disabled by default on openssh servers; plus it does
  TCP-over-TCP, which has terrible performance (see below).


Client side Requirements
------------------------

- sudo, or logged in as root on your client machine.
  (The server doesn't need admin access.)
- Python 2.7 or Python 3.5.

+-------+--------+------------+-----------------------------------------------+
| OS    | Method | Features   | Requirements                                  |
+=======+========+============+===============================================+
| Linux | NAT    | * IPv4 TCP + iptables DNAT, REDIRECT, and ttl modules.     |
+       +--------+------------+-----------------------------------------------+
|       | TPROXY | * IPv4 TCP + Linux with TPROXY support.                    |
|       |        | * IPv4 UDP + Python 3.5 preferred (see below).             |
|       |        | * IPv6 TCP +                                               |
|       |        | * IPv6 UDP +                                               |
+-------+--------+------------+-----------------------------------------------+
| BSD   | IPFW   | * IPv4 TCP | Your kernel needs to be compiled with         |
|       |        |            | `IPFIREWALL_FORWARD` and you need to have ipfw|
|       |        |            | available.                                    |
+-------+--------+------------+-----------------------------------------------+
| MacOS | PF     | * IPv4 TCP + You need to have the pfctl command.           |
+-------+--------+------------+-----------------------------------------------+

Server side Requirements
------------------------
Python 2.7 or Python 3.5. This should match what is used on the client side.


Additional Suggested Software
-----------------------------

- You may want to use autossh, available in various package management
  systems


Additional information for TPROXY
---------------------------------
TPROXY is the only method that supports full support of IPv6 and UDP.

Full UDP or DNS support with the TPROXY method requires the `recvmsg()`
syscall. This is not available in Python 2.7, however is in Python 3.5 and
later.

- For Python 2.7, you need PyXAPI, available here:
  http://www.pps.univ-paris-diderot.fr/~ylg/PyXAPI/

There are some things you need to consider for TPROXY to work:

1. The following commands need to be run first as root. This only needs to be
   done once after booting up::

       ip route add local default dev lo table 100
       ip rule add fwmark 1 lookup 100
       ip -6 route add local default dev lo table 100
       ip -6 rule add fwmark 1 lookup 100

2. The client needs to be run as root. e.g.::

       sudo SSH_AUTH_SOCK="$SSH_AUTH_SOCK" $HOME/tree/sshuttle.tproxy/sshuttle  --method=tproxy ...

3. You do need the `--method=tproxy` parameter, as above.

4. The routes for the outgoing packets must already exist. For example, if your
   connection does not have IPv6 support, no IPv6 routes will exist, IPv6
   packets will not be generated and sshuttle cannot intercept them. Add some
   dummy routes to external interfaces. Make sure they get removed however
   after sshuttle exits.


Obtaining sshuttle
------------------

- From PyPI::

      pip install sshuttle

- Clone::

      git clone https://github.com/sshuttle/sshuttle.git
      ./setup.py install


Usage
-----

- Forward all traffic::

      sshuttle -r username@sshserver 0.0.0.0/0 -vv

- By default sshuttle will automatically choose a method to use. Override with
  the `--method=` parameter.

- There is a shortcut for 0.0.0.0/0 for those that value
  their wrists::

      sshuttle -r username@sshserver 0/0 -vv

- If you would also like your DNS queries to be proxied
  through the DNS server of the server you are connect to::

      sshuttle --dns -vvr username@sshserver 0/0

  The above is probably what you want to use to prevent
  local network attacks such as Firesheep and friends.

(You may be prompted for one or more passwords; first, the local password to
become root using sudo, and then the remote ssh password.  Or you might have
sudo and ssh set up to not require passwords, in which case you won't be
prompted at all.)


Usage Notes
-----------

That's it!  Now your local machine can access the remote network as if you
were right there.  And if your "client" machine is a router, everyone on
your local network can make connections to your remote network.

You don't need to install sshuttle on the remote server;
the remote server just needs to have python available. 
sshuttle will automatically upload and run its source code
to the remote python interpreter.

This creates a transparent proxy server on your local machine for all IP
addresses that match 0.0.0.0/0.  (You can use more specific IP addresses if
you want; use any number of IP addresses or subnets to change which
addresses get proxied.  Using 0.0.0.0/0 proxies *everything*, which is
interesting if you don't trust the people on your local network.)

Any TCP session you initiate to one of the proxied IP addresses will be
captured by sshuttle and sent over an ssh session to the remote copy of
sshuttle, which will then regenerate the connection on that end, and funnel
the data back and forth through ssh.

Fun, right?  A poor man's instant VPN, and you don't even have to have
admin access on the server.


Support
-------

Mailing list:

* Subscribe by sending a message to <sshuttle+subscribe@googlegroups.com>
* List archives are at: http://groups.google.com/group/sshuttle

Issue tracker and pull requests at github:

* https://github.com/sshuttle/sshuttle


Theory of Operation
-------------------

sshuttle is not exactly a VPN, and not exactly port forwarding.  It's kind
of both, and kind of neither.

It's like a VPN, since it can forward every port on an entire network, not
just ports you specify.  Conveniently, it lets you use the "real" IP
addresses of each host rather than faking port numbers on localhost.

On the other hand, the way it *works* is more like ssh port forwarding than
a VPN.  Normally, a VPN forwards your data one packet at a time, and
doesn't care about individual connections; ie. it's "stateless" with respect
to the traffic.  sshuttle is the opposite of stateless; it tracks every
single connection.

You could compare sshuttle to something like the old `Slirp
<http://en.wikipedia.org/wiki/Slirp>`_ program, which was a userspace TCP/IP
implementation that did something similar.  But it operated on a
packet-by-packet basis on the client side, reassembling the packets on the
server side.  That worked okay back in the "real live serial port" days,
because serial ports had predictable latency and buffering.

But you can't safely just forward TCP packets over a TCP session (like ssh),
because TCP's performance depends fundamentally on packet loss; it
*must* experience packet loss in order to know when to slow down!  At
the same time, the outer TCP session (ssh, in this case) is a reliable
transport, which means that what you forward through the tunnel *never*
experiences packet loss.  The ssh session itself experiences packet loss, of
course, but TCP fixes it up and ssh (and thus you) never know the
difference.  But neither does your inner TCP session, and extremely screwy
performance ensues.

sshuttle assembles the TCP stream locally, multiplexes it statefully over
an ssh session, and disassembles it back into packets at the other end.  So
it never ends up doing TCP-over-TCP.  It's just data-over-TCP, which is
safe.


Useless Trivia
--------------
This section written by Avery Pennarun <apenwarr@gmail.com>.

Back in 1998 (12 years ago!  Yikes!), I released the first version of `Tunnel
Vision <http://alumnit.ca/wiki/?TunnelVisionReadMe>`_, a semi-intelligent VPN
client for Linux.  Unfortunately, I made two big mistakes: I implemented the
key exchange myself (oops), and I ended up doing TCP-over-TCP (double oops).
The resulting program worked okay - and people used it for years - but the
performance was always a bit funny.  And nobody ever found any security flaws
in my key exchange, either, but that doesn't mean anything. :)

The same year, dcoombs and I also released Fast Forward, a proxy server
supporting transparent proxying.  Among other things, we used it for
automatically splitting traffic across more than one Internet connection (a
tool we called "Double Vision").

I was still in university at the time.  A couple years after that, one of my
professors was working with some graduate students on the technology that would
eventually become `Slipstream Internet Acceleration
<http://www.slipstream.com/>`_.  He asked me to do a contract for him to build
an initial prototype of a transparent proxy server for mobile networks.  The
idea was similar to sshuttle: if you reassemble and then disassemble the TCP
packets, you can reduce latency and improve performance vs.  just forwarding
the packets over a plain VPN or mobile network.  (It's unlikely that any of my
code has persisted in the Slipstream product today, but the concept is still
pretty cool.  I'm still horrified that people use plain TCP on complex mobile
networks with crazily variable latency, for which it was never really
intended.)

That project I did for Slipstream was what first gave me the idea to merge
the concepts of Fast Forward, Double Vision, and Tunnel Vision into a single
program that was the best of all worlds.  And here we are, at last, 10 years
later.  You're welcome.
