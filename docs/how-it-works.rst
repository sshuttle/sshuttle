How it works
============
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

