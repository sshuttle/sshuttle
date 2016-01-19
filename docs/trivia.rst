Useless Trivia
==============
This section written by the original author, Avery Pennarun
<apenwarr@gmail.com>.

Back in 1998, I released the first version of `Tunnel
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
program that was the best of all worlds.  And here we are, at last.
You're welcome.

