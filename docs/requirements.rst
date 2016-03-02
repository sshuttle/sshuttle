Requirements
============

Client side Requirements
------------------------

- sudo, or root access on your client machine.
  (The server doesn't need admin access.)
- Python 2.7 or Python 3.5.


Linux with NAT method
~~~~~~~~~~~~~~~~~~~~~
Supports:

* IPv4 TCP
* IPv4 DNS

Requires:

* iptables DNAT, REDIRECT, and ttl modules.


Linux with TPROXY method
~~~~~~~~~~~~~~~~~~~~~~~~
Supports:

* IPv4 TCP
* IPv4 UDP (requires ``recmsg`` - see below)
* IPv6 DNS (requires ``recmsg`` - see below)
* IPv6 TCP
* IPv6 UDP (requires ``recmsg`` - see below)
* IPv6 DNS (requires ``recmsg`` - see below)

.. _PyXAPI: http://www.pps.univ-paris-diderot.fr/~ylg/PyXAPI/

Full UDP or DNS support with the TPROXY method requires the ``recvmsg()``
syscall. This is not available in Python 2, however is in Python 3.5 and
later. Under Python 2 you might find it sufficient installing PyXAPI_ to get
the ``recvmsg()`` function. See :doc:`tproxy` for more information.


MacOS / FreeBSD / OpenBSD
~~~~~~~~~~~~~~~~~~~~~~~~~
Method: pf

Supports:

* IPv4 TCP
* IPv4 DNS

Requires:

* You need to have the pfctl command.

Windows
~~~~~~~

Not officially supported, however can be made to work with Vagrant. Requires
cmd.exe with Administrator access. See :doc:`windows` for more information.


Server side Requirements
------------------------
Python 2.7 or Python 3.5.


Additional Suggested Software
-----------------------------

- You may want to use autossh, available in various package management
  systems
