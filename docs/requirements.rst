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
* IPv4 UDP (requires ``recvmsg`` - see below)
* IPv6 DNS (requires ``recvmsg`` - see below)
* IPv6 TCP
* IPv6 UDP (requires ``recvmsg`` - see below)
* IPv6 DNS (requires ``recvmsg`` - see below)

.. _PyXAPI: http://www.pps.univ-paris-diderot.fr/~ylg/PyXAPI/

Full UDP or DNS support with the TPROXY method requires the ``recvmsg()``
syscall. This is not available in Python 2, however it is in Python 3.5 and
later. Under Python 2 you might find it sufficient to install PyXAPI_ in
order to get the ``recvmsg()`` function. See :doc:`tproxy` for more
information.


MacOS / FreeBSD / OpenBSD / pfSense
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Method: pf

Supports:

* IPv4 TCP
* IPv4 DNS
* IPv6 TCP
* IPv6 DNS

Requires:

* You need to have the pfctl command.

Windows
~~~~~~~

Not officially supported, however can be made to work with Vagrant. Requires
cmd.exe with Administrator access. See :doc:`windows` for more information.


Server side Requirements
------------------------
The server can run in any version of Python between 2.4 and 3.6.
However it is recommended that you use Python 2.7, Python 3.5 or later whenever
possible as support for older versions might be dropped in the future.


Additional Suggested Software
-----------------------------

- If you are using systemd, sshuttle can notify it when the connection to
  the remote end is established and the firewall rules are installed. For
  this feature to work you must configure the process start-up type for the
  sshuttle service unit to notify, as shown in the example below. 

.. code-block:: ini
   :emphasize-lines: 6

   [Unit]
   Description=sshuttle
   After=network.target
   
   [Service]
   Type=notify
   ExecStart=/usr/bin/sshuttle --dns --remote <user>@<server> <subnets...>
   
   [Install]
   WantedBy=multi-user.target
