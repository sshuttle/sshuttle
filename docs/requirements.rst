Requirements
============

Client side Requirements
------------------------

- sudo, or root access on your client machine.
  (The server doesn't need admin access.)
- Python 3.5 or greater.


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

- Python 3.5 or greater.


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
