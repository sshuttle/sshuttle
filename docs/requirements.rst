Requirements
============

Client side Requirements
------------------------

- sudo, or root access on your client machine.
  (The server doesn't need admin access.)
- Python 2.7 or Python 3.5.

+-------+--------+------------+-----------------------------------------------+
| OS    | Method | Features   | Requirements                                  |
+=======+========+============+===============================================+
| Linux | NAT    | * IPv4 TCP + iptables DNAT, REDIRECT, and ttl modules.     |
+       +--------+------------+-----------------------------------------------+
|       | TPROXY | * IPv4 TCP + Linux with TPROXY support.                    |
|       |        | * IPv4 UDP + Python 3.5 preferred (see below).             |
|       |        | * IPv6 TCP + Python 2 may require PyXAPI_ (see below).     |
|       |        | * IPv6 UDP +                                               |
+-------+--------+------------+-----------------------------------------------+
| MacOS | PF     | * IPv4 TCP + You need to have the pfctl command.           |
+-------+--------+------------+-----------------------------------------------+

.. _PyXAPI: http://www.pps.univ-paris-diderot.fr/~ylg/PyXAPI/ 

Server side Requirements
------------------------
Python 2.7 or Python 3.5.


Additional Suggested Software
-----------------------------

- You may want to use autossh, available in various package management
  systems
