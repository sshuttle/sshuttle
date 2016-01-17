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


Obtaining sshuttle
------------------

- From PyPI::

      pip install sshuttle

- Clone::

      git clone https://github.com/sshuttle/sshuttle.git
      ./setup.py install

Documentation
-------------
The documentation for the stable version is available at:
http://sshuttle.readthedocs.org/

The documentation for the latest development version is available at:
http://sshuttle.readthedocs.org/en/latest/
