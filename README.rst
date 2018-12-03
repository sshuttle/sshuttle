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
  TCP-over-TCP, which has `terrible performance`_.
  
.. _terrible performance: https://sshuttle.readthedocs.io/en/stable/how-it-works.html

Obtaining sshuttle
------------------

- Debian stretch or later::

      apt-get install sshuttle
      
- Arch Linux::

      pacman -S sshuttle

- Fedora::

      dnf install sshuttle

- NixOS::

      nix-env -iA nixos.sshuttle

- From PyPI::

      sudo pip install sshuttle

- Clone::

      git clone https://github.com/sshuttle/sshuttle.git
      cd sshuttle
      sudo ./setup.py install

- FreeBSD::

      # ports
      cd /usr/ports/net/py-sshuttle && make install clean
      # pkg
      pkg install py36-sshuttle

It is also possible to install into a virtualenv as a non-root user.

- From PyPI::

      virtualenv -p python3 /tmp/sshuttle
      . /tmp/sshuttle/bin/activate
      pip install sshuttle

- Clone::

      virtualenv -p python3 /tmp/sshuttle
      . /tmp/sshuttle/bin/activate
      git clone https://github.com/sshuttle/sshuttle.git
      cd sshuttle
      ./setup.py install

- Homebrew::

      brew install sshuttle

- Nix::

      nix-env -iA nixpkgs.sshuttle


Documentation
-------------
The documentation for the stable version is available at:
https://sshuttle.readthedocs.org/

The documentation for the latest development version is available at:
https://sshuttle.readthedocs.org/en/latest/
