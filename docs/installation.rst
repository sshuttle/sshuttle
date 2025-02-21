Installation
============

- Ubuntu 16.04 or later::

      apt-get install sshuttle

- Debian stretch or later::

      apt-get install sshuttle

- Arch Linux::

      pacman -S sshuttle

- Fedora::

      dnf install sshuttle

- openSUSE::

      zypper in sshuttle

- Gentoo::

      emerge -av net-proxy/sshuttle

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
      pkg install py39-sshuttle

- OpenBSD::

      pkg_add sshuttle

- macOS, via MacPorts::

      sudo port selfupdate
      sudo port install sshuttle

It is also possible to install into a virtualenv as a non-root user.

- From PyPI::

      python3 -m venv /tmp/sshuttle
      . /tmp/sshuttle/bin/activate
      pip install sshuttle

- Clone::

      git clone https://github.com/sshuttle/sshuttle.git
      cd sshuttle
      python3 -m venv /tmp/sshuttle
      . /tmp/sshuttle/bin/activate
      python -m pip install .

- Homebrew::

      brew install sshuttle

- Nix::

      nix-shell -p sshuttle

- Windows::

      pip install sshuttle
