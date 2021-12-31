TPROXY
======
TPROXY is the only method that supports UDP.

There are some things you need to consider for TPROXY to work:

- The following commands need to be run first as root. This only needs to be
  done once after booting up::

      ip route add local default dev lo table 100
      ip rule add fwmark {TMARK} lookup 100
      ip -6 route add local default dev lo table 100
      ip -6 rule add fwmark {TMARK} lookup 100

  where {TMARK} is the identifier mark passed with -t or --tmark flag
  as a hexadecimal string (default value is '0x01').

- The ``--auto-nets`` feature does not detect IPv6 routes automatically. Add IPv6
  routes manually. e.g. by adding ``'::/0'`` to the end of the command line.

- The client needs to be run as root. e.g.::

      sudo SSH_AUTH_SOCK="$SSH_AUTH_SOCK" $HOME/tree/sshuttle.tproxy/sshuttle --method=tproxy ...

- You may need to exclude the IP address of the server you are connecting to.
  Otherwise sshuttle may attempt to intercept the ssh packets, which will not
  work. Use the ``--exclude`` parameter for this.

- You need the ``--method=tproxy`` parameter, as above.

- The routes for the outgoing packets must already exist. For example, if your
  connection does not have IPv6 support, no IPv6 routes will exist, IPv6
  packets will not be generated and sshuttle cannot intercept them::

      telnet -6 www.google.com 80
      Trying 2404:6800:4001:805::1010...
      telnet: Unable to connect to remote host: Network is unreachable

  Add some dummy routes to external interfaces. Make sure they get removed
  however after sshuttle exits.
