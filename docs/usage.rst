Usage
=====
- Forward all traffic::

      sshuttle -r username@sshserver 0.0.0.0/0

- By default sshuttle will automatically choose a method to use. Override with
  the ``--method=`` parameter.

- There is a shortcut for 0.0.0.0/0 for those that value
  their wrists::

      sshuttle -r username@sshserver 0/0

- If you would also like your DNS queries to be proxied
  through the DNS server of the server you are connect to::

      sshuttle --dns -r username@sshserver 0/0

  The above is probably what you want to use to prevent
  local network attacks such as Firesheep and friends.

(You may be prompted for one or more passwords; first, the local password to
become root using sudo, and then the remote ssh password.  Or you might have
sudo and ssh set up to not require passwords, in which case you won't be
prompted at all.)


Usage Notes
-----------
That's it!  Now your local machine can access the remote network as if you
were right there.  And if your "client" machine is a router, everyone on
your local network can make connections to your remote network.

You don't need to install sshuttle on the remote server;
the remote server just needs to have python available. 
sshuttle will automatically upload and run its source code
to the remote python interpreter.

This creates a transparent proxy server on your local machine for all IP
addresses that match 0.0.0.0/0.  (You can use more specific IP addresses if
you want; use any number of IP addresses or subnets to change which
addresses get proxied.  Using 0.0.0.0/0 proxies *everything*, which is
interesting if you don't trust the people on your local network.)

Any TCP session you initiate to one of the proxied IP addresses will be
captured by sshuttle and sent over an ssh session to the remote copy of
sshuttle, which will then regenerate the connection on that end, and funnel
the data back and forth through ssh.

Fun, right?  A poor man's instant VPN, and you don't even have to have
admin access on the server.

Additional information for TPROXY
---------------------------------
TPROXY is the only method that supports full support of IPv6 and UDP.

There are some things you need to consider for TPROXY to work:

- The following commands need to be run first as root. This only needs to be
  done once after booting up::

      ip route add local default dev lo table 100
      ip rule add fwmark 1 lookup 100
      ip -6 route add local default dev lo table 100
      ip -6 rule add fwmark 1 lookup 100

- The ``--auto-nets`` feature does not detect IPv6 routes automatically. Add IPv6
  routes manually. e.g. by adding ``'::/0'`` to the end of the command line.

- The client needs to be run as root. e.g.::

      sudo SSH_AUTH_SOCK="$SSH_AUTH_SOCK" $HOME/tree/sshuttle.tproxy/sshuttle  --method=tproxy ...

- You may need to exclude the IP address of the server you are connecting to.
  Otherwise sshuttle may attempt to intercept the ssh packets, which will not
  work. Use the ``--exclude`` parameter for this.

- Similarly, UDP return packets (including DNS) could get intercepted and
  bounced back. This is the case if you have a broad subnet such as
  ``0.0.0.0/0`` or ``::/0`` that includes the IP address of the client. Use the
  ``--exclude`` parameter for this.

- You need the ``--method=tproxy`` parameter, as above.

- The routes for the outgoing packets must already exist. For example, if your
  connection does not have IPv6 support, no IPv6 routes will exist, IPv6
  packets will not be generated and sshuttle cannot intercept them::

      telnet -6 www.google.com 80
      Trying 2404:6800:4001:805::1010...
      telnet: Unable to connect to remote host: Network is unreachable

  Add some dummy routes to external interfaces. Make sure they get removed
  however after sshuttle exits.
