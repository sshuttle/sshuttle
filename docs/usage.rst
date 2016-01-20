Usage
=====

.. note::

    For information on usage with Windows, see the :doc:`windows` section.
    For information on using the TProxy method, see the :doc:`tproxy` section.

Forward all traffic::

    sshuttle -r username@sshserver 0.0.0.0/0

- Use the :option:`sshuttle -r` parameter to specify a remote server.

- By default sshuttle will automatically choose a method to use. Override with
  the :option:`sshuttle --method` parameter.

- There is a shortcut for 0.0.0.0/0 for those that value
  their wrists::

      sshuttle -r username@sshserver 0/0

If you would also like your DNS queries to be proxied
through the DNS server of the server you are connect to::

  sshuttle --dns -r username@sshserver 0/0

The above is probably what you want to use to prevent
local network attacks such as Firesheep and friends.
See the documentation for the :option:`sshuttle --dns` parameter.

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

