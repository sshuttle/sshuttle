Usage
=====

.. note::

    For information on usage with Windows, see the :doc:`windows` section.
    For information on using the TProxy method, see the :doc:`tproxy` section.

Forward all traffic::

    sshuttle -r username@sshserver 0.0.0.0/0

- Use the :option:`sshuttle -r` parameter to specify a remote server.
  One some systems, you may also need to use the :option:`sshuttle -x`
  parameter to exclude sshserver or sshserver:22 so that your local
  machine can communicate directly to sshserver without it being
  redirected by sshuttle.

- By default sshuttle will automatically choose a method to use. Override with
  the :option:`sshuttle --method` parameter.

- There is a shortcut for 0.0.0.0/0 for those that value
  their wrists::

      sshuttle -r username@sshserver 0/0


- For 'My VPN broke and need a temporary solution FAST to access local IPv4 addresses'::

      sshuttle --dns -NHr username@sshserver 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

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

Sudoers File
------------

sshuttle can generate a sudoers.d file for Linux and MacOS. This
allows one or more users to run sshuttle without entering the
local sudo password. **WARNING:** This option is *insecure*
because, with some cleverness, it also allows these users to run any
command (via the --ssh-cmd option) as root without a password.

To print a sudo configuration file and see a suggested way to install it, run::

  sshuttle --sudoers-no-modify

A custom user or group can be set with the 
:option:`sshuttle --sudoers-no-modify --sudoers-user {user_descriptor}`
option. Valid values for this vary based on how your system is configured.
Values such as usernames, groups pre-pended with `%` and sudoers user 
aliases will work. See the sudoers manual for more information on valid
user specif actions. The option must be used with `--sudoers-no-modify`::

  sshuttle --sudoers-no-modify --sudoers-user mike
  sshuttle --sudoers-no-modify --sudoers-user %sudo
