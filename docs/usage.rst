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

Sudoers File
------------
sshuttle can auto-generate the proper sudoers.d file using the current user 
for Linux and OSX. Doing this will allow sshuttle to run without asking for
the local sudo password and to give users who do not have sudo access
ability to run sshuttle.

  sshuttle --sudoers

DO NOT run this command with sudo, it will ask for your sudo password when
it is needed.

A costume user or group can be set with the :
option:`sshuttle --sudoers --sudoers-username {user_descriptor}` option. Valid
values for this vary based on how your system is configured. Values such as 
usernames, groups pre-pended with `%` and sudoers user aliases will work. See
the sudoers manual for more information on valid user specif actions.
The options must be used with `--sudoers`

  sshuttle --sudoers --sudoers-user mike
  sshuttle --sudoers --sudoers-user %sudo

The name of the file to be added to sudoers.d can be configured as well. This
is mostly not necessary but can be useful for giving more than one user
access to sshuttle. The default is `sshuttle_auto`

  sshuttle --sudoer --sudoers-filename sshuttle_auto_mike
  sshuttle --sudoer --sudoers-filename sshuttle_auto_tommy

You can also see what configuration will be added to your system without
modifying anything. This can be helpfull is the auto feature does not work, or
you want more control. This option also works with `--sudoers-username`.
`--sudoers-filename` has no effect with this option.

  sshuttle --sudoers-no-modify

This will simply sprint the generated configuration to STDOUT. Example

  08:40 PM william$ sshuttle --sudoers-no-modify

  Cmnd_Alias SSHUTTLE304 = /usr/bin/env PYTHONPATH=/usr/local/lib/python2.7/dist-packages/sshuttle-0.78.5.dev30+gba5e6b5.d20180909-py2.7.egg /usr/bin/python /usr/local/bin/sshuttle --method auto --firewall

  william ALL=NOPASSWD: SSHUTTLE304
