sshuttle
========


Synopsis
--------
**sshuttle** [*options*] **-r** *[username@]sshserver[:port]* \<*subnets* ...\>


Description
-----------
:program:`sshuttle` allows you to create a VPN connection from your
machine to any remote server that you can connect to via ssh, as long
as that server has a sufficiently new Python installation.

To work, you must have root access on the local machine,
but you can have a normal account on the server.

It's valid to run :program:`sshuttle` more than once simultaneously on
a single client machine, connecting to a different server
every time, so you can be on more than one VPN at once.

If run on a router, :program:`sshuttle` can forward traffic for your
entire subnet to the VPN.


Options
-------
.. program:: sshuttle

.. option:: <subnets>

    A list of subnets to route over the VPN, in the form
    ``a.b.c.d[/width][port[-port]]``. Valid examples are 1.2.3.4 (a
    single IP address) and 1.2.3.4/32 (equivalent to 1.2.3.4),
    1.2.3.0/24 (a 24-bit subnet, ie. with a 255.255.255.0 netmask).
    Specify subnets 0/0 to match all IPv4 addresses and ::/0 to match
    all IPv6 addresses. Any of the previous examples are also valid if
    you append a port or a port range, so 1.2.3.4:8000 will only
    tunnel traffic that has as the destination port 8000 of 1.2.3.4
    and 1.2.3.0/24:8000-9000 will tunnel traffic going to any port
    between 8000 and 9000 (inclusive) for all IPs in the 1.2.3.0/24
    subnet. A hostname can be provided instead of an IP address. If
    the hostname resolves to multiple IPs, all of the IPs are
    included. If a width is provided with a hostname, the width is
    applied to all of the hostnames IPs (if they are all either IPv4
    or IPv6). Widths cannot be supplied to hostnames that resolve to
    both IPv4 and IPv6. Valid examples are example.com,
    example.com:8000, example.com/24, example.com/24:8000 and
    example.com:8000-9000.

.. option:: --method <auto|nat|nft|tproxy|pf|ipfw>

   Which firewall method should sshuttle use? For auto, sshuttle attempts to
   guess the appropriate method depending on what it can find in PATH. The
   default value is auto.

.. option:: -l <[ip:]port>, --listen=<[ip:]port>

    Use this ip address and port number as the transparent
    proxy port.  By default :program:`sshuttle` finds an available
    port automatically and listens on IP 127.0.0.1
    (localhost), so you don't need to override it, and
    connections are only proxied from the local machine,
    not from outside machines.  If you want to accept
    connections from other machines on your network (ie. to
    run :program:`sshuttle` on a router) try enabling IP Forwarding in
    your kernel, then using ``--listen 0.0.0.0:0``.
    You can use any name resolving to an IP address of the machine running
    :program:`sshuttle`, e.g. ``--listen localhost``.

    For the nft, tproxy and pf methods this can be an IPv6 address. Use
    this option with comma separated values if required, to provide both
    IPv4 and IPv6 addresses, e.g. ``--listen 127.0.0.1:0,[::1]:0``.

.. option:: -H, --auto-hosts

    Scan for remote hostnames and update the local /etc/hosts
    file with matching entries for as long as the VPN is
    open.  This is nicer than changing your system's DNS
    (/etc/resolv.conf) settings, for several reasons.  First,
    hostnames are added without domain names attached, so
    you can ``ssh thatserver`` without worrying if your local
    domain matches the remote one.  Second, if you :program:`sshuttle`
    into more than one VPN at a time, it's impossible to
    use more than one DNS server at once anyway, but
    :program:`sshuttle` correctly merges /etc/hosts entries between
    all running copies.  Third, if you're only routing a
    few subnets over the VPN, you probably would prefer to
    keep using your local DNS server for everything else.

    :program:`sshuttle` tries to store a cache of the hostnames in
    ~/.sshuttle.hosts on the remote host. Similarly, it tries to read
    the file when you later reconnect to the host with --auto-hosts
    enabled to quickly populate the host list. When troubleshooting
    this feature, try removing this file on the remote host when
    sshuttle is not running.

.. option:: -N, --auto-nets

    In addition to the subnets provided on the command
    line, ask the server which subnets it thinks we should
    route, and route those automatically.  The suggestions
    are taken automatically from the server's routing
    table.

    This feature does not detect IPv6 routes. Specify IPv6 subnets
    manually. For example, specify the ``::/0`` subnet on the command
    line to route all IPv6 traffic.

.. option:: --dns

    Capture local DNS requests and forward to the remote DNS
    server. All queries to any of the local system's DNS
    servers (/etc/resolv.conf and, if it exists,
    /run/systemd/resolve/resolv.conf) will be intercepted and
    resolved on the remote side of the tunnel instead, there
    using the DNS specified via the :option:`--to-ns` option,
    if specified. Only plain DNS traffic sent to these servers
    on port 53 are captured.

.. option:: --ns-hosts=<server1[,server2[,server3[...]]]>

    Capture local DNS requests to the specified server(s)
    and forward to the remote DNS server. Contrary to the
    :option:`--dns` option, this flag allows to specify the
    DNS server(s) the queries to which to intercept,
    instead of intercepting all DNS traffic on the local
    machine. This can be useful when only certain DNS
    requests should be resolved on the remote side of the
    tunnel, e.g. in combination with dnsmasq.

.. option:: --to-ns=<server>

    The DNS to forward requests to when remote DNS
    resolution is enabled. If not given, sshuttle will
    simply resolve using the system configured resolver on
    the remote side (via /etc/resolv.conf on the remote
    side).

.. option:: --python

    Specify the name/path of the remote python interpreter. The
    default is to use ``python3`` (or ``python``, if ``python3``
    fails) in the remote system's PATH.

.. option:: -r <[username@]sshserver[:port]>, --remote=<[username@]sshserver[:port]>

    The remote hostname and optional username and ssh
    port number to use for connecting to the remote server.
    For example, example.com, testuser@example.com,
    testuser@example.com:2222, or example.com:2244. This
    hostname is passed to ssh, so it will recognize any
    aliases and settings you may have configured in
    ~/.ssh/config.

.. option:: -x <subnet>, --exclude=<subnet>

    Explicitly exclude this subnet from forwarding.  The
    format of this option is the same as the ``<subnets>``
    option.  To exclude more than one subnet, specify the
    ``-x`` option more than once.  You can say something like
    ``0/0 -x 1.2.3.0/24`` to forward everything except the
    local subnet over the VPN, for example.

.. option:: -X <file>, --exclude-from=<file>

    Exclude the subnets specified in a file, one subnet per
    line. Useful when you have lots of subnets to exclude.

.. option:: -v, --verbose

    Print more information about the session.  This option
    can be used more than once for increased verbosity.  By
    default, :program:`sshuttle` prints only error messages.

.. option:: -e, --ssh-cmd

    The command to use to connect to the remote server. The
    default is just ``ssh``.  Use this if your ssh client is
    in a non-standard location or you want to provide extra
    options to the ssh command, for example, ``-e 'ssh -v'``.

.. option:: --seed-hosts

    A comma-separated list of hostnames to use to
    initialize the :option:`--auto-hosts` scan algorithm.
    :option:`--auto-hosts` does things like poll netstat output
    for lists of local hostnames, but can speed things up
    if you use this option to give it a few names to start
    from.

    If this option is used *without* :option:`--auto-hosts`,
    then the listed hostnames will be scanned and added, but
    no further hostnames will be added.

.. option:: --no-latency-control

    Sacrifice latency to improve bandwidth benchmarks. ssh
    uses really big socket buffers, which can overload the
    connection if you start doing large file transfers,
    thus making all your other sessions inside the same
    tunnel go slowly. Normally, :program:`sshuttle` tries to avoid
    this problem using a "fullness check" that allows only
    a certain amount of outstanding data to be buffered at
    a time.  But on high-bandwidth links, this can leave a
    lot of your bandwidth underutilized.  It also makes
    :program:`sshuttle` seem slow in bandwidth benchmarks (benchmarks
    rarely test ping latency, which is what :program:`sshuttle` is
    trying to control).  This option disables the latency
    control feature, maximizing bandwidth usage.  Use at
    your own risk.

.. option:: --latency-buffer-size

    Set the size of the buffer used in latency control. The
    default is ``32768``. Changing this option allows a compromise
    to be made between latency and bandwidth without completely
    disabling latency control (with :option:`--no-latency-control`).

.. option:: -D, --daemon

    Automatically fork into the background after connecting
    to the remote server.  Implies :option:`--syslog`.

.. option:: -s <file>, --subnets=<file>

    Include the subnets specified in a file instead of on the
    command line. One subnet per line.

.. option:: --syslog

    after connecting, send all log messages to the
    :manpage:`syslog(3)` service instead of stderr.  This is
    implicit if you use :option:`--daemon`.

.. option:: --pidfile=<pidfilename>

    when using :option:`--daemon`, save :program:`sshuttle`'s pid to
    *pidfilename*.  The default is ``sshuttle.pid`` in the
    current directory.

.. option:: --disable-ipv6

    Disable IPv6 support for methods that support it (nat, nft,
    tproxy, and pf).

.. option:: --firewall

    (internal use only) run the firewall manager.  This is
    the only part of :program:`sshuttle` that must run as root.  If
    you start :program:`sshuttle` as a non-root user, it will
    automatically run ``sudo`` or ``su`` to start the firewall
    manager, but the core of :program:`sshuttle` still runs as a
    normal user.

.. option:: --hostwatch

    (internal use only) run the hostwatch daemon.  This
    process runs on the server side and collects hostnames for
    the :option:`--auto-hosts` option.  Using this option by itself
    makes it a lot easier to debug and test the :option:`--auto-hosts`
    feature.

.. option:: --sudoers-no-modify

    sshuttle prints a configuration to stdout which allows a user to
    run sshuttle without a password. This option is INSECURE because,
    with some cleverness, it also allows the user to run any command
    as root without a password. The output also includes a suggested
    method for you to install the configuration.

    Use --sudoers-user to modify the user that it applies to.

.. option:: --sudoers-user

    Set the user name or group with %group_name for passwordless
    operation. Default is the current user. Set to ALL for all users
    (NOT RECOMMENDED: See note about security in --sudoers-no-modify
    documentation above). Only works with the --sudoers-no-modify
    option.

.. option:: -t <mark>, --tmark=<mark>

    An option used by the tproxy method: Use the specified traffic
    mark. The mark must be a hexadecimal value. Defaults to 0x01.

.. option:: --version

    Print program version.


Configuration File
------------------
All the options described above can optionally be specified in a configuration
file.

To run :program:`sshuttle` with options defined in, e.g., `/etc/sshuttle.conf`
just pass the path to the file preceded by the `@` character, e.g.
`@/etc/sshuttle.conf`.

When running :program:`sshuttle` with options defined in a configuration file,
options can still be passed via the command line in addition to what is
defined in the file. If a given option is defined both in the file and in
the command line, the value in the command line will take precedence.

Arguments read from a file must be one per line, as shown below::

    value
    --option1
    value1
    --option2
    value2

The configuration file supports comments for human-readable
annotations. For example::

    # company-internal API
    8.8.8.8/32
    # home IoT
    192.168.63.0/24


Examples
--------

Use the following command to route all IPv4 TCP traffic through remote
(-r) host example.com (and possibly other traffic too, depending on
the selected --method). The 0/0 subnet, short for 0.0.0.0/0, matches
all IPv4 addresses. The ::/0 subnet, matching all IPv6 addresses could
be added to the example. We also exclude (-x) example.com:22 so that
we can establish ssh connections from our local machine to the remote
host without them being routed through sshuttle. Excluding the remote
host may be necessary on some machines for sshuttle to work properly.
Press Ctrl+C to exit. To also route DNS queries through sshuttle, try
adding --dns. Add or remove -v options to see more or less
information::

    $ sshuttle -r example.com -x example.com:22 0/0

    Starting sshuttle proxy (version ...).
    [local sudo] Password:
    fw: Starting firewall with Python version 3.9.5
    fw: ready method name nat.
    c : IPv6 disabled since it isn't supported by method nat.
    c : Method: nat
    c : IPv4: on
    c : IPv6: off (not available with nat method)
    c : UDP : off (not available with nat method)
    c : DNS : off (available)
    c : User: off (available)
    c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
    c :   (<AddressFamily.AF_INET: 2>, '0.0.0.0', 0, 0, 0)
    c : Subnets to exclude from forwarding:
    c :   (<AddressFamily.AF_INET: 2>, '...', 32, 22, 22)
    c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
    c : TCP redirector listening on ('127.0.0.1', 12299).
    c : Starting client with Python version 3.9.5
    c : Connecting to server...
    user@example.com's password:
     s: Starting server with Python version 3.6.8
     s: latency control setting = True
     s: auto-nets:False
    c : Connected to server.
    fw: setting up.
    fw: iptables -w -t nat -N sshuttle-12299
    fw: iptables -w -t nat -F sshuttle-12299
    ...
    Accept: 192.168.42.121:60554 -> 77.141.99.22:22.
    ^C
    c : Keyboard interrupt: exiting.
    c : SW'unknown':Mux#1: deleting (1 remain)
    c : SW#7:192.168.42.121:60554: deleting (0 remain)


Connect to a remote server, with automatic hostname
and subnet guessing::

    $ sshuttle -vNHr example.com -x example.com:22
    Starting sshuttle proxy (version ...).
    [local sudo] Password:
    fw: Starting firewall with Python version 3.9.5
    fw: ready method name nat.
    c : IPv6 disabled since it isn't supported by method nat.
    c : Method: nat
    c : IPv4: on
    c : IPv6: off (not available with nat method)
    c : UDP : off (not available with nat method)
    c : DNS : off (available)
    c : User: off (available)
    c : Subnets to forward through remote host (type, IP, cidr mask width, startPort, endPort):
    c : NOTE: Additional subnets to forward may be added below by --auto-nets.
    c : Subnets to exclude from forwarding:
    c :   (<AddressFamily.AF_INET: 2>, '...', 32, 22, 22)
    c :   (<AddressFamily.AF_INET: 2>, '127.0.0.1', 32, 0, 0)
    c : TCP redirector listening on ('127.0.0.1', 12300).
    c : Starting client with Python version 3.9.5
    c : Connecting to server...
    user@example.com's password:
     s: Starting server with Python version 3.6.8
     s: latency control setting = True
     s: auto-nets:True
    c : Connected to server.
    c : seed_hosts: []
     s: available routes:
     s:   77.141.99.0/24
    fw: setting up.
    fw: iptables -w -t nat -N sshuttle-12300
    fw: iptables -w -t nat -F sshuttle-12300
    ...
    c : Accept: 192.168.42.121:60554 -> 77.141.99.22:22.
    ^C
    c : Keyboard interrupt: exiting.
    c : SW'unknown':Mux#1: deleting (1 remain)
    c : SW#7:192.168.42.121:60554: deleting (0 remain)

Run :program:`sshuttle` with a `/etc/sshuttle.conf` configuration file::

    $ sshuttle @/etc/sshuttle.conf

Use the options defined in `/etc/sshuttle.conf` but be more verbose::

    $ sshuttle @/etc/sshuttle.conf -vvv

Override the remote server defined in `/etc/sshuttle.conf`::

    $ sshuttle @/etc/sshuttle.conf -r otheruser@test.example.com

Example configuration file::

    192.168.0.0/16
    --remote
    user@example.com


Discussion
----------
When it starts, :program:`sshuttle` creates an ssh session to the
server specified by the ``-r`` option.

After connecting to the remote server, :program:`sshuttle` uploads its
(python) source code to the remote end and executes it
there.  Thus, you don't need to install :program:`sshuttle` on the
remote server, and there are never :program:`sshuttle` version
conflicts between client and server.

Unlike most VPNs, :program:`sshuttle` forwards sessions, not packets.
That is, it uses kernel transparent proxying (`iptables
REDIRECT` rules on Linux) to
capture outgoing TCP sessions, then creates entirely
separate TCP sessions out to the original destination at
the other end of the tunnel.

Packet-level forwarding (eg. using the tun/tap devices on
Linux) seems elegant at first, but it results in
several problems, notably the 'tcp over tcp' problem.  The
tcp protocol depends fundamentally on packets being dropped
in order to implement its congestion control algorithm; if
you pass tcp packets through a tcp-based tunnel (such as
ssh), the inner tcp packets will never be dropped, and so
the inner tcp stream's congestion control will be
completely broken, and performance will be terrible.  Thus,
packet-based VPNs (such as IPsec and openvpn) cannot use
tcp-based encrypted streams like ssh or ssl, and have to
implement their own encryption from scratch, which is very
complex and error prone.

:program:`sshuttle`'s simplicity comes from the fact that it can
safely use the existing ssh encrypted tunnel without
incurring a performance penalty.  It does this by letting
the client-side kernel manage the incoming tcp stream, and
the server-side kernel manage the outgoing tcp stream;
there is no need for congestion control to be shared
between the two separate streams, so a tcp-based tunnel is
fine.

.. seealso::

   :manpage:`ssh(1)`, :manpage:`python(1)`
