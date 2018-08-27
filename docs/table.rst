Tables
======

"Table" feature enables efficient circumvention of some
implementations of Internet censorship. The idea is that you create a
text file that lists IP addresses, subnetworks and domains that should
be unblocked, for example:

    *.rutracker.org
    *.linkedin.com
    95.211.178.194
    51.136.0.0/15

and pass this file to sshuttle using ``--table path_to_the_file``
option.  sshuttle will redirect all the traffic to the specified IPs
and subnets via the ssh connection. Moreover, if you use ``--dns``
option, it will monitor DNS requests and add any IP addresses for
blocked domains to the list of IPs to unblock, at the same time
updating the table file, so restarting sshuttle will not cause any
problems due to local DNS response caching.

This "wholesale" circumvention method is implemented using `ipset`
command on Linux and pf 'table' feature of Mac OS X (it may also
work with FreeBSD but this is currently untested). This way,
you can easily add hundreds of thousands of IPs and domain names
to the table without overwhelming your system resources.

The feature is currently supported by 'pf' (tested on Mac OS X) and
'nat' methods.
