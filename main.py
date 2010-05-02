#!/usr/bin/env python
import sys
import options, client

optspec = """
sshuttle [-l [ip:]port] [-r [username@]sshserver] <subnets...>
--
l,listen=  transproxy to this ip address and port number [default=0]
r,remote=  ssh hostname (and optional username) of remote sshuttle server
server     [internal use only]
iptables   [internal use only]
"""
o = options.Options('sshuttle', optspec)
(opt, flags, extra) = o.parse(sys.argv[1:])

if opt.server:
    o.fatal('server mode not implemented yet')
    sys.exit(1)
elif opt.iptables:
    o.fatal('iptables mode not implemented yet')
    sys.exit(1)
else:
    if len(extra) < 1:
        o.fatal('at least one argument expected')
    remotename = extra[0]
    if remotename == '' or remotename == '-':
        remotename = None
    subnets = extra[1:]
    sys.exit(client.main(remotename, subnets))
