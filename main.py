#!/usr/bin/env python
import sys, re
import options, client, iptables


# list of:
# 1.2.3.4/5 or just 1.2.3.4
def parse_subnets(subnets_str):
    subnets = []
    for s in subnets_str:
        m = re.match(r'(\d+)(?:\.(\d+)\.(\d+)\.(\d+))?(?:/(\d+))?$', s)
        if not m:
            raise Exception('%r is not a valid IP subnet format' % s)
        (a,b,c,d,width) = m.groups()
        (a,b,c,d) = (int(a or 0), int(b or 0), int(c or 0), int(d or 0))
        if width == None:
            width = 32
        else:
            width = int(width)
        if a > 255 or b > 255 or c > 255 or d > 255:
            raise Exception('%d.%d.%d.%d has numbers > 255' % (a,b,c,d))
        if width > 32:
            raise Exception('*/%d is greater than the maximum of 32' % width)
        subnets.append(('%d.%d.%d.%d' % (a,b,c,d), width))
    return subnets


# 1.2.3.4:567 or just 1.2.3.4 or just 567
def parse_ipport(s):
    s = str(s)
    m = re.match(r'(?:(\d+)\.(\d+)\.(\d+)\.(\d+))?(?::)?(?:(\d+))?$', s)
    if not m:
        raise Exception('%r is not a valid IP:port format' % s)
    (a,b,c,d,port) = m.groups()
    (a,b,c,d,port) = (int(a or 0), int(b or 0), int(c or 0), int(d or 0),
                      int(port or 0))
    if a > 255 or b > 255 or c > 255 or d > 255:
        raise Exception('%d.%d.%d.%d has numbers > 255' % (a,b,c,d))
    if port > 65535:
        raise Exception('*:%d is greater than the maximum of 65535' % port)
    if a == None:
        a = b = c = d = 0
    return ('%d.%d.%d.%d' % (a,b,c,d), port)


optspec = """
sshuttle [-l [ip:]port] [-r [username@]sshserver] <subnets...>
sshuttle --iptables <port> <subnets...>
sshuttle --server
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
    if len(extra) < 1:
        o.fatal('at least one argument expected')
    sys.exit(iptables.main(int(extra[0]),
                           parse_subnets(extra[1:])))
else:
    if len(extra) < 1:
        o.fatal('at least one subnet expected')
    remotename = extra[0]
    if remotename == '' or remotename == '-':
        remotename = None
    sys.exit(client.main(parse_ipport(opt.listen or '0.0.0.0:0'),
                         remotename,
                         parse_subnets(extra)))
