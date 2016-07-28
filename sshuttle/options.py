import re
import socket
from argparse import ArgumentParser, Action, ArgumentTypeError as Fatal
from sshuttle import __version__


# 1.2.3.4/5 or just 1.2.3.4
def parse_subnet4(s):
    m = re.match(r'(\d+)(?:\.(\d+)\.(\d+)\.(\d+))?(?:/(\d+))?$', s)
    if not m:
        raise Fatal('%r is not a valid IP subnet format' % s)
    (a, b, c, d, width) = m.groups()
    (a, b, c, d) = (int(a or 0), int(b or 0), int(c or 0), int(d or 0))
    if width is None:
        width = 32
    else:
        width = int(width)
    if a > 255 or b > 255 or c > 255 or d > 255:
        raise Fatal('%d.%d.%d.%d has numbers > 255' % (a, b, c, d))
    if width > 32:
        raise Fatal('*/%d is greater than the maximum of 32' % width)
    return(socket.AF_INET, '%d.%d.%d.%d' % (a, b, c, d), width)


# 1:2::3/64 or just 1:2::3
def parse_subnet6(s):
    m = re.match(r'(?:([a-fA-F\d:]+))?(?:/(\d+))?$', s)
    if not m:
        raise Fatal('%r is not a valid IP subnet format' % s)
    (net, width) = m.groups()
    if width is None:
        width = 128
    else:
        width = int(width)
    if width > 128:
        raise Fatal('*/%d is greater than the maximum of 128' % width)
    return(socket.AF_INET6, net, width)


# Subnet file, supporting empty lines and hash-started comment lines
def parse_subnet_file(s):
    try:
        handle = open(s, 'r')
    except OSError:
        raise Fatal('Unable to open subnet file: %s' % s)

    raw_config_lines = handle.readlines()
    subnets = []
    for line_no, line in enumerate(raw_config_lines):
        line = line.strip()
        if len(line) == 0:
            continue
        if line[0] == '#':
            continue
        subnets.append(parse_subnet(line))

    return subnets


# 1.2.3.4/5 or just 1.2.3.4
# 1:2::3/64 or just 1:2::3
def parse_subnet(subnet_str):
    if ':' in subnet_str:
        return parse_subnet6(subnet_str)
    else:
        return parse_subnet4(subnet_str)


# 1.2.3.4:567 or just 1.2.3.4 or just 567
def parse_ipport4(s):
    s = str(s)
    m = re.match(r'(?:(\d+)\.(\d+)\.(\d+)\.(\d+))?(?::)?(?:(\d+))?$', s)
    if not m:
        raise Fatal('%r is not a valid IP:port format' % s)
    (a, b, c, d, port) = m.groups()
    (a, b, c, d, port) = (int(a or 0), int(b or 0), int(c or 0), int(d or 0),
                          int(port or 0))
    if a > 255 or b > 255 or c > 255 or d > 255:
        raise Fatal('%d.%d.%d.%d has numbers > 255' % (a, b, c, d))
    if port > 65535:
        raise Fatal('*:%d is greater than the maximum of 65535' % port)
    if a is None:
        a = b = c = d = 0
    return ('%d.%d.%d.%d' % (a, b, c, d), port)


# [1:2::3]:456 or [1:2::3] or 456
def parse_ipport6(s):
    s = str(s)
    m = re.match(r'(?:\[([^]]*)])?(?::)?(?:(\d+))?$', s)
    if not m:
        raise Fatal('%s is not a valid IP:port format' % s)
    (ip, port) = m.groups()
    (ip, port) = (ip or '::', int(port or 0))
    return (ip, port)


def parse_list(list):
    return re.split(r'[\s,]+', list.strip()) if list else []


class Concat(Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not supported")
        super(Concat, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        curr_value = getattr(namespace, self.dest, [])
        setattr(namespace, self.dest, curr_value + values)


parser = ArgumentParser(
    prog="sshuttle",
    usage="%(prog)s [-l [ip:]port] [-r [user@]sshserver[:port]] <subnets...>"
)
parser.add_argument(
    "subnets",
    metavar="IP/MASK [IP/MASK...]",
    nargs="*",
    type=parse_subnet,
    help="""
    capture and forward traffic to these subnets (whitespace separated)
    """
)
parser.add_argument(
    "-l", "--listen",
    metavar="[IP:]PORT",
    help="""
    transproxy to this ip address and port number
    """
)
parser.add_argument(
    "-H", "--auto-hosts",
    action="store_true",
    help="""
    continuously scan for remote hostnames and update local /etc/hosts as they are found
    """
)
parser.add_argument(
    "-N", "--auto-nets",
    action="store_true",
    help="""
    automatically determine subnets to route
    """
)
parser.add_argument(
    "--dns",
    action="store_true",
    help="""
    capture local DNS requests and forward to the remote DNS server
    """
)
parser.add_argument(
    "--ns-hosts",
    metavar="IP[,IP]",
    default=[],
    type=parse_list,
    help="""
    capture and forward DNS requests made to the following servers
    """
)
parser.add_argument(
    "--method",
    choices=["auto", "nat", "tproxy", "pf"],
    metavar="TYPE",
    default="auto",
    help="""
    %(choices)s
    """
)
parser.add_argument(
    "--python",
    metavar="PATH",
    help="""
    path to python interpreter on the remote server
    """
)
parser.add_argument(
    "-r", "--remote",
    metavar="[USERNAME@]ADDR[:PORT]",
    help="""
    ssh hostname (and optional username) of remote %(prog)s server
    """
)
parser.add_argument(
    "-x", "--exclude",
    metavar="IP/MASK",
    action="append",
    default=[],
    type=parse_subnet,
    help="""
    exclude this subnet (can be used more than once)
    """
)
parser.add_argument(
    "-X", "--exclude-from",
    metavar="PATH",
    action=Concat,
    dest="exclude",
    type=parse_subnet_file,
    help="""
    exclude the subnets in a file (whitespace separated)
    """
)
parser.add_argument(
    "-v", "--verbose",
    action="count",
    default=0,
    help="""
    increase debug message verbosity
    """
)
parser.add_argument(
    "-V", "--version",
    action="version",
    version=__version__,
    help="""
    print the %(prog)s version number and exit
    """
)
parser.add_argument(
    "-e", "--ssh-cmd",
    metavar="CMD",
    default="ssh",
    help="""
    the command to use to connect to the remote [%(default)s]
    """
)
parser.add_argument(
    "--seed-hosts",
    metavar="HOSTNAME[,HOSTNAME]",
    default=[],
    help="""
    comma-separated list of hostnames for initial scan (may be used with or without --auto-hosts)
    """
)
parser.add_argument(
    "--no-latency-control",
    action="store_false",
    dest="latency_control",
    help="""
    sacrifice latency to improve bandwidth benchmarks
    """
)
parser.add_argument(
    "--wrap",
    metavar="NUM",
    type=int,
    help="""
    restart counting channel numbers after this number (for testing)
    """
)
parser.add_argument(
    "--disable-ipv6",
    action="store_true",
    help="""
    disable IPv6 support
    """
)
parser.add_argument(
    "-D", "--daemon",
    action="store_true",
    help="""
    run in the background as a daemon
    """
)
parser.add_argument(
    "-s", "--subnets",
    metavar="PATH",
    action=Concat,
    dest="subnets",
    type=parse_subnet_file,
    help="""
    file where the subnets are stored, instead of on the command line
    """
)
parser.add_argument(
    "--syslog",
    action="store_true",
    help="""
    send log messages to syslog (default if you use --daemon)
    """
)
parser.add_argument(
    "--pidfile",
    metavar="PATH",
    default="./sshuttle.pid",
    help="""
    pidfile name (only if using --daemon) [%(default)s]
    """
)
parser.add_argument(
    "--firewall",
    action="store_true",
    help="""
    (internal use only)
    """
)
parser.add_argument(
    "--hostwatch",
    action="store_true",
    help="""
    (internal use only)
    """
)
