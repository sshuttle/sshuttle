import re
import socket
from argparse import ArgumentParser, Action, ArgumentTypeError as Fatal

from sshuttle import __version__


# Subnet file, supporting empty lines and hash-started comment lines
def parse_subnetport_file(s):
    try:
        handle = open(s, 'r')
    except OSError:
        raise Fatal('Unable to open subnet file: %s' % s)

    raw_config_lines = handle.readlines()
    subnets = []
    for _, line in enumerate(raw_config_lines):
        line = line.strip()
        if not line:
            continue
        if line[0] == '#':
            continue
        subnets.append(parse_subnetport(line))

    return subnets


# 1.2.3.4/5:678, 1.2.3.4:567, 1.2.3.4/16 or just 1.2.3.4
# [1:2::3/64]:456, [1:2::3]:456, 1:2::3/64 or just 1:2::3
# example.com:123 or just example.com
def parse_subnetport(s):
    if s.count(':') > 1:
        rx = r'(?:\[?([\w\:]+)(?:/(\d+))?]?)(?::(\d+)(?:-(\d+))?)?$'
    else:
        rx = r'([\w\.\-]+)(?:/(\d+))?(?::(\d+)(?:-(\d+))?)?$'

    m = re.match(rx, s)
    if not m:
        raise Fatal('%r is not a valid address/mask:port format' % s)

    addr, width, fport, lport = m.groups()
    try:
        addrinfo = socket.getaddrinfo(addr, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise Fatal('Unable to resolve address: %s' % addr)

    family, _, _, _, addr = min(addrinfo)
    max_width = 32 if family == socket.AF_INET else 128
    width = int(width or max_width)
    if not 0 <= width <= max_width:
        raise Fatal('width %d is not between 0 and %d' % (width, max_width))

    return (family, addr[0], width, int(fport or 0), int(lport or fport or 0))


# 1.2.3.4:567 or just 1.2.3.4 or just 567
# [1:2::3]:456 or [1:2::3] or just [::]:567
# example.com:123 or just example.com
def parse_ipport(s):
    s = str(s)
    if s.isdigit():
        rx = r'()(\d+)$'
    elif ']' in s:
        rx = r'(?:\[([^]]+)])(?::(\d+))?$'
    else:
        rx = r'([\w\.\-]+)(?::(\d+))?$'

    m = re.match(rx, s)
    if not m:
        raise Fatal('%r is not a valid IP:port format' % s)

    ip, port = m.groups()
    ip = ip or '0.0.0.0'
    port = int(port or 0)

    try:
        addrinfo = socket.getaddrinfo(ip, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise Fatal('%r is not a valid IP:port format' % s)

    family, _, _, _, addr = min(addrinfo)
    return (family,) + addr[:2]


def parse_list(lst):
    return re.split(r'[\s,]+', lst.strip()) if lst else []


class Concat(Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not supported")
        super(Concat, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        curr_value = getattr(namespace, self.dest, None) or []
        setattr(namespace, self.dest, curr_value + values)


parser = ArgumentParser(
    prog="sshuttle",
    usage="%(prog)s [-l [ip:]port] [-r [user@]sshserver[:port]] <subnets...>",
    fromfile_prefix_chars="@"
)
parser.add_argument(
    "subnets",
    metavar="IP/MASK[:PORT[-PORT]]...",
    nargs="*",
    type=parse_subnetport,
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
    continuously scan for remote hostnames and update local /etc/hosts as
    they are found
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
    "--to-ns",
    metavar="IP[:PORT]",
    type=parse_ipport,
    help="""
    the DNS server to forward requests to; defaults to servers in
    /etc/resolv.conf on remote side if not given.
    """
)

parser.add_argument(
    "--method",
    choices=["auto", "nat", "nft", "tproxy", "pf", "ipfw"],
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
    metavar="[USERNAME[:PASSWORD]@]ADDR[:PORT]",
    help="""
    ssh hostname (and optional username and password) of remote %(prog)s server
    """
)
parser.add_argument(
    "-x", "--exclude",
    metavar="IP/MASK[:PORT[-PORT]]",
    action="append",
    default=[],
    type=parse_subnetport,
    help="""
    exclude this subnet (can be used more than once)
    """
)
parser.add_argument(
    "-X", "--exclude-from",
    metavar="PATH",
    action=Concat,
    dest="exclude",
    type=parse_subnetport_file,
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
    comma-separated list of hostnames for initial scan (may be used with
    or without --auto-hosts)
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
    "--latency-buffer-size",
    metavar="SIZE",
    type=int,
    default=32768,
    dest="latency_buffer_size",
    help="""
    size of latency control buffer
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
    dest="subnets_file",
    default=[],
    type=parse_subnetport_file,
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
    "--user",
    help="""
    apply all the rules only to this linux user
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
parser.add_argument(
    "--sudoers",
    action="store_true",
    help="""
    Add sshuttle to the sudoers for this user
    """
)
parser.add_argument(
    "--sudoers-no-modify",
    action="store_true",
    help="""
    Prints the sudoers config to STDOUT and DOES NOT modify anything.
    """
)
parser.add_argument(
    "--sudoers-user",
    default="",
    help="""
    Set the user name or group with %%group_name for passwordless operation.
    Default is the current user.set ALL for all users. Only works with
    --sudoers or --sudoers-no-modify option.
    """
)
parser.add_argument(
    "--sudoers-filename",
    default="sshuttle_auto",
    help="""
    Set the file name for the sudoers.d file to be added. Default is
    "sshuttle_auto". Only works with --sudoers or --sudoers-no-modify option.
    """
)
parser.add_argument(
    "--no-sudo-pythonpath",
    action="store_false",
    dest="sudo_pythonpath",
    help="""
    do not set PYTHONPATH when invoking sudo
    """
)
