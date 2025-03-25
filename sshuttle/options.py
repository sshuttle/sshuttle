import re
import socket
import sys
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
#
# In addition, the port number can be specified as a range:
# 1.2.3.4:8000-8080.
#
# Can return multiple matches if the domain name used in the request
# has multiple IP addresses.
def parse_subnetport(s):

    if s.count(':') > 1:
        rx = r'(?:\[?(?:\*\.)?([\w\:]+)(?:/(\d+))?]?)(?::(\d+)(?:-(\d+))?)?$'
    else:
        rx = r'((?:\*\.)?[\w\.\-]+)(?:/(\d+))?(?::(\d+)(?:-(\d+))?)?$'

    m = re.match(rx, s)
    if not m:
        raise Fatal('%r is not a valid address/mask:port format' % s)

    # Ports range from fport to lport. If only one port is specified,
    # fport is defined and lport is None.
    #
    # cidr is the mask defined with the slash notation
    host, cidr, fport, lport = m.groups()
    try:
        addrinfo = socket.getaddrinfo(host, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise Fatal('Unable to resolve address: %s' % host)

    # If the address is a domain with multiple IPs and a mask is also
    # provided, proceed cautiously:
    if cidr is not None:
        addr_v6 = [a for a in addrinfo if a[0] == socket.AF_INET6]
        addr_v4 = [a for a in addrinfo if a[0] == socket.AF_INET]

        # Refuse to proceed if IPv4 and IPv6 addresses are present:
        if len(addr_v6) > 0 and len(addr_v4) > 0:
            raise Fatal("%s has IPv4 and IPv6 addresses, so the mask "
                        "of /%s is not supported. Specify the IP "
                        "addresses directly if you wish to specify "
                        "a mask." % (host, cidr))

        # Warn if a domain has multiple IPs of the same type (IPv4 vs
        # IPv6) and the mask is applied to all of the IPs.
        if len(addr_v4) > 1 or len(addr_v6) > 1:
            print("WARNING: %s has multiple IP addresses. The "
                  "mask of /%s is applied to all of the addresses."
                  % (host, cidr))

    rv = []
    for a in addrinfo:
        family, _, _, _, addr = a

        # Largest possible slash value we can use with this IP:
        max_cidr = 32 if family == socket.AF_INET else 128

        if cidr is None:  # if no mask, use largest mask
            cidr_to_use = max_cidr
        else:   # verify user-provided mask is appropriate
            cidr_to_use = int(cidr)
            if not 0 <= cidr_to_use <= max_cidr:
                raise Fatal('Slash in CIDR notation (/%d) is '
                            'not between 0 and %d'
                            % (cidr_to_use, max_cidr))

        rv.append((family, addr[0], cidr_to_use,
                   int(fport or 0), int(lport or fport or 0)))

    return rv


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

    host, port = m.groups()
    host = host or '0.0.0.0'
    port = int(port or 0)

    try:
        addrinfo = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        raise Fatal('Unable to resolve address: %s' % host)

    if len(addrinfo) > 1:
        print("WARNING: Host %s has more than one IP, only using one of them."
              % host)

    family, _, _, _, addr = min(addrinfo)
    # Note: addr contains (ip, port)
    return (family,) + addr[:2]


def parse_list(lst):
    """Parse a comma separated string into a list."""
    return re.split(r'[\s,]+', lst.strip()) if lst else []


def parse_namespace(namespace):
    try:
        assert re.fullmatch(
            r'(@?[a-z_A-Z]\w+(?:\.@?[a-z_A-Z]\w+)*)', namespace)
        return namespace
    except AssertionError:
        raise Fatal("%r is not a valid namespace name." % namespace)


class Concat(Action):
    def __init__(self, option_strings, dest, nargs=None, **kwargs):
        if nargs is not None:
            raise ValueError("nargs not supported")
        super(Concat, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        curr_value = getattr(namespace, self.dest, None) or []
        setattr(namespace, self.dest, curr_value + values)


# Override one function in the ArgumentParser so that we can have
# better control for how we parse files containing arguments. We
# expect one argument per line, but strip whitespace/quotes from the
# beginning/end of the lines.
class MyArgumentParser(ArgumentParser):
    def convert_arg_line_to_args(self, arg_line):
        # Ignore comments
        if arg_line.startswith("#"):
            return []

        # strip whitespace at beginning and end of line
        arg_line = arg_line.strip()

        # When copying parameters from the command line to a file,
        # some users might copy the quotes they used on the command
        # line into the config file. We ignore these if the line
        # starts and ends with the same quote.
        if arg_line.startswith("'") and arg_line.endswith("'") or \
           arg_line.startswith('"') and arg_line.endswith('"'):
            arg_line = arg_line[1:-1]

        return [arg_line]


parser = MyArgumentParser(
    prog="sshuttle",
    usage="%(prog)s [-l [ip:]port] -r [user@]sshserver[:port] <subnets...>",
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
    (comma separated)
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

if sys.platform == 'win32':
    method_choices = ["auto", "windivert"]
else:
    method_choices = ["auto", "nft", "nat", "tproxy", "pf", "ipfw"]

parser.add_argument(
    "--method",
    choices=method_choices,
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
    increase debug message verbosity (can be used more than once)
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
    "--no-cmd-delimiter",
    action="store_false",
    dest="add_cmd_delimiter",
    help="""
    do not add a double dash before the python command
    """
)
parser.add_argument(
    "--remote-shell",
    metavar="PROGRAM",
    help="""
    alternate remote shell program instead of defacto posix shell.
    For Windows targets it would be either `cmd` or `powershell` unless something like git-bash is in use.
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
    "--group",
    help="""
    apply all the rules only to this linux group
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
    "--sudoers-no-modify",
    action="store_true",
    help="""
    Prints a sudo configuration to STDOUT which allows a user to
    run sshuttle without a password. This option is INSECURE because,
    with some cleverness, it also allows the user to run any command
    as root without a password. The output also includes a suggested
    method for you to install the configuration.
    """
)
parser.add_argument(
    "--sudoers-user",
    default="",
    help="""
    Set the user name or group with %%group_name for passwordless operation.
    Default is the current user. Only works with the --sudoers-no-modify option.
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
parser.add_argument(
    "-t", "--tmark",
    metavar="[MARK]",
    default="0x01",
    help="""
    tproxy optional traffic mark with provided MARK value in
    hexadecimal (default '0x01')
    """
)

if sys.platform == 'linux':
    net_ns_group = parser.add_mutually_exclusive_group(
        required=False)

    net_ns_group.add_argument(
        '--namespace',
        type=parse_namespace,
        help="Run inside of a net namespace with the given name."
    )
    net_ns_group.add_argument(
        '--namespace-pid',
        type=int,
        help="""
        Run inside the net namespace used by the process with
        the given pid."""
    )
