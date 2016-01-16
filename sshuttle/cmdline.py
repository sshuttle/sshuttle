import sys
import re
import socket
import sshuttle.helpers as helpers
import sshuttle.options as options
import sshuttle.client as client
import sshuttle.firewall as firewall
import sshuttle.hostwatch as hostwatch
import sshuttle.ssyslog as ssyslog
from sshuttle.helpers import family_ip_tuple, log, Fatal


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
    config_lines = []
    for line_no, line in enumerate(raw_config_lines):
        line = line.strip()
        if len(line) == 0:
            continue
        if line[0] == '#':
            continue
        config_lines.append(line)

    return config_lines


# list of:
# 1.2.3.4/5 or just 1.2.3.4
# 1:2::3/64 or just 1:2::3
def parse_subnets(subnets_str):
    subnets = []
    for s in subnets_str:
        if ':' in s:
            subnet = parse_subnet6(s)
        else:
            subnet = parse_subnet4(s)
        subnets.append(subnet)
    return subnets


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


optspec = """
sshuttle [-l [ip:]port] [-r [username@]sshserver[:port]] <subnets...>
sshuttle --firewall <port> <subnets...>
sshuttle --hostwatch
--
l,listen=  transproxy to this ip address and port number
H,auto-hosts scan for remote hostnames and update local /etc/hosts
N,auto-nets  automatically determine subnets to route
dns        capture local DNS requests and forward to the remote DNS server
ns-hosts=  capture and forward remote DNS requests to the following servers
method=    auto, nat, tproxy or pf
python=    path to python interpreter on the remote server
r,remote=  ssh hostname (and optional username) of remote sshuttle server
x,exclude= exclude this subnet (can be used more than once)
X,exclude-from=  exclude the subnets in a file (whitespace separated)
v,verbose  increase debug message verbosity
V,version  print the sshuttle version number and exit
e,ssh-cmd= the command to use to connect to the remote [ssh]
seed-hosts= with -H, use these hostnames for initial scan (comma-separated)
no-latency-control  sacrifice latency to improve bandwidth benchmarks
wrap=      restart counting channel numbers after this number (for testing)
disable-ipv6 disables ipv6 support
D,daemon   run in the background as a daemon
s,subnets= file where the subnets are stored, instead of on the command line
syslog     send log messages to syslog (default if you use --daemon)
pidfile=   pidfile name (only if using --daemon) [./sshuttle.pid]
server     (internal use only)
firewall   (internal use only)
hostwatch  (internal use only)
"""


def main():
    o = options.Options(optspec)
    (opt, flags, extra) = o.parse(sys.argv[1:])

    if opt.version:
        from sshuttle.version import version
        print(version)
        return 0
    if opt.daemon:
        opt.syslog = 1
    if opt.wrap:
        import sshuttle.ssnet as ssnet
        ssnet.MAX_CHANNEL = int(opt.wrap)
    helpers.verbose = opt.verbose or 0

    try:
        if opt.firewall:
            if len(extra) != 0:
                o.fatal('exactly zero arguments expected')
            return firewall.main(opt.method, opt.syslog)
        elif opt.hostwatch:
            return hostwatch.hw_main(extra)
        else:
            if len(extra) < 1 and not opt.auto_nets and not opt.subnets:
                o.fatal('at least one subnet, subnet file, or -N expected')
            includes = extra
            excludes = ['127.0.0.0/8']
            for k, v in flags:
                if k in ('-x', '--exclude'):
                    excludes.append(v)
                if k in ('-X', '--exclude-from'):
                    excludes += open(v).read().split()
            remotename = opt.remote
            if remotename == '' or remotename == '-':
                remotename = None
            nslist = [family_ip_tuple(ns) for ns in parse_list(opt.ns_hosts)]
            if opt.seed_hosts and not opt.auto_hosts:
                o.fatal('--seed-hosts only works if you also use -H')
            if opt.seed_hosts:
                sh = re.split(r'[\s,]+', (opt.seed_hosts or "").strip())
            elif opt.auto_hosts:
                sh = []
            else:
                sh = None
            if opt.subnets:
                includes = parse_subnet_file(opt.subnets)
            if not opt.method:
                method_name = "auto"
            elif opt.method in ["auto", "nat", "tproxy", "pf"]:
                method_name = opt.method
            else:
                o.fatal("method_name %s not supported" % opt.method)
            if opt.listen:
                ipport_v6 = None
                ipport_v4 = None
                list = opt.listen.split(",")
                for ip in list:
                    if '[' in ip and ']' in ip:
                        ipport_v6 = parse_ipport6(ip)
                    else:
                        ipport_v4 = parse_ipport4(ip)
            else:
                # parse_ipport4('127.0.0.1:0')
                ipport_v4 = "auto"
                # parse_ipport6('[::1]:0')
                ipport_v6 = "auto" if not opt.disable_ipv6 else None
            if opt.syslog:
                ssyslog.start_syslog()
                ssyslog.stderr_to_syslog()
            return_code = client.main(ipport_v6, ipport_v4,
                                      opt.ssh_cmd,
                                      remotename,
                                      opt.python,
                                      opt.latency_control,
                                      opt.dns,
                                      nslist,
                                      method_name,
                                      sh,
                                      opt.auto_nets,
                                      parse_subnets(includes),
                                      parse_subnets(excludes),
                                      opt.daemon, opt.pidfile)

            if return_code == 0:
                log('Normal exit code, exiting...')
            else:
                log('Abnormal exit code detected, failing...' % return_code)
            return return_code

    except Fatal as e:
        log('fatal: %s\n' % e)
        return 99
    except KeyboardInterrupt:
        log('\n')
        log('Keyboard interrupt: exiting.\n')
        return 1
