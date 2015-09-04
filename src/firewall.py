import errno
import socket
import select
import signal
import struct
import compat.ssubprocess as ssubprocess
import ssyslog
import sys
import os
import re
from helpers import log, debug1, debug3, islocal, Fatal, family_to_string, \
    resolvconf_nameservers
from fcntl import ioctl
from ctypes import c_char, c_uint8, c_uint16, c_uint32, Union, Structure, \
	sizeof, addressof, memmove


# python doesn't have a definition for this
IPPROTO_DIVERT = 254


def nonfatal(func, *args):
    try:
        func(*args)
    except Fatal, e:
        log('error: %s\n' % e)


def ipt_chain_exists(family, table, name):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-t', table, '-nL']
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE)
    for line in p.stdout:
        if line.startswith('Chain %s ' % name):
            return True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def _ipt(family, table, *args):
    if family == socket.AF_INET6:
        argv = ['ip6tables', '-t', table] + list(args)
    elif family == socket.AF_INET:
        argv = ['iptables', '-t', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


_no_ttl_module = False


def _ipt_ttl(family, *args):
    global _no_ttl_module
    if not _no_ttl_module:
        # we avoid infinite loops by generating server-side connections
        # with ttl 42.  This makes the client side not recapture those
        # connections, in case client == server.
        try:
            argsplus = list(args) + ['-m', 'ttl', '!', '--ttl', '42']
            _ipt(family, *argsplus)
        except Fatal:
            _ipt(family, *args)
            # we only get here if the non-ttl attempt succeeds
            log('sshuttle: warning: your iptables is missing '
                'the ttl module.\n')
            _no_ttl_module = True
    else:
        _ipt(family, *args)


# We name the chain based on the transproxy port number so that it's possible
# to run multiple copies of sshuttle at the same time.  Of course, the
# multiple copies shouldn't have overlapping subnets, or only the most-
# recently-started one will win (because we use "-I OUTPUT 1" instead of
# "-A OUTPUT").
def do_iptables_nat(port, dnsport, family, subnets, udp):
    # only ipv4 supported with NAT
    if family != socket.AF_INET:
        raise Exception(
            'Address family "%s" unsupported by nat method'
            % family_to_string(family))
    if udp:
        raise Exception("UDP not supported by nat method")

    table = "nat"

    def ipt(*args):
        return _ipt(family, table, *args)

    def ipt_ttl(*args):
        return _ipt_ttl(family, table, *args)

    chain = 'sshuttle-%s' % port

    # basic cleanup/setup of chains
    if ipt_chain_exists(family, table, chain):
        nonfatal(ipt, '-D', 'OUTPUT', '-j', chain)
        nonfatal(ipt, '-D', 'PREROUTING', '-j', chain)
        nonfatal(ipt, '-F', chain)
        ipt('-X', chain)

    if subnets or dnsport:
        ipt('-N', chain)
        ipt('-F', chain)
        ipt('-I', 'OUTPUT', '1', '-j', chain)
        ipt('-I', 'PREROUTING', '1', '-j', chain)

    if subnets:
        # create new subnet entries.  Note that we're sorting in a very
        # particular order: we need to go from most-specific (largest swidth)
        # to least-specific, and at any given level of specificity, we want
        # excludes to come first.  That's why the columns are in such a non-
        # intuitive order.
        for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: s[1], reverse=True):
            if sexclude:
                ipt('-A', chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-p', 'tcp')
            else:
                ipt_ttl('-A', chain, '-j', 'REDIRECT',
                        '--dest', '%s/%s' % (snet, swidth),
                        '-p', 'tcp',
                        '--to-ports', str(port))

    if dnsport:
        nslist = resolvconf_nameservers()
        for f, ip in filter(lambda i: i[0] == family, nslist):
            ipt_ttl('-A', chain, '-j', 'REDIRECT',
                    '--dest', '%s/32' % ip,
                    '-p', 'udp',
                    '--dport', '53',
                    '--to-ports', str(dnsport))


def do_iptables_tproxy(port, dnsport, family, subnets, udp):
    if family not in [socket.AF_INET, socket.AF_INET6]:
        raise Exception(
            'Address family "%s" unsupported by tproxy method'
            % family_to_string(family))

    table = "mangle"

    def ipt(*args):
        return _ipt(family, table, *args)

    def ipt_ttl(*args):
        return _ipt_ttl(family, table, *args)

    mark_chain = 'sshuttle-m-%s' % port
    tproxy_chain = 'sshuttle-t-%s' % port
    divert_chain = 'sshuttle-d-%s' % port

    # basic cleanup/setup of chains
    if ipt_chain_exists(family, table, mark_chain):
        ipt('-D', 'OUTPUT', '-j', mark_chain)
        ipt('-F', mark_chain)
        ipt('-X', mark_chain)

    if ipt_chain_exists(family, table, tproxy_chain):
        ipt('-D', 'PREROUTING', '-j', tproxy_chain)
        ipt('-F', tproxy_chain)
        ipt('-X', tproxy_chain)

    if ipt_chain_exists(family, table, divert_chain):
        ipt('-F', divert_chain)
        ipt('-X', divert_chain)

    if subnets or dnsport:
        ipt('-N', mark_chain)
        ipt('-F', mark_chain)
        ipt('-N', divert_chain)
        ipt('-F', divert_chain)
        ipt('-N', tproxy_chain)
        ipt('-F', tproxy_chain)
        ipt('-I', 'OUTPUT', '1', '-j', mark_chain)
        ipt('-I', 'PREROUTING', '1', '-j', tproxy_chain)
        ipt('-A', divert_chain, '-j', 'MARK', '--set-mark', '1')
        ipt('-A', divert_chain, '-j', 'ACCEPT')
        ipt('-A', tproxy_chain, '-m', 'socket', '-j', divert_chain,
            '-m', 'tcp', '-p', 'tcp')
    if subnets and udp:
        ipt('-A', tproxy_chain, '-m', 'socket', '-j', divert_chain,
            '-m', 'udp', '-p', 'udp')

    if dnsport:
        nslist = resolvconf_nameservers()
        for f, ip in filter(lambda i: i[0] == family, nslist):
            ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', '1',
                '--dest', '%s/32' % ip,
                '-m', 'udp', '-p', 'udp', '--dport', '53')
            ipt('-A', tproxy_chain, '-j', 'TPROXY', '--tproxy-mark', '0x1/0x1',
                '--dest', '%s/32' % ip,
                '-m', 'udp', '-p', 'udp', '--dport', '53',
                '--on-port', str(dnsport))

    if subnets:
        for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: s[1], reverse=True):
            if sexclude:
                ipt('-A', mark_chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'tcp', '-p', 'tcp')
                ipt('-A', tproxy_chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'tcp', '-p', 'tcp')
            else:
                ipt('-A', mark_chain, '-j', 'MARK',
                    '--set-mark', '1',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'tcp', '-p', 'tcp')
                ipt('-A', tproxy_chain, '-j', 'TPROXY',
                    '--tproxy-mark', '0x1/0x1',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'tcp', '-p', 'tcp',
                    '--on-port', str(port))

            if sexclude and udp:
                ipt('-A', mark_chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'udp', '-p', 'udp')
                ipt('-A', tproxy_chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'udp', '-p', 'udp')
            elif udp:
                ipt('-A', mark_chain, '-j', 'MARK',
                    '--set-mark', '1',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'udp', '-p', 'udp')
                ipt('-A', tproxy_chain, '-j', 'TPROXY',
                    '--tproxy-mark', '0x1/0x1',
                    '--dest', '%s/%s' % (snet, swidth),
                    '-m', 'udp', '-p', 'udp',
                    '--on-port', str(port))


def ipfw_rule_exists(n):
    argv = ['ipfw', 'list']
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE)
    found = False
    for line in p.stdout:
        if line.startswith('%05d ' % n):
            if not ('ipttl 42' in line
                    or ('skipto %d' % (n + 1)) in line
                    or 'check-state' in line):
                log('non-sshuttle ipfw rule: %r\n' % line.strip())
                raise Fatal('non-sshuttle ipfw rule #%d already exists!' % n)
            found = True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    return found


_oldctls = {}


def _fill_oldctls(prefix):
    argv = ['sysctl', prefix]
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE)
    for line in p.stdout:
        assert(line[-1] == '\n')
        (k, v) = line[:-1].split(': ', 1)
        _oldctls[k] = v
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    if not line:
        raise Fatal('%r returned no data' % (argv,))


def _sysctl_set(name, val):
    argv = ['sysctl', '-w', '%s=%s' % (name, val)]
    debug1('>> %s\n' % ' '.join(argv))
    return ssubprocess.call(argv, stdout=open('/dev/null', 'w'))


_changedctls = []


def sysctl_set(name, val, permanent=False):
    PREFIX = 'net.inet.ip'
    assert(name.startswith(PREFIX + '.'))
    val = str(val)
    if not _oldctls:
        _fill_oldctls(PREFIX)
    if not (name in _oldctls):
        debug1('>> No such sysctl: %r\n' % name)
        return False
    oldval = _oldctls[name]
    if val != oldval:
        rv = _sysctl_set(name, val)
        if rv == 0 and permanent:
            debug1('>>   ...saving permanently in /etc/sysctl.conf\n')
            f = open('/etc/sysctl.conf', 'a')
            f.write('\n'
                    '# Added by sshuttle\n'
                    '%s=%s\n' % (name, val))
            f.close()
        else:
            _changedctls.append(name)
        return True


def _udp_unpack(p):
    src = (socket.inet_ntoa(p[12:16]), struct.unpack('!H', p[20:22])[0])
    dst = (socket.inet_ntoa(p[16:20]), struct.unpack('!H', p[22:24])[0])
    return src, dst


def _udp_repack(p, src, dst):
    addrs = socket.inet_aton(src[0]) + socket.inet_aton(dst[0])
    ports = struct.pack('!HH', src[1], dst[1])
    return p[:12] + addrs + ports + p[24:]


_real_dns_server = [None]


def _handle_diversion(divertsock, dnsport):
    p, tag = divertsock.recvfrom(4096)
    src, dst = _udp_unpack(p)
    debug3('got diverted packet from %r to %r\n' % (src, dst))
    if dst[1] == 53:
        # outgoing DNS
        debug3('...packet is a DNS request.\n')
        _real_dns_server[0] = dst
        dst = ('127.0.0.1', dnsport)
    elif src[1] == dnsport:
        if islocal(src[0], divertsock.family):
            debug3('...packet is a DNS response.\n')
            src = _real_dns_server[0]
    else:
        log('weird?! unexpected divert from %r to %r\n' % (src, dst))
        assert(0)
    newp = _udp_repack(p, src, dst)
    divertsock.sendto(newp, tag)


def ipfw(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def do_ipfw(port, dnsport, family, subnets, udp):
    # IPv6 not supported
    if family not in [socket.AF_INET, ]:
        raise Exception(
            'Address family "%s" unsupported by ipfw method'
            % family_to_string(family))
    if udp:
        raise Exception("UDP not supported by ipfw method")

    sport = str(port)
    xsport = str(port + 1)

    # cleanup any existing rules
    if ipfw_rule_exists(port):
        ipfw('delete', sport)

    while _changedctls:
        name = _changedctls.pop()
        oldval = _oldctls[name]
        _sysctl_set(name, oldval)

    if subnets or dnsport:
        sysctl_set('net.inet.ip.fw.enable', 1)
        changed = sysctl_set('net.inet.ip.scopedroute', 0, permanent=True)
        if changed:
            log("\n"
                "        WARNING: ONE-TIME NETWORK DISRUPTION:\n"
                "        =====================================\n"
                "sshuttle has changed a MacOS kernel setting to work around\n"
                "a bug in MacOS 10.6.  This will cause your network to drop\n"
                "within 5-10 minutes unless you restart your network\n"
                "interface (change wireless networks or unplug/plug the\n"
                "ethernet port) NOW, then restart sshuttle.  The fix is\n"
                "permanent; you only have to do this once.\n\n")
            sys.exit(1)

        ipfw('add', sport, 'check-state', 'ip',
             'from', 'any', 'to', 'any')

    if subnets:
        # create new subnet entries
        for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: s[1], reverse=True):
            if sexclude:
                ipfw('add', sport, 'skipto', xsport,
                     'tcp',
                     'from', 'any', 'to', '%s/%s' % (snet, swidth))
            else:
                ipfw('add', sport, 'fwd', '127.0.0.1,%d' % port,
                     'tcp',
                     'from', 'any', 'to', '%s/%s' % (snet, swidth),
                     'not', 'ipttl', '42', 'keep-state', 'setup')

    # This part is much crazier than it is on Linux, because MacOS (at least
    # 10.6, and probably other versions, and maybe FreeBSD too) doesn't
    # correctly fixup the dstip/dstport for UDP packets when it puts them
    # through a 'fwd' rule.  It also doesn't fixup the srcip/srcport in the
    # response packet.  In Linux iptables, all that happens magically for us,
    # so we just redirect the packets and relax.
    #
    # On MacOS, we have to fix the ports ourselves.  For that, we use a
    # 'divert' socket, which receives raw packets and lets us mangle them.
    #
    # Here's how it works.  Let's say the local DNS server is 1.1.1.1:53,
    # and the remote DNS server is 2.2.2.2:53, and the local transproxy port
    # is 10.0.0.1:12300, and a client machine is making a request from
    # 10.0.0.5:9999. We see a packet like this:
    #    10.0.0.5:9999 -> 1.1.1.1:53
    # Since the destip:port matches one of our local nameservers, it will
    # match a 'fwd' rule, thus grabbing it on the local machine.  However,
    # the local kernel will then see a packet addressed to *:53 and
    # not know what to do with it; there's nobody listening on port 53.  Thus,
    # we divert it, rewriting it into this:
    #    10.0.0.5:9999 -> 10.0.0.1:12300
    # This gets proxied out to the server, which sends it to 2.2.2.2:53,
    # and the answer comes back, and the proxy sends it back out like this:
    #    10.0.0.1:12300 -> 10.0.0.5:9999
    # But that's wrong!  The original machine expected an answer from
    # 1.1.1.1:53, so we have to divert the *answer* and rewrite it:
    #    1.1.1.1:53 -> 10.0.0.5:9999
    #
    # See?  Easy stuff.
    if dnsport:
        divertsock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                   IPPROTO_DIVERT)
        divertsock.bind(('0.0.0.0', port))  # IP field is ignored

        nslist = resolvconf_nameservers()
        for f, ip in filter(lambda i: i[0] == family, nslist):
            # relabel and then catch outgoing DNS requests
            ipfw('add', sport, 'divert', sport,
                 'udp',
                 'from', 'any', 'to', '%s/32' % ip, '53',
                 'not', 'ipttl', '42')
        # relabel DNS responses
        ipfw('add', sport, 'divert', sport,
             'udp',
             'from', 'any', str(dnsport), 'to', 'any',
             'not', 'ipttl', '42')

        def do_wait():
            while 1:
                r, w, x = select.select([sys.stdin, divertsock], [], [])
                if divertsock in r:
                    _handle_diversion(divertsock, dnsport)
                if sys.stdin in r:
                    return
    else:
        do_wait = None

    return do_wait


def pfctl(args, stdin = None):
    argv = ['pfctl'] + list(args.split(" "))
    debug1('>> %s\n' % ' '.join(argv))

    p = ssubprocess.Popen(argv, stdin = ssubprocess.PIPE, 
                                stdout = ssubprocess.PIPE, 
                                stderr = ssubprocess.PIPE)
    o = p.communicate(stdin)
    if p.returncode:
        raise Fatal('%r returned %d' % (argv, p.returncode))

    return o

_pf_context = {'started_by_sshuttle': False, 'Xtoken':''}

def do_pf(port, dnsport, family, subnets, udp):
    global _pf_started_by_sshuttle
    tables = []
    translating_rules = []
    filtering_rules = []

    if subnets:
        includes=[]
        # If a given subnet is both included and excluded, list the exclusion
        # first; the table will ignore the second, opposite definition
        for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: (s[1], s[2]), reverse=True):
                    includes.append("%s%s/%s" % ("!" if sexclude else "", snet, swidth))

        tables.append('table <forward_subnets> {%s}' % ','.join(includes))
        translating_rules.append('rdr pass on lo0 proto tcp to <forward_subnets> -> 127.0.0.1 port %r' % port)
        filtering_rules.append('pass out route-to lo0 inet proto tcp to <forward_subnets> keep state')

        if dnsport:
            nslist = resolvconf_nameservers()
            tables.append('table <dns_servers> {%s}' % ','.join([ns[1] for ns in nslist]))
            translating_rules.append('rdr pass on lo0 proto udp to <dns_servers> port 53 -> 127.0.0.1 port %r' % dnsport)
            filtering_rules.append('pass out route-to lo0 inet proto udp to <dns_servers> port 53 keep state')

        rules = '\n'.join(tables + translating_rules + filtering_rules) + '\n'

        pf_status = pfctl('-s all')[0]
        if not '\nrdr-anchor "sshuttle" all\n' in pf_status:
            pf_add_anchor_rule(PF_RDR, "sshuttle")        
        if not '\nanchor "sshuttle" all\n' in pf_status:
            pf_add_anchor_rule(PF_PASS, "sshuttle")

        pfctl('-a sshuttle -f /dev/stdin', rules)
        if sys.platform == "darwin":
            o = pfctl('-E')
            _pf_context['Xtoken'] = re.search(r'Token : (.+)', o[1]).group(1)
        elif 'INFO:\nStatus: Disabled' in pf_status: 
            pfctl('-e')
            _pf_context['started_by_sshuttle'] = True
    else:
        pfctl('-a sshuttle -F all')
        if sys.platform == "darwin":
            pfctl('-X %s' % _pf_context['Xtoken'])
        elif _pf_context['started_by_sshuttle']:
            pfctl('-d')


def program_exists(name):
    paths = (os.getenv('PATH') or os.defpath).split(os.pathsep)
    for p in paths:
        fn = '%s/%s' % (p, name)
        if os.path.exists(fn):
            return not os.path.isdir(fn) and os.access(fn, os.X_OK)


hostmap = {}


def rewrite_etc_hosts(port):
    HOSTSFILE = '/etc/hosts'
    BAKFILE = '%s.sbak' % HOSTSFILE
    APPEND = '# sshuttle-firewall-%d AUTOCREATED' % port
    old_content = ''
    st = None
    try:
        old_content = open(HOSTSFILE).read()
        st = os.stat(HOSTSFILE)
    except IOError, e:
        if e.errno == errno.ENOENT:
            pass
        else:
            raise
    if old_content.strip() and not os.path.exists(BAKFILE):
        os.link(HOSTSFILE, BAKFILE)
    tmpname = "%s.%d.tmp" % (HOSTSFILE, port)
    f = open(tmpname, 'w')
    for line in old_content.rstrip().split('\n'):
        if line.find(APPEND) >= 0:
            continue
        f.write('%s\n' % line)
    for (name, ip) in sorted(hostmap.items()):
        f.write('%-30s %s\n' % ('%s %s' % (ip, name), APPEND))
    f.close()

    if st:
        os.chown(tmpname, st.st_uid, st.st_gid)
        os.chmod(tmpname, st.st_mode)
    else:
        os.chown(tmpname, 0, 0)
        os.chmod(tmpname, 0644)
    os.rename(tmpname, HOSTSFILE)


def restore_etc_hosts(port):
    global hostmap
    hostmap = {}
    rewrite_etc_hosts(port)


# This are some classes and functions used to support pf in yosemite. 
class pf_state_xport(Union):
    _fields_ = [("port", c_uint16),
                ("call_id", c_uint16),
                ("spi", c_uint32)]

class pf_addr(Structure):
    class _pfa(Union):
        _fields_ = [("v4",            c_uint32),      # struct in_addr
                    ("v6",            c_uint32 * 4),  # struct in6_addr
                    ("addr8",         c_uint8 * 16),
                    ("addr16",        c_uint16 * 8),
                    ("addr32",        c_uint32 * 4)]

    _fields_ = [("pfa",               _pfa)]
    _anonymous_ = ("pfa",)

class pfioc_natlook(Structure):
    _fields_ = [("saddr", pf_addr),
                ("daddr", pf_addr),
                ("rsaddr", pf_addr),
                ("rdaddr", pf_addr),
                ("sxport", pf_state_xport),
                ("dxport", pf_state_xport),
                ("rsxport", pf_state_xport),
                ("rdxport", pf_state_xport),
                ("af", c_uint8),                      # sa_family_t  
                ("proto", c_uint8),
                ("proto_variant", c_uint8),
                ("direction", c_uint8)]

pfioc_rule = c_char * 3104  # sizeof(struct pfioc_rule)

pfioc_pooladdr = c_char * 1136 # sizeof(struct pfioc_pooladdr) 

MAXPATHLEN = 1024

DIOCNATLOOK = ((0x40000000L | 0x80000000L) | ((sizeof(pfioc_natlook) & 0x1fff) << 16) | ((ord('D')) << 8) | (23))
DIOCCHANGERULE = ((0x40000000L | 0x80000000L) | ((sizeof(pfioc_rule) & 0x1fff) << 16) | ((ord('D')) << 8) | (26))
DIOCBEGINADDRS = ((0x40000000L | 0x80000000L) | ((sizeof(pfioc_pooladdr) & 0x1fff) << 16) | ((ord('D')) << 8) | (51))

PF_CHANGE_ADD_TAIL = 2
PF_CHANGE_GET_TICKET = 6

PF_PASS = 0
PF_RDR = 8

PF_OUT = 2

_pf_fd = None

def pf_get_dev():
    global _pf_fd
    if _pf_fd == None:
        _pf_fd = os.open('/dev/pf', os.O_RDWR)

    return _pf_fd

def pf_query_nat(family, proto, src_ip, src_port, dst_ip, dst_port):
    [proto, family, src_port, dst_port] = [int(v) for v in [proto, family, src_port, dst_port]]
    
    length = 4 if family == socket.AF_INET else 16

    pnl = pfioc_natlook()
    pnl.proto = proto
    pnl.direction = PF_OUT
    pnl.af = family
    memmove(addressof(pnl.saddr), socket.inet_pton(pnl.af, src_ip), length)
    pnl.sxport.port = socket.htons(src_port)
    memmove(addressof(pnl.daddr), socket.inet_pton(pnl.af, dst_ip), length)
    pnl.dxport.port = socket.htons(dst_port)

    ioctl(pf_get_dev(), DIOCNATLOOK, (c_char * sizeof(pnl)).from_address(addressof(pnl)))

    ip = socket.inet_ntop(pnl.af, (c_char * length).from_address(addressof(pnl.rdaddr)))
    port = socket.ntohs(pnl.rdxport.port)
    return (ip, port)

def pf_add_anchor_rule(type, name):
    ACTION_OFFSET = 0
    POOL_TICKET_OFFSET = 8
    ANCHOR_CALL_OFFSET = 1040
    RULE_ACTION_OFFSET = 3068

    pr = pfioc_rule()
    ppa = pfioc_pooladdr()

    ioctl(pf_get_dev(), DIOCBEGINADDRS, ppa)

    memmove(addressof(pr) + POOL_TICKET_OFFSET, ppa[4:8], 4)  #pool_ticket
    memmove(addressof(pr) + ANCHOR_CALL_OFFSET, name, min(MAXPATHLEN, len(name)))  #anchor_call = name
    memmove(addressof(pr) + RULE_ACTION_OFFSET, struct.pack('I', type), 4)  #rule.action = type

    memmove(addressof(pr) + ACTION_OFFSET, struct.pack('I', PF_CHANGE_GET_TICKET), 4) #action = PF_CHANGE_GET_TICKET
    ioctl(pf_get_dev(), DIOCCHANGERULE, pr)

    memmove(addressof(pr) + ACTION_OFFSET, struct.pack('I', PF_CHANGE_ADD_TAIL), 4) #action = PF_CHANGE_ADD_TAIL
    ioctl(pf_get_dev(), DIOCCHANGERULE, pr)


# This is some voodoo for setting up the kernel's transparent
# proxying stuff.  If subnets is empty, we just delete our sshuttle rules;
# otherwise we delete it, then make them from scratch.
#
# This code is supposed to clean up after itself by deleting its rules on
# exit.  In case that fails, it's not the end of the world; future runs will
# supercede it in the transproxy list, at least, so the leftover rules
# are hopefully harmless.
def main(port_v6, port_v4, dnsport_v6, dnsport_v4, method, udp, syslog):
    assert(port_v6 >= 0)
    assert(port_v6 <= 65535)
    assert(port_v4 >= 0)
    assert(port_v4 <= 65535)
    assert(dnsport_v6 >= 0)
    assert(dnsport_v6 <= 65535)
    assert(dnsport_v4 >= 0)
    assert(dnsport_v4 <= 65535)

    if os.getuid() != 0:
        raise Fatal('you must be root (or enable su/sudo) to set the firewall')

    if method == "auto":
        if program_exists('ipfw'):
            method = "ipfw"
        elif program_exists('iptables'):
            method = "nat"
        elif program_exists('pfctl'):
            method = "pf"
        else:
            raise Fatal("can't find either ipfw, iptables or pfctl; check your PATH")

    if method == "nat":
        do_it = do_iptables_nat
    elif method == "tproxy":
        do_it = do_iptables_tproxy
    elif method == "ipfw":
        do_it = do_ipfw
    elif method == "pf":
        do_it = do_pf
    else:
        raise Exception('Unknown method "%s"' % method)

    # because of limitations of the 'su' command, the *real* stdin/stdout
    # are both attached to stdout initially.  Clone stdout into stdin so we
    # can read from it.
    os.dup2(1, 0)

    if syslog:
        ssyslog.start_syslog()
        ssyslog.stderr_to_syslog()

    debug1('firewall manager ready method %s.\n' % method)
    sys.stdout.write('READY %s\n' % method)
    sys.stdout.flush()

    # don't disappear if our controlling terminal or stdout/stderr
    # disappears; we still have to clean up.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # ctrl-c shouldn't be passed along to me.  When the main sshuttle dies,
    # I'll die automatically.
    os.setsid()

    # we wait until we get some input before creating the rules.  That way,
    # sshuttle can launch us as early as possible (and get sudo password
    # authentication as early in the startup process as possible).
    line = sys.stdin.readline(128)
    if not line:
        return  # parent died; nothing to do

    subnets = []
    if line != 'ROUTES\n':
        raise Fatal('firewall: expected ROUTES but got %r' % line)
    while 1:
        line = sys.stdin.readline(128)
        if not line:
            raise Fatal('firewall: expected route but got %r' % line)
        elif line == 'GO\n':
            break
        try:
            (family, width, exclude, ip) = line.strip().split(',', 3)
        except:
            raise Fatal('firewall: expected route or GO but got %r' % line)
        subnets.append((int(family), int(width), bool(int(exclude)), ip))

    try:
        if line:
            debug1('firewall manager: starting transproxy.\n')

            subnets_v6 = filter(lambda i: i[0] == socket.AF_INET6, subnets)
            if port_v6:
                do_wait = do_it(
                    port_v6, dnsport_v6, socket.AF_INET6, subnets_v6, udp)
            elif len(subnets_v6) > 0:
                debug1("IPv6 subnets defined but IPv6 disabled\n")

            subnets_v4 = filter(lambda i: i[0] == socket.AF_INET, subnets)
            if port_v4:
                do_wait = do_it(
                    port_v4, dnsport_v4, socket.AF_INET, subnets_v4, udp)
            elif len(subnets_v4) > 0:
                debug1('IPv4 subnets defined but IPv4 disabled\n')

            sys.stdout.write('STARTED\n')

        try:
            sys.stdout.flush()
        except IOError:
            # the parent process died for some reason; he's surely been loud
            # enough, so no reason to report another error
            return

        # Now we wait until EOF or any other kind of exception.  We need
        # to stay running so that we don't need a *second* password
        # authentication at shutdown time - that cleanup is important!
        while 1:
            if do_wait:
                do_wait()
            line = sys.stdin.readline(128)
            if line.startswith('HOST '):
                (name, ip) = line[5:].strip().split(',', 1)
                hostmap[name] = ip
                rewrite_etc_hosts(port_v6 or port_v4)
            elif line.startswith('QUERY_PF_NAT '):
                try:
                    dst = pf_query_nat(*(line[13:].split(',')))
                    sys.stdout.write('QUERY_PF_NAT_SUCCESS %s,%r\n' % dst)
                except IOError, e:
                    sys.stdout.write('QUERY_PF_NAT_FAILURE %s\n' % e)

                sys.stdout.flush()
            elif line:
                raise Fatal('expected EOF, got %r' % line)
            else:
                break
    finally:
        try:
            debug1('firewall manager: undoing changes.\n')
        except:
            pass
        if port_v6:
            do_it(port_v6, 0, socket.AF_INET6, [], udp)
        if port_v4:
            do_it(port_v4, 0, socket.AF_INET, [], udp)
        restore_etc_hosts(port_v6 or port_v4)
