import sys
import select
import socket
import struct
import subprocess as ssubprocess
from sshuttle.helpers import log, debug1, debug3, islocal, \
    Fatal, family_to_string
from sshuttle.methods import BaseMethod


# python doesn't have a definition for this
IPPROTO_DIVERT = 254


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


class Method(BaseMethod):

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        # IPv6 not supported
        if family not in [socket.AF_INET, ]:
            raise Exception(
                'Address family "%s" unsupported by ipfw method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by ipfw method_name")

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

        # This part is much crazier than it is on Linux, because MacOS (at
        # least 10.6, and probably other versions, and maybe FreeBSD too)
        # doesn't correctly fixup the dstip/dstport for UDP packets when it
        # puts them through a 'fwd' rule.  It also doesn't fixup the
        # srcip/srcport in the response packet.  In Linux iptables, all that
        # happens magically for us, so we just redirect the packets and relax.
        #
        # On MacOS, we have to fix the ports ourselves.  For that, we use a
        # 'divert' socket, which receives raw packets and lets us mangle them.
        #
        # Here's how it works.  Let's say the local DNS server is 1.1.1.1:53,
        # and the remote DNS server is 2.2.2.2:53, and the local transproxy
        # port is 10.0.0.1:12300, and a client machine is making a request from
        # 10.0.0.5:9999. We see a packet like this:
        #    10.0.0.5:9999 -> 1.1.1.1:53
        # Since the destip:port matches one of our local nameservers, it will
        # match a 'fwd' rule, thus grabbing it on the local machine.  However,
        # the local kernel will then see a packet addressed to *:53 and not
        # know what to do with it; there's nobody listening on port 53.  Thus,
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

            for f, ip in [i for i in nslist if i[0] == family]:
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
