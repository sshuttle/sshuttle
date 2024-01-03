import os
import subprocess as ssubprocess
from sshuttle.methods import BaseMethod
from sshuttle.helpers import log, debug1, debug2, debug3, \
    Fatal, family_to_string, get_env, which

import socket

IP_BINDANY = 24
IP_RECVDSTADDR = 7
SOL_IPV6 = 41
IPV6_RECVDSTADDR = 74


def recv_udp(listener, bufsize):
    debug3('Accept UDP python using recvmsg.')
    data, ancdata, _, srcip = listener.recvmsg(4096,
                                               socket.CMSG_SPACE(4))
    dstip = None
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVDSTADDR:
            port = 53
            ip = socket.inet_ntop(socket.AF_INET, cmsg_data[0:4])
            dstip = (ip, port)
            break
    return (srcip, dstip, data)


def ipfw_rule_exists(n):
    argv = ['ipfw', 'list', '%d' % n]
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=get_env())

    found = False
    for line in p.stdout:
        if line.startswith(b'%05d ' % n):
            if 'check-state :sshuttle' not in line:
                log('non-sshuttle ipfw rule: %r' % line.strip())
                raise Fatal('non-sshuttle ipfw rule #%d already exists!' % n)
            found = True
            break
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    return found


_oldctls = {}


def _fill_oldctls(prefix):
    argv = ['sysctl', prefix]
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=get_env())
    for line in p.stdout:
        line = line.decode()
        assert line[-1] == '\n'
        (k, v) = line[:-1].split(': ', 1)
        _oldctls[k] = v.strip()
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    if not line:
        raise Fatal('%r returned no data' % (argv,))


def _sysctl_set(name, val):
    argv = ['sysctl', '-w', '%s=%s' % (name, val)]
    debug1('>> %s' % ' '.join(argv))
    return ssubprocess.call(argv, stdout=open(os.devnull, 'w'), env=get_env())
    # No env: No output. (Or error that won't be parsed.)


_changedctls = []


def sysctl_set(name, val, permanent=False):
    PREFIX = 'net.inet.ip'
    assert name.startswith(PREFIX + '.')
    val = str(val)
    if not _oldctls:
        _fill_oldctls(PREFIX)
    if not (name in _oldctls):
        debug1('>> No such sysctl: %r' % name)
        return False
    oldval = _oldctls[name]
    if val != oldval:
        rv = _sysctl_set(name, val)
        if rv == 0 and permanent:
            debug1('>>   ...saving permanently in /etc/sysctl.conf')
            f = open('/etc/sysctl.conf', 'a')
            f.write('\n'
                    '# Added by sshuttle\n'
                    '%s=%s\n' % (name, val))
            f.close()
        else:
            _changedctls.append(name)
        return True


def ipfw(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s' % ' '.join(argv))
    rv = ssubprocess.call(argv, env=get_env())
    # No env: No output. (Or error that won't be parsed.)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def ipfw_noexit(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s' % ' '.join(argv))
    ssubprocess.call(argv, env=get_env())
    # No env: No output. (Or error that won't be parsed.)


class Method(BaseMethod):

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.ipv6 = False
        result.udp = False  # NOTE: Almost there, kernel patch needed
        result.dns = True
        return result

    def get_tcp_dstip(self, sock):
        return sock.getsockname()

    def recv_udp(self, udp_listener, bufsize):
        srcip, dstip, data = recv_udp(udp_listener, bufsize)
        if not dstip:
            debug1(
                   "-- ignored UDP from %r: "
                   "couldn't determine destination IP address" % (srcip,))
            return None
        return srcip, dstip, data

    def send_udp(self, sock, srcip, dstip, data):
        if not srcip:
            debug1(
               "-- ignored UDP to %r: "
               "couldn't determine source IP address" % (dstip,))
            return

        # debug3('Sending SRC: %r DST: %r' % (srcip, dstip))
        sender = socket.socket(sock.family, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_IP, IP_BINDANY, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sender.bind(srcip)
        sender.sendto(data, dstip)
        sender.close()

    def setup_udp_listener(self, udp_listener):
        if udp_listener.v4 is not None:
            udp_listener.v4.setsockopt(socket.SOL_IP, IP_RECVDSTADDR, 1)
        # if udp_listener.v6 is not None:
        #     udp_listener.v6.setsockopt(SOL_IPV6, IPV6_RECVDSTADDR, 1)

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, group, tmark):
        # IPv6 not supported
        if family not in [socket.AF_INET]:
            raise Exception(
                'Address family "%s" unsupported by ipfw method_name'
                % family_to_string(family))

        # XXX: Any risk from this?
        ipfw_noexit('delete', '1')

        while _changedctls:
            name = _changedctls.pop()
            oldval = _oldctls[name]
            _sysctl_set(name, oldval)

        if subnets or dnsport:
            sysctl_set('net.inet.ip.fw.enable', 1)

        ipfw('add', '1', 'check-state', ':sshuttle')

        ipfw('add', '1', 'skipto', '2',
             'tcp',
             'from', 'any', 'to', 'table(125)')
        ipfw('add', '1', 'fwd', '127.0.0.1,%d' % port,
             'tcp',
             'from', 'any', 'to', 'table(126)',
             'setup', 'keep-state', ':sshuttle')

        ipfw_noexit('table', '124', 'flush')
        dnscount = 0
        for _, ip in [i for i in nslist if i[0] == family]:
            ipfw('table', '124', 'add', '%s' % (ip))
            dnscount += 1
        if dnscount > 0:
            ipfw('add', '1', 'fwd', '127.0.0.1,%d' % dnsport,
                 'udp',
                 'from', 'any', 'to', 'table(124)',
                 'keep-state', ':sshuttle')
        ipfw('add', '1', 'allow',
             'udp',
             'from', 'any', 'to', 'any')

        if subnets:
            # create new subnet entries
            for _, swidth, sexclude, snet, fport, lport \
                    in sorted(subnets, key=lambda s: s[1], reverse=True):
                if sexclude:
                    ipfw('table', '125', 'add', '%s/%s' % (snet, swidth))
                else:
                    ipfw('table', '126', 'add', '%s/%s' % (snet, swidth))

    def restore_firewall(self, port, family, udp, user, group):
        if family not in [socket.AF_INET]:
            raise Exception(
                'Address family "%s" unsupported by ipfw method'
                % family_to_string(family))

        ipfw_noexit('delete', '1')
        ipfw_noexit('table', '124', 'flush')
        ipfw_noexit('table', '125', 'flush')
        ipfw_noexit('table', '126', 'flush')

    def is_supported(self):
        if which("ipfw"):
            return True
        debug2("ipfw method not supported because 'ipfw' command is "
               "missing.")
        return False
