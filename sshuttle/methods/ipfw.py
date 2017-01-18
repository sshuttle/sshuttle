import os
import sys
import struct
import subprocess as ssubprocess
from sshuttle.methods import BaseMethod
from sshuttle.helpers import log, debug1, debug3, \
    Fatal, family_to_string

recvmsg = None
try:
    # try getting recvmsg from python
    import socket as pythonsocket
    getattr(pythonsocket.socket, "recvmsg")
    socket = pythonsocket
    recvmsg = "python"
except AttributeError:
    # try getting recvmsg from socket_ext library
    try:
        import socket_ext
        getattr(socket_ext.socket, "recvmsg")
        socket = socket_ext
        recvmsg = "socket_ext"
    except ImportError:
        import socket

IP_BINDANY = 24
IP_RECVDSTADDR = 7
SOL_IPV6 = 41
IPV6_RECVDSTADDR = 74

if recvmsg == "python":
    def recv_udp(listener, bufsize):
        debug3('Accept UDP python using recvmsg.\n')
        data, ancdata, msg_flags, srcip = listener.recvmsg(4096, socket.CMSG_SPACE(4))
        dstip = None
        family = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == IP_RECVDSTADDR:
                port = 53
                ip = socket.inet_ntop(socket.AF_INET, cmsg_data[0:4])
                dstip = (ip, port)
                break
        return (srcip, dstip, data)
elif recvmsg == "socket_ext":
    def recv_udp(listener, bufsize):
        debug3('Accept UDP using socket_ext recvmsg.\n')
        srcip, data, adata, flags = listener.recvmsg((bufsize,), socket.CMSG_SPACE(4))
        dstip = None
        family = None
        for a in adata:
            if a.cmsg_level == socket.SOL_IP and a.cmsg_type == IP_RECVDSTADDR:
                port = 53
                ip = socket.inet_ntop(socket.AF_INET, cmsg_data[0:4])
                dstip = (ip, port)
                break
        return (srcip, dstip, data[0])
else:
    def recv_udp(listener, bufsize):
        debug3('Accept UDP using recvfrom.\n')
        data, srcip = listener.recvfrom(bufsize)
        return (srcip, None, data)


def ipfw_rule_exists(n):
    argv = ['ipfw', 'list']
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=env)

    found = False
    for line in p.stdout:
        if line.startswith(b'%05d ' % n):
            if not ('ipttl 42' in line or 'check-state' in line):
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
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=env)
    for line in p.stdout:
        line = line.decode()
        assert(line[-1] == '\n')
        (k, v) = line[:-1].split(': ', 1)
        _oldctls[k] = v.strip()
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

def ipfw(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def ipfw_noexit(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    ssubprocess.call(argv)

class Method(BaseMethod):
    
    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.ipv6 = False
        result.udp = False #NOTE: Almost there, kernel patch needed
        result.dns = True
        return result
    
    def get_tcp_dstip(self, sock):
        return sock.getsockname()
    
    def recv_udp(self, udp_listener, bufsize):
        srcip, dstip, data = recv_udp(udp_listener, bufsize)
        if not dstip:
            debug1(
                   "-- ignored UDP from %r: "
                   "couldn't determine destination IP address\n" % (srcip,))
            return None
        return srcip, dstip, data

    def send_udp(self, sock, srcip, dstip, data):
        if not srcip:
            debug1(
               "-- ignored UDP to %r: "
               "couldn't determine source IP address\n" % (dstip,))
            return

        #debug3('Sending SRC: %r DST: %r\n' % (srcip, dstip))
        sender = socket.socket(sock.family, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_IP, IP_BINDANY, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sender.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)
        sender.bind(srcip)
        sender.sendto(data,dstip)
        sender.close()

    def setup_udp_listener(self, udp_listener):
        if udp_listener.v4 is not None:
            udp_listener.v4.setsockopt(socket.SOL_IP, IP_RECVDSTADDR, 1)
        #if udp_listener.v6 is not None:
        #    udp_listener.v6.setsockopt(SOL_IPV6, IPV6_RECVDSTADDR, 1)

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        # IPv6 not supported
        if family not in [socket.AF_INET ]:
            raise Exception(
                'Address family "%s" unsupported by ipfw method_name'
                % family_to_string(family))
    
        #XXX: Any risk from this?
        ipfw_noexit('delete', '1')

        while _changedctls:
            name = _changedctls.pop()
            oldval = _oldctls[name]
            _sysctl_set(name, oldval)
    
        if subnets or dnsport:
            sysctl_set('net.inet.ip.fw.enable', 1)
            
        ipfw('add', '1', 'check-state', 'ip',
             'from', 'any', 'to', 'any')
        
        ipfw('add', '1', 'skipto', '2',
             'tcp',
             'from', 'any', 'to', 'table(125)')
        ipfw('add', '1', 'fwd', '127.0.0.1,%d' % port,
             'tcp',
             'from', 'any', 'to', 'table(126)',
             'not', 'ipttl', '42', 'keep-state', 'setup')

        ipfw_noexit('table', '124', 'flush')
        dnscount = 0
        for f, ip in [i for i in nslist if i[0] == family]:
            ipfw('table', '124', 'add', '%s' % (ip))
            dnscount += 1
        if dnscount > 0:
            ipfw('add', '1', 'fwd', '127.0.0.1,%d' % dnsport,
                 'udp',
                 'from', 'any', 'to', 'table(124)',
                 'not', 'ipttl', '42')
        """if udp:
            ipfw('add', '1', 'skipto', '2',
                 'udp',
                 'from', 'any', 'to', 'table(125)')
            ipfw('add', '1', 'fwd', '127.0.0.1,%d' % port,
                 'udp',
                 'from', 'any', 'to', 'table(126)',
                 'not', 'ipttl', '42')
        """
        ipfw('add', '1', 'allow', 
             'udp',
             'from', 'any', 'to', 'any',
             'ipttl', '42')

        if subnets:
            # create new subnet entries
            for f, swidth, sexclude, snet \
                in sorted(subnets, key=lambda s: s[1], reverse=True):
                if sexclude:
                    ipfw('table', '125', 'add', '%s/%s' % (snet, swidth))
            else:
                ipfw('table', '126', 'add', '%s/%s' % (snet, swidth))

    def restore_firewall(self, port, family, udp):
        if family not in [socket.AF_INET]:
            raise Exception(
                'Address family "%s" unsupported by tproxy method'
                % family_to_string(family))

        ipfw_noexit('delete', '1')
        ipfw_noexit('table', '124', 'flush')
        ipfw_noexit('table', '125', 'flush')
        ipfw_noexit('table', '126', 'flush')

