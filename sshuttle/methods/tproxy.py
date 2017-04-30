import struct
from sshuttle.firewall import subnet_weight
from sshuttle.helpers import family_to_string
from sshuttle.linux import ipt, ipt_ttl, ipt_chain_exists
from sshuttle.methods import BaseMethod
from sshuttle.helpers import debug1, debug3, Fatal

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


IP_TRANSPARENT = 19
IP_ORIGDSTADDR = 20
IP_RECVORIGDSTADDR = IP_ORIGDSTADDR
SOL_IPV6 = 41
IPV6_ORIGDSTADDR = 74
IPV6_RECVORIGDSTADDR = IPV6_ORIGDSTADDR

if recvmsg == "python":
    def recv_udp(listener, bufsize):
        debug3('Accept UDP python using recvmsg.\n')
        data, ancdata, msg_flags, srcip = listener.recvmsg(
            4096, socket.CMSG_SPACE(24))
        dstip = None
        family = None
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if cmsg_level == socket.SOL_IP and cmsg_type == IP_ORIGDSTADDR:
                family, port = struct.unpack('=HH', cmsg_data[0:4])
                port = socket.htons(port)
                if family == socket.AF_INET:
                    start = 4
                    length = 4
                else:
                    raise Fatal("Unsupported socket type '%s'" % family)
                ip = socket.inet_ntop(family, cmsg_data[start:start + length])
                dstip = (ip, port)
                break
            elif cmsg_level == SOL_IPV6 and cmsg_type == IPV6_ORIGDSTADDR:
                family, port = struct.unpack('=HH', cmsg_data[0:4])
                port = socket.htons(port)
                if family == socket.AF_INET6:
                    start = 8
                    length = 16
                else:
                    raise Fatal("Unsupported socket type '%s'" % family)
                ip = socket.inet_ntop(family, cmsg_data[start:start + length])
                dstip = (ip, port)
                break
        return (srcip, dstip, data)
elif recvmsg == "socket_ext":
    def recv_udp(listener, bufsize):
        debug3('Accept UDP using socket_ext recvmsg.\n')
        srcip, data, adata, flags = listener.recvmsg(
            (bufsize,), socket.CMSG_SPACE(24))
        dstip = None
        family = None
        for a in adata:
            if a.cmsg_level == socket.SOL_IP and a.cmsg_type == IP_ORIGDSTADDR:
                family, port = struct.unpack('=HH', a.cmsg_data[0:4])
                port = socket.htons(port)
                if family == socket.AF_INET:
                    start = 4
                    length = 4
                else:
                    raise Fatal("Unsupported socket type '%s'" % family)
                ip = socket.inet_ntop(
                    family, a.cmsg_data[start:start + length])
                dstip = (ip, port)
                break
            elif a.cmsg_level == SOL_IPV6 and a.cmsg_type == IPV6_ORIGDSTADDR:
                family, port = struct.unpack('=HH', a.cmsg_data[0:4])
                port = socket.htons(port)
                if family == socket.AF_INET6:
                    start = 8
                    length = 16
                else:
                    raise Fatal("Unsupported socket type '%s'" % family)
                ip = socket.inet_ntop(
                    family, a.cmsg_data[start:start + length])
                dstip = (ip, port)
                break
        return (srcip, dstip, data[0])
else:
    def recv_udp(listener, bufsize):
        debug3('Accept UDP using recvfrom.\n')
        data, srcip = listener.recvfrom(bufsize)
        return (srcip, None, data)


class Method(BaseMethod):

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.ipv6 = True
        if recvmsg is None:
            result.udp = False
            result.dns = False
        else:
            result.udp = True
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
        sender = socket.socket(sock.family, socket.SOCK_DGRAM)
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sender.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        sender.bind(srcip)
        sender.sendto(data, dstip)
        sender.close()

    def setup_tcp_listener(self, tcp_listener):
        tcp_listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)

    def setup_udp_listener(self, udp_listener):
        udp_listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
        if udp_listener.v4 is not None:
            udp_listener.v4.setsockopt(
                socket.SOL_IP, IP_RECVORIGDSTADDR, 1)
        if udp_listener.v6 is not None:
            udp_listener.v6.setsockopt(SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        if family not in [socket.AF_INET, socket.AF_INET6]:
            raise Exception(
                'Address family "%s" unsupported by tproxy method'
                % family_to_string(family))

        table = "mangle"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        def _ipt_proto_ports(proto, fport, lport):
            return proto + ('--dport', '%d:%d' % (fport, lport)) \
                    if fport else proto


        mark_chain = 'sshuttle-m-%s' % port
        tproxy_chain = 'sshuttle-t-%s' % port
        divert_chain = 'sshuttle-d-%s' % port

        # basic cleanup/setup of chains
        self.restore_firewall(port, family, udp)

        _ipt('-N', mark_chain)
        _ipt('-F', mark_chain)
        _ipt('-N', divert_chain)
        _ipt('-F', divert_chain)
        _ipt('-N', tproxy_chain)
        _ipt('-F', tproxy_chain)
        _ipt('-I', 'OUTPUT', '1', '-j', mark_chain)
        _ipt('-I', 'PREROUTING', '1', '-j', tproxy_chain)
        _ipt('-A', divert_chain, '-j', 'MARK', '--set-mark', '1')
        _ipt('-A', divert_chain, '-j', 'ACCEPT')
        _ipt('-A', tproxy_chain, '-m', 'socket', '-j', divert_chain,
             '-m', 'tcp', '-p', 'tcp')

        if udp:
            _ipt('-A', tproxy_chain, '-m', 'socket', '-j', divert_chain,
                 '-m', 'udp', '-p', 'udp')

        for f, ip in [i for i in nslist if i[0] == family]:
            _ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', '1',
                 '--dest', '%s/32' % ip,
                 '-m', 'udp', '-p', 'udp', '--dport', '53')
            _ipt('-A', tproxy_chain, '-j', 'TPROXY',
                 '--tproxy-mark', '0x1/0x1',
                 '--dest', '%s/32' % ip,
                 '-m', 'udp', '-p', 'udp', '--dport', '53',
                 '--on-port', str(dnsport))

        for f, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):
            tcp_ports = ('-p', 'tcp')
            tcp_ports = _ipt_proto_ports(tcp_ports, fport, lport)

            if sexclude:
                _ipt('-A', mark_chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *tcp_ports)
                _ipt('-A', tproxy_chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *tcp_ports)
            else:
                _ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', '1',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *tcp_ports)
                _ipt('-A', tproxy_chain, '-j', 'TPROXY',
                     '--tproxy-mark', '0x1/0x1',
                     '--dest', '%s/%s' % (snet, swidth),
                     '-m', 'tcp',
                     *(tcp_ports + ('--on-port', str(port))))

            if udp:
                udp_ports = ('-p', 'udp')
                udp_ports = _ipt_proto_ports(udp_ports, fport, lport)

                if sexclude:
                    _ipt('-A', mark_chain, '-j', 'RETURN',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *udp_ports)
                    _ipt('-A', tproxy_chain, '-j', 'RETURN',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *udp_ports)
                else:
                    _ipt('-A', mark_chain, '-j', 'MARK', '--set-mark', '1',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp', '-p', 'udp')
                    _ipt('-A', tproxy_chain, '-j', 'TPROXY',
                         '--tproxy-mark', '0x1/0x1',
                         '--dest', '%s/%s' % (snet, swidth),
                         '-m', 'udp',
                         *(udp_ports + ('--on-port', str(port))))

    def restore_firewall(self, port, family, udp):
        if family not in [socket.AF_INET, socket.AF_INET6]:
            raise Exception(
                'Address family "%s" unsupported by tproxy method'
                % family_to_string(family))

        table = "mangle"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        mark_chain = 'sshuttle-m-%s' % port
        tproxy_chain = 'sshuttle-t-%s' % port
        divert_chain = 'sshuttle-d-%s' % port

        # basic cleanup/setup of chains
        if ipt_chain_exists(family, table, mark_chain):
            _ipt('-D', 'OUTPUT', '-j', mark_chain)
            _ipt('-F', mark_chain)
            _ipt('-X', mark_chain)

        if ipt_chain_exists(family, table, tproxy_chain):
            _ipt('-D', 'PREROUTING', '-j', tproxy_chain)
            _ipt('-F', tproxy_chain)
            _ipt('-X', tproxy_chain)

        if ipt_chain_exists(family, table, divert_chain):
            _ipt('-F', divert_chain)
            _ipt('-X', divert_chain)
