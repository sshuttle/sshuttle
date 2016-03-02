import os
import sys
import re
import socket
import struct
import subprocess as ssubprocess
from fcntl import ioctl
from ctypes import c_char, c_uint8, c_uint16, c_uint32, Union, Structure, \
    sizeof, addressof, memmove
from sshuttle.helpers import debug1, debug2, debug3, Fatal, family_to_string
from sshuttle.methods import BaseMethod


_pf_context = {'started_by_sshuttle': False, 'Xtoken': None}
_pf_fd = None


class Generic(object):
    MAXPATHLEN = 1024
    PF_CHANGE_ADD_TAIL = 2
    PF_CHANGE_GET_TICKET = 6
    PF_PASS = 0
    PF_RDR = 8
    PF_OUT = 2
    ACTION_OFFSET = 0
    POOL_TICKET_OFFSET = 8
    ANCHOR_CALL_OFFSET = 1040

    class pf_addr(Structure):
        class _pfa(Union):
             _fields_ = [("v4", c_uint32),     # struct in_addr
                        ("v6", c_uint32 * 4),  # struct in6_addr
                        ("addr8", c_uint8 * 16),
                        ("addr16", c_uint16 * 8),
                        ("addr32", c_uint32 * 4)]

        _fields_ = [("pfa", _pfa)]
        _anonymous_ = ("pfa",)

    def __init__(self):
        self.status = b''
        self.pfioc_pooladdr = c_char * 1136

        self.DIOCNATLOOK = (
            (0x40000000 | 0x80000000) |
            ((sizeof(self.pfioc_natlook) & 0x1fff) << 16) |
            ((ord('D')) << 8) | (23))
        self.DIOCCHANGERULE = (
            (0x40000000 | 0x80000000) |
            ((sizeof(self.pfioc_rule) & 0x1fff) << 16) |
            ((ord('D')) << 8) | (26))
        self.DIOCBEGINADDRS = (
            (0x40000000 | 0x80000000) |
            ((sizeof(self.pfioc_pooladdr) & 0x1fff) << 16) |
            ((ord('D')) << 8) | (51))

    def enable(self):
        if b'INFO:\nStatus: Disabled' in self.status:
            pfctl('-e')
            _pf_context['started_by_sshuttle'] = True

    def disable(self):
        if _pf_context['started_by_sshuttle']:
            pfctl('-d')

    def query_nat(self, family, proto, src_ip, src_port, dst_ip, dst_port):
        [proto, family, src_port, dst_port] = [
            int(v) for v in [proto, family, src_port, dst_port]]

        packed_src_ip = socket.inet_pton(family, src_ip)
        packed_dst_ip = socket.inet_pton(family, dst_ip)

        assert len(packed_src_ip) == len(packed_dst_ip)
        length = len(packed_src_ip)

        pnl = self.pfioc_natlook()
        pnl.proto = proto
        pnl.direction = self.PF_OUT
        pnl.af = family
        memmove(addressof(pnl.saddr), packed_src_ip, length)
        memmove(addressof(pnl.daddr), packed_dst_ip, length)
        self._add_natlook_ports(pnl, src_port, dst_port)

        ioctl(pf_get_dev(), self.DIOCNATLOOK,
              (c_char * sizeof(pnl)).from_address(addressof(pnl)))

        ip = socket.inet_ntop(
            pnl.af, (c_char * length).from_address(addressof(pnl.rdaddr)).raw)
        port = socket.ntohs(self._get_natlook_port(pnl.rdxport))
        return (ip, port)

    def _add_natlook_ports(self, pnl, src_port, dst_port):
        pnl.sxport = socket.htons(src_port)
        pnl.dxport = socket.htons(dst_port)

    def _get_natlook_port(self, xport):
        return xport

    def add_anchors(self, status=None):
        if status is None:
            status = pfctl('-s all')[0]
        self.status = status
        if b'\nanchor "sshuttle"' not in status:
            self._add_anchor_rule(self.PF_PASS, b"sshuttle")

    def _add_anchor_rule(self, type, name, pr=None):
        if pr is None:
            pr = self.pfioc_rule()

        memmove(addressof(pr) + self.ANCHOR_CALL_OFFSET, name,
                min(self.MAXPATHLEN, len(name)))  # anchor_call = name
        memmove(addressof(pr) + self.RULE_ACTION_OFFSET,
                struct.pack('I', type), 4)  # rule.action = type

        memmove(addressof(pr) + self.ACTION_OFFSET, struct.pack(
            'I', self.PF_CHANGE_GET_TICKET), 4)  # action = PF_CHANGE_GET_TICKET
        ioctl(pf_get_dev(), pf.DIOCCHANGERULE, pr)

        memmove(addressof(pr) + self.ACTION_OFFSET, struct.pack(
            'I', self.PF_CHANGE_ADD_TAIL), 4)  # action = PF_CHANGE_ADD_TAIL
        ioctl(pf_get_dev(), pf.DIOCCHANGERULE, pr)

    def add_rules(self, rules):
        assert isinstance(rules, bytes)
        debug3("rules:\n" + rules.decode("ASCII"))
        pfctl('-a sshuttle -f /dev/stdin', rules)


class FreeBsd(Generic):
    RULE_ACTION_OFFSET = 2968

    def __new__(cls):
        class pfioc_natlook(Structure):
            pf_addr = Generic.pf_addr
            _fields_ = [("saddr", pf_addr),
                        ("daddr", pf_addr),
                        ("rsaddr", pf_addr),
                        ("rdaddr", pf_addr),
                        ("sxport", c_uint16),
                        ("dxport", c_uint16),
                        ("rsxport", c_uint16),
                        ("rdxport", c_uint16),
                        ("af", c_uint8),                      # sa_family_t
                        ("proto", c_uint8),
                        ("proto_variant", c_uint8),
                        ("direction", c_uint8)]

        freebsd = Generic.__new__(cls)
        freebsd.pfioc_rule = c_char * 3040
        freebsd.pfioc_natlook = pfioc_natlook
        return freebsd

    def __init__(self):
        super(FreeBsd, self).__init__()

    def add_anchors(self):
        status = pfctl('-s all')[0]
        if b'\nrdr-anchor "sshuttle"' not in status:
            self._add_anchor_rule(self.PF_RDR, b'sshuttle')
        super(FreeBsd, self).add_anchors(status=status)

    def _add_anchor_rule(self, type, name):
        pr = self.pfioc_rule()
        ppa = self.pfioc_pooladdr()

        ioctl(pf_get_dev(), self.DIOCBEGINADDRS, ppa)
        # pool ticket
        memmove(addressof(pr) + self.POOL_TICKET_OFFSET, ppa[4:8], 4)
        super(FreeBsd, self)._add_anchor_rule(type, name, pr=pr)

    def add_rules(self, includes, port, dnsport, nslist):
        tables = [
            b'table <forward_subnets> {%s}' % b','.join(includes)
        ]
        translating_rules = [
            b'rdr pass on lo0 proto tcp '
            b'to <forward_subnets> -> 127.0.0.1 port %r' % port
        ]
        filtering_rules = [
            b'pass out route-to lo0 inet proto tcp '
            b'to <forward_subnets> keep state'
        ]

        if len(nslist) > 0:
            tables.append(
                b'table <dns_servers> {%s}' %
                b','.join([ns[1].encode("ASCII") for ns in nslist]))
            translating_rules.append(
                b'rdr pass on lo0 proto udp to '
                b'<dns_servers> port 53 -> 127.0.0.1 port %r' % dnsport)
            filtering_rules.append(
                b'pass out route-to lo0 inet proto udp to '
                b'<dns_servers> port 53 keep state')

        rules = b'\n'.join(tables + translating_rules + filtering_rules) \
                + b'\n'

        super(FreeBsd, self).add_rules(rules)


class OpenBsd(Generic):
    POOL_TICKET_OFFSET = 4
    RULE_ACTION_OFFSET = 3324
    ANCHOR_CALL_OFFSET = 1036

    def __init__(self):
        class pfioc_natlook(Structure):
            pf_addr = Generic.pf_addr
            _fields_ = [("saddr", pf_addr),
                        ("daddr", pf_addr),
                        ("rsaddr", pf_addr),
                        ("rdaddr", pf_addr),
                        ("rdomain", c_uint16),
                        ("rrdomain", c_uint16),
                        ("sxport", c_uint16),
                        ("dxport", c_uint16),
                        ("rsxport", c_uint16),
                        ("rdxport", c_uint16),
                        ("af", c_uint8),                      # sa_family_t
                        ("proto", c_uint8),
                        ("proto_variant", c_uint8),
                        ("direction", c_uint8)]

        self.pfioc_rule = c_char * 3400
        self.pfioc_natlook = pfioc_natlook
        super(OpenBsd, self).__init__()

    def add_anchors(self):
        # before adding anchors and rules we must override the skip lo
        # that comes by default in openbsd pf.conf so the rules we will add,
        # which rely on translating/filtering  packets on lo, can work
        pfctl('-f /dev/stdin', b'match on lo\n')
        super(OpenBsd, self).add_anchors()

    def add_rules(self, includes, port, dnsport, nslist):
        tables = [
            b'table <forward_subnets> {%s}' % b','.join(includes)
        ]
        translating_rules = [
            b'pass in on lo0 inet proto tcp '
            b'divert-to 127.0.0.1 port %r' % port
        ]
        filtering_rules = [
            b'pass out inet proto tcp '
            b'to <forward_subnets> route-to lo0 keep state'
        ]

        if len(nslist) > 0:
            tables.append(
                b'table <dns_servers> {%s}' %
                b','.join([ns[1].encode("ASCII") for ns in nslist]))
            translating_rules.append(
                b'pass in on lo0 inet proto udp to <dns_servers>'
                b'port 53 rdr-to 127.0.0.1 port %r' % dnsport)
            filtering_rules.append(
                b'pass out inet proto udp to '
                b'<dns_servers> port 53 route-to lo0 keep state')

        rules = b'\n'.join(tables + translating_rules + filtering_rules) \
                + b'\n'

        super(OpenBsd, self).add_rules(rules)


class Darwin(FreeBsd):
    RULE_ACTION_OFFSET = 3068

    def __init__(self):
        class pf_state_xport(Union):
            _fields_ = [("port", c_uint16),
                        ("call_id", c_uint16),
                        ("spi", c_uint32)]

        class pfioc_natlook(Structure):
            pf_addr = Generic.pf_addr
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

        self.pfioc_rule = c_char * 3104
        self.pfioc_natlook = pfioc_natlook
        super(Darwin, self).__init__()

    def enable(self):
        o = pfctl('-E')
        _pf_context['Xtoken'] = \
            re.search(b'Token : (.+)', o[1]).group(1)

    def disable(self):
        if _pf_context['Xtoken'] is not None:
            pfctl('-X %s' % _pf_context['Xtoken'].decode("ASCII"))

    def add_anchors(self):
        # before adding anchors and rules we must override the skip lo
        # that in some cases ends up in the chain so the rules we will add,
        # which rely on translating/filtering  packets on lo, can work
        pfctl('-f /dev/stdin', b'pass on lo\n')
        super(Darwin, self).add_anchors()

    def _add_natlook_ports(self, pnl, src_port, dst_port):
        pnl.sxport.port = socket.htons(src_port)
        pnl.dxport.port = socket.htons(dst_port)

    def _get_natlook_port(self, xport):
        return xport.port


if sys.platform == 'darwin':
    pf = Darwin()
elif sys.platform.startswith('openbsd'):
    pf = OpenBsd()
else:
    pf = FreeBsd()


def pfctl(args, stdin=None):
    argv = ['pfctl'] + list(args.split(" "))
    debug1('>> %s\n' % ' '.join(argv))

    p = ssubprocess.Popen(argv, stdin=ssubprocess.PIPE,
                          stdout=ssubprocess.PIPE,
                          stderr=ssubprocess.PIPE)
    o = p.communicate(stdin)
    if p.returncode:
        raise Fatal('%r returned %d' % (argv, p.returncode))

    return o


def pf_get_dev():
    global _pf_fd
    if _pf_fd is None:
        _pf_fd = os.open('/dev/pf', os.O_RDWR)

    return _pf_fd



class Method(BaseMethod):

    def get_tcp_dstip(self, sock):
        pfile = self.firewall.pfile

        peer = sock.getpeername()
        proxy = sock.getsockname()

        argv = (sock.family, socket.IPPROTO_TCP,
                peer[0].encode("ASCII"), peer[1],
                proxy[0].encode("ASCII"), proxy[1])
        out_line = b"QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % argv
        pfile.write(out_line)
        pfile.flush()
        in_line = pfile.readline()
        debug2(out_line.decode("ASCII") + ' > ' + in_line.decode("ASCII"))
        if in_line.startswith(b'QUERY_PF_NAT_SUCCESS '):
            (ip, port) = in_line[21:].split(b',')
            return (ip.decode("ASCII"), int(port))

        return sock.getsockname()

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        tables = []
        translating_rules = []
        filtering_rules = []

        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by pf method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by pf method_name")

        if len(subnets) > 0:
            includes = []
            # If a given subnet is both included and excluded, list the
            # exclusion first; the table will ignore the second, opposite
            # definition
            for f, swidth, sexclude, snet in sorted(
                    subnets, key=lambda s: (s[1], s[2]), reverse=True):
                includes.append(b"%s%s/%d" %
                                (b"!" if sexclude else b"",
                                    snet.encode("ASCII"),
                                    swidth))

        pf.add_anchors()
        pf.add_rules(includes, port, dnsport, nslist)
        pf.enable()

    def restore_firewall(self, port, family, udp):
        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by pf method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by pf method_name")

        pfctl('-a sshuttle -F all')
        pf.disable()

    def firewall_command(self, line):
        if line.startswith('QUERY_PF_NAT '):
            try:
                dst = pf.query_nat(*(line[13:].split(',')))
                sys.stdout.write('QUERY_PF_NAT_SUCCESS %s,%r\n' % dst)
            except IOError as e:
                sys.stdout.write('QUERY_PF_NAT_FAILURE %s\n' % e)

            sys.stdout.flush()
            return True
        else:
            return False
