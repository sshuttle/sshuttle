import os
import sys
import re
import socket
import struct
import subprocess as ssubprocess
from fcntl import ioctl
from ctypes import c_char, c_uint8, c_uint16, c_uint32, Union, Structure, \
    sizeof, addressof, memmove
from sshuttle.helpers import debug1, debug2, Fatal, family_to_string
from sshuttle.methods import BaseMethod


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

_pf_context = {'started_by_sshuttle': False, 'Xtoken': ''}


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

pfioc_pooladdr = c_char * 1136  # sizeof(struct pfioc_pooladdr)

MAXPATHLEN = 1024

DIOCNATLOOK = ((0x40000000 | 0x80000000) | (
    (sizeof(pfioc_natlook) & 0x1fff) << 16) | ((ord('D')) << 8) | (23))
DIOCCHANGERULE = ((0x40000000 | 0x80000000) | (
    (sizeof(pfioc_rule) & 0x1fff) << 16) | ((ord('D')) << 8) | (26))
DIOCBEGINADDRS = ((0x40000000 | 0x80000000) | (
    (sizeof(pfioc_pooladdr) & 0x1fff) << 16) | ((ord('D')) << 8) | (51))

PF_CHANGE_ADD_TAIL = 2
PF_CHANGE_GET_TICKET = 6

PF_PASS = 0
PF_RDR = 8

PF_OUT = 2

_pf_fd = None


def pf_get_dev():
    global _pf_fd
    if _pf_fd is None:
        _pf_fd = os.open('/dev/pf', os.O_RDWR)

    return _pf_fd


def pf_query_nat(family, proto, src_ip, src_port, dst_ip, dst_port):
    [proto, family, src_port, dst_port] = [
        int(v) for v in [proto, family, src_port, dst_port]]

    packed_src_ip = socket.inet_pton(family, src_ip)
    packed_dst_ip = socket.inet_pton(family, dst_ip)

    assert len(packed_src_ip) == len(packed_dst_ip)
    length = len(packed_src_ip)

    pnl = pfioc_natlook()
    pnl.proto = proto
    pnl.direction = PF_OUT
    pnl.af = family
    memmove(addressof(pnl.saddr), packed_src_ip, length)
    pnl.sxport.port = socket.htons(src_port)
    memmove(addressof(pnl.daddr), packed_dst_ip, length)
    pnl.dxport.port = socket.htons(dst_port)

    ioctl(pf_get_dev(), DIOCNATLOOK,
          (c_char * sizeof(pnl)).from_address(addressof(pnl)))

    ip = socket.inet_ntop(
        pnl.af, (c_char * length).from_address(addressof(pnl.rdaddr)).raw)
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

    memmove(addressof(pr) + POOL_TICKET_OFFSET, ppa[4:8], 4)  # pool_ticket
    memmove(addressof(pr) + ANCHOR_CALL_OFFSET, name,
            min(MAXPATHLEN, len(name)))  # anchor_call = name
    memmove(addressof(pr) + RULE_ACTION_OFFSET,
            struct.pack('I', type), 4)  # rule.action = type

    memmove(addressof(pr) + ACTION_OFFSET, struct.pack(
        'I', PF_CHANGE_GET_TICKET), 4)  # action = PF_CHANGE_GET_TICKET
    ioctl(pf_get_dev(), DIOCCHANGERULE, pr)

    memmove(addressof(pr) + ACTION_OFFSET, struct.pack(
        'I', PF_CHANGE_ADD_TAIL), 4)  # action = PF_CHANGE_ADD_TAIL
    ioctl(pf_get_dev(), DIOCCHANGERULE, pr)


class Method(BaseMethod):

    def get_tcp_dstip(self, sock):
        pfile = self.firewall.pfile

        peer = sock.getpeername()
        proxy = sock.getsockname()

        argv = (sock.family, socket.IPPROTO_TCP,
                peer[0], peer[1], proxy[0], proxy[1])
        pfile.write("QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % argv)
        pfile.flush()
        line = pfile.readline()
        debug2("QUERY_PF_NAT %d,%d,%s,%d,%s,%d" % argv + ' > ' + line)
        if line.startswith('QUERY_PF_NAT_SUCCESS '):
            (ip, port) = line[21:].split(',')
            return (ip, int(port))

        return sock.getsockname()

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        global _pf_started_by_sshuttle
        tables = []
        translating_rules = []
        filtering_rules = []

        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by pf method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by pf method_name")

        if subnets:
            includes = []
            # If a given subnet is both included and excluded, list the
            # exclusion first; the table will ignore the second, opposite
            # definition
            for f, swidth, sexclude, snet in sorted(
                    subnets, key=lambda s: (s[1], s[2]), reverse=True):
                includes.append("%s%s/%s" %
                                ("!" if sexclude else "", snet, swidth))

            tables.append('table <forward_subnets> {%s}' % ','.join(includes))
            translating_rules.append(
                'rdr pass on lo0 proto tcp '
                'to <forward_subnets> -> 127.0.0.1 port %r' % port)
            filtering_rules.append(
                'pass out route-to lo0 inet proto tcp '
                'to <forward_subnets> keep state')

            if dnsport:
                tables.append('table <dns_servers> {%s}' % ','.join(
                    [ns[1] for ns in nslist]))
                translating_rules.append(
                    'rdr pass on lo0 proto udp to '
                    '<dns_servers> port 53 -> 127.0.0.1 port %r' % dnsport)
                filtering_rules.append(
                    'pass out route-to lo0 inet proto udp to '
                    '<dns_servers> port 53 keep state')

            rules = '\n'.join(tables + translating_rules + filtering_rules) \
                    + '\n'

            pf_status = pfctl('-s all')[0]
            if '\nrdr-anchor "sshuttle" all\n' not in pf_status:
                pf_add_anchor_rule(PF_RDR, "sshuttle")
            if '\nanchor "sshuttle" all\n' not in pf_status:
                pf_add_anchor_rule(PF_PASS, "sshuttle")

            pfctl('-a sshuttle -f /dev/stdin', rules)
            if sys.platform == "darwin":
                o = pfctl('-E')
                _pf_context['Xtoken'] = \
                    re.search(r'Token : (.+)', o[1]).group(1)
            elif 'INFO:\nStatus: Disabled' in pf_status:
                pfctl('-e')
                _pf_context['started_by_sshuttle'] = True
        else:
            pfctl('-a sshuttle -F all')
            if sys.platform == "darwin":
                pfctl('-X %s' % _pf_context['Xtoken'])
            elif _pf_context['started_by_sshuttle']:
                pfctl('-d')

    def firewall_command(self, line):
        if line.startswith('QUERY_PF_NAT '):
            try:
                dst = pf_query_nat(*(line[13:].split(',')))
                sys.stdout.write('QUERY_PF_NAT_SUCCESS %s,%r\n' % dst)
            except IOError as e:
                sys.stdout.write('QUERY_PF_NAT_FAILURE %s\n' % e)

            sys.stdout.flush()
            return True
        else:
            return False
