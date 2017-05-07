import socket
from sshuttle.firewall import subnet_weight
from sshuttle.helpers import family_to_string
from sshuttle.linux import ipt, ipt_ttl, ipt_chain_exists, nonfatal
from sshuttle.methods import BaseMethod


class Method(BaseMethod):

    # We name the chain based on the transproxy port number so that it's
    # possible to run multiple copies of sshuttle at the same time.  Of course,
    # the multiple copies shouldn't have overlapping subnets, or only the most-
    # recently-started one will win (because we use "-I OUTPUT 1" instead of
    # "-A OUTPUT").
    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        # only ipv4 supported with NAT
        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")

        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        self.restore_firewall(port, family, udp)

        _ipt('-N', chain)
        _ipt('-F', chain)
        _ipt('-I', 'OUTPUT', '1', '-j', chain)
        _ipt('-I', 'PREROUTING', '1', '-j', chain)

        # create new subnet entries.
        for f, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):
            tcp_ports = ('-p', 'tcp')
            if fport:
                tcp_ports = tcp_ports + ('--dport', '%d:%d' % (fport, lport))

            if sexclude:
                _ipt('-A', chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     *tcp_ports)
            else:
                _ipt_ttl('-A', chain, '-j', 'REDIRECT',
                         '--dest', '%s/%s' % (snet, swidth),
                         *(tcp_ports + ('--to-ports', str(port))))

        for f, ip in [i for i in nslist if i[0] == family]:
            _ipt_ttl('-A', chain, '-j', 'REDIRECT',
                     '--dest', '%s/32' % ip,
                     '-p', 'udp',
                     '--dport', '53',
                     '--to-ports', str(dnsport))

    def restore_firewall(self, port, family, udp):
        # only ipv4 supported with NAT
        if family != socket.AF_INET:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")

        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipt_ttl(*args):
            return ipt_ttl(family, table, *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        if ipt_chain_exists(family, table, chain):
            nonfatal(_ipt, '-D', 'OUTPUT', '-j', chain)
            nonfatal(_ipt, '-D', 'PREROUTING', '-j', chain)
            nonfatal(_ipt, '-F', chain)
            _ipt('-X', chain)
