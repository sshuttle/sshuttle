import socket
from sshuttle.firewall import subnet_weight
from sshuttle.linux import nft, nonfatal
from sshuttle.methods import BaseMethod


class Method(BaseMethod):

    # We name the chain based on the transproxy port number so that it's
    # possible to run multiple copies of sshuttle at the same time.  Of course,
    # the multiple copies shouldn't have overlapping subnets, or only the most-
    # recently-started one will win (because we use "-I OUTPUT 1" instead of
    # "-A OUTPUT").
    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user):
        if udp:
            raise Exception("UDP not supported by nft")

        table = 'sshuttle-%s' % port

        def _nft(action, *args):
            return nft(family, table, action, *args)

        chain = table

        # basic cleanup/setup of chains
        _nft('add table', '')
        _nft('add chain', 'prerouting',
             '{ type nat hook prerouting priority -100; policy accept; }')
        _nft('add chain', 'output',
             '{ type nat hook output priority -100; policy accept; }')
        _nft('add chain', chain)
        _nft('flush chain', chain)
        _nft('add rule', 'output jump %s' % chain)
        _nft('add rule', 'prerouting jump %s' % chain)

        # create new subnet entries.
        for _, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):
            tcp_ports = ('ip', 'protocol', 'tcp')
            if fport and fport != lport:
                tcp_ports = \
                    tcp_ports + \
                    ('tcp', 'dport', '{ %d-%d }' % (fport, lport))
            elif fport and fport == lport:
                tcp_ports = tcp_ports + ('tcp', 'dport', '%d' % (fport))

            if sexclude:
                _nft('add rule', chain, *(tcp_ports + (
                     'ip daddr %s/%s' % (snet, swidth), 'return')))
            else:
                _nft('add rule', chain, *(tcp_ports + (
                     'ip daddr %s/%s' % (snet, swidth), 'ip ttl != 42',
                     ('redirect to :' + str(port)))))

        for _, ip in [i for i in nslist if i[0] == family]:
            if family == socket.AF_INET:
                _nft('add rule', chain, 'ip protocol udp ip daddr %s' % ip,
                     'udp dport { 53 }', 'ip ttl != 42',
                     ('redirect to :' + str(dnsport)))
            elif family == socket.AF_INET6:
                _nft('add rule', chain, 'ip6 protocol udp ip6 daddr %s' % ip,
                     'udp dport { 53 }', 'ip ttl != 42',
                     ('redirect to :' + str(dnsport)))

    def restore_firewall(self, port, family, udp, user):
        if udp:
            raise Exception("UDP not supported by nft method_name")

        table = 'sshuttle-%s' % port

        def _nft(action, *args):
            return nft(family, table, action, *args)

        # basic cleanup/setup of chains
        nonfatal(_nft, 'delete table', '')
