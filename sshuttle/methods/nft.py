import socket
from sshuttle.firewall import subnet_weight
from sshuttle.helpers import Fatal, log
from sshuttle.linux import nft, nft_get_handle, nonfatal
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

        table = "nat"

        def _nft(action, *args):
            return nft(family, table, action, *args)

        # basic cleanup/setup of chains
        _nft('add table', '')
        # prerouting, postrouting, and output chains may already exist
        for chain in ['prerouting', 'postrouting', 'output']:
            rules = '{{ type nat hook {} priority -100; policy accept; }}' \
                    .format(chain)
            try:
                _nft('add chain', chain, rules)
            except Fatal:
                log('Chain {} already exists, ignoring\n'.format(chain))

        chain = 'sshuttle-%s' % port

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

        table = "nat"

        def _nft(action, *args):
            return nft(family, table, action, *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        handle = nft_get_handle('chain ip nat output', chain)
        nonfatal(_nft, 'delete rule', 'output', handle)
        handle = nft_get_handle('chain ip nat prerouting', chain)
        nonfatal(_nft, 'delete rule', 'prerouting', handle)
        nonfatal(_nft, 'delete chain', chain)
