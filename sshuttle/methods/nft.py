import socket
from sshuttle.firewall import subnet_weight
from sshuttle.linux import nft, nonfatal
from sshuttle.methods import BaseMethod
from sshuttle.helpers import debug2, which


class Method(BaseMethod):

    # We name the chain based on the transproxy port number so that it's
    # possible to run multiple copies of sshuttle at the same time.  Of course,
    # the multiple copies shouldn't have overlapping subnets, or only the most-
    # recently-started one will win (because we use "-I OUTPUT 1" instead of
    # "-A OUTPUT").
    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, group, tmark):
        if udp:
            raise Exception("UDP not supported by nft")

        if family == socket.AF_INET:
            table = 'sshuttle-ipv4-%s' % port
        if family == socket.AF_INET6:
            table = 'sshuttle-ipv6-%s' % port

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

        # setup_firewall() gets called separately for ipv4 and ipv6. Make sure
        # we only handle the version that we expect to.
        if family == socket.AF_INET:
            _nft('add rule', chain, 'meta', 'nfproto', '!=', 'ipv4', 'return')
        else:
            _nft('add rule', chain, 'meta', 'nfproto', '!=', 'ipv6', 'return')

        # Strings to use below to simplify our code
        if family == socket.AF_INET:
            ip_version_l = 'ipv4'
            ip_version = 'ip'
        elif family == socket.AF_INET6:
            ip_version_l = 'ipv6'
            ip_version = 'ip6'

        # Redirect DNS traffic as requested. This includes routing traffic
        # to localhost DNS servers through sshuttle.
        for _, ip in [i for i in nslist if i[0] == family]:
            _nft('add rule', chain, ip_version,
                 'daddr %s' % ip, 'udp dport 53',
                 ('redirect to :' + str(dnsport)))

        # Don't route any remaining local traffic through sshuttle
        _nft('add rule', chain, 'fib daddr type local return')

        # create new subnet entries.
        for _, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):

            # match using nfproto as described at
            # https://superuser.com/questions/1560376/match-ipv6-protocol-using-nftables
            if fport and fport != lport:
                tcp_ports = ('meta', 'nfproto', ip_version_l, 'tcp',
                             'dport', '{ %d-%d }' % (fport, lport))
            elif fport and fport == lport:
                tcp_ports = ('meta', 'nfproto', ip_version_l, 'tcp',
                             'dport', '%d' % (fport))
            else:
                tcp_ports = ('meta', 'nfproto', ip_version_l,
                             'meta', 'l4proto', 'tcp')

            if sexclude:
                _nft('add rule', chain, *(tcp_ports + (
                     ip_version, 'daddr %s/%s' % (snet, swidth), 'return')))
            else:
                _nft('add rule', chain, *(tcp_ports + (
                    ip_version, 'daddr %s/%s' % (snet, swidth),
                    ('redirect to :' + str(port)))))

    def restore_firewall(self, port, family, udp, user, group):
        if udp:
            raise Exception("UDP not supported by nft method_name")

        if family == socket.AF_INET:
            table = 'sshuttle-ipv4-%s' % port
        if family == socket.AF_INET6:
            table = 'sshuttle-ipv6-%s' % port

        def _nft(action, *args):
            return nft(family, table, action, *args)

        # basic cleanup/setup of chains
        nonfatal(_nft, 'delete table', '')

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.ipv6 = True
        return result

    def is_supported(self):
        if which("nft"):
            return True
        debug2("nft method not supported because 'nft' command is missing.")
        return False
