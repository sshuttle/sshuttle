from socket import AF_INET6
from unittest.mock import call, patch

from sshuttle.methods import get_method


@patch('sshuttle.methods.nft.nft')
def test_setup_firewall_scoped_nameserver(mock_nft):
    """The zone id of a link-local nameserver is left out of the nft rule."""
    method = get_method('nft')
    assert method.name == 'nft'

    method.setup_firewall(
        1024, 1026,
        [(AF_INET6, u'fe80::e5a2%wlp3s0'),
         (AF_INET6, u'2404:6800:4004:80c::33')],
        AF_INET6,
        [(AF_INET6, 64, False, u'2404:6800:4004:80c::', 0, 0)],
        False,
        None,
        None,
        '0x01')

    table = 'sshuttle-ipv6-1024'
    dns_rules = [c for c in mock_nft.mock_calls if 'udp dport 53' in c.args]
    assert dns_rules == [
        call(AF_INET6, table, 'add rule', table, 'ip6',
             'daddr fe80::e5a2', 'udp dport 53', 'redirect to :1026'),
        call(AF_INET6, table, 'add rule', table, 'ip6',
             'daddr 2404:6800:4004:80c::33', 'udp dport 53',
             'redirect to :1026'),
    ]
