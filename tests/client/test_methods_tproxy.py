import socket
from socket import AF_INET, AF_INET6

from unittest.mock import Mock, patch, call

from sshuttle.methods import get_method


def test_get_supported_features():
    method = get_method('tproxy')
    features = method.get_supported_features()
    assert features.ipv6
    assert features.udp
    assert features.dns


def test_get_tcp_dstip():
    sock = Mock()
    sock.getsockname.return_value = ('127.0.0.1', 1024)
    method = get_method('tproxy')
    assert method.get_tcp_dstip(sock) == ('127.0.0.1', 1024)
    assert sock.mock_calls == [call.getsockname()]


@patch("sshuttle.methods.tproxy.recv_udp")
def test_recv_udp(mock_recv_udp):
    mock_recv_udp.return_value = ("127.0.0.1", "127.0.0.2", "11111")

    sock = Mock()
    method = get_method('tproxy')
    result = method.recv_udp(sock, 1024)
    assert sock.mock_calls == []
    assert mock_recv_udp.mock_calls == [call(sock, 1024)]
    assert result == ("127.0.0.1", "127.0.0.2", "11111")


@patch("sshuttle.methods.socket.socket")
def test_send_udp(mock_socket):
    sock = Mock()
    method = get_method('tproxy')
    method.send_udp(sock, "127.0.0.2", "127.0.0.1", "2222222")
    assert sock.mock_calls == []
    assert mock_socket.mock_calls == [
        call(sock.family, 2),
        call().setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
        call().setsockopt(0, 19, 1),
        call().bind('127.0.0.2'),
        call().sendto("2222222", '127.0.0.1'),
        call().close()
    ]


def test_setup_tcp_listener():
    listener = Mock()
    method = get_method('tproxy')
    method.setup_tcp_listener(listener)
    assert listener.mock_calls == [
        call.setsockopt(0, 19, 1)
    ]


def test_setup_udp_listener():
    listener = Mock()
    method = get_method('tproxy')
    method.setup_udp_listener(listener)
    assert listener.mock_calls == [
        call.setsockopt(0, 19, 1),
        call.v4.setsockopt(0, 20, 1),
        call.v6.setsockopt(41, 74, 1)
    ]


def test_assert_features():
    method = get_method('tproxy')
    features = method.get_supported_features()
    method.assert_features(features)


def test_firewall_command():
    method = get_method('tproxy')
    assert not method.firewall_command("something")


@patch('sshuttle.methods.tproxy.ipt')
@patch('sshuttle.methods.tproxy.ipt_chain_exists')
def test_setup_firewall(mock_ipt_chain_exists, mock_ipt):
    mock_ipt_chain_exists.return_value = True
    method = get_method('tproxy')
    assert method.name == 'tproxy'

    # IPV6

    method.setup_firewall(
        1024, 1026,
        [(AF_INET6, u'2404:6800:4004:80c::33')],
        AF_INET6,
        [(AF_INET6, 64, False, u'2404:6800:4004:80c::', 8000, 9000),
            (AF_INET6, 128, True, u'2404:6800:4004:80c::101f', 8080, 8080)],
        True,
        None,
        None,
        '0x01')
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET6, 'mangle', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', 'sshuttle-d-1024')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET6, 'mangle', '-D', 'OUTPUT', '-j', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-D', 'PREROUTING', '-j', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-d-1024'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-d-1024'),
        call(AF_INET6, 'mangle', '-N', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-N', 'sshuttle-d-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-d-1024'),
        call(AF_INET6, 'mangle', '-N', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-I', 'OUTPUT', '1', '-j', 'sshuttle-m-1024'),
        call(AF_INET6, 'mangle', '-I', 'PREROUTING', '1', '-j',
             'sshuttle-t-1024'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'2404:6800:4004:80c::33/32',
             '-m', 'udp', '-p', 'udp', '--dport', '53'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'TPROXY',
             '--tproxy-mark', '0x01',
             '--dest', u'2404:6800:4004:80c::33/32',
             '-m', 'udp', '-p', 'udp', '--dport', '53', '--on-port', '1026'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-d-1024', '-j', 'MARK',
             '--set-mark', '0x01'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-d-1024', '-j', 'ACCEPT'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-m', 'socket',
             '-j', 'sshuttle-d-1024', '-m', 'tcp', '-p', 'tcp'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-m', 'socket',
             '-j', 'sshuttle-d-1024', '-m', 'udp', '-p', 'udp'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'RETURN',
             '--dest', u'2404:6800:4004:80c::101f/128',
             '-m', 'tcp', '-p', 'tcp', '--dport', '8080:8080'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'RETURN',
             '--dest', u'2404:6800:4004:80c::101f/128',
             '-m', 'tcp', '-p', 'tcp', '--dport', '8080:8080'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'RETURN',
             '--dest', u'2404:6800:4004:80c::101f/128',
             '-m', 'udp', '-p', 'udp', '--dport', '8080:8080'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'RETURN',
             '--dest', u'2404:6800:4004:80c::101f/128',
             '-m', 'udp', '-p', 'udp', '--dport', '8080:8080'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'2404:6800:4004:80c::/64',
             '-m', 'tcp', '-p', 'tcp', '--dport', '8000:9000'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'TPROXY',
             '--tproxy-mark', '0x01', '--dest',
             u'2404:6800:4004:80c::/64',
             '-m', 'tcp', '-p', 'tcp', '--dport', '8000:9000',
             '--on-port', '1024'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-m-1024', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'2404:6800:4004:80c::/64',
             '-m', 'udp', '-p', 'udp', '--dport', '8000:9000'),
        call(AF_INET6, 'mangle', '-A', 'sshuttle-t-1024', '-j', 'TPROXY',
             '--tproxy-mark', '0x01', '--dest',
             u'2404:6800:4004:80c::/64',
             '-m', 'udp', '-p', 'udp', '--dport', '8000:9000',
             '--on-port', '1024')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    method.restore_firewall(1025, AF_INET6, True, None, None)
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET6, 'mangle', 'sshuttle-m-1025'),
        call(AF_INET6, 'mangle', 'sshuttle-t-1025'),
        call(AF_INET6, 'mangle', 'sshuttle-d-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET6, 'mangle', '-D', 'OUTPUT', '-j', 'sshuttle-m-1025'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-m-1025'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-m-1025'),
        call(AF_INET6, 'mangle', '-D', 'PREROUTING', '-j', 'sshuttle-t-1025'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-t-1025'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-t-1025'),
        call(AF_INET6, 'mangle', '-F', 'sshuttle-d-1025'),
        call(AF_INET6, 'mangle', '-X', 'sshuttle-d-1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    # IPV4

    method.setup_firewall(
        1025, 1027,
        [(AF_INET, u'1.2.3.33')],
        AF_INET,
        [(AF_INET, 24, False, u'1.2.3.0', 0, 0),
            (AF_INET, 32, True, u'1.2.3.66', 80, 80)],
        True,
        None,
        None,
        '0x01')
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET, 'mangle', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', 'sshuttle-d-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET, 'mangle', '-D', 'OUTPUT', '-j', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-D', 'PREROUTING', '-j', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-d-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-d-1025'),
        call(AF_INET, 'mangle', '-N', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-N', 'sshuttle-d-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-d-1025'),
        call(AF_INET, 'mangle', '-N', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-I', 'OUTPUT', '1', '-j', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-I', 'PREROUTING', '1', '-j',
             'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'1.2.3.33/32',
             '-m', 'udp', '-p', 'udp', '--dport', '53'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'TPROXY',
             '--tproxy-mark', '0x01', '--dest', u'1.2.3.33/32',
             '-m', 'udp', '-p', 'udp', '--dport', '53', '--on-port', '1027'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-d-1025',
             '-j', 'MARK', '--set-mark', '0x01'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-d-1025', '-j', 'ACCEPT'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-m', 'socket',
             '-j', 'sshuttle-d-1025', '-m', 'tcp', '-p', 'tcp'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-m', 'socket',
             '-j', 'sshuttle-d-1025', '-m', 'udp', '-p', 'udp'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'RETURN',
             '--dest', u'1.2.3.66/32', '-m', 'tcp', '-p', 'tcp',
             '--dport', '80:80'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'RETURN',
             '--dest', u'1.2.3.66/32', '-m', 'tcp', '-p', 'tcp',
             '--dport', '80:80'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'RETURN',
             '--dest', u'1.2.3.66/32', '-m', 'udp', '-p', 'udp',
             '--dport', '80:80'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'RETURN',
             '--dest', u'1.2.3.66/32', '-m', 'udp', '-p', 'udp',
             '--dport', '80:80'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'1.2.3.0/24',
             '-m', 'tcp', '-p', 'tcp'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'TPROXY',
             '--tproxy-mark', '0x01', '--dest', u'1.2.3.0/24',
             '-m', 'tcp', '-p', 'tcp', '--on-port', '1025'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-m-1025', '-j', 'MARK',
             '--set-mark', '0x01', '--dest', u'1.2.3.0/24',
             '-m', 'udp', '-p', 'udp'),
        call(AF_INET, 'mangle', '-A', 'sshuttle-t-1025', '-j', 'TPROXY',
             '--tproxy-mark', '0x01', '--dest', u'1.2.3.0/24',
             '-m', 'udp', '-p', 'udp', '--on-port', '1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    method.restore_firewall(1025, AF_INET, True, None, None)
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET, 'mangle', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', 'sshuttle-d-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET, 'mangle', '-D', 'OUTPUT', '-j', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-m-1025'),
        call(AF_INET, 'mangle', '-D', 'PREROUTING', '-j', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-t-1025'),
        call(AF_INET, 'mangle', '-F', 'sshuttle-d-1025'),
        call(AF_INET, 'mangle', '-X', 'sshuttle-d-1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()
