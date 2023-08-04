import socket
from socket import AF_INET, AF_INET6
import struct

import pytest
from unittest.mock import Mock, patch, call
from sshuttle.helpers import Fatal
from sshuttle.methods import get_method


def test_get_supported_features():
    method = get_method('nat')
    features = method.get_supported_features()
    assert features.ipv6
    assert not features.udp
    assert features.dns


def test_get_tcp_dstip():
    sock = Mock()
    sock.family = AF_INET
    sock.getsockopt.return_value = struct.pack(
        '!HHBBBB', socket.ntohs(AF_INET), 1024, 127, 0, 0, 1)
    method = get_method('nat')
    assert method.get_tcp_dstip(sock) == ('127.0.0.1', 1024)
    assert sock.mock_calls == [call.getsockopt(0, 80, 16)]

    sock = Mock()
    sock.family = AF_INET6
    sock.getsockopt.return_value = struct.pack(
        '!HH4xBBBBBBBBBBBBBBBB', socket.ntohs(AF_INET6),
        1024, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
    method = get_method('nft')
    assert method.get_tcp_dstip(sock) == ('::1', 1024)
    assert sock.mock_calls == [call.getsockopt(41, 80, 64)]


def test_recv_udp():
    sock = Mock()
    sock.recvfrom.return_value = "11111", "127.0.0.1"
    method = get_method('nat')
    result = method.recv_udp(sock, 1024)
    assert sock.mock_calls == [call.recvfrom(1024)]
    assert result == ("127.0.0.1", None, "11111")


def test_send_udp():
    sock = Mock()
    method = get_method('nat')
    method.send_udp(sock, None, "127.0.0.1", "22222")
    assert sock.mock_calls == [call.sendto("22222", "127.0.0.1")]


def test_setup_tcp_listener():
    listener = Mock()
    method = get_method('nat')
    method.setup_tcp_listener(listener)
    assert listener.mock_calls == []


def test_setup_udp_listener():
    listener = Mock()
    method = get_method('nat')
    method.setup_udp_listener(listener)
    assert listener.mock_calls == []


def test_assert_features():
    method = get_method('nat')
    features = method.get_supported_features()
    method.assert_features(features)

    features.udp = True
    with pytest.raises(Fatal):
        method.assert_features(features)

    features.ipv6 = True
    with pytest.raises(Fatal):
        method.assert_features(features)


def test_firewall_command():
    method = get_method('nat')
    assert not method.firewall_command("something")


@patch('sshuttle.methods.nat.ipt')
@patch('sshuttle.methods.nat.ipt_chain_exists')
def test_setup_firewall(mock_ipt_chain_exists, mock_ipt):
    mock_ipt_chain_exists.return_value = True
    method = get_method('nat')
    assert method.name == 'nat'

    assert mock_ipt_chain_exists.mock_calls == []
    assert mock_ipt.mock_calls == []
    method.setup_firewall(
        1024, 1026,
        [(AF_INET6, u'2404:6800:4004:80c::33')],
        AF_INET6,
        [(AF_INET6, 64, False, u'2404:6800:4004:80c::', 0, 0),
         (AF_INET6, 128, True, u'2404:6800:4004:80c::101f', 80, 80)],
        False,
        None,
        None,
        '0x01')

    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET6, 'nat', 'sshuttle-1024')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET6, 'nat', '-D', 'OUTPUT', '-j', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-D', 'PREROUTING', '-j', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-F', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-X', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-N', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-F', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-I', 'OUTPUT', '1', '-j', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-I', 'PREROUTING', '1', '-j', 'sshuttle-1024'),
        call(AF_INET6, 'nat', '-A', 'sshuttle-1024', '-j', 'REDIRECT',
             '--dest', u'2404:6800:4004:80c::33', '-p', 'udp',
             '--dport', '53', '--to-ports', '1026'),
        call(AF_INET6, 'nat', '-A', 'sshuttle-1024', '-j', 'RETURN',
             '--dest', u'2404:6800:4004:80c::101f/128', '-p', 'tcp',
             '--dport', '80:80'),
        call(AF_INET6, 'nat', '-A', 'sshuttle-1024', '-j', 'REDIRECT',
             '--dest', u'2404:6800:4004:80c::/64', '-p', 'tcp',
             '--to-ports', '1024'),
        call(AF_INET6, 'nat', '-A', 'sshuttle-1024', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    assert mock_ipt_chain_exists.mock_calls == []
    assert mock_ipt.mock_calls == []

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(AF_INET, u'1.2.3.33')],
            AF_INET,
            [(AF_INET, 24, False, u'1.2.3.0', 8000, 9000),
                (AF_INET, 32, True, u'1.2.3.66', 8080, 8080)],
            True,
            None,
            None,
            '0x01')
    assert str(excinfo.value) == 'UDP not supported by nat method_name'
    assert mock_ipt_chain_exists.mock_calls == []
    assert mock_ipt.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(AF_INET, u'1.2.3.33')],
        AF_INET,
        [(AF_INET, 24, False, u'1.2.3.0', 8000, 9000),
            (AF_INET, 32, True, u'1.2.3.66', 8080, 8080)],
        False,
        None,
        None,
        '0x01')
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET, 'nat', 'sshuttle-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET, 'nat', '-D', 'OUTPUT', '-j', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-D', 'PREROUTING', '-j', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-F', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-X', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-N', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-F', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-I', 'OUTPUT', '1', '-j', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-I', 'PREROUTING', '1', '-j', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-A', 'sshuttle-1025', '-j', 'REDIRECT',
             '--dest', u'1.2.3.33', '-p', 'udp',
             '--dport', '53', '--to-ports', '1027'),
        call(AF_INET, 'nat', '-A', 'sshuttle-1025', '-j', 'RETURN',
             '--dest', u'1.2.3.66/32', '-p', 'tcp', '--dport', '8080:8080'),
        call(AF_INET, 'nat', '-A', 'sshuttle-1025', '-j', 'REDIRECT',
             '--dest', u'1.2.3.0/24', '-p', 'tcp', '--dport', '8000:9000',
             '--to-ports', '1025'),
        call(AF_INET, 'nat', '-A', 'sshuttle-1025', '-j', 'RETURN',
             '-m', 'addrtype', '--dst-type', 'LOCAL'),
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    method.restore_firewall(1025, AF_INET, False, None, None)
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET, 'nat', 'sshuttle-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET, 'nat', '-D', 'OUTPUT', '-j',
             'sshuttle-1025'),
        call(AF_INET, 'nat', '-D', 'PREROUTING', '-j',
             'sshuttle-1025'),
        call(AF_INET, 'nat', '-F', 'sshuttle-1025'),
        call(AF_INET, 'nat', '-X', 'sshuttle-1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()

    method.restore_firewall(1025, AF_INET6, False, None, None)
    assert mock_ipt_chain_exists.mock_calls == [
        call(AF_INET6, 'nat', 'sshuttle-1025')
    ]
    assert mock_ipt.mock_calls == [
        call(AF_INET6, 'nat', '-D', 'OUTPUT', '-j', 'sshuttle-1025'),
        call(AF_INET6, 'nat', '-D', 'PREROUTING', '-j',
             'sshuttle-1025'),
        call(AF_INET6, 'nat', '-F', 'sshuttle-1025'),
        call(AF_INET6, 'nat', '-X', 'sshuttle-1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt.reset_mock()
