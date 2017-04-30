import pytest
from mock import Mock, patch, call
import socket
import struct

from sshuttle.helpers import Fatal
from sshuttle.methods import get_method


def test_get_supported_features():
    method = get_method('nat')
    features = method.get_supported_features()
    assert not features.ipv6
    assert not features.udp
    assert features.dns


def test_get_tcp_dstip():
    sock = Mock()
    sock.getsockopt.return_value = struct.pack(
        '!HHBBBB', socket.ntohs(socket.AF_INET), 1024, 127, 0, 0, 1)
    method = get_method('nat')
    assert method.get_tcp_dstip(sock) == ('127.0.0.1', 1024)
    assert sock.mock_calls == [call.getsockopt(0, 80, 16)]


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
    assert not method.firewall_command("somthing")


@patch('sshuttle.methods.nat.ipt')
@patch('sshuttle.methods.nat.ipt_ttl')
@patch('sshuttle.methods.nat.ipt_chain_exists')
def test_setup_firewall(mock_ipt_chain_exists, mock_ipt_ttl, mock_ipt):
    mock_ipt_chain_exists.return_value = True
    method = get_method('nat')
    assert method.name == 'nat'

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1024, 1026,
            [(10, u'2404:6800:4004:80c::33')],
            10,
            [(10, 64, False, u'2404:6800:4004:80c::', 0, 0),
                (10, 128, True, u'2404:6800:4004:80c::101f', 80, 80)],
            True)
    assert str(excinfo.value) \
        == 'Address family "AF_INET6" unsupported by nat method_name'
    assert mock_ipt_chain_exists.mock_calls == []
    assert mock_ipt_ttl.mock_calls == []
    assert mock_ipt.mock_calls == []

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0', 8000, 9000),
                (2, 32, True, u'1.2.3.66', 8080, 8080)],
            True)
    assert str(excinfo.value) == 'UDP not supported by nat method_name'
    assert mock_ipt_chain_exists.mock_calls == []
    assert mock_ipt_ttl.mock_calls == []
    assert mock_ipt.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(2, u'1.2.3.33')],
        2,
        [(2, 24, False, u'1.2.3.0', 8000, 9000),
            (2, 32, True, u'1.2.3.66', 8080, 8080)],
        False)
    assert mock_ipt_chain_exists.mock_calls == [
        call(2, 'nat', 'sshuttle-1025')
    ]
    assert mock_ipt_ttl.mock_calls == [
        call(2, 'nat', '-A', 'sshuttle-1025', '-j', 'REDIRECT',
            '--dest', u'1.2.3.0/24', '-p', 'tcp', '--dport', '8000:9000',
             '--to-ports', '1025'),
        call(2, 'nat', '-A', 'sshuttle-1025', '-j', 'REDIRECT',
             '--dest', u'1.2.3.33/32', '-p', 'udp',
             '--dport', '53', '--to-ports', '1027')
    ]
    assert mock_ipt.mock_calls == [
        call(2, 'nat', '-D', 'OUTPUT', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-D', 'PREROUTING', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-F', 'sshuttle-1025'),
        call(2, 'nat', '-X', 'sshuttle-1025'),
        call(2, 'nat', '-N', 'sshuttle-1025'),
        call(2, 'nat', '-F', 'sshuttle-1025'),
        call(2, 'nat', '-I', 'OUTPUT', '1', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-I', 'PREROUTING', '1', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-A', 'sshuttle-1025', '-j', 'RETURN',
            '--dest', u'1.2.3.66/32', '-p', 'tcp', '--dport', '8080:8080')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt_ttl.reset_mock()
    mock_ipt.reset_mock()

    method.restore_firewall(1025, 2, False)
    assert mock_ipt_chain_exists.mock_calls == [
        call(2, 'nat', 'sshuttle-1025')
    ]
    assert mock_ipt_ttl.mock_calls == []
    assert mock_ipt.mock_calls == [
        call(2, 'nat', '-D', 'OUTPUT', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-D', 'PREROUTING', '-j', 'sshuttle-1025'),
        call(2, 'nat', '-F', 'sshuttle-1025'),
        call(2, 'nat', '-X', 'sshuttle-1025')
    ]
    mock_ipt_chain_exists.reset_mock()
    mock_ipt_ttl.reset_mock()
    mock_ipt.reset_mock()
