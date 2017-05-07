import pytest
from mock import Mock, patch, call, ANY
import socket

from sshuttle.methods import get_method
from sshuttle.helpers import Fatal
from sshuttle.methods.pf import FreeBsd, Darwin, OpenBsd


def test_get_supported_features():
    method = get_method('pf')
    features = method.get_supported_features()
    assert features.ipv6
    assert not features.udp
    assert features.dns


@patch('sshuttle.helpers.verbose', new=3)
def test_get_tcp_dstip():
    sock = Mock()
    sock.getpeername.return_value = ("127.0.0.1", 1024)
    sock.getsockname.return_value = ("127.0.0.2", 1025)
    sock.family = socket.AF_INET

    firewall = Mock()
    firewall.pfile.readline.return_value = \
        b"QUERY_PF_NAT_SUCCESS 127.0.0.3,1026\n"

    method = get_method('pf')
    method.set_firewall(firewall)
    assert method.get_tcp_dstip(sock) == ('127.0.0.3', 1026)

    assert sock.mock_calls == [
        call.getpeername(),
        call.getsockname(),
    ]
    assert firewall.mock_calls == [
        call.pfile.write(b'QUERY_PF_NAT 2,6,127.0.0.1,1024,127.0.0.2,1025\n'),
        call.pfile.flush(),
        call.pfile.readline()
    ]


def test_recv_udp():
    sock = Mock()
    sock.recvfrom.return_value = "11111", "127.0.0.1"
    method = get_method('pf')
    result = method.recv_udp(sock, 1024)
    assert sock.mock_calls == [call.recvfrom(1024)]
    assert result == ("127.0.0.1", None, "11111")


def test_send_udp():
    sock = Mock()
    method = get_method('pf')
    method.send_udp(sock, None, "127.0.0.1", "22222")
    assert sock.mock_calls == [call.sendto("22222", "127.0.0.1")]


def test_setup_tcp_listener():
    listener = Mock()
    method = get_method('pf')
    method.setup_tcp_listener(listener)
    assert listener.mock_calls == []


def test_setup_udp_listener():
    listener = Mock()
    method = get_method('pf')
    method.setup_udp_listener(listener)
    assert listener.mock_calls == []


def test_assert_features():
    method = get_method('pf')
    features = method.get_supported_features()
    method.assert_features(features)

    features.udp = True
    with pytest.raises(Fatal):
        method.assert_features(features)

    features.ipv6 = True
    with pytest.raises(Fatal):
        method.assert_features(features)


@patch('sshuttle.methods.pf.pf', Darwin())
@patch('sshuttle.methods.pf.sys.stdout')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_firewall_command_darwin(mock_pf_get_dev, mock_ioctl, mock_stdout):
    method = get_method('pf')
    assert not method.firewall_command("somthing")

    command = "QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % (
        socket.AF_INET, socket.IPPROTO_TCP,
        "127.0.0.1", 1025, "127.0.0.2", 1024)
    assert method.firewall_command(command)

    assert mock_pf_get_dev.mock_calls == [call()]
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xc0544417, ANY),
    ]
    assert mock_stdout.mock_calls == [
        call.write('QUERY_PF_NAT_SUCCESS 0.0.0.0,0\n'),
        call.flush(),
    ]


@patch('sshuttle.methods.pf.pf', FreeBsd())
@patch('sshuttle.methods.pf.sys.stdout')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_firewall_command_freebsd(mock_pf_get_dev, mock_ioctl, mock_stdout):
    method = get_method('pf')
    assert not method.firewall_command("somthing")

    command = "QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % (
        socket.AF_INET, socket.IPPROTO_TCP,
        "127.0.0.1", 1025, "127.0.0.2", 1024)
    assert method.firewall_command(command)

    assert mock_pf_get_dev.mock_calls == [call()]
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xc04c4417, ANY),
    ]
    assert mock_stdout.mock_calls == [
        call.write('QUERY_PF_NAT_SUCCESS 0.0.0.0,0\n'),
        call.flush(),
    ]


@patch('sshuttle.methods.pf.pf', OpenBsd())
@patch('sshuttle.methods.pf.sys.stdout')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_firewall_command_openbsd(mock_pf_get_dev, mock_ioctl, mock_stdout):
    method = get_method('pf')
    assert not method.firewall_command("somthing")

    command = "QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % (
        socket.AF_INET, socket.IPPROTO_TCP,
        "127.0.0.1", 1025, "127.0.0.2", 1024)
    assert method.firewall_command(command)

    assert mock_pf_get_dev.mock_calls == [call()]
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xc0504417, ANY),
    ]
    assert mock_stdout.mock_calls == [
        call.write('QUERY_PF_NAT_SUCCESS 0.0.0.0,0\n'),
        call.flush(),
    ]


def pfctl(args, stdin=None):
    if args == '-s Interfaces -i lo -v':
        return (b'lo0 (skip)',)
    if args == '-s all':
        return (b'INFO:\nStatus: Disabled\nanother mary had a little lamb\n',
                b'little lamb\n')
    if args == '-E':
        return (b'\n', b'Token : abcdefg\n')
    return None


@patch('sshuttle.helpers.verbose', new=3)
@patch('sshuttle.methods.pf.pf', Darwin())
@patch('sshuttle.methods.pf.pfctl')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_setup_firewall_darwin(mock_pf_get_dev, mock_ioctl, mock_pfctl):
    mock_pfctl.side_effect = pfctl

    method = get_method('pf')
    assert method.name == 'pf'

    # IPV6

    method.setup_firewall(
        1024, 1026,
        [(10, u'2404:6800:4004:80c::33')],
        10,
        [(10, 64, False, u'2404:6800:4004:80c::', 8000, 9000),
            (10, 128, True, u'2404:6800:4004:80c::101f', 8080, 8080)],
        False)
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
    ]
    assert mock_pfctl.mock_calls == [
        call('-s Interfaces -i lo -v'),
        call('-f /dev/stdin', b'pass on lo\n'),
        call('-s all'),
        call('-a sshuttle6-1024 -f /dev/stdin',
             b'table <dns_servers> {2404:6800:4004:80c::33}\n'
             b'rdr pass on lo0 inet6 proto tcp to '
             b'2404:6800:4004:80c::/64 port 8000:9000 -> ::1 port 1024\n'
             b'rdr pass on lo0 inet6 proto udp '
             b'to <dns_servers> port 53 -> ::1 port 1026\n'
             b'pass out quick inet6 proto tcp to '
             b'2404:6800:4004:80c::101f/128 port 8080:8080\n'
             b'pass out route-to lo0 inet6 proto tcp to '
             b'2404:6800:4004:80c::/64 port 8000:9000 keep state\n'
             b'pass out route-to lo0 inet6 proto udp '
             b'to <dns_servers> port 53 keep state\n'),
        call('-E'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0', 0, 0),
                (2, 32, True, u'1.2.3.66', 80, 80)],
            True)
    assert str(excinfo.value) == 'UDP not supported by pf method_name'
    assert mock_pf_get_dev.mock_calls == []
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(2, u'1.2.3.33')],
        2,
        [(2, 24, False, u'1.2.3.0', 0, 0), (2, 32, True, u'1.2.3.66', 80, 80)],
        False)
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
        call(mock_pf_get_dev(), 0xCC20441A, ANY),
    ]
    assert mock_pfctl.mock_calls == [
        call('-s Interfaces -i lo -v'),
        call('-f /dev/stdin', b'pass on lo\n'),
        call('-s all'),
        call('-a sshuttle-1025 -f /dev/stdin',
             b'table <dns_servers> {1.2.3.33}\n'
             b'rdr pass on lo0 inet proto tcp to 1.2.3.0/24 '
             b'-> 127.0.0.1 port 1025\n'
             b'rdr pass on lo0 inet proto udp '
             b'to <dns_servers> port 53 -> 127.0.0.1 port 1027\n'
             b'pass out quick inet proto tcp to 1.2.3.66/32 port 80:80\n'
             b'pass out route-to lo0 inet proto tcp to 1.2.3.0/24 keep state\n'
             b'pass out route-to lo0 inet proto udp '
             b'to <dns_servers> port 53 keep state\n'),
        call('-E'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    method.restore_firewall(1025, 2, False)
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == [
        call('-a sshuttle-1025 -F all'),
        call("-X abcdefg"),
    ]
    mock_pf_get_dev.reset_mock()
    mock_pfctl.reset_mock()
    mock_ioctl.reset_mock()


@patch('sshuttle.helpers.verbose', new=3)
@patch('sshuttle.methods.pf.pf', FreeBsd())
@patch('sshuttle.methods.pf.pfctl')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_setup_firewall_freebsd(mock_pf_get_dev, mock_ioctl, mock_pfctl):
    mock_pfctl.side_effect = pfctl

    method = get_method('pf')
    assert method.name == 'pf'

    method.setup_firewall(
        1024, 1026,
        [(10, u'2404:6800:4004:80c::33')],
        10,
        [(10, 64, False, u'2404:6800:4004:80c::', 8000, 9000),
            (10, 128, True, u'2404:6800:4004:80c::101f', 8080, 8080)],
        False)

    assert mock_pfctl.mock_calls == [
        call('-s all'),
        call('-a sshuttle6-1024 -f /dev/stdin',
             b'table <dns_servers> {2404:6800:4004:80c::33}\n'
             b'rdr pass on lo0 inet6 proto tcp to 2404:6800:4004:80c::/64 '
             b'port 8000:9000 -> ::1 port 1024\n'
             b'rdr pass on lo0 inet6 proto udp '
             b'to <dns_servers> port 53 -> ::1 port 1026\n'
             b'pass out quick inet6 proto tcp to '
             b'2404:6800:4004:80c::101f/128 port 8080:8080\n'
             b'pass out route-to lo0 inet6 proto tcp to '
             b'2404:6800:4004:80c::/64 port 8000:9000 keep state\n'
             b'pass out route-to lo0 inet6 proto udp '
             b'to <dns_servers> port 53 keep state\n'),
        call('-e'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0', 0, 0),
                (2, 32, True, u'1.2.3.66', 80, 80)],
            True)
    assert str(excinfo.value) == 'UDP not supported by pf method_name'
    assert mock_pf_get_dev.mock_calls == []
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(2, u'1.2.3.33')],
        2,
        [(2, 24, False, u'1.2.3.0', 0, 0), (2, 32, True, u'1.2.3.66', 80, 80)],
        False)
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCBE0441A, ANY),
        call(mock_pf_get_dev(), 0xCBE0441A, ANY),
        call(mock_pf_get_dev(), 0xC4704433, ANY),
        call(mock_pf_get_dev(), 0xCBE0441A, ANY),
        call(mock_pf_get_dev(), 0xCBE0441A, ANY),
    ]
    assert mock_pfctl.mock_calls == [
        call('-s all'),
        call('-a sshuttle-1025 -f /dev/stdin',
             b'table <dns_servers> {1.2.3.33}\n'
             b'rdr pass on lo0 inet proto tcp to 1.2.3.0/24 -> '
             b'127.0.0.1 port 1025\n'
             b'rdr pass on lo0 inet proto udp '
             b'to <dns_servers> port 53 -> 127.0.0.1 port 1027\n'
             b'pass out quick inet proto tcp to 1.2.3.66/32 port 80:80\n'
             b'pass out route-to lo0 inet proto tcp to 1.2.3.0/24 keep state\n'
             b'pass out route-to lo0 inet proto udp '
             b'to <dns_servers> port 53 keep state\n'),
        call('-e'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    method.restore_firewall(1025, 2, False)
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == [
        call('-a sshuttle-1025 -F all'),
        call("-d"),
    ]
    mock_pf_get_dev.reset_mock()
    mock_pfctl.reset_mock()
    mock_ioctl.reset_mock()


@patch('sshuttle.helpers.verbose', new=3)
@patch('sshuttle.methods.pf.pf', OpenBsd())
@patch('sshuttle.methods.pf.pfctl')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_setup_firewall_openbsd(mock_pf_get_dev, mock_ioctl, mock_pfctl):
    mock_pfctl.side_effect = pfctl

    method = get_method('pf')
    assert method.name == 'pf'

    method.setup_firewall(
        1024, 1026,
        [(10, u'2404:6800:4004:80c::33')],
        10,
        [(10, 64, False, u'2404:6800:4004:80c::', 8000, 9000),
            (10, 128, True, u'2404:6800:4004:80c::101f', 8080, 8080)],
        False)

    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xcd48441a, ANY),
        call(mock_pf_get_dev(), 0xcd48441a, ANY),
    ]
    assert mock_pfctl.mock_calls == [
        call('-s Interfaces -i lo -v'),
        call('-f /dev/stdin', b'match on lo\n'),
        call('-s all'),
        call('-a sshuttle6-1024 -f /dev/stdin',
             b'table <dns_servers> {2404:6800:4004:80c::33}\n'
             b'pass in on lo0 inet6 proto tcp to 2404:6800:4004:80c::/64 '
             b'port 8000:9000 divert-to ::1 port 1024\n'
             b'pass in on lo0 inet6 proto udp '
             b'to <dns_servers> port 53 rdr-to ::1 port 1026\n'
             b'pass out quick inet6 proto tcp to '
             b'2404:6800:4004:80c::101f/128 port 8080:8080\n'
             b'pass out inet6 proto tcp to 2404:6800:4004:80c::/64 '
             b'port 8000:9000 route-to lo0 keep state\n'
             b'pass out inet6 proto udp to '
             b'<dns_servers> port 53 route-to lo0 keep state\n'),
        call('-e'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()
    
    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0', 0, 0),
                (2, 32, True, u'1.2.3.66', 80, 80)],
            True)
    assert str(excinfo.value) == 'UDP not supported by pf method_name'
    assert mock_pf_get_dev.mock_calls == []
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(2, u'1.2.3.33')],
        2,
        [(2, 24, False, u'1.2.3.0', 0, 0),
            (2, 32, True, u'1.2.3.66', 80, 80)],
        False)
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 0xcd48441a, ANY),
        call(mock_pf_get_dev(), 0xcd48441a, ANY),
    ]
    assert mock_pfctl.mock_calls == [
        call('-s Interfaces -i lo -v'),
        call('-f /dev/stdin', b'match on lo\n'),
        call('-s all'),
        call('-a sshuttle-1025 -f /dev/stdin',
             b'table <dns_servers> {1.2.3.33}\n'
             b'pass in on lo0 inet proto tcp to 1.2.3.0/24 divert-to '
             b'127.0.0.1 port 1025\n'
             b'pass in on lo0 inet proto udp to '
             b'<dns_servers> port 53 rdr-to 127.0.0.1 port 1027\n'
             b'pass out quick inet proto tcp to 1.2.3.66/32 port 80:80\n'
             b'pass out inet proto tcp to 1.2.3.0/24 route-to lo0 keep state\n'
             b'pass out inet proto udp to '
             b'<dns_servers> port 53 route-to lo0 keep state\n'),
        call('-e'),
    ]
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    method.restore_firewall(1025, 2, False)
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == [
        call('-a sshuttle-1025 -F all'),
        call("-d"),
    ]
    mock_pf_get_dev.reset_mock()
    mock_pfctl.reset_mock()
    mock_ioctl.reset_mock()
