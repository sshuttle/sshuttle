import pytest
from mock import Mock, patch, call, ANY
import socket

from sshuttle.methods import get_method


def test_get_supported_features():
    method = get_method('pf')
    features = method.get_supported_features()
    assert not features.ipv6
    assert not features.udp


def test_get_tcp_dstip():
    sock = Mock()
    sock.getpeername.return_value = ("127.0.0.1", 1024)
    sock.getsockname.return_value = ("127.0.0.2", 1025)
    sock.family = socket.AF_INET

    firewall = Mock()
    firewall.pfile.readline.return_value = \
        "QUERY_PF_NAT_SUCCESS 127.0.0.3,1026\n"

    method = get_method('pf')
    method.set_firewall(firewall)
    assert method.get_tcp_dstip(sock) == ('127.0.0.3', 1026)

    assert sock.mock_calls == [
        call.getpeername(),
        call.getsockname(),
    ]
    assert firewall.mock_calls == [
        call.pfile.write('QUERY_PF_NAT 2,6,127.0.0.1,1024,127.0.0.2,1025\n'),
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


def test_check_settings():
    method = get_method('pf')
    method.check_settings(True, True)
    method.check_settings(False, True)


@patch('sshuttle.methods.pf.sys.stdout')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_firewall_command(mock_pf_get_dev, mock_ioctl, mock_stdout):
    method = get_method('pf')
    assert not method.firewall_command("somthing")

    command = "QUERY_PF_NAT %d,%d,%s,%d,%s,%d\n" % (
        socket.AF_INET, socket.IPPROTO_TCP,
        "127.0.0.1", 1025, "127.0.0.2", 1024)
    assert method.firewall_command(command)

    assert mock_pf_get_dev.mock_calls == [call()]
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 3226747927, ANY),
    ]
    assert mock_stdout.mock_calls == [
        call.write('QUERY_PF_NAT_SUCCESS 0.0.0.0,0\n'),
        call.flush(),
    ]


# FIXME - test fails with platform=='darwin' due re.search not liking Mock
# objects.
@patch('sshuttle.methods.pf.sys.platform', 'not_darwin')
@patch('sshuttle.methods.pf.pfctl')
@patch('sshuttle.methods.pf.ioctl')
@patch('sshuttle.methods.pf.pf_get_dev')
def test_setup_firewall(mock_pf_get_dev, mock_ioctl, mock_pfctl):
    method = get_method('pf')
    assert method.name == 'pf'

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1024, 1026,
            [(10, u'2404:6800:4004:80c::33')],
            10,
            [(10, 64, False, u'2404:6800:4004:80c::'),
                (10, 128, True, u'2404:6800:4004:80c::101f')],
            True)
    assert str(excinfo.value) \
        == 'Address family "AF_INET6" unsupported by pf method_name'
    assert mock_pf_get_dev.mock_calls == []
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == []

    with pytest.raises(Exception) as excinfo:
        method.setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0'), (2, 32, True, u'1.2.3.66')],
            True)
    assert str(excinfo.value) == 'UDP not supported by pf method_name'
    assert mock_pf_get_dev.mock_calls == []
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == []

    method.setup_firewall(
        1025, 1027,
        [(2, u'1.2.3.33')],
        2,
        [(2, 24, False, u'1.2.3.0'), (2, 32, True, u'1.2.3.66')],
        False)
    assert mock_ioctl.mock_calls == [
        call(mock_pf_get_dev(), 3295691827, ANY),
        call(mock_pf_get_dev(), 3424666650, ANY),
        call(mock_pf_get_dev(), 3424666650, ANY),
        call(mock_pf_get_dev(), 3295691827, ANY),
        call(mock_pf_get_dev(), 3424666650, ANY),
        call(mock_pf_get_dev(), 3424666650, ANY),
    ]
    # FIXME - needs more work
    # print(mock_pfctl.mock_calls)
    # assert mock_pfctl.mock_calls == []
    mock_pf_get_dev.reset_mock()
    mock_ioctl.reset_mock()
    mock_pfctl.reset_mock()

    method.setup_firewall(1025, 0, [], 2, [], False)
    assert mock_ioctl.mock_calls == []
    assert mock_pfctl.mock_calls == [call('-a sshuttle -F all')]
    mock_pf_get_dev.reset_mock()
    mock_pfctl.reset_mock()
    mock_ioctl.reset_mock()
