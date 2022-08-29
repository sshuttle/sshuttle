import io
import socket
from socket import AF_INET, AF_INET6
import errno

from unittest.mock import patch, call
import sshuttle.helpers


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_log(mock_stderr, mock_stdout):
    sshuttle.helpers.log("message")
    sshuttle.helpers.log("abc")
    sshuttle.helpers.log("message 1\n")
    sshuttle.helpers.log("message 2\nline2\nline3\n")
    sshuttle.helpers.log("message 3\nline2\nline3")
    assert mock_stdout.mock_calls == [
        call.flush(),
        call.flush(),
        call.flush(),
        call.flush(),
        call.flush(),
    ]
    assert mock_stderr.mock_calls == [
        call.write('prefix: message\r\n'),
        call.flush(),
        call.write('prefix: abc\r\n'),
        call.flush(),
        call.write('prefix: message 1\r\n'),
        call.flush(),
        call.write('prefix: message 2\r\n'),
        call.write('    line2\r\n'),
        call.write('    line3\r\n'),
        call.flush(),
        call.write('prefix: message 3\r\n'),
        call.write('    line2\r\n'),
        call.write('    line3\r\n'),
        call.flush(),
    ]


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=1)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug1(mock_stderr, mock_stdout):
    sshuttle.helpers.debug1("message")
    assert mock_stdout.mock_calls == [
        call.flush(),
    ]
    assert mock_stderr.mock_calls == [
        call.write('prefix: message\r\n'),
        call.flush(),
    ]


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=0)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug1_nop(mock_stderr, mock_stdout):
    sshuttle.helpers.debug1("message")
    assert mock_stdout.mock_calls == []
    assert mock_stderr.mock_calls == []


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=2)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug2(mock_stderr, mock_stdout):
    sshuttle.helpers.debug2("message")
    assert mock_stdout.mock_calls == [
        call.flush(),
    ]
    assert mock_stderr.mock_calls == [
        call.write('prefix: message\r\n'),
        call.flush(),
    ]


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=1)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug2_nop(mock_stderr, mock_stdout):
    sshuttle.helpers.debug2("message")
    assert mock_stdout.mock_calls == []
    assert mock_stderr.mock_calls == []


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=3)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug3(mock_stderr, mock_stdout):
    sshuttle.helpers.debug3("message")
    assert mock_stdout.mock_calls == [
        call.flush(),
    ]
    assert mock_stderr.mock_calls == [
        call.write('prefix: message\r\n'),
        call.flush(),
    ]


@patch('sshuttle.helpers.logprefix', new='prefix: ')
@patch('sshuttle.helpers.verbose', new=2)
@patch('sshuttle.helpers.sys.stdout')
@patch('sshuttle.helpers.sys.stderr')
def test_debug3_nop(mock_stderr, mock_stdout):
    sshuttle.helpers.debug3("message")
    assert mock_stdout.mock_calls == []
    assert mock_stderr.mock_calls == []


@patch('sshuttle.helpers.open', create=True)
def test_resolvconf_nameservers(mock_open):
    mock_open.return_value = io.StringIO(u"""
# Generated by NetworkManager
search pri
nameserver 192.168.1.1
nameserver 192.168.2.1
nameserver 192.168.3.1
nameserver 192.168.4.1
nameserver 2404:6800:4004:80c::1
nameserver 2404:6800:4004:80c::2
nameserver 2404:6800:4004:80c::3
nameserver 2404:6800:4004:80c::4
""")

    ns = sshuttle.helpers.resolvconf_nameservers(False)
    assert ns == [
        (AF_INET, u'192.168.1.1'), (AF_INET, u'192.168.2.1'),
        (AF_INET, u'192.168.3.1'), (AF_INET, u'192.168.4.1'),
        (AF_INET6, u'2404:6800:4004:80c::1'),
        (AF_INET6, u'2404:6800:4004:80c::2'),
        (AF_INET6, u'2404:6800:4004:80c::3'),
        (AF_INET6, u'2404:6800:4004:80c::4')
    ]


@patch('sshuttle.helpers.open', create=True)
def test_resolvconf_random_nameserver(mock_open):
    mock_open.return_value = io.StringIO(u"""
# Generated by NetworkManager
search pri
nameserver 192.168.1.1
nameserver 192.168.2.1
nameserver 192.168.3.1
nameserver 192.168.4.1
nameserver 2404:6800:4004:80c::1
nameserver 2404:6800:4004:80c::2
nameserver 2404:6800:4004:80c::3
nameserver 2404:6800:4004:80c::4
""")
    ns = sshuttle.helpers.resolvconf_random_nameserver(False)
    assert ns in [
        (AF_INET, u'192.168.1.1'), (AF_INET, u'192.168.2.1'),
        (AF_INET, u'192.168.3.1'), (AF_INET, u'192.168.4.1'),
        (AF_INET6, u'2404:6800:4004:80c::1'),
        (AF_INET6, u'2404:6800:4004:80c::2'),
        (AF_INET6, u'2404:6800:4004:80c::3'),
        (AF_INET6, u'2404:6800:4004:80c::4')
    ]


@patch('sshuttle.helpers.socket.socket.bind')
def test_islocal(mock_bind):
    bind_error = socket.error(errno.EADDRNOTAVAIL)
    mock_bind.side_effect = [None, bind_error, None, bind_error]

    assert sshuttle.helpers.islocal("127.0.0.1", AF_INET)
    assert not sshuttle.helpers.islocal("192.0.2.1", AF_INET)
    assert sshuttle.helpers.islocal("::1", AF_INET6)
    assert not sshuttle.helpers.islocal("2001:db8::1", AF_INET6)


def test_family_ip_tuple():
    assert sshuttle.helpers.family_ip_tuple("127.0.0.1") \
        == (AF_INET, "127.0.0.1")
    assert sshuttle.helpers.family_ip_tuple("192.168.2.6") \
        == (AF_INET, "192.168.2.6")
    assert sshuttle.helpers.family_ip_tuple("::1") \
        == (AF_INET6, "::1")
    assert sshuttle.helpers.family_ip_tuple("2404:6800:4004:80c::1") \
        == (AF_INET6, "2404:6800:4004:80c::1")


def test_family_to_string():
    assert sshuttle.helpers.family_to_string(AF_INET) == "AF_INET"
    assert sshuttle.helpers.family_to_string(AF_INET6) == "AF_INET6"
    assert isinstance(sshuttle.helpers.family_to_string(socket.AF_UNIX), str)
