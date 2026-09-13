import io
import socket
import time

from unittest.mock import patch, Mock

import sshuttle.server
import sshuttle.ssnet as ssnet


def test__ipmatch():
    assert sshuttle.server._ipmatch("1.2.3.4") is not None
    assert sshuttle.server._ipmatch("::1") is None   # ipv6 not supported
    assert sshuttle.server._ipmatch("42 Example Street, Melbourne") is None


def test__ipstr():
    assert sshuttle.server._ipstr("1.2.3.4", 24) == "1.2.3.4/24"
    assert sshuttle.server._ipstr("1.2.3.4", 32) == "1.2.3.4"


def test__maskbits():
    netmask = sshuttle.server._ipmatch("255.255.255.0")
    sshuttle.server._maskbits(netmask)


@patch('sshuttle.server.which', side_effect=lambda x: x == 'netstat')
@patch('sshuttle.server.ssubprocess.Popen')
def test_listroutes_netstat(mock_popen, mock_which):
    mock_pobj = Mock()
    mock_pobj.stdout = io.BytesIO(b"""
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 wlan0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 wlan0
""")
    mock_pobj.wait.return_value = 0
    mock_popen.return_value = mock_pobj

    routes = sshuttle.server.list_routes()

    assert list(routes) == [
        (socket.AF_INET, '192.168.1.0', 24)
    ]


@patch('sshuttle.server.which', side_effect=lambda x: x == 'ip')
@patch('sshuttle.server.ssubprocess.Popen')
def test_listroutes_iproute(mock_popen, mock_which):
    mock_pobj = Mock()
    mock_pobj.stdout = io.BytesIO(b"""
default via 192.168.1.1 dev wlan0  proto static
192.168.1.0/24 dev wlan0  proto kernel  scope link  src 192.168.1.1
""")
    mock_pobj.wait.return_value = 0
    mock_popen.return_value = mock_pobj

    routes = sshuttle.server.list_routes()

    assert list(routes) == [
        (socket.AF_INET, '192.168.1.0', 24)
    ]


def _drain(timeout=5.0):
    """Wait for ssnet's close helpers to work through the queue."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ssnet._close_q is None or ssnet._close_q.empty():
            return True
        time.sleep(0.01)
    return False


def test_dnsproxy_dispose_closes_every_socket_it_made():
    """try_send() records a socket in self.peers before send(); a socket
    whose send() failed never reaches self.socks, but still needs closing."""
    a, b = socket.socketpair()
    h = sshuttle.server.DnsProxy.__new__(sshuttle.server.DnsProxy)
    h.peers = {a: 'nameserver'}
    h.socks = []  # send() failed, so it never got here
    h.dispose()
    assert _drain()

    deadline = time.monotonic() + 5.0
    while a.fileno() != -1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert a.fileno() == -1
    b.close()


def test_udpproxy_dispose_closes_its_socket():
    a, b = socket.socketpair()
    h = sshuttle.server.UdpProxy.__new__(sshuttle.server.UdpProxy)
    h.sock = a
    h.dispose()
    assert _drain()

    deadline = time.monotonic() + 5.0
    while a.fileno() != -1 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert a.fileno() == -1
    b.close()
