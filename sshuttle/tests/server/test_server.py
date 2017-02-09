import os
import io
import socket
import sshuttle.server
from mock import patch, Mock, call


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
