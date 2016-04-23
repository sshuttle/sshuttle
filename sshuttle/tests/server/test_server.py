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


@patch('sshuttle.server.ssubprocess.Popen')
def test__listroutes(mock_popen):
    mock_pobj = Mock()
    mock_pobj.stdout = io.BytesIO(b"""
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.1     0.0.0.0         UG        0 0          0 wlan0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 wlan0
""")
    mock_pobj.wait.return_value = 0
    mock_popen.return_value = mock_pobj

    routes = sshuttle.server._list_routes()

    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    assert mock_popen.mock_calls == [
        call(['netstat', '-rn'], stdout=-1, env=env),
        call().wait()
    ]
    assert routes == [
        (socket.AF_INET, '0.0.0.0', 0),
        (socket.AF_INET, '192.168.1.0', 24)
    ]


@patch('sshuttle.server.ssubprocess.Popen')
def test_listroutes(mock_popen):
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
