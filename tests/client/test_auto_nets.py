import io
import socket
from unittest.mock import Mock

from sshuttle import client


def start_firewall(subnets_include, subnets_exclude, auto_nets):
    fw = client.FirewallClient.__new__(client.FirewallClient)
    fw.argv = ['sshuttle', '--firewall']
    fw.p = Mock()
    fw.p.poll.return_value = None
    fw.setup(subnets_include, subnets_exclude, [], 0, 12300, 0, 0, False,
             None, None, '0x01')
    fw.auto_nets = auto_nets
    written = io.BytesIO()
    fw.pfile = Mock()
    fw.pfile.write.side_effect = written.write
    fw.pfile.readline.return_value = b'STARTED\n'
    fw.start()
    routes = written.getvalue().split(b'ROUTES\n')[1].split(b'NSLIST\n')[0]
    return routes.decode('ascii').splitlines()


def test_auto_nets_inside_an_exclude_are_not_forwarded():
    v4, v6 = socket.AF_INET, socket.AF_INET6
    routes = start_firewall(
        subnets_include=[],
        subnets_exclude=[(v4, '192.0.2.0', 24, 0, 0),
                         (v4, '198.51.100.0', 24, 22, 22),
                         (v6, '2001:db8::', 32, 0, 0)],
        auto_nets=[(v4, '192.0.2.48', 28, 0, 0),
                   (v4, '192.0.2.53', 32, 0, 0),
                   (v4, '192.0.0.0', 16, 0, 0),
                   (v4, '198.51.100.7', 32, 0, 0),
                   (v4, '203.0.113.0', 24, 0, 0),
                   (v6, '2001:db8:1::', 48, 0, 0)])
    assert routes == [
        f'{v4},16,0,192.0.0.0,0,0',
        f'{v4},32,0,198.51.100.7,0,0',
        f'{v4},24,0,203.0.113.0,0,0',
        f'{v4},24,1,192.0.2.0,0,0',
        f'{v4},24,1,198.51.100.0,22,22',
        f'{v6},32,1,2001:db8::,0,0',
    ]
