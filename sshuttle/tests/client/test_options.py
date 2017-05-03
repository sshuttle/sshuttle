import socket
import pytest
import sshuttle.options
from argparse import ArgumentTypeError as Fatal

_ip4_reprs = {
        '0.0.0.0': '0.0.0.0',
        '255.255.255.255': '255.255.255.255',
        '10.0': '10.0.0.0',
        '184.172.10.74': '184.172.10.74',
        '3098282570': '184.172.10.74',
        '0xb8.0xac.0x0a.0x4a': '184.172.10.74',
        '0270.0254.0012.0112': '184.172.10.74',
        'localhost': '127.0.0.1'
}

_ip4_swidths = (1, 8, 22, 27, 32)

_ip6_reprs = {
        '::': '::',
        '::1': '::1',
        'fc00::': 'fc00::',
        '2a01:7e00:e000:188::1': '2a01:7e00:e000:188::1'
}

_ip6_swidths = (48, 64, 96, 115, 128)

def test_parse_subnetport_ip4():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr) \
                == (socket.AF_INET, ip, 32, 0, 0)
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('10.256.0.0')
    assert str(excinfo.value) == 'Unable to resolve address: 10.256.0.0'


def test_parse_subnetport_ip4_with_mask():
    for ip_repr, ip in _ip4_reprs.items():
        for swidth in _ip4_swidths:
            assert sshuttle.options.parse_subnetport(
                    '/'.join((ip_repr, str(swidth)))
                    ) == (socket.AF_INET, ip, swidth, 0, 0)
    assert sshuttle.options.parse_subnetport('0/0') \
            == (socket.AF_INET, '0.0.0.0', 0, 0, 0)
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('10.0.0.0/33')
    assert str(excinfo.value) == 'width 33 is not between 0 and 32'


def test_parse_subnetport_ip4_with_port():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(':'.join((ip_repr, '80'))) \
                == (socket.AF_INET, ip, 32, 80, 80)
        assert sshuttle.options.parse_subnetport(':'.join((ip_repr, '80-90'))) \
                == (socket.AF_INET, ip, 32, 80, 90)


def test_parse_subnetport_ip4_with_mask_and_port():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr + '/32:80') \
                == (socket.AF_INET, ip, 32, 80, 80)
        assert sshuttle.options.parse_subnetport(ip_repr + '/16:80-90') \
                == (socket.AF_INET, ip, 16, 80, 90)


def test_parse_subnetport_ip6():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr) \
                == (socket.AF_INET6, ip, 128, 0, 0)
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('2001::1::3f')
    assert str(excinfo.value) == 'Unable to resolve address: 2001::1::3f'


def test_parse_subnetport_ip6_with_mask():
    for ip_repr, ip in _ip6_reprs.items():
        for swidth in _ip4_swidths + _ip6_swidths:
            assert sshuttle.options.parse_subnetport(
                    '/'.join((ip_repr, str(swidth)))
                    ) == (socket.AF_INET6, ip, swidth, 0, 0)
    assert sshuttle.options.parse_subnetport('::/0') \
            == (socket.AF_INET6, '::', 0, 0, 0)
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('fc00::/129')
    assert str(excinfo.value) == 'width 129 is not between 0 and 128'


def test_parse_subnetport_ip6_with_port():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport('[' + ip_repr + ']:80') \
                == (socket.AF_INET6, ip, 128, 80, 80)
        assert sshuttle.options.parse_subnetport('[' + ip_repr + ']:80-90') \
                == (socket.AF_INET6, ip, 128, 80, 90)


def test_parse_subnetport_ip6_with_mask_and_port():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport('[' + ip_repr + '/128]:80') \
                == (socket.AF_INET6, ip, 128, 80, 80)
        assert sshuttle.options.parse_subnetport('[' + ip_repr + '/16]:80-90') \
                == (socket.AF_INET6, ip, 16, 80, 90)
