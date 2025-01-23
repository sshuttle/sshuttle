import socket
from argparse import ArgumentTypeError as Fatal
from unittest.mock import patch

import pytest

import sshuttle.options

_ip4_reprs = {
        '0.0.0.0': '0.0.0.0',
        '255.255.255.255': '255.255.255.255',
        '10.0': '10.0.0.0',
        '184.172.10.74': '184.172.10.74',
        '3098282570': '184.172.10.74',
        '0xb8.0xac.0x0a.0x4a': '184.172.10.74',
        '0270.0254.0012.0112': '184.172.10.74',
}

_ip4_swidths = (1, 8, 22, 27, 32)

_ip6_reprs = {
        '::': '::',
        '::1': '::1',
        'fc00::': 'fc00::',
        '2a01:7e00:e000:188::1': '2a01:7e00:e000:188::1'
}

_ip6_swidths = (48, 64, 96, 115, 128)


def _mock_getaddrinfo(host, *_):
    return {
        "example.com": [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('2606:2800:220:1:248:1893:25c8:1946', 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('93.184.216.34', 0)),
        ],
        "my.local": [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('::1', 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('127.0.0.1', 0)),
        ],
        "*.blogspot.com": [
            (socket.AF_INET6, socket.SOCK_STREAM, 0, '', ('2404:6800:4004:821::2001', 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, '', ('142.251.42.129', 0)),
        ],
    }.get(host, [])


def test_parse_subnetport_ip4():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr) \
                == [(socket.AF_INET, ip, 32, 0, 0)]
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('10.256.0.0')
    assert str(excinfo.value) == 'Unable to resolve address: 10.256.0.0'


def test_parse_subnetport_ip4_with_mask():
    for ip_repr, ip in _ip4_reprs.items():
        for swidth in _ip4_swidths:
            assert sshuttle.options.parse_subnetport(
                    '/'.join((ip_repr, str(swidth)))
                    ) == [(socket.AF_INET, ip, swidth, 0, 0)]
    assert sshuttle.options.parse_subnetport('0/0') \
        == [(socket.AF_INET, '0.0.0.0', 0, 0, 0)]
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('10.0.0.0/33')
    assert str(excinfo.value) \
        == 'Slash in CIDR notation (/33) is not between 0 and 32'


def test_parse_subnetport_ip4_with_port():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(':'.join((ip_repr, '80'))) \
            == [(socket.AF_INET, ip, 32, 80, 80)]
        assert sshuttle.options.parse_subnetport(':'.join((ip_repr, '80-90')))\
            == [(socket.AF_INET, ip, 32, 80, 90)]


def test_parse_subnetport_ip4_with_mask_and_port():
    for ip_repr, ip in _ip4_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr + '/32:80') \
            == [(socket.AF_INET, ip, 32, 80, 80)]
        assert sshuttle.options.parse_subnetport(ip_repr + '/16:80-90') \
            == [(socket.AF_INET, ip, 16, 80, 90)]


def test_parse_subnetport_ip6():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport(ip_repr) \
                == [(socket.AF_INET6, ip, 128, 0, 0)]


def test_parse_subnetport_ip6_with_mask():
    for ip_repr, ip in _ip6_reprs.items():
        for swidth in _ip4_swidths + _ip6_swidths:
            assert sshuttle.options.parse_subnetport(
                    '/'.join((ip_repr, str(swidth)))
                    ) == [(socket.AF_INET6, ip, swidth, 0, 0)]
    assert sshuttle.options.parse_subnetport('::/0') \
        == [(socket.AF_INET6, '::', 0, 0, 0)]
    with pytest.raises(Fatal) as excinfo:
        sshuttle.options.parse_subnetport('fc00::/129')
    assert str(excinfo.value) \
        == 'Slash in CIDR notation (/129) is not between 0 and 128'


def test_parse_subnetport_ip6_with_port():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport('[' + ip_repr + ']:80') \
            == [(socket.AF_INET6, ip, 128, 80, 80)]
        assert sshuttle.options.parse_subnetport('[' + ip_repr + ']:80-90') \
            == [(socket.AF_INET6, ip, 128, 80, 90)]


def test_parse_subnetport_ip6_with_mask_and_port():
    for ip_repr, ip in _ip6_reprs.items():
        assert sshuttle.options.parse_subnetport('[' + ip_repr + '/128]:80') \
            == [(socket.AF_INET6, ip, 128, 80, 80)]
        assert sshuttle.options.parse_subnetport('[' + ip_repr + '/16]:80-90')\
            == [(socket.AF_INET6, ip, 16, 80, 90)]


def test_convert_arg_line_to_args_skips_comments():
    parser = sshuttle.options.MyArgumentParser()
    assert parser.convert_arg_line_to_args("# whatever something") == []


@patch('sshuttle.options.socket.getaddrinfo', side_effect=_mock_getaddrinfo)
def test_parse_subnetport_host(mock_getaddrinfo):
    assert set(sshuttle.options.parse_subnetport('example.com')) \
        == set([
            (socket.AF_INET6, '2606:2800:220:1:248:1893:25c8:1946', 128, 0, 0),
            (socket.AF_INET, '93.184.216.34', 32, 0, 0),
        ])
    assert set(sshuttle.options.parse_subnetport('my.local')) \
        == set([
            (socket.AF_INET6, '::1', 128, 0, 0),
            (socket.AF_INET, '127.0.0.1', 32, 0, 0),
        ])
    assert set(sshuttle.options.parse_subnetport('*.blogspot.com')) \
        == set([
            (socket.AF_INET6, '2404:6800:4004:821::2001', 128, 0, 0),
            (socket.AF_INET, '142.251.42.129', 32, 0, 0),
        ])


@patch('sshuttle.options.socket.getaddrinfo', side_effect=_mock_getaddrinfo)
def test_parse_subnetport_host_with_port(mock_getaddrinfo):
    assert set(sshuttle.options.parse_subnetport('example.com:80')) \
        == set([
            (socket.AF_INET6, '2606:2800:220:1:248:1893:25c8:1946', 128, 80, 80),
            (socket.AF_INET, '93.184.216.34', 32, 80, 80),
        ])
    assert set(sshuttle.options.parse_subnetport('example.com:80-90')) \
        == set([
            (socket.AF_INET6, '2606:2800:220:1:248:1893:25c8:1946', 128, 80, 90),
            (socket.AF_INET, '93.184.216.34', 32, 80, 90),
        ])
    assert set(sshuttle.options.parse_subnetport('my.local:445')) \
        == set([
            (socket.AF_INET6, '::1', 128, 445, 445),
            (socket.AF_INET, '127.0.0.1', 32, 445, 445),
        ])
    assert set(sshuttle.options.parse_subnetport('my.local:445-450')) \
        == set([
            (socket.AF_INET6, '::1', 128, 445, 450),
            (socket.AF_INET, '127.0.0.1', 32, 445, 450),
        ])
    assert set(sshuttle.options.parse_subnetport('*.blogspot.com:80')) \
        == set([
            (socket.AF_INET6, '2404:6800:4004:821::2001', 128, 80, 80),
            (socket.AF_INET, '142.251.42.129', 32, 80, 80),
        ])
    assert set(sshuttle.options.parse_subnetport('*.blogspot.com:80-90')) \
        == set([
            (socket.AF_INET6, '2404:6800:4004:821::2001', 128, 80, 90),
            (socket.AF_INET, '142.251.42.129', 32, 80, 90),
        ])


def test_parse_namespace():
    valid_namespaces = [
        'my_namespace',
        'my.namespace',
        'my_namespace_with_underscore',
        'MyNamespace',
        '@my_namespace',
        'my.long_namespace.with.multiple.dots',
        '@my.long_namespace.with.multiple.dots',
        'my.Namespace.With.Mixed.Case',
    ]

    for namespace in valid_namespaces:
        assert sshuttle.options.parse_namespace(namespace) == namespace

    invalid_namespaces = [
        '',
        '123namespace',
        'my-namespace',
        'my_namespace!',
        '.my_namespace',
        'my_namespace.',
        'my..namespace',
    ]

    for namespace in invalid_namespaces:
        with pytest.raises(Fatal, match="'.*' is not a valid namespace name."):
            sshuttle.options.parse_namespace(namespace)
