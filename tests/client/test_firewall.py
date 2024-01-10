import io
import os
from socket import AF_INET, AF_INET6

from unittest.mock import Mock, patch, call

import pytest

import sshuttle.firewall


def setup_daemon():
    stdin = io.BytesIO(u"""ROUTES
{inet},24,0,1.2.3.0,8000,9000
{inet},32,1,1.2.3.66,8080,8080
{inet6},64,0,2404:6800:4004:80c::,0,0
{inet6},128,1,2404:6800:4004:80c::101f,80,80
NSLIST
{inet},1.2.3.33
{inet6},2404:6800:4004:80c::33
PORTS 1024,1025,1026,1027
GO 1 - - 0x01 12345
HOST 1.2.3.3,existing
""".format(inet=AF_INET, inet6=AF_INET6).encode('ASCII'))
    stdout = Mock()
    return stdin, stdout


def test_rewrite_etc_hosts(tmpdir):
    orig_hosts = tmpdir.join("hosts.orig")
    orig_hosts.write("1.2.3.3 existing\n")

    new_hosts = tmpdir.join("hosts")
    orig_hosts.copy(new_hosts)

    hostmap = {
        'myhost': '1.2.3.4',
        'myotherhost': '1.2.3.5',
    }
    with patch('sshuttle.firewall.HOSTSFILE', new=str(new_hosts)):
        sshuttle.firewall.rewrite_etc_hosts(hostmap, 10)

    with new_hosts.open() as f:
        line = f.readline()
        s = line.split()
        assert s == ['1.2.3.3', 'existing']

        line = f.readline()
        s = line.split()
        assert s == ['1.2.3.4', 'myhost',
                     '#', 'sshuttle-firewall-10', 'AUTOCREATED']

        line = f.readline()
        s = line.split()
        assert s == ['1.2.3.5', 'myotherhost',
                     '#', 'sshuttle-firewall-10', 'AUTOCREATED']

        line = f.readline()
        assert line == ""

    with patch('sshuttle.firewall.HOSTSFILE', new=str(new_hosts)):
        sshuttle.firewall.restore_etc_hosts(hostmap, 10)
    assert orig_hosts.computehash() == new_hosts.computehash()


@patch('os.link')
@patch('os.rename')
def test_rewrite_etc_hosts_no_overwrite(mock_link, mock_rename, tmpdir):
    mock_link.side_effect = OSError
    mock_rename.side_effect = OSError

    with pytest.raises(OSError):
        os.link('/test_from', '/test_to')

    with pytest.raises(OSError):
        os.rename('/test_from', '/test_to')

    test_rewrite_etc_hosts(tmpdir)


def test_subnet_weight():
    subnets = [
        (AF_INET, 16, 0, '192.168.0.0', 0, 0),
        (AF_INET, 24, 0, '192.168.69.0', 0, 0),
        (AF_INET, 32, 0, '192.168.69.70', 0, 0),
        (AF_INET, 32, 1, '192.168.69.70', 0, 0),
        (AF_INET, 32, 1, '192.168.69.70', 80, 80),
        (AF_INET, 0, 1, '0.0.0.0', 0, 0),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 9000),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 8500),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 8000),
        (AF_INET, 0, 1, '0.0.0.0', 400, 450)
    ]
    subnets_sorted = [
        (AF_INET, 32, 1, '192.168.69.70', 80, 80),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 8000),
        (AF_INET, 0, 1, '0.0.0.0', 400, 450),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 8500),
        (AF_INET, 0, 1, '0.0.0.0', 8000, 9000),
        (AF_INET, 32, 1, '192.168.69.70', 0, 0),
        (AF_INET, 32, 0, '192.168.69.70', 0, 0),
        (AF_INET, 24, 0, '192.168.69.0', 0, 0),
        (AF_INET, 16, 0, '192.168.0.0', 0, 0),
        (AF_INET, 0, 1, '0.0.0.0', 0, 0)
    ]

    assert subnets_sorted == sorted(subnets,
                                    key=sshuttle.firewall.subnet_weight,
                                    reverse=True)


@patch('sshuttle.firewall.rewrite_etc_hosts')
@patch('sshuttle.firewall.setup_daemon')
@patch('sshuttle.firewall.get_method')
def test_main(mock_get_method, mock_setup_daemon, mock_rewrite_etc_hosts):
    stdin, stdout = setup_daemon()
    mock_setup_daemon.return_value = stdin, stdout

    mock_get_method("not_auto").name = "test"
    mock_get_method.reset_mock()

    sshuttle.firewall.main("not_auto", False)

    assert mock_rewrite_etc_hosts.mock_calls == [
        call({'1.2.3.3': 'existing'}, 1024),
        call({}, 1024),
    ]

    assert stdout.mock_calls == [
        call.write(b'READY test\n'),
        call.flush(),
        call.write(b'STARTED\n'),
        call.flush()
    ]
    assert mock_setup_daemon.mock_calls == [call()]
    assert mock_get_method.mock_calls == [
        call('not_auto'),
        call().is_supported(),
        call().is_supported().__bool__(),
        call().setup_firewall(
            1024, 1026,
            [(AF_INET6, u'2404:6800:4004:80c::33')],
            AF_INET6,
            [(AF_INET6, 64, False, u'2404:6800:4004:80c::', 0, 0),
             (AF_INET6, 128, True, u'2404:6800:4004:80c::101f', 80, 80)],
            True,
            None,
            None,
            '0x01'),
        call().setup_firewall(
            1025, 1027,
            [(AF_INET, u'1.2.3.33')],
            AF_INET,
            [(AF_INET, 24, False, u'1.2.3.0', 8000, 9000),
             (AF_INET, 32, True, u'1.2.3.66', 8080, 8080)],
            True,
            None,
            None,
            '0x01'),
        call().wait_for_firewall_ready(12345),
        call().restore_firewall(1024, AF_INET6, True, None, None),
        call().restore_firewall(1025, AF_INET, True, None, None),
    ]
