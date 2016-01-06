from mock import Mock, patch, call
import io

import sshuttle.firewall


def setup_daemon():
    stdin = io.StringIO(u"""ROUTES
2,24,0,1.2.3.0
2,32,1,1.2.3.66
10,64,0,2404:6800:4004:80c::
10,128,1,2404:6800:4004:80c::101f
NSLIST
2,1.2.3.33
10,2404:6800:4004:80c::33
PORTS 1024,1025,1026,1027
GO 1
HOST 1.2.3.3,existing
""")
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
        sshuttle.firewall.restore_etc_hosts(10)
    assert orig_hosts.computehash() == new_hosts.computehash()


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
        call.write('READY test\n'),
        call.flush(),
        call.write('STARTED\n'),
        call.flush()
    ]
    assert mock_setup_daemon.mock_calls == [call()]
    assert mock_get_method.mock_calls == [
        call('not_auto'),
        call().setup_firewall(
            1024, 1026,
            [(10, u'2404:6800:4004:80c::33')],
            10,
            [(10, 64, False, u'2404:6800:4004:80c::'),
                (10, 128, True, u'2404:6800:4004:80c::101f')],
            True),
        call().setup_firewall(
            1025, 1027,
            [(2, u'1.2.3.33')],
            2,
            [(2, 24, False, u'1.2.3.0'), (2, 32, True, u'1.2.3.66')],
            True),
        call().restore_firewall(1024, 10, True),
        call().restore_firewall(1025, 2, True),
    ]
