import io
import os
import threading
import time
from socket import AF_INET, AF_INET6

from unittest.mock import ANY, Mock, patch, call

import pytest

import sshuttle.firewall


@pytest.fixture(autouse=True)
def no_dns_flush():
    # firewall.main() would otherwise run the real "resolvectl
    # flush-caches", which triggers a polkit prompt when run unprivileged.
    with patch('sshuttle.firewall.flush_systemd_dns_cache') as flush:
        yield flush


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
HOSTS_END
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


@patch('sshuttle.firewall.HostsWriter')
@patch('sshuttle.firewall.rewrite_etc_hosts')
@patch('sshuttle.firewall.setup_daemon')
@patch('sshuttle.firewall.get_method')
def test_main(mock_get_method, mock_setup_daemon, mock_rewrite_etc_hosts,
              mock_hosts_writer):
    stdin, stdout = setup_daemon()
    mock_setup_daemon.return_value = stdin, stdout
    mock_hosts_writer.return_value.hostmap = {'1.2.3.3': 'existing'}

    mock_get_method("not_auto").name = "test"
    mock_get_method.reset_mock()

    sshuttle.firewall.main("not_auto", False)

    assert mock_hosts_writer.mock_calls == [
        call(1024),
        call().update({'1.2.3.3': 'existing'}),
        call().stop(),
    ]
    assert mock_rewrite_etc_hosts.mock_calls == [call({}, 1024)]

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


@patch('sshuttle.firewall.HostsWriter')
@patch('sshuttle.firewall.rewrite_etc_hosts')
@patch('sshuttle.firewall.setup_daemon')
@patch('sshuttle.firewall.get_method')
def test_main_hosts_batches(mock_get_method, mock_setup_daemon,
                            mock_rewrite_etc_hosts, mock_hosts_writer):
    stdin, stdout = setup_daemon()
    stdin = io.BytesIO(stdin.getvalue() + b"""\
HOST host-a,1.2.3.4
HOST malformed-without-ip
HOST %s,1.2.3.9
HOST host-b,1.2.3.5
OTHER
HOSTS_END
HOST %s,1.2.3.6
HOSTS_END
""" % (b'x' * 2000, b'y' * 253))
    mock_setup_daemon.return_value = stdin, stdout

    sshuttle.firewall.main("not_auto", False)

    # One HostsWriter, fed one dict per batch. Malformed and overlong
    # lines are skipped and do not end the session.
    assert mock_hosts_writer.mock_calls[:5] == [
        call(1024),
        call().update({'1.2.3.3': 'existing'}),
        call().update({'host-a': '1.2.3.4', 'host-b': '1.2.3.5'}),
        call().update({'y' * 253: '1.2.3.6'}),
        call().stop(),
    ]
    assert call().firewall_command('OTHER') in mock_get_method.mock_calls


@patch('sshuttle.firewall.rewrite_etc_hosts')
@patch('sshuttle.firewall.setup_daemon')
@patch('sshuttle.firewall.get_method')
def test_main_restores_hosts_after_writer_finished(
        mock_get_method, mock_setup_daemon, mock_rewrite_etc_hosts):
    started = threading.Event()
    events = []

    def slow_rewrite(hostmap, port):
        events.append(('start', dict(hostmap)))
        started.set()
        time.sleep(0.1)
        events.append(('end', dict(hostmap)))
    mock_rewrite_etc_hosts.side_effect = slow_rewrite

    class EofWhileWriterBusy(io.BytesIO):
        def readline(self, *args):
            line = super().readline(*args)
            if not line:
                started.wait(5)
            return line

    stdin, stdout = setup_daemon()
    mock_setup_daemon.return_value = \
        EofWhileWriterBusy(stdin.getvalue()), stdout

    sshuttle.firewall.main("not_auto", False)

    # The client went away while the real HostsWriter was rewriting. The
    # restore must only start once that rewrite has finished.
    host = {'1.2.3.3': 'existing'}
    assert events == [('start', host), ('end', host),
                      ('start', {}), ('end', {})]


def rewrites_signalled(mock_rewrite_etc_hosts, side_effect=None):
    """Make each rewrite release a semaphore, so tests can wait for it."""
    done = threading.Semaphore(0)

    def rewrite(hostmap, port):
        try:
            if side_effect:
                side_effect(hostmap, port)
        finally:
            done.release()
    mock_rewrite_etc_hosts.side_effect = rewrite
    return done


@patch('sshuttle.firewall.rewrite_etc_hosts')
def test_hosts_writer_coalesces_while_busy(mock_rewrite_etc_hosts):
    started, release = threading.Event(), threading.Event()
    written = []

    def slow_rewrite(hostmap, port):
        written.append(dict(hostmap))
        started.set()
        release.wait(5)
    done = rewrites_signalled(mock_rewrite_etc_hosts, slow_rewrite)

    writer = sshuttle.firewall.HostsWriter(1024)
    # A single host is written right away.
    writer.update({'a': '1.2.3.4'})
    assert started.wait(5)
    # Everything that arrives during that rewrite goes into the next one.
    writer.update({'b': '1.2.3.5'})
    writer.update({'c': '1.2.3.6', 'a': '1.2.3.4'})
    release.set()
    assert done.acquire(timeout=5) and done.acquire(timeout=5)
    writer.stop()

    assert written == [
        {'a': '1.2.3.4'},
        {'a': '1.2.3.4', 'b': '1.2.3.5', 'c': '1.2.3.6'},
    ]
    assert mock_rewrite_etc_hosts.call_args_list == [
        call(ANY, 1024), call(ANY, 1024)]


@patch('sshuttle.firewall.rewrite_etc_hosts')
def test_hosts_writer_ignores_unchanged_hosts(mock_rewrite_etc_hosts):
    done = rewrites_signalled(mock_rewrite_etc_hosts)
    writer = sshuttle.firewall.HostsWriter(1024)
    writer.update({'a': '1.2.3.4'})
    assert done.acquire(timeout=5)
    writer.update({'a': '1.2.3.4'})
    writer.update({})
    assert not writer._dirty
    writer.stop()
    assert mock_rewrite_etc_hosts.call_count == 1


@patch('sshuttle.firewall.log')
@patch('sshuttle.firewall.rewrite_etc_hosts')
def test_hosts_writer_logs_each_error_once(mock_rewrite_etc_hosts, mock_log):
    errors = [OSError('denied'), OSError('denied'), OSError('full')]

    def fail(hostmap, port):
        raise errors.pop(0)
    done = rewrites_signalled(mock_rewrite_etc_hosts, fail)

    writer = sshuttle.firewall.HostsWriter(1024)
    for i in range(3):
        writer.update({'host%d' % i: '1.2.3.4'})
        assert done.acquire(timeout=5)
    writer.stop()
    assert mock_log.mock_calls == [
        call('Failed to update /etc/hosts: denied'),
        call('Failed to update /etc/hosts: full'),
    ]


@patch('sshuttle.firewall.rewrite_etc_hosts')
def test_hosts_writer_stop_drops_pending_hosts(mock_rewrite_etc_hosts):
    started, release = threading.Event(), threading.Event()

    def faster_rewrite(hostmap, port):
        started.set()
        release.wait(5)

    def slow_rewrite(hostmap, port):
        started.set()
        release.wait(5)
    rewrites_signalled(mock_rewrite_etc_hosts, slow_rewrite)

    writer = sshuttle.firewall.HostsWriter(1024)
    writer.update({'a': '1.2.3.4'})
    assert started.wait(5)
    writer.update({'b': '1.2.3.5'})
    stopper = threading.Thread(target=writer.stop)
    stopper.start()
    release.set()
    stopper.join(5)
    # The rewrite in progress finished, the pending one was dropped.
    assert not stopper.is_alive()
    assert mock_rewrite_etc_hosts.call_count == 1
