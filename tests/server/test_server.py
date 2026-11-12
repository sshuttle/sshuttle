import errno
import io
import os
import socket
import struct
import threading
import time

from unittest.mock import patch, Mock

import pytest

import sshuttle.helpers
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


def test_dnsproxy_tries_another_nameserver_when_one_is_unreachable():
    """With no route to a nameserver (say an IPv6 one in resolv.conf on a
    host without IPv6), connect() on the UDP socket fails straight away."""
    unreachable, reachable = Mock(), Mock()
    unreachable.connect.side_effect = OSError(
        errno.ENETUNREACH, 'Network is unreachable')
    nameservers = [(socket.AF_INET6, '2001:db8::53'),
                   (socket.AF_INET, '192.0.2.53')]
    with patch('sshuttle.server.socket.socket',
               side_effect=[unreachable, reachable]), \
            patch('sshuttle.server.get_random_nameserver',
                  side_effect=nameservers):
        h = sshuttle.server.DnsProxy(Mock(), 5, b'query', None)

    unreachable.send.assert_not_called()
    reachable.connect.assert_called_once_with(('192.0.2.53', 53))
    reachable.send.assert_called_once_with(b'query')
    assert h.socks == [reachable]
    # dispose() closes what is in peers
    assert set(h.peers) == {unreachable, reachable}


def test_dnsproxy_gives_up_when_the_nameserver_stays_unreachable():
    sock = Mock()
    sock.connect.side_effect = OSError(
        errno.ENETUNREACH, 'Network is unreachable')
    with patch('sshuttle.server.socket.socket', return_value=sock):
        h = sshuttle.server.DnsProxy(Mock(), 5, b'query', '192.0.2.53@53')

    assert sock.connect.call_count == 3
    sock.send.assert_not_called()
    assert h.socks == []


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


def test_start_hostwatch_without_fork(monkeypatch):
    """A server without os.fork (Windows) skips hostwatch instead of crashing."""
    monkeypatch.delattr(sshuttle.server.os, 'fork')
    with patch('sshuttle.server.socket.socketpair') as mock_socketpair, \
            patch('sshuttle.server.log') as mock_log:
        assert sshuttle.server.start_hostwatch(['host1'], True) is None
    mock_socketpair.assert_not_called()
    assert '--auto-hosts' in mock_log.call_args[0][0]


def _packet(channel, cmd, data=b''):
    return struct.pack('!ccHHH', b'S', b'S', channel, cmd, len(data)) + data


def _read_packets(sock, until, timeout=5.0):
    """Mux packets from sock, up to and including the packet `until`."""
    sock.settimeout(timeout)
    buf = b''
    packets = []
    try:
        while until not in packets:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= ssnet.HDR_LEN:
                _, _, channel, cmd, size = struct.unpack(
                    '!ccHHH', buf[:ssnet.HDR_LEN])
                if len(buf) < ssnet.HDR_LEN + size:
                    break
                packets.append(
                    (channel, cmd, buf[ssnet.HDR_LEN:ssnet.HDR_LEN + size]))
                buf = buf[ssnet.HDR_LEN + size:]
    except socket.timeout:
        pass
    return packets


@pytest.mark.parametrize("opening", [
    [(1, ssnet.CMD_TCP_CONNECT, b'%d,127.0.0.1,9' % socket.AF_INET)],
    [(2, ssnet.CMD_UDP_OPEN, b'%d' % socket.AF_INET),
     (2, ssnet.CMD_UDP_DATA, b'127.0.0.1,9,payload')],
    [(3, ssnet.CMD_DNS_REQ, b'query')],
], ids=['tcp', 'udp', 'dns'])
def test_server_survives_running_out_of_file_descriptors(opening, monkeypatch):
    """The real server loop on a socketpair, with the process really out of
    descriptors when a new channel needs a socket."""
    resource = pytest.importorskip('resource')
    monkeypatch.setattr(sshuttle.helpers, 'logprefix',
                        sshuttle.helpers.logprefix)
    ours, theirs = socket.socketpair()
    stdio = [theirs.makefile('rb', buffering=0),
             theirs.makefile('wb', buffering=0)]
    with patch.object(sshuttle.server.io, 'FileIO', side_effect=stdio):
        server = threading.Thread(
            target=sshuttle.server.main,
            args=(False, ssnet.LATENCY_BUFFER_SIZE, False, '127.0.0.1@53',
                  False), daemon=True)
        server.start()
        ready = (0, ssnet.CMD_ROUTES, b'')
        assert ready in _read_packets(ours, ready)

    limits = resource.getrlimit(resource.RLIMIT_NOFILE)
    hogs = []
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE,
                           (min(limits[0], 256), limits[1]))
        try:
            while True:
                hogs.append(os.open(os.devnull, os.O_RDONLY))
        except OSError:
            pass
        alive = (0, ssnet.CMD_PONG, b'alive?')
        ours.sendall(b''.join(_packet(*p) for p in opening) +
                     _packet(0, ssnet.CMD_PING, b'alive?'))
        replies = _read_packets(ours, alive)
    finally:
        for fd in hogs:
            os.close(fd)
        resource.setrlimit(resource.RLIMIT_NOFILE, limits)

    assert alive in replies
    assert server.is_alive()
    if opening[0][1] == ssnet.CMD_TCP_CONNECT:
        # the client is told that the connection is over
        assert (1, ssnet.CMD_TCP_EOF, b'') in replies
        assert (1, ssnet.CMD_TCP_STOP_SENDING, b'') in replies
    ours.sendall(_packet(0, ssnet.CMD_EXIT))
    server.join(5)
    assert not server.is_alive()
    ours.close()
    theirs.close()
