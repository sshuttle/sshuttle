import queue
import select
import socket
import struct
import time
from unittest.mock import Mock

import pytest

import sshuttle.ssnet as ssnet


def _drain(timeout=5.0):
    """Wait for the close helpers to work through the queue."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ssnet._close_q is None or ssnet._close_q.empty():
            return True
        time.sleep(0.01)
    return False


def test_close_later_closes_the_socket():
    a, b = socket.socketpair()
    try:
        ssnet.close_later(a)
        assert _drain()
        # give the helper a moment to actually run close() after the get()
        deadline = time.monotonic() + 5.0
        while a.fileno() != -1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert a.fileno() == -1
    finally:
        b.close()


def test_close_later_tolerates_none_and_double_close():
    ssnet.close_later(None)
    s, other = socket.socketpair()
    s.close()
    ssnet.close_later(s)  # already closed; must not raise
    assert _drain()
    other.close()


def test_close_later_closes_inline_when_the_backlog_is_full():
    """A full queue means the closers cannot keep up; holding the fd open
    would be worse than taking the stall here."""
    class FullQueue:
        # raises from put() too, so a regression fails instead of hanging
        def put_nowait(self, item):
            raise queue.Full

        put = put_nowait

    a, b = socket.socketpair()
    saved = ssnet._close_q
    ssnet._close_q = FullQueue()
    try:
        ssnet.close_later(a)
        assert a.fileno() == -1  # closed inline, not queued
    finally:
        ssnet._close_q = saved
        b.close()


def test_handler_dispose_is_a_noop():
    ssnet.Handler(socks=[]).dispose()


def test_proxy_dispose_leaves_the_mux_alone():
    """A MuxWrapper's rsock/wsock are the mux's own stdin/stdout, and must
    never be handed to close_later()."""
    closed = []

    class FakeSock:
        def __init__(self, name):
            self.name = name

        def fileno(self):
            return -1

        def close(self):
            closed.append(self.name)

    def wrap(cls, name):
        # __new__ skips __init__, but these wrappers still run __del__ (and
        # through it __repr__ and MuxWrapper.nowrite()) when the collector
        # gets to them, so fill in the attributes those touch.
        w = cls.__new__(cls)
        w.rsock = w.wsock = FakeSock(name)
        w.exc = None
        w.peername = name
        w.shut_read = w.shut_write = True
        w.channel = 0  # MuxWrapper.__repr__ wants one
        return w

    proxy = ssnet.Proxy.__new__(ssnet.Proxy)
    proxy.wrap1 = wrap(ssnet.MuxWrapper, 'mux')
    proxy.wrap2 = wrap(ssnet.SockWrapper, 'real')
    proxy.dispose()
    assert _drain()

    deadline = time.monotonic() + 5.0
    while 'real' not in closed and time.monotonic() < deadline:
        time.sleep(0.01)
    assert closed == ['real']


@pytest.fixture
def above_fd_setsize():
    """Returns a function that moves a socket to a descriptor numbered
    1024 (FD_SETSIZE) or more, which select() cannot watch."""
    fcntl = pytest.importorskip('fcntl')
    resource = pytest.importorskip('resource')
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = 1024 + 64
    if soft < want:
        if hard != resource.RLIM_INFINITY and hard < want:
            pytest.skip('the open file limit cannot be raised above 1024')
        resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
    moved = []

    def move(sock):
        high = socket.socket(
            fileno=fcntl.fcntl(sock.fileno(), fcntl.F_DUPFD, 1024))
        sock.close()
        moved.append(high)
        return high

    yield move
    for sock in moved:
        sock.close()
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_runonce_relays_on_descriptors_above_fd_setsize(above_fd_setsize):
    """With about a thousand connections open, new sockets get descriptors
    that select() rejects with "filedescriptor out of range in select()"."""
    a, a_peer = socket.socketpair()
    b, b_peer = socket.socketpair()
    a, b = above_fd_setsize(a), above_fd_setsize(b)
    assert min(a.fileno(), b.fileno()) >= 1024
    handlers = [ssnet.Proxy(ssnet.SockWrapper(a, a), ssnet.SockWrapper(b, b))]
    try:
        a_peer.sendall(b'ping')
        ssnet.runonce(handlers, Mock(fullness=0, too_full=False))
        b_peer.settimeout(5)
        assert b_peer.recv(16) == b'ping'
    finally:
        a_peer.close()
        b_peer.close()


def test_mux_callback_on_descriptors_above_fd_setsize(above_fd_setsize):
    def packet(cmd, data):
        return struct.pack('!ccHHH', b'S', b'S', 0, cmd, len(data)) + data

    ours, theirs = socket.socketpair()
    ours = above_fd_setsize(ours)
    assert ours.fileno() >= 1024
    mux = ssnet.Mux(ours.makefile('rb', buffering=0),
                    ours.makefile('wb', buffering=0))
    try:
        theirs.sendall(packet(ssnet.CMD_PING, b'hi'))
        mux.callback(None)
        while mux.outbuf:  # one queued packet is written per call
            mux.callback(None)
        theirs.settimeout(5)
        expected = (packet(ssnet.CMD_PING, b'chicken') +
                    packet(ssnet.CMD_PONG, b'hi'))
        received = b''
        while len(received) < len(expected):
            received += theirs.recv(64)
        assert received == expected
    finally:
        theirs.close()


def test_select_above_fd_setsize_reports_what_select_does(above_fd_setsize):
    a, b = socket.socketpair()
    a, b = above_fd_setsize(a), above_fd_setsize(b)
    # two objects on one descriptor, like the client's mux rfile and wfile
    rfile = a.makefile('rb', buffering=0)
    wfile = a.makefile('wb', buffering=0)
    with pytest.raises(ValueError):
        select.select([a], [], [], 0)
    assert ssnet._select([rfile, b], [wfile], [], 0) == ([], [wfile], [])
    b.send(b'x')
    assert ssnet._select([rfile, b], [wfile], [], 0) == ([rfile], [wfile], [])
    assert ssnet._select([rfile, a.fileno()], [], [], 0) == \
        ([rfile, a.fileno()], [], [])
    a.recv(1)
    assert ssnet._select([rfile], [], [], 0.01) == ([], [], [])
    b.close()  # end of file counts as readable
    assert ssnet._select([rfile], [], []) == ([rfile], [], [])


def test_select_without_poll_still_refuses_high_descriptors(
        above_fd_setsize, monkeypatch):
    a, b = socket.socketpair()
    a = above_fd_setsize(a)
    b.close()
    monkeypatch.delattr(select, 'poll', raising=False)
    with pytest.raises(ValueError):
        ssnet._select([a], [], [], 0)


def test_proxy_reads_an_idle_connection_only_when_it_is_ready():
    """Every Proxy wakes up when the shared mux is ready. Reading each idle
    connection then costs a recv() per connection per round."""
    class RecvCounter(socket.socket):
        recvs = 0

        def recv(self, *args):
            self.recvs += 1
            return super().recv(*args)

    def packet(channel, cmd, data):
        return struct.pack('!ccHHH', b'S', b'S', channel, cmd,
                           len(data)) + data

    ours, theirs = socket.socketpair()
    conn, peer = socket.socketpair()
    conn = RecvCounter(fileno=conn.detach())
    mux = ssnet.Mux(ours.makefile('rb', buffering=0),
                    ours.makefile('wb', buffering=0))
    handlers = [mux, ssnet.Proxy(ssnet.SockWrapper(conn, conn),
                                 ssnet.MuxWrapper(mux, 1))]
    sent = b''

    def mux_sent(expected):
        nonlocal sent
        while mux.outbuf:
            mux.flush()
        theirs.settimeout(5)
        try:
            while expected not in sent:
                chunk = theirs.recv(4096)
                if not chunk:
                    break
                sent += chunk
        except socket.timeout:
            pass
        return expected in sent

    try:
        theirs.sendall(packet(0, ssnet.CMD_PING, b'hi'))
        ssnet.runonce(handlers, mux)
        assert conn.recvs == 0

        # data and EOF on the connection are still relayed
        peer.sendall(b'data')
        ssnet.runonce(handlers, mux)
        assert mux_sent(packet(1, ssnet.CMD_TCP_DATA, b'data'))
        peer.close()
        ssnet.runonce(handlers, mux)
        assert mux_sent(packet(1, ssnet.CMD_TCP_EOF, b''))
    finally:
        for s in (mux.rfile, mux.wfile, ours, theirs, conn, peer):
            s.close()


@pytest.mark.parametrize('verbose', [0, 2])
def test_runonce_builds_debug_strings_only_when_logging(
        verbose, monkeypatch, capsys):
    """Formatting the descriptor lists costs time on every round."""
    monkeypatch.setattr('sshuttle.helpers.verbose', verbose)
    fds = Mock(wraps=ssnet._fds)
    monkeypatch.setattr(ssnet, '_fds', fds)
    a, a_peer = socket.socketpair()
    b, b_peer = socket.socketpair()
    handlers = [ssnet.Proxy(ssnet.SockWrapper(a, a), ssnet.SockWrapper(b, b))]
    try:
        a_peer.sendall(b'ping')
        ssnet.runonce(handlers, Mock(fullness=0, too_full=False))
        logged = capsys.readouterr().err
        if verbose:
            assert fds.called
            assert 'Waiting: 1 r=' in logged and 'Ready: 1 r=' in logged
        else:
            assert not fds.called
            assert logged == ''
    finally:
        for s in (a, a_peer, b, b_peer):
            s.close()


@pytest.mark.parametrize('verbose', [0, 2, 3])
def test_mux_debug_messages_follow_the_verbosity(verbose, monkeypatch, capsys):
    monkeypatch.setattr('sshuttle.helpers.verbose', verbose)
    ours, theirs = socket.socketpair()
    mux = ssnet.Mux(ours.makefile('rb', buffering=0),
                    ours.makefile('wb', buffering=0))  # sends a PING
    try:
        mux.flush()
        theirs.sendall(b'x')
        mux.fill()
        mux.got_packet(0, ssnet.CMD_PONG, b'')
        ours.setblocking(False)
        assert ssnet._nb_clean(ours.recv, 1) is None
        logged = capsys.readouterr().err
    finally:
        for s in (mux.rfile, mux.wfile, ours, theirs):
            s.close()
    for message, level in ((' > channel=0 cmd=PING', 2), ('mux wrote:', 2),
                           ('mux read: 1', 2), ('<  channel=0 cmd=PONG', 2),
                           ('recv: err was:', 3)):
        assert (message in logged) == (verbose >= level), message
