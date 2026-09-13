import queue
import socket
import time

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
