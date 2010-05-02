import socket, errno, select
from helpers import *

def _nb_clean(func, *args):
    try:
        return func(*args)
    except socket.error, e:
        if e.args[0] in (errno.EWOULDBLOCK, errno.EAGAIN):
            return None
        raise


class SockWrapper:
    def __init__(self, sock):
        self.sock = sock
        self.peername = self.sock.getpeername()
        self.shut_read = self.shut_write = False
        self.buf = []

    def __del__(self):
        log('%r: deleting\n' % self)

    def __repr__(self):
        return 'SW%r' % (self.peername,)

    def noread(self):
        if not self.shut_read:
            log('%r: done reading\n' % self)
            self.shut_read = True
            #self.sock.shutdown(socket.SHUT_RD)  # doesn't do anything anyway
        
    def nowrite(self):
        if not self.shut_write:
            log('%r: done writing\n' % self)
            self.shut_write = True
            self.sock.shutdown(socket.SHUT_WR)
        
    def write(self, buf):
        assert(buf)
        self.sock.setblocking(False)
        return _nb_clean(self.sock.send, buf)

    def fill(self):
        if self.shut_read:
            return
        self.sock.setblocking(False)
        rb = _nb_clean(self.sock.recv, 65536)
        if rb:
            self.buf.append(rb)
        if rb == '':  # empty string means EOF; None means temporarily empty
            self.noread()

    def maybe_fill(self):
        if not self.buf:
            self.fill()

    def copy_to(self, outwrap):
        if self.buf and self.buf[0]:
            wrote = outwrap.sock.send(self.buf[0])
            self.buf[0] = self.buf[0][wrote:]
        while self.buf and not self.buf[0]:
            self.buf.pop(0)
        if not self.buf and self.shut_read:
            outwrap.nowrite()


class Handler:
    def __init__(self, socks = None, callback = None):
        self.ok = True
        self.socks = set(socks or [])
        if callback:
            self.callback = callback

    def pre_select(self, r, w, x):
        r |= self.socks

    def callback(self):
        log('--no callback defined-- %r\n' % self)
        (r,w,x) = select.select(self.socks, [], [], 0)
        for s in r:
            v = s.recv(4096)
            if not v:
                log('--closed-- %r\n' % self)
                self.socks = set()
                self.ok = False


class Proxy(Handler):
    def __init__(self, wrap1, wrap2):
        Handler.__init__(self, [wrap1.sock, wrap2.sock])
        self.wrap1 = wrap1
        self.wrap2 = wrap2

    def pre_select(self, r, w, x):
        if self.wrap1.buf:
            w.add(self.wrap2.sock)
        elif not self.wrap1.shut_read:
            r.add(self.wrap1.sock)
        if self.wrap2.buf:
            w.add(self.wrap1.sock)
        elif not self.wrap2.shut_read:
            r.add(self.wrap2.sock)

    def callback(self):
        self.wrap1.maybe_fill()
        self.wrap2.maybe_fill()
        self.wrap1.copy_to(self.wrap2)
        self.wrap2.copy_to(self.wrap1)
        if (self.wrap1.shut_read and self.wrap2.shut_read and
            not self.wrap1.buf and not self.wrap2.buf):
            self.ok = False


