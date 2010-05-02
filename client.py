import struct, select, errno
from socket import *
from helpers import *


def _nb_clean(func, *args):
    try:
        return func(*args)
    except error, e:
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
            #self.sock.shutdown(SHUT_RD)  # doesn't do anything anyway
        
    def nowrite(self):
        if not self.shut_write:
            log('%r: done writing\n' % self)
            self.shut_write = True
            self.sock.shutdown(SHUT_WR)
        
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
        if rb == '':  # empty string means EOF; None means nothing available
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
    def __init__(self, sock1, sock2):
        Handler.__init__(self, [sock1, sock2])
        self.wrap1 = SockWrapper(sock1)
        self.wrap2 = SockWrapper(sock2)

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


def original_dst(sock):
    SO_ORIGINAL_DST = 80
    SOCKADDR_MIN = 16
    sockaddr_in = sock.getsockopt(SOL_IP, SO_ORIGINAL_DST, SOCKADDR_MIN)
    (proto, port, a,b,c,d) = struct.unpack('!hhBBBB', sockaddr_in[:8])
    assert(htons(proto) == AF_INET)
    ip = '%d.%d.%d.%d' % (a,b,c,d)
    return (ip,port)


def main(remotename, subnets):
    log('Starting sshuttle proxy.\n')
    listener = socket()
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.bind(('0.0.0.0',1234))
    listener.listen(10)
    log('Listening on %r.\n' % (listener.getsockname(),))

    handlers = []
    def onaccept():
        sock,srcip = listener.accept()
        dstip = original_dst(sock)
        log('Incoming connection from %r to %r.\n' % (srcip,dstip))
        if dstip == sock.getsockname():
            log("-- ignored: that's my address!\n")
            sock.close()
            return
        outsock = socket()
        outsock.setsockopt(SOL_IP, IP_TTL, 42)
        outsock.connect(dstip)
        handlers.append(Proxy(sock, outsock))
    handlers.append(Handler([listener], onaccept))
    
    while 1:
        r = set()
        w = set()
        x = set()
        handlers = filter(lambda s: s.ok, handlers)
        for s in handlers:
            s.pre_select(r,w,x)
        log('\nWaiting: %d[%d,%d,%d]...\n' 
            % (len(handlers), len(r), len(w), len(x)))
        (r,w,x) = select.select(r,w,x)
        log('r=%r w=%r x=%r\n' % (r,w,x))
        ready = set(r) | set(w) | set(x)
        for s in handlers:
            if s.socks & ready:
                s.callback()
