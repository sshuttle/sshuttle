import struct, socket, errno, select
from helpers import *

HDR_LEN = 8


CMD_EXIT = 0x4200
CMD_PING = 0x4201
CMD_PONG = 0x4202
CMD_CONNECT = 0x4203
CMD_CLOSE = 0x4204
CMD_EOF = 0x4205
CMD_DATA = 0x4206

cmd_to_name = {
    CMD_EXIT: 'EXIT',
    CMD_PING: 'PING',
    CMD_PONG: 'PONG',
    CMD_CONNECT: 'CONNECT',
    CMD_CLOSE: 'CLOSE',
    CMD_EOF: 'EOF',
    CMD_DATA: 'DATA',
}
    


def _nb_clean(func, *args):
    try:
        return func(*args)
    except OSError, e:
        if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        else:
            return None


def _try_peername(sock):
    try:
        pn = sock.getpeername()
        if pn:
            return '%s:%s' % (pn[0], pn[1])
    except socket.error, e:
        if e.args[0] not in (errno.ENOTCONN, errno.ENOTSOCK):
            raise
    return 'unknown'


class SockWrapper:
    def __init__(self, rsock, wsock, connect_to=None, peername=None):
        self.exc = None
        self.rsock = rsock
        self.wsock = wsock
        self.shut_read = self.shut_write = False
        self.buf = []
        self.connect_to = connect_to
        self.peername = peername or _try_peername(self.rsock)
        self.try_connect()

    def __del__(self):
        debug1('%r: deleting\n' % self)
        if self.exc:
            debug1('%r: error was: %r\n' % (self, self.exc))

    def __repr__(self):
        return 'SW:%s' % (self.peername,)

    def seterr(self, e):
        if not self.exc:
            self.exc = e

    def try_connect(self):
        if not self.connect_to:
            return  # already connected
        self.rsock.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)
        self.rsock.setblocking(False)
        try:
            self.rsock.connect(self.connect_to)
            self.connect_to = None
        except socket.error, e:
            if e.args[0] in [errno.EINPROGRESS, errno.EALREADY]:
                pass  # not connected yet
            elif e.args[0] in [errno.ECONNREFUSED, errno.ETIMEDOUT]:
                # a "normal" kind of error
                self.connect_to = None
                self.seterr(e)
            else:
                raise  # error we've never heard of?!  barf completely.

    def noread(self):
        if not self.shut_read:
            debug2('%r: done reading\n' % self)
            self.shut_read = True
            #self.rsock.shutdown(socket.SHUT_RD)  # doesn't do anything anyway
        
    def nowrite(self):
        if not self.shut_write:
            debug2('%r: done writing\n' % self)
            self.shut_write = True
            try:
                self.wsock.shutdown(socket.SHUT_WR)
            except socket.error, e:
                self.seterr(e)

    def too_full(self):
        return False  # fullness is determined by the socket's select() state

    def uwrite(self, buf):
        if self.connect_to:
            return 0  # still connecting
        self.wsock.setblocking(False)
        try:
            return _nb_clean(os.write, self.wsock.fileno(), buf)
        except OSError, e:
            # unexpected error... stream is dead
            self.seterr(e)
            self.nowrite()
            self.noread()
            return 0
        
    def write(self, buf):
        assert(buf)
        return self.uwrite(buf)

    def uread(self):
        if self.connect_to:
            return None  # still connecting
        if self.shut_read:
            return
        self.rsock.setblocking(False)
        try:
            return _nb_clean(os.read, self.rsock.fileno(), 65536)
        except OSError, e:
            self.seterr(e)
            return '' # unexpected error... we'll call it EOF

    def fill(self):
        if self.buf:
            return
        rb = self.uread()
        if rb:
            self.buf.append(rb)
        if rb == '':  # empty string means EOF; None means temporarily empty
            self.noread()

    def copy_to(self, outwrap):
        if self.buf and self.buf[0]:
            wrote = outwrap.write(self.buf[0])
            self.buf[0] = self.buf[0][wrote:]
        while self.buf and not self.buf[0]:
            self.buf[0:1] = []
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
        Handler.__init__(self, [wrap1.rsock, wrap1.wsock,
                                wrap2.rsock, wrap2.wsock])
        self.wrap1 = wrap1
        self.wrap2 = wrap2

    def pre_select(self, r, w, x):
        if self.wrap1.connect_to:
            w.add(self.wrap1.rsock)
        elif self.wrap1.buf:
            if not self.wrap2.too_full():
                w.add(self.wrap2.wsock)
        elif not self.wrap1.shut_read:
            r.add(self.wrap1.rsock)

        if self.wrap2.connect_to:
            w.add(self.wrap2.rsock)
        elif self.wrap2.buf:
            if not self.wrap1.too_full():
                w.add(self.wrap1.wsock)
        elif not self.wrap2.shut_read:
            r.add(self.wrap2.rsock)

    def callback(self):
        self.wrap1.try_connect()
        self.wrap2.try_connect()
        self.wrap1.fill()
        self.wrap2.fill()
        self.wrap1.copy_to(self.wrap2)
        self.wrap2.copy_to(self.wrap1)
        if (self.wrap1.shut_read and self.wrap2.shut_read and
            not self.wrap1.buf and not self.wrap2.buf):
            self.ok = False


class Mux(Handler):
    def __init__(self, rsock, wsock):
        Handler.__init__(self, [rsock, wsock])
        self.rsock = rsock
        self.wsock = wsock
        self.new_channel = None
        self.channels = {}
        self.chani = 0
        self.want = 0
        self.inbuf = ''
        self.outbuf = []
        self.fullness = 0
        self.too_full = False
        self.send(0, CMD_PING, 'chicken')

    def next_channel(self):
        # channel 0 is special, so we never allocate it
        for timeout in xrange(1024):
            self.chani += 1
            if self.chani > 65535:
                self.chani = 1
            if not self.channels.get(self.chani):
                return self.chani

    def amount_queued(self):
        return sum(len(b) for b in self.outbuf)
            
    def check_fullness(self):
        if self.fullness > 32768:
            if not self.too_full:
                self.send(0, CMD_PING, 'rttest')
            self.too_full = True
        #ob = []
        #for b in self.outbuf:
        #    (s1,s2,c) = struct.unpack('!ccH', b[:4])
        #    ob.append(c)
        #log('outbuf: %d %r\n' % (self.amount_queued(), ob))
        
    def send(self, channel, cmd, data):
        data = str(data)
        assert(len(data) <= 65535)
        p = struct.pack('!ccHHH', 'S', 'S', channel, cmd, len(data)) + data
        self.outbuf.append(p)
        debug2(' > channel=%d cmd=%s len=%d (fullness=%d)\n'
               % (channel, cmd_to_name[cmd], len(data), self.fullness))
        self.fullness += len(data)

    def got_packet(self, channel, cmd, data):
        debug2('<  channel=%d cmd=%s len=%d\n' 
               % (channel, cmd_to_name[cmd], len(data)))
        if cmd == CMD_PING:
            self.send(0, CMD_PONG, data)
        elif cmd == CMD_PONG:
            debug2('received PING response\n')
            self.too_full = False
            self.fullness = 0
        elif cmd == CMD_EXIT:
            self.ok = False
        elif cmd == CMD_CONNECT:
            assert(not self.channels.get(channel))
            if self.new_channel:
                self.new_channel(channel, data)
        else:
            callback = self.channels[channel]
            callback(cmd, data)

    def flush(self):
        self.wsock.setblocking(False)
        if self.outbuf and self.outbuf[0]:
            wrote = _nb_clean(os.write, self.wsock.fileno(), self.outbuf[0])
            debug2('mux wrote: %d/%d\n' % (wrote, len(self.outbuf[0])))
            if wrote:
                self.outbuf[0] = self.outbuf[0][wrote:]
        while self.outbuf and not self.outbuf[0]:
            self.outbuf[0:1] = []

    def fill(self):
        self.rsock.setblocking(False)
        try:
            b = _nb_clean(os.read, self.rsock.fileno(), 32768)
        except OSError, e:
            raise Fatal('other end: %r' % e)
        #log('<<< %r\n' % b)
        if b == '': # EOF
            self.ok = False
        if b:
            self.inbuf += b

    def handle(self):
        self.fill()
        #log('inbuf is: (%d,%d) %r\n'
        #     % (self.want, len(self.inbuf), self.inbuf))
        while 1:
            if len(self.inbuf) >= (self.want or HDR_LEN):
                (s1,s2,channel,cmd,datalen) = \
                    struct.unpack('!ccHHH', self.inbuf[:HDR_LEN])
                assert(s1 == 'S')
                assert(s2 == 'S')
                self.want = datalen + HDR_LEN
            if self.want and len(self.inbuf) >= self.want:
                data = self.inbuf[HDR_LEN:self.want]
                self.inbuf = self.inbuf[self.want:]
                self.want = 0
                self.got_packet(channel, cmd, data)
            else:
                break

    def pre_select(self, r, w, x):
        r.add(self.rsock)
        if self.outbuf:
            w.add(self.wsock)

    def callback(self):
        (r,w,x) = select.select([self.rsock], [self.wsock], [], 0)
        if self.rsock in r:
            self.handle()
        if self.outbuf and self.wsock in w:
            self.flush()


class MuxWrapper(SockWrapper):
    def __init__(self, mux, channel):
        SockWrapper.__init__(self, mux.rsock, mux.wsock)
        self.mux = mux
        self.channel = channel
        self.mux.channels[channel] = self.got_packet
        self.socks = []
        debug2('new channel: %d\n' % channel)

    def __del__(self):
        self.nowrite()
        SockWrapper.__del__(self)

    def __repr__(self):
        return 'SW%r:Mux#%d' % (self.peername,self.channel)

    def noread(self):
        if not self.shut_read:
            self.shut_read = True

    def nowrite(self):
        if not self.shut_write:
            self.shut_write = True
            self.mux.send(self.channel, CMD_EOF, '')

    def too_full(self):
        return self.mux.too_full

    def uwrite(self, buf):
        if self.mux.too_full:
            return 0  # too much already enqueued
        if len(buf) > 2048:
            buf = buf[:2048]
        self.mux.send(self.channel, CMD_DATA, buf)
        return len(buf)

    def uread(self):
        if self.shut_read:
            return '' # EOF
        else:
            return None  # no data available right now

    def got_packet(self, cmd, data):
        if cmd == CMD_CLOSE:
            self.noread()
            self.nowrite()
        elif cmd == CMD_EOF:
            self.noread()
        elif cmd == CMD_DATA:
            self.buf.append(data)
        else:
            raise Exception('unknown command %d (%d bytes)' 
                            % (cmd, len(data)))


def connect_dst(ip, port):
    debug2('Connecting to %s:%d\n' % (ip, port))
    outsock = socket.socket()
    return SockWrapper(outsock, outsock,
                       connect_to = (ip,port),
                       peername = '%s:%d' % (ip,port))
