import struct, socket, errno, select
if not globals().get('skip_imports'):
    from helpers import *

MAX_CHANNEL = 65535
    
# these don't exist in the socket module in python 2.3!
SHUT_RD = 0
SHUT_WR = 1
SHUT_RDWR = 2


HDR_LEN = 8


CMD_EXIT = 0x4200
CMD_PING = 0x4201
CMD_PONG = 0x4202
CMD_TCP_CONNECT = 0x4203
CMD_TCP_STOP_SENDING = 0x4204
CMD_TCP_EOF = 0x4205
CMD_TCP_DATA = 0x4206
CMD_ROUTES = 0x4207
CMD_HOST_REQ = 0x4208
CMD_HOST_LIST = 0x4209
CMD_DNS_REQ = 0x420a
CMD_DNS_RESPONSE = 0x420b
CMD_UDP_OPEN = 0x420c
CMD_UDP_DATA = 0x420d
CMD_UDP_CLOSE = 0x420e

cmd_to_name = {
    CMD_EXIT: 'EXIT',
    CMD_PING: 'PING',
    CMD_PONG: 'PONG',
    CMD_TCP_CONNECT: 'TCP_CONNECT',
    CMD_TCP_STOP_SENDING: 'TCP_STOP_SENDING',
    CMD_TCP_EOF: 'TCP_EOF',
    CMD_TCP_DATA: 'TCP_DATA',
    CMD_ROUTES: 'ROUTES',
    CMD_HOST_REQ: 'HOST_REQ',
    CMD_HOST_LIST: 'HOST_LIST',
    CMD_DNS_REQ: 'DNS_REQ',
    CMD_DNS_RESPONSE: 'DNS_RESPONSE',
    CMD_UDP_OPEN: 'UDP_OPEN',
    CMD_UDP_DATA: 'UDP_DATA',
    CMD_UDP_CLOSE: 'UDP_CLOSE',
}


NET_ERRS = [errno.ECONNREFUSED, errno.ETIMEDOUT,
            errno.EHOSTUNREACH, errno.ENETUNREACH,
            errno.EHOSTDOWN, errno.ENETDOWN]


def _add(l, elem):
    if not elem in l:
        l.append(elem)


def _fds(l):
    out = []
    for i in l:
        try:
            out.append(i.fileno())
        except AttributeError:
            out.append(i)
    out.sort()
    return out


def _nb_clean(func, *args):
    try:
        return func(*args)
    except OSError, e:
        if e.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        else:
            debug3('%s: err was: %s\n' % (func.__name__, e))
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


_swcount = 0
class SockWrapper:
    def __init__(self, rsock, wsock, connect_to=None, peername=None):
        global _swcount
        _swcount += 1
        debug3('creating new SockWrapper (%d now exist)\n' % _swcount)
        self.exc = None
        self.rsock = rsock
        self.wsock = wsock
        self.shut_read = self.shut_write = False
        self.buf = []
        self.connect_to = connect_to
        self.peername = peername or _try_peername(self.rsock)
        self.try_connect()

    def __del__(self):
        global _swcount
        _swcount -= 1
        debug1('%r: deleting (%d remain)\n' % (self, _swcount))
        if self.exc:
            debug1('%r: error was: %s\n' % (self, self.exc))

    def __repr__(self):
        if self.rsock == self.wsock:
            fds = '#%d' % self.rsock.fileno()
        else:
            fds = '#%d,%d' % (self.rsock.fileno(), self.wsock.fileno())
        return 'SW%s:%s' % (fds, self.peername)

    def seterr(self, e):
        if not self.exc:
            self.exc = e
        self.nowrite()
        self.noread()

    def try_connect(self):
        if self.connect_to and self.shut_write:
            self.noread()
            self.connect_to = None
        if not self.connect_to:
            return  # already connected
        self.rsock.setblocking(False)
        debug3('%r: trying connect to %r\n' % (self, self.connect_to))
        family = self.rsock.family
        if family==socket.AF_INET and socket.inet_pton(family, self.connect_to[0])[0] == '\0':
            self.seterr(Exception("Can't connect to %r: "
                                  "IP address starts with zero\n"
                                  % (self.connect_to,)))
            self.connect_to = None
            return
        try:
            self.rsock.connect(self.connect_to)
            # connected successfully (Linux)
            self.connect_to = None
        except socket.error, e:
            debug3('%r: connect result: %s\n' % (self, e))
            if e.args[0] == errno.EINVAL:
                # this is what happens when you call connect() on a socket
                # that is now connected but returned EINPROGRESS last time,
                # on BSD, on python pre-2.5.1.  We need to use getsockopt()
                # to get the "real" error.  Later pythons do this
                # automatically, so this code won't run.
                realerr = self.rsock.getsockopt(socket.SOL_SOCKET,
                                                socket.SO_ERROR)
                e = socket.error(realerr, os.strerror(realerr))
                debug3('%r: fixed connect result: %s\n' % (self, e))
            if e.args[0] in [errno.EINPROGRESS, errno.EALREADY]:
                pass  # not connected yet
            elif e.args[0] == 0:
                # connected successfully (weird Linux bug?)
                # Sometimes Linux seems to return EINVAL when it isn't
                # invalid.  This *may* be caused by a race condition
                # between connect() and getsockopt(SO_ERROR) (ie. it
                # finishes connecting in between the two, so there is no
                # longer an error).  However, I'm not sure of that.
                #
                # I did get at least one report that the problem went away
                # when we added this, however.
                self.connect_to = None
            elif e.args[0] == errno.EISCONN:
                # connected successfully (BSD)
                self.connect_to = None
            elif e.args[0] in NET_ERRS + [errno.EACCES, errno.EPERM]:
                # a "normal" kind of error
                self.connect_to = None
                self.seterr(e)
            else:
                raise  # error we've never heard of?!  barf completely.

    def noread(self):
        if not self.shut_read:
            debug2('%r: done reading\n' % self)
            self.shut_read = True
            #self.rsock.shutdown(SHUT_RD)  # doesn't do anything anyway
        
    def nowrite(self):
        if not self.shut_write:
            debug2('%r: done writing\n' % self)
            self.shut_write = True
            try:
                self.wsock.shutdown(SHUT_WR)
            except socket.error, e:
                self.seterr('nowrite: %s' % e)

    def too_full(self):
        return False  # fullness is determined by the socket's select() state

    def uwrite(self, buf):
        if self.connect_to:
            return 0  # still connecting
        self.wsock.setblocking(False)
        try:
            return _nb_clean(os.write, self.wsock.fileno(), buf)
        except OSError, e:
            if e.errno == errno.EPIPE:
                debug1('%r: uwrite: got EPIPE\n' % self)
                self.nowrite()
                return 0
            else:
                # unexpected error... stream is dead
                self.seterr('uwrite: %s' % e)
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
            self.seterr('uread: %s' % e)
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
            self.buf.pop(0)
        if not self.buf and self.shut_read:
            outwrap.nowrite()


class Handler:
    def __init__(self, socks = None, callback = None):
        self.ok = True
        self.socks = socks or []
        if callback:
            self.callback = callback

    def pre_select(self, r, w, x):
        for i in self.socks:
            _add(r, i)

    def callback(self):
        log('--no callback defined-- %r\n' % self)
        (r,w,x) = select.select(self.socks, [], [], 0)
        for s in r:
            v = s.recv(4096)
            if not v:
                log('--closed-- %r\n' % self)
                self.socks = []
                self.ok = False


class Proxy(Handler):
    def __init__(self, wrap1, wrap2):
        Handler.__init__(self, [wrap1.rsock, wrap1.wsock,
                                wrap2.rsock, wrap2.wsock])
        self.wrap1 = wrap1
        self.wrap2 = wrap2

    def pre_select(self, r, w, x):
        if self.wrap1.shut_write: self.wrap2.noread()
        if self.wrap2.shut_write: self.wrap1.noread()
        
        if self.wrap1.connect_to:
            _add(w, self.wrap1.rsock)
        elif self.wrap1.buf:
            if not self.wrap2.too_full():
                _add(w, self.wrap2.wsock)
        elif not self.wrap1.shut_read:
            _add(r, self.wrap1.rsock)

        if self.wrap2.connect_to:
            _add(w, self.wrap2.rsock)
        elif self.wrap2.buf:
            if not self.wrap1.too_full():
                _add(w, self.wrap1.wsock)
        elif not self.wrap2.shut_read:
            _add(r, self.wrap2.rsock)

    def callback(self):
        self.wrap1.try_connect()
        self.wrap2.try_connect()
        self.wrap1.fill()
        self.wrap2.fill()
        self.wrap1.copy_to(self.wrap2)
        self.wrap2.copy_to(self.wrap1)
        if self.wrap1.buf and self.wrap2.shut_write:
            self.wrap1.buf = []
            self.wrap1.noread()
        if self.wrap2.buf and self.wrap1.shut_write:
            self.wrap2.buf = []
            self.wrap2.noread()
        if (self.wrap1.shut_read and self.wrap2.shut_read and
            not self.wrap1.buf and not self.wrap2.buf):
            self.ok = False
            self.wrap1.nowrite()
            self.wrap2.nowrite()


class Mux(Handler):
    def __init__(self, rsock, wsock):
        Handler.__init__(self, [rsock, wsock])
        self.rsock = rsock
        self.wsock = wsock
        self.new_channel = self.got_dns_req = self.got_routes = None
        self.got_udp_open = self.got_udp_data = self.got_udp_close = None
        self.got_host_req = self.got_host_list = None
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
            if self.chani > MAX_CHANNEL:
                self.chani = 1
            if not self.channels.get(self.chani):
                return self.chani

    def amount_queued(self):
        total = 0
        for b in self.outbuf:
            total += len(b)
        return total
            
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
               % (channel, cmd_to_name.get(cmd,hex(cmd)),
                  len(data), self.fullness))
        self.fullness += len(data)

    def got_packet(self, channel, cmd, data):
        debug2('<  channel=%d cmd=%s len=%d\n' 
               % (channel, cmd_to_name.get(cmd,hex(cmd)), len(data)))
        if cmd == CMD_PING:
            self.send(0, CMD_PONG, data)
        elif cmd == CMD_PONG:
            debug2('received PING response\n')
            self.too_full = False
            self.fullness = 0
        elif cmd == CMD_EXIT:
            self.ok = False
        elif cmd == CMD_TCP_CONNECT:
            assert(not self.channels.get(channel))
            if self.new_channel:
                self.new_channel(channel, data)
        elif cmd == CMD_DNS_REQ:
            assert(not self.channels.get(channel))
            if self.got_dns_req:
                self.got_dns_req(channel, data)
        elif cmd == CMD_UDP_OPEN:
            assert(not self.channels.get(channel))
            if self.got_udp_open:
                self.got_udp_open(channel, data)
        elif cmd == CMD_ROUTES:
            if self.got_routes:
                self.got_routes(data)
            else:
                raise Exception('got CMD_ROUTES without got_routes?')
        elif cmd == CMD_HOST_REQ:
            if self.got_host_req:
                self.got_host_req(data)
            else:
                raise Exception('got CMD_HOST_REQ without got_host_req?')
        elif cmd == CMD_HOST_LIST:
            if self.got_host_list:
                self.got_host_list(data)
            else:
                raise Exception('got CMD_HOST_LIST without got_host_list?')
        else:
            callback = self.channels.get(channel)
            if not callback:
                log('warning: closed channel %d got cmd=%s len=%d\n' 
                       % (channel, cmd_to_name.get(cmd,hex(cmd)), len(data)))
            else:
                callback(cmd, data)

    def flush(self):
        self.wsock.setblocking(False)
        if self.outbuf and self.outbuf[0]:
            wrote = _nb_clean(os.write, self.wsock.fileno(), self.outbuf[0])
            debug2('mux wrote: %r/%d\n' % (wrote, len(self.outbuf[0])))
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
        _add(r, self.rsock)
        if self.outbuf:
            _add(w, self.wsock)

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
            self.mux.send(self.channel, CMD_TCP_STOP_SENDING, '')
            self.maybe_close()

    def nowrite(self):
        if not self.shut_write:
            self.shut_write = True
            self.mux.send(self.channel, CMD_TCP_EOF, '')
            self.maybe_close()

    def maybe_close(self):
        if self.shut_read and self.shut_write:
            # remove the mux's reference to us.  The python garbage collector
            # will then be able to reap our object.
            self.mux.channels[self.channel] = None

    def too_full(self):
        return self.mux.too_full

    def uwrite(self, buf):
        if self.mux.too_full:
            return 0  # too much already enqueued
        if len(buf) > 2048:
            buf = buf[:2048]
        self.mux.send(self.channel, CMD_TCP_DATA, buf)
        return len(buf)

    def uread(self):
        if self.shut_read:
            return '' # EOF
        else:
            return None  # no data available right now

    def got_packet(self, cmd, data):
        if cmd == CMD_TCP_EOF:
            self.noread()
        elif cmd == CMD_TCP_STOP_SENDING:
            self.nowrite()
        elif cmd == CMD_TCP_DATA:
            self.buf.append(data)
        else:
            raise Exception('unknown command %d (%d bytes)' 
                            % (cmd, len(data)))


def connect_dst(family, ip, port):
    debug2('Connecting to %s:%d\n' % (ip, port))
    outsock = socket.socket(family)
    outsock.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)
    return SockWrapper(outsock, outsock,
                       connect_to = (ip,port),
                       peername = '%s:%d' % (ip,port))


def runonce(handlers, mux):
    r = []
    w = []
    x = []
    to_remove = filter(lambda s: not s.ok, handlers)
    for h in to_remove:
        handlers.remove(h)

    for s in handlers:
        s.pre_select(r,w,x)
    debug2('Waiting: %d r=%r w=%r x=%r (fullness=%d/%d)\n' 
            % (len(handlers), _fds(r), _fds(w), _fds(x),
               mux.fullness, mux.too_full))
    (r,w,x) = select.select(r,w,x)
    debug2('  Ready: %d r=%r w=%r x=%r\n' 
        % (len(handlers), _fds(r), _fds(w), _fds(x)))
    ready = r+w+x
    did = {}
    for h in handlers:
        for s in h.socks:
            if s in ready:
                h.callback()
                did[s] = 1
    for s in ready:
        if not s in did:
            raise Fatal('socket %r was not used by any handler' % s)
