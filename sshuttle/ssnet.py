import sys
import struct
import socket
import errno
import select
import os
from sshuttle.helpers import b, binary_type, log, debug1, debug2, debug3, Fatal

MAX_CHANNEL = 65535
BUFFER_SIZE = 65536
FULLNESS_SIZE = 1048576

# Pause/Resume traffic between client and edge
MB = 1024 * 1024
PAUSE_TRAFFIC_TO_EDGE_THRESHOLD = 100 * MB
INDIVIDUAL_BUFFER_PAUSE_SIZE = 10 * MB
INDIVIDUAL_BUFFER_RESUME_SIZE = 1 * MB

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
CMD_PAUSE = 0x420f      # Use when client -> to edge too fast for edge to handle - pause reading
CMD_RESUME = 0x4210     # Use when client -> to edge too fast for edge to handle - resume reading

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
    CMD_PAUSE: 'PAUSE',
    CMD_RESUME: 'RESUME',
}


NET_ERRS = [errno.ECONNREFUSED, errno.ETIMEDOUT,
            errno.EHOSTUNREACH, errno.ENETUNREACH,
            errno.EHOSTDOWN, errno.ENETDOWN,
            errno.ENETUNREACH]


def _add(l, elem):
    if elem not in l:
        l.append(elem)

def _add_map(m, key, value):
    m[key] = value

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
    except OSError:
        _, e = sys.exc_info()[:2]
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
    except socket.error:
        _, e = sys.exc_info()[:2]
        if e.args[0] not in (errno.ENOTCONN, errno.ENOTSOCK):
            raise
    return 'unknown'


_swcount = 0
_global_mux_wrapper_buffer_size = 0  # Keep track of all buffer movement from client -> when too big, pause on busy channels


class SockWrapper:

    def __init__(self, rsock, wsock, connect_to=None, peername=None, connection_is_allowed_callback=None):
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
        self.connection_is_allowed_callback = connection_is_allowed_callback
        self.try_connect()
        self.isWrite = False
        self.isPaused = False   # traffic to the edge is paused (always false in SockWrapper; may be true in MuxWrapper)

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

    def isMux(self):
        return False

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
        try:
            self.rsock.connect(self.connect_to)
            # connected successfully (Linux)
            self.connect_to = None
        except socket.error:
            _, e = sys.exc_info()[:2]
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
            # self.rsock.shutdown(SHUT_RD)  # doesn't do anything anyway

    def nowrite(self):
        if not self.shut_write:
            debug2('%r: done writing\n' % self)
            self.shut_write = True
            try:
                self.wsock.shutdown(SHUT_WR)
            except socket.error:
                _, e = sys.exc_info()[:2]
                self.seterr('nowrite: %s' % e)

    @staticmethod
    def too_full():
        return False  # fullness is determined by the socket's select() state

    def uwrite(self, buf):
        if self.connect_to or (self.connection_is_allowed_callback and not self.connection_is_allowed_callback()):
            return 0  # still connecting
        self.wsock.setblocking(False)
        try:
            return _nb_clean(os.write, self.wsock.fileno(), buf)
        except OSError:
            _, e = sys.exc_info()[:2]
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
        if self.connect_to or (self.connection_is_allowed_callback and not self.connection_is_allowed_callback()):
            return None  # still connecting
        if self.shut_read:
            return
        self.rsock.setblocking(False)
        try:
            return _nb_clean(os.read, self.rsock.fileno(), 65536)
        except OSError:
            _, e = sys.exc_info()[:2]
            self.seterr('uread: %s' % e)
            return b('')  # unexpected error... we'll call it EOF

    def fill(self):
        if self.buf:
            return
        rb = self.uread()
        if rb:
            self.buf.append(rb)
        if rb == b(''):  # empty string means EOF; None means temporarily empty
            self.noread()

    def copy_to(self, outwrap):
        wrote = 0
        if self.buf and self.buf[0]:
            wrote = outwrap.write(self.buf[0])
            self.buf[0] = self.buf[0][wrote:]
        while self.buf and not self.buf[0]:
            self.buf.pop(0)
        if not self.buf and self.shut_read:
            outwrap.nowrite()
        return wrote


class Handler:

    def __init__(self, socks=None, callback=None):
        self.ok = True
        self.socks = socks or []
        if callback:
            self.callback = callback

    def is_ready(self):
        return False

    def pre_select(self, r, w, x, rh, wh):
        for i in self.socks:
            _add(r, i)
            _add_map(rh, i.fileno(), self)

    def callback(self, sock):
        log('--no callback defined-- %r\n' % self)
        (r, _, _) = select.select(self.socks, [], [], 0)
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

    def is_ready(self):
        if self.wrap1.isWrite or self.wrap2.isWrite:
            return True

        return False

    def maybe_noread(self):
        if self.wrap1.shut_write:
            self.wrap2.noread()
        if self.wrap2.shut_write:
            self.wrap1.noread()

    def process_wrap(self, wrap1, wrap2, r, w, rh, wh):
        if wrap1.connect_to:
            wrap1.isWrite = True
            if not wrap2.isPaused:
                _add(w, wrap1.rsock)
        elif wrap1.buf:
            if not wrap2.too_full():
                wrap2.isWrite = True
                _add(w, wrap2.wsock)
        elif not wrap1.shut_read:
            if not wrap2.isPaused:
                _add(r, wrap1.rsock)
                _add_map(rh, wrap1.rsock.fileno(), self)

    def maybe_add_to_wh(self,wh):
        if self.wrap2.isWrite or self.wrap1.isWrite:
            _add(wh, self)
    
    def pre_select(self, r, w, x, rh, wh):

        if self.wrap2.too_full() or self.wrap1.too_full():
            self.maybe_add_to_wh(wh)
            return

        self.maybe_noread()
        self.process_wrap(self.wrap1,self.wrap2,r,w,rh,wh)
        self.process_wrap(self.wrap2,self.wrap1,r,w,rh,wh)
        self.maybe_add_to_wh(wh)

    def callback(self, sock):
        self.wrap1.try_connect()
        self.wrap2.try_connect()
        if self.wrap1.rsock is sock:
            self.wrap1.fill()
        elif self.wrap2.rsock is sock:
            self.wrap2.fill()

        self.wrap1.copy_to(self.wrap2)
        self.wrap2.copy_to(self.wrap1)

        if self.wrap1.isMux() and not self.wrap1.buf and self.wrap1.shut_read and self.wrap2.shut_write:
            self.wrap1.nowrite()

        if self.wrap2.isMux() and not self.wrap2.buf and self.wrap2.shut_read and self.wrap1.shut_write:
            self.wrap2.nowrite()

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

        if self.wrap1.shut_read or self.wrap1.shut_write or self.wrap2.shut_read or self.wrap2.shut_write:
            self.wrap1.isWrite = True
            self.wrap2.isWrite = True
        else:
            self.wrap1.isWrite = False
            self.wrap2.isWrite = False

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
        self.inbuf = b('')
        self.outbuf = []
        self.fullness = 0
        self.too_full = False
        self.send(0, CMD_PING, b('chicken'))

    def next_channel(self):
        # channel 0 is special, so we never allocate it
        for _ in range(1024):
            self.chani += 1
            if self.chani > MAX_CHANNEL:
                self.chani = 1
            if not self.channels.get(self.chani):
                return self.chani

    def amount_queued(self):
        total = 0
        for byte in self.outbuf:
            total += len(byte)
        return total

    def check_fullness(self):

        if self.fullness > FULLNESS_SIZE:
            if not self.too_full:
                self.send(0, CMD_PING, b'rttest')
            self.too_full = True
        # ob = []
        # for b in self.outbuf:
        #    (s1,s2,c) = struct.unpack('!ccH', b[:4])
        #    ob.append(c)
        # log('outbuf: %d %r\n' % (self.amount_queued(), ob))

    def room_left(self):
        room_left = -1
        if self.outbuf:
            room_left = BUFFER_SIZE - (len(self.outbuf[-1]) + HDR_LEN)
        if room_left < 0:
            room_left = BUFFER_SIZE - HDR_LEN
        return room_left

    def send(self, channel, cmd, data):
        assert isinstance(data, binary_type)
        assert len(data) <= 65535
        p = struct.pack('!ccHHH', b('S'), b('S'), channel, cmd, len(data)) \
            + data
        if self.outbuf and (len(data) + HDR_LEN) <= (BUFFER_SIZE - len(self.outbuf[-1])):
            self.outbuf[-1] = self.outbuf[-1] + p
        else:
            self.outbuf.append(p)
        debug2(' > channel=%d cmd=%s len=%d outbuf=%d (fullness=%d)\n'
               % (channel, cmd_to_name.get(cmd, hex(cmd)),
                  len(data), len(self.outbuf[-1]), self.fullness))
        self.fullness += len(data)

    def got_packet(self, channel, cmd, data):
        debug2('<  channel=%d cmd=%s len=%d\n'
               % (channel, cmd_to_name.get(cmd, hex(cmd)), len(data)))
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
                debug1('warning: closed channel %d got cmd=%s len=%d\n'
                    % (channel, cmd_to_name.get(cmd, hex(cmd)), len(data)))
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
            read = _nb_clean(os.read, self.rsock.fileno(), BUFFER_SIZE)
        except OSError:
            _, e = sys.exc_info()[:2]
            raise Fatal('other end: %r' % e)
        # log('<<< %r\n' % b)
        if read == b(''):  # EOF
            self.ok = False
        if read:
            self.inbuf += read

    def handle(self):
        self.fill()
        # log('inbuf is: (%d,%d) %r\n'
        #     % (self.want, len(self.inbuf), self.inbuf))
        while 1:
            if len(self.inbuf) >= (self.want or HDR_LEN):
                (s1, s2, channel, cmd, datalen) = \
                    struct.unpack_from('!ccHHH', self.inbuf, 0)
                assert(s1 == b('S'))
                assert(s2 == b('S'))
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

    def callback(self, r, w):
        if self.rsock in r:
            r.remove(self.rsock)
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
        self.buf_total = 0      # total size of this mux wrapper's buffer
        debug2('new channel: %d\n' % channel)

    def __del__(self):
        self.nowrite()

        if self.buf_total > 0:
            # If the wrapper is destroyed (e.g., by iperf3), might still have data in the buffer
            # Do not need to make sure buffer is flushed but do need to reduce the size of the global var
            global _global_mux_wrapper_buffer_size
            _global_mux_wrapper_buffer_size -= self.buf_total
            debug3('MuxWrapper on channel %d dead. Remove %d from global mux wrap buf size, which is now %d\n' %
                   (self.channel, self.buf_total, _global_mux_wrapper_buffer_size))

        SockWrapper.__del__(self)

    def __repr__(self):
        return 'SW%r:Mux#%d' % (self.peername, self.channel)

    def isMux(self):
        return True

    def noread(self):
        if not self.shut_read:
            self.mux.send(self.channel, CMD_TCP_STOP_SENDING, b(''))
            self.setnoread()

    def setnoread(self):
        if not self.shut_read:
            debug2('%r: done reading\n' % self)
            self.shut_read = True
            self.maybe_close()

    def nowrite(self):
        if not self.shut_write:
            self.mux.send(self.channel, CMD_TCP_EOF, b(''))
            self.setnowrite()

    def setnowrite(self):
        if not self.shut_write:
            debug2('%r: done writing\n' % self)
            self.shut_write = True
            self.maybe_close()

    def maybe_close(self):
        if self.shut_read and self.shut_write:
            debug2('%r: closing connection\n' % self)
            # remove the mux's reference to us.
            del self.mux.channels[self.channel]

    def too_full(self):
        return self.mux.too_full

    def uwrite(self, buf):
        if self.mux.too_full:
            return 0  # too much already enqueued
        room_left = self.mux.room_left()
        if len(buf) >= room_left:
            buf = buf[:room_left]
        self.mux.send(self.channel, CMD_TCP_DATA, buf)
        return len(buf)

    def uread(self):
        if self.shut_read:
            return b('')  # EOF
        else:
            return None  # no data available right now

    def got_packet(self, cmd, data):
        if cmd == CMD_TCP_EOF:
            # Remote side already knows the status - set flag but don't notify
            self.isWrite = True
            self.setnoread()
        elif cmd == CMD_TCP_STOP_SENDING:
            # Remote side already knows the status - set flag but don't notify
            self.setnowrite()
        elif cmd == CMD_TCP_DATA:
            self.isWrite = True
            self.buf.append(data)
            self.maybe_pause(data)
        elif cmd == CMD_PAUSE:
            self.isPaused = True
            debug2('MuxWrapper.got_packet received CMD_PAUSE on channel %s\n' % self.channel)
        elif cmd == CMD_RESUME:
            self.isPaused = False
            debug2('MuxWrapper.got_packet received CMD_RESUME on channel %s\n' % self.channel)
        else:
            raise Exception('unknown command %d (%d bytes)'
                            % (cmd, len(data)))

    # Check size of overall buffer; if too big, and individual buffer too big, send a pause.
    def maybe_pause(self, data):
        self.buf_total = self.buf_total + len(data)

        global _global_mux_wrapper_buffer_size
        _global_mux_wrapper_buffer_size += len(data)

        debug3('Global mux wrap buf size: %d. Individual buf size: %d. On channel %s\n'
            % (_global_mux_wrapper_buffer_size, self.buf_total, self.channel))

        if not self.isPaused and _global_mux_wrapper_buffer_size > PAUSE_TRAFFIC_TO_EDGE_THRESHOLD and self.buf_total\
                > INDIVIDUAL_BUFFER_PAUSE_SIZE:
            self.mux.send(self.channel, CMD_PAUSE, b(''))
            self.isPaused = True
            log('Global mux wrap buf size: %d (above threshold). Individual buf size: %d (above threshold). Sent CMD_PAUSE on channel %s\n'
                % (_global_mux_wrapper_buffer_size, self.buf_total, self.channel))

    # Overwrite super method in SockWrapper
    def copy_to(self, outwrap):
        # Get the num bits written from super's usual method
        wrote = SockWrapper.copy_to(self, outwrap)
        # If there are any bits written, decrease from this wrapper's buffer size and check if we should resume or not
        if wrote:
            self.maybe_resume(wrote)
        else:
            # sometimes wrote might be 0 or none
            debug3('MuxWrapper.copy_to on channel %d show wrote = %s\n' % (self.channel, wrote))

    # Check size of individual buffer; if small enough, send a resume.
    def maybe_resume(self, wrote):
        self.buf_total = self.buf_total - wrote

        global _global_mux_wrapper_buffer_size
        _global_mux_wrapper_buffer_size -= wrote

        debug3('Global mux wrap buf size: %d. Individual buf size: %d. On channel %s\n' %
            (_global_mux_wrapper_buffer_size, self.buf_total, self.channel))

        if self.isPaused and self.buf_total < INDIVIDUAL_BUFFER_RESUME_SIZE:
            self.mux.send(self.channel, CMD_RESUME, b(''))
            self.isPaused = False
            log('Global mux wrap buf size: %d. Individual buf size: %d (below threshold). Sent CMD_RESUME on channel %s\n' %
                (_global_mux_wrapper_buffer_size, self.buf_total, self.channel))


def connect_dst(family, ip, port):
    debug2('Connecting to %s:%d\n' % (ip, port))
    outsock = socket.socket(family)
    return SockWrapper(outsock, outsock,
                       connect_to=(ip, port),
                       peername='%s:%d' % (ip, port))

def runonce(handlers, mux):
    r = []
    w = []
    x = []
    
    wh = []
    rh = {}
    to_remove = [s for s in handlers if not s.ok]
    for h in to_remove:
        handlers.remove(h)

    mux.pre_select(r, w, x)

    for s in handlers:
        s.pre_select(r, w, x, rh, wh)
    debug2('Waiting: %d r=%r w=%r x=%r (fullness=%d/%d)\n'
           % (len(handlers), _fds(r), _fds(w), _fds(x),
               mux.fullness, mux.too_full))
    waitingr = len(r)
    waitingw = len(w)
    (r, w, x) = select.select(r, w, x)
    debug2('  Ready: %d r=%r w=%r x=%r\n'
           % (len(handlers), _fds(r), _fds(w), _fds(x)))
    mux.callback(r, w)

    handler_count = 0
    for sock in r:
         h = rh.get(sock.fileno()) 
         h.callback(sock)
         handler_count += 1

    for handler in wh:
        if handler.is_ready():
            handler.callback(None)
            handler_count += 1

    debug1('Total Handler %d, Waiting r %d,  Ready r %d, Waiting w %d,  Ready w %d, Executed %d, mux too full %s\n' %
           (len(handlers), waitingr,  len(r), waitingw, len(w), handler_count, mux.too_full))

