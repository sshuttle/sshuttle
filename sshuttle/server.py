import re
import struct
import socket
import traceback
import time
import sys
import os
import platform

import sshuttle.ssnet as ssnet
import sshuttle.helpers as helpers
import sshuttle.hostwatch as hostwatch
import subprocess as ssubprocess
from sshuttle.ssnet import Handler, Proxy, Mux, MuxWrapper
from sshuttle.helpers import log, debug1, debug2, debug3, Fatal, \
    resolvconf_random_nameserver


def _ipmatch(ipstr):
    if ipstr == b'default':
        ipstr = b'0.0.0.0/0'
    m = re.match(b'^(\d+(\.\d+(\.\d+(\.\d+)?)?)?)(?:/(\d+))?$', ipstr)
    if m:
        g = m.groups()
        ips = g[0]
        width = int(g[4] or 32)
        if g[1] is None:
            ips += b'.0.0.0'
            width = min(width, 8)
        elif g[2] is None:
            ips += b'.0.0'
            width = min(width, 16)
        elif g[3] is None:
            ips += b'.0'
            width = min(width, 24)
        ips = ips.decode("ASCII")
        return (struct.unpack('!I', socket.inet_aton(ips))[0], width)


def _ipstr(ip, width):
    if width >= 32:
        return ip
    else:
        return "%s/%d" % (ip, width)


def _maskbits(netmask):
    if not netmask:
        return 32
    for i in range(32):
        if netmask[0] & _shl(1, i):
            return 32 - i
    return 0


def _shl(n, bits):
    return n * int(2 ** bits)


def _list_routes():
    # FIXME: IPv4 only
    argv = ['netstat', '-rn']
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE)
    routes = []
    for line in p.stdout:
        cols = re.split(b'\s+', line)
        ipw = _ipmatch(cols[0])
        if not ipw:
            continue  # some lines won't be parseable; never mind
        maskw = _ipmatch(cols[2])  # linux only
        mask = _maskbits(maskw)   # returns 32 if maskw is null
        width = min(ipw[1], mask)
        ip = ipw[0] & _shl(_shl(1, width) - 1, 32 - width)
        routes.append(
            (socket.AF_INET, socket.inet_ntoa(struct.pack('!I', ip)), width))
    rv = p.wait()
    if rv != 0:
        log('WARNING: %r returned %d\n' % (argv, rv))
        log('WARNING: That prevents --auto-nets from working.\n')
    return routes


def list_routes():
    for (family, ip, width) in _list_routes():
        if not ip.startswith('0.') and not ip.startswith('127.'):
            yield (family, ip, width)


def _exc_dump():
    exc_info = sys.exc_info()
    return ''.join(traceback.format_exception(*exc_info))


def start_hostwatch(seed_hosts):
    s1, s2 = socket.socketpair()
    pid = os.fork()
    if not pid:
        # child
        rv = 99
        try:
            try:
                s2.close()
                os.dup2(s1.fileno(), 1)
                os.dup2(s1.fileno(), 0)
                s1.close()
                rv = hostwatch.hw_main(seed_hosts) or 0
            except Exception:
                log('%s\n' % _exc_dump())
                rv = 98
        finally:
            os._exit(rv)
    s1.close()
    return pid, s2


class Hostwatch:

    def __init__(self):
        self.pid = 0
        self.sock = None


class DnsProxy(Handler):

    def __init__(self, mux, chan, request):
        Handler.__init__(self, [])
        self.timeout = time.time() + 30
        self.mux = mux
        self.chan = chan
        self.tries = 0
        self.request = request
        self.peers = {}
        self.try_send()

    def try_send(self):
        if self.tries >= 3:
            return
        self.tries += 1

        family, peer = resolvconf_random_nameserver()

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)
        sock.connect((peer, 53))

        self.peers[sock] = peer

        debug2('DNS: sending to %r (try %d)\n' % (peer, self.tries))
        try:
            sock.send(self.request)
            self.socks.append(sock)
        except socket.error as e:
            if e.args[0] in ssnet.NET_ERRS:
                # might have been spurious; try again.
                # Note: these errors sometimes are reported by recv(),
                # and sometimes by send().  We have to catch both.
                debug2('DNS send to %r: %s\n' % (peer, e))
                self.try_send()
                return
            else:
                log('DNS send to %r: %s\n' % (peer, e))
                return

    def callback(self, sock):
        peer = self.peers[sock]

        try:
            data = sock.recv(4096)
        except socket.error as e:
            self.socks.remove(sock)
            del self.peers[sock]

            if e.args[0] in ssnet.NET_ERRS:
                # might have been spurious; try again.
                # Note: these errors sometimes are reported by recv(),
                # and sometimes by send().  We have to catch both.
                debug2('DNS recv from %r: %s\n' % (peer, e))
                self.try_send()
                return
            else:
                log('DNS recv from %r: %s\n' % (peer, e))
                return
        debug2('DNS response: %d bytes\n' % len(data))
        self.mux.send(self.chan, ssnet.CMD_DNS_RESPONSE, data)
        self.ok = False


class UdpProxy(Handler):

    def __init__(self, mux, chan, family):
        sock = socket.socket(family, socket.SOCK_DGRAM)
        Handler.__init__(self, [sock])
        self.timeout = time.time() + 30
        self.mux = mux
        self.chan = chan
        self.sock = sock
        if family == socket.AF_INET:
            self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)

    def send(self, dstip, data):
        debug2('UDP: sending to %r port %d\n' % dstip)
        try:
            self.sock.sendto(data, dstip)
        except socket.error as e:
            log('UDP send to %r port %d: %s\n' % (dstip[0], dstip[1], e))
            return

    def callback(self, sock):
        try:
            data, peer = sock.recvfrom(4096)
        except socket.error as e:
            log('UDP recv from %r port %d: %s\n' % (peer[0], peer[1], e))
            return
        debug2('UDP response: %d bytes\n' % len(data))
        hdr = "%s,%r," % (peer[0], peer[1])
        self.mux.send(self.chan, ssnet.CMD_UDP_DATA, hdr + data)


def main(latency_control):
    debug1('Starting server with Python version %s\n'
           % platform.python_version())

    if helpers.verbose >= 1:
        helpers.logprefix = ' s: '
    else:
        helpers.logprefix = 'server: '
    debug1('latency control setting = %r\n' % latency_control)

    routes = list(list_routes())
    debug1('available routes:\n')
    for r in routes:
        debug1('  %d/%s/%d\n' % r)

    # synchronization header
    sys.stdout.write('\0\0SSHUTTLE0001')
    sys.stdout.flush()

    handlers = []
    mux = Mux(socket.fromfd(sys.stdin.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM),
              socket.fromfd(sys.stdout.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM))
    handlers.append(mux)
    routepkt = b''
    for r in routes:
        routepkt += b'%d,%s,%d\n' % (r[0], r[1].encode("ASCII"), r[2])
    mux.send(0, ssnet.CMD_ROUTES, routepkt)

    hw = Hostwatch()
    hw.leftover = b''

    def hostwatch_ready(sock):
        assert(hw.pid)
        content = hw.sock.recv(4096)
        if content:
            lines = (hw.leftover + content).split(b'\n')
            if lines[-1]:
                # no terminating newline: entry isn't complete yet!
                hw.leftover = lines.pop()
                lines.append(b'')
            else:
                hw.leftover = b''
            mux.send(0, ssnet.CMD_HOST_LIST, b'\n'.join(lines))
        else:
            raise Fatal('hostwatch process died')

    def got_host_req(data):
        if not hw.pid:
            (hw.pid, hw.sock) = start_hostwatch(data.strip().split())
            handlers.append(Handler(socks=[hw.sock],
                                    callback=hostwatch_ready))
    mux.got_host_req = got_host_req

    def new_channel(channel, data):
        (family, dstip, dstport) = data.split(b',', 2)
        family = int(family)
        dstport = int(dstport)
        outwrap = ssnet.connect_dst(family, dstip, dstport)
        handlers.append(Proxy(MuxWrapper(mux, channel), outwrap))
    mux.new_channel = new_channel

    dnshandlers = {}

    def dns_req(channel, data):
        debug2('Incoming DNS request channel=%d.\n' % channel)
        h = DnsProxy(mux, channel, data)
        handlers.append(h)
        dnshandlers[channel] = h
    mux.got_dns_req = dns_req

    udphandlers = {}

    def udp_req(channel, cmd, data):
        debug2('Incoming UDP request channel=%d, cmd=%d\n' % (channel, cmd))
        if cmd == ssnet.CMD_UDP_DATA:
            (dstip, dstport, data) = data.split(",", 2)
            dstport = int(dstport)
            debug2('is incoming UDP data. %r %d.\n' % (dstip, dstport))
            h = udphandlers[channel]
            h.send((dstip, dstport), data)
        elif cmd == ssnet.CMD_UDP_CLOSE:
            debug2('is incoming UDP close\n')
            h = udphandlers[channel]
            h.ok = False
            del mux.channels[channel]

    def udp_open(channel, data):
        debug2('Incoming UDP open.\n')
        family = int(data)
        mux.channels[channel] = lambda cmd, data: udp_req(channel, cmd, data)
        if channel in udphandlers:
            raise Fatal('UDP connection channel %d already open' % channel)
        else:
            h = UdpProxy(mux, channel, family)
            handlers.append(h)
            udphandlers[channel] = h
    mux.got_udp_open = udp_open

    while mux.ok:
        if hw.pid:
            assert(hw.pid > 0)
            (rpid, rv) = os.waitpid(hw.pid, os.WNOHANG)
            if rpid:
                raise Fatal(
                    'hostwatch exited unexpectedly: code 0x%04x\n' % rv)

        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()

        if dnshandlers:
            now = time.time()
            remove = []
            for channel, h in dnshandlers.items():
                if h.timeout < now or not h.ok:
                    debug3('expiring dnsreqs channel=%d\n' % channel)
                    remove.append(channel)
                    h.ok = False
            for channel in remove:
                del dnshandlers[channel]
        if udphandlers:
            remove = []
            for channel, h in udphandlers.items():
                if not h.ok:
                    debug3('expiring UDP channel=%d\n' % channel)
                    remove.append(channel)
                    h.ok = False
            for channel in remove:
                del udphandlers[channel]
