import re, struct, socket, select, traceback
if not globals().get('skip_imports'):
    import ssnet, helpers, hostwatch
    import compat.ssubprocess as ssubprocess
    from ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
    from helpers import *


def _ipmatch(ipstr):
    if ipstr == 'default':
        ipstr = '0.0.0.0/0'
    m = re.match(r'^(\d+(\.\d+(\.\d+(\.\d+)?)?)?)(?:/(\d+))?$', ipstr)
    if m:
        g = m.groups()
        ips = g[0]
        width = int(g[4] or 32)
        if g[1] == None:
            ips += '.0.0.0'
            width = min(width, 8)
        elif g[2] == None:
            ips += '.0.0'
            width = min(width, 16)
        elif g[3] == None:
            ips += '.0'
            width = min(width, 24)
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
            return 32-i
    return 0
    
    
def _shl(n, bits):
    return n * int(2**bits)


def _list_routes():
    argv = ['netstat', '-rn']
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE)
    routes = []
    for line in p.stdout:
        cols = re.split(r'\s+', line)
        ipw = _ipmatch(cols[0])
        if not ipw:
            continue  # some lines won't be parseable; never mind
        maskw = _ipmatch(cols[2])  # linux only
        mask = _maskbits(maskw)   # returns 32 if maskw is null
        width = min(ipw[1], mask)
        ip = ipw[0] & _shl(_shl(1, width) - 1, 32-width)
        routes.append((socket.inet_ntoa(struct.pack('!I', ip)), width))
    rv = p.wait()
    if rv != 0:
        log('WARNING: %r returned %d\n' % (argv, rv))
        log('WARNING: That prevents --auto-nets from working.\n')
    return routes


def list_routes():
    for (ip,width) in _list_routes():
        if not ip.startswith('0.') and not ip.startswith('127.'):
            yield (ip,width)


def _exc_dump():
    exc_info = sys.exc_info()
    return ''.join(traceback.format_exception(*exc_info))


def start_hostwatch(seed_hosts):
    s1,s2 = socket.socketpair()
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
            except Exception, e:
                log('%s\n' % _exc_dump())
                rv = 98
        finally:
            os._exit(rv)
    s1.close()
    return pid,s2


class Hostwatch:
    def __init__(self):
        self.pid = 0
        self.sock = None


def main():
    if helpers.verbose >= 1:
        helpers.logprefix = ' s: '
    else:
        helpers.logprefix = 'server: '
    debug1('latency control setting = %r\n' % latency_control)

    routes = list(list_routes())
    debug1('available routes:\n')
    for r in routes:
        debug1('  %s/%d\n' % r)
        
    # synchronization header
    sys.stdout.write('SSHUTTLE0001')
    sys.stdout.flush()

    handlers = []
    mux = Mux(socket.fromfd(sys.stdin.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM),
              socket.fromfd(sys.stdout.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM))
    handlers.append(mux)
    routepkt = ''
    for r in routes:
        routepkt += '%s,%d\n' % r
    mux.send(0, ssnet.CMD_ROUTES, routepkt)

    hw = Hostwatch()
    hw.leftover = ''
        
    def hostwatch_ready():
        assert(hw.pid)
        content = hw.sock.recv(4096)
        if content:
            lines = (hw.leftover + content).split('\n')
            if lines[-1]:
                # no terminating newline: entry isn't complete yet!
                hw.leftover = lines.pop()
                lines.append('')
            else:
                hw.leftover = ''
            mux.send(0, ssnet.CMD_HOST_LIST, '\n'.join(lines))
        else:
            raise Fatal('hostwatch process died')

    def got_host_req(data):
        if not hw.pid:
            (hw.pid,hw.sock) = start_hostwatch(data.strip().split())
            handlers.append(Handler(socks = [hw.sock],
                                    callback = hostwatch_ready))
    mux.got_host_req = got_host_req

    def new_channel(channel, data):
        (dstip,dstport) = data.split(',', 1)
        dstport = int(dstport)
        outwrap = ssnet.connect_dst(dstip,dstport)
        handlers.append(Proxy(MuxWrapper(mux, channel), outwrap))
    mux.new_channel = new_channel

    while mux.ok:
        if hw.pid:
            assert(hw.pid > 0)
            (rpid, rv) = os.waitpid(hw.pid, os.WNOHANG)
            if rpid:
                raise Fatal('hostwatch exited unexpectedly: code 0x%04x\n' % rv)
        
        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()
        mux.callback()
