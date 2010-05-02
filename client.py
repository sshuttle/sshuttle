import struct, socket, select, subprocess, errno
import helpers, ssnet, ssh
from ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from helpers import *

def original_dst(sock):
    SO_ORIGINAL_DST = 80
    SOCKADDR_MIN = 16
    sockaddr_in = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, SOCKADDR_MIN)
    (proto, port, a,b,c,d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
    assert(socket.htons(proto) == socket.AF_INET)
    ip = '%d.%d.%d.%d' % (a,b,c,d)
    return (ip,port)


def iptables_setup(port, subnets):
    subnets_str = ['%s/%d' % (ip,width) for ip,width in subnets]
    argv = (['sudo', sys.argv[0]] +
            ['-v'] * (helpers.verbose or 0) +
            ['--iptables', str(port)] + subnets_str)
    rv = subprocess.call(argv)
    if rv != 0:
        raise Fatal('%r returned %d' % (argv, rv))


def _main(listener, listenport, use_server, remotename, subnets):
    handlers = []
    if use_server:
        if helpers.verbose >= 1:
            helpers.logprefix = 'c : '
        else:
            helpers.logprefix = 'client: '
        (serverproc, serversock) = ssh.connect(remotename)
        mux = Mux(serversock, serversock)
        handlers.append(mux)

        expected = 'SSHUTTLE0001'
        initstring = serversock.recv(len(expected))
        
        rv = serverproc.poll()
        if rv:
            raise Fatal('server died with error code %d' % rv)
            
        if initstring != expected:
            raise Fatal('expected server init string %r; got %r'
                            % (expected, initstring))

    # we definitely want to do this *after* starting ssh, or we might end
    # up intercepting the ssh connection!
    iptables_setup(listenport, subnets)

    def onaccept():
        sock,srcip = listener.accept()
        dstip = original_dst(sock)
        debug1('Accept: %r:%r -> %r:%r.\n' % (srcip[0],srcip[1],
                                           dstip[0],dstip[1]))
        if dstip == sock.getsockname():
            debug1("-- ignored: that's my address!\n")
            sock.close()
            return
        if use_server:
            chan = mux.next_channel()
            mux.send(chan, ssnet.CMD_CONNECT, '%s,%s' % dstip)
            outwrap = MuxWrapper(mux, chan)
        else:
            outwrap = ssnet.connect_dst(dstip[0], dstip[1])
        handlers.append(Proxy(SockWrapper(sock, sock), outwrap))
    handlers.append(Handler([listener], onaccept))
    
    while 1:
        if use_server:
            rv = serverproc.poll()
            if rv:
                raise Fatal('server died with error code %d' % rv)
        
        r = set()
        w = set()
        x = set()
        handlers = filter(lambda s: s.ok, handlers)
        for s in handlers:
            s.pre_select(r,w,x)
        debug2('Waiting: %d[%d,%d,%d]...\n' 
            % (len(handlers), len(r), len(w), len(x)))
        (r,w,x) = select.select(r,w,x)
        #log('r=%r w=%r x=%r\n' % (r,w,x))
        ready = set(r) | set(w) | set(x)
        for s in handlers:
            if s.socks & ready:
                s.callback()
        mux.callback()
        mux.check_fullness()


def main(listenip, use_server, remotename, subnets):
    debug1('Starting sshuttle proxy.\n')
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if listenip[1]:
        ports = [listenip[1]]
    else:
        ports = xrange(12300,65536)
    last_e = None
    bound = False
    debug2('Binding:')
    for port in ports:
        debug2(' %d' % port)
        try:
            listener.bind((listenip[0], port))
            bound = True
            break
        except socket.error, e:
            last_e = e
    debug2('\n')
    if not bound:
        assert(last_e)
        raise last_e
    listener.listen(10)
    listenip = listener.getsockname()
    debug1('Listening on %r.\n' % (listenip,))

    try:
        return _main(listener, listenip[1], use_server, remotename, subnets)
    finally:
        iptables_setup(listenip[1], [])
