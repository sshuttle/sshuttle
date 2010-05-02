import struct, socket, select, subprocess
from ssnet import SockWrapper, Handler, Proxy
from helpers import *


def original_dst(sock):
    SO_ORIGINAL_DST = 80
    SOCKADDR_MIN = 16
    sockaddr_in = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, SOCKADDR_MIN)
    (proto, port, a,b,c,d) = struct.unpack('!hhBBBB', sockaddr_in[:8])
    assert(socket.htons(proto) == socket.AF_INET)
    ip = '%d.%d.%d.%d' % (a,b,c,d)
    return (ip,port)


def iptables_setup(port, subnets):
    subnets_str = ['%s/%d' % (ip,width) for ip,width in subnets]
    argv = ['sudo', sys.argv[0], '--iptables', str(port)] + subnets_str
    rv = subprocess.call(argv)
    if rv != 0:
        raise Exception('%r returned %d' % (argv, rv))


def main(listenip, remotename, subnets):
    log('Starting sshuttle proxy.\n')
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(listenip)
    listener.listen(10)
    log('Listening on %r.\n' % (listener.getsockname(),))

    iptables_setup(listenip[1], subnets)

    handlers = []
    def onaccept():
        sock,srcip = listener.accept()
        dstip = original_dst(sock)
        log('Incoming connection from %r to %r.\n' % (srcip,dstip))
        if dstip == sock.getsockname():
            log("-- ignored: that's my address!\n")
            sock.close()
            return
        outsock = socket.socket()
        outsock.setsockopt(socket.SOL_IP, socket.IP_TTL, 42)
        outsock.connect(dstip)
        handlers.append(Proxy(SockWrapper(sock), SockWrapper(outsock)))
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
