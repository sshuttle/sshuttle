import struct, socket, select
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


def main(remotename, subnets):
    log('Starting sshuttle proxy.\n')
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
