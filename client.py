import struct
from socket import *
from helpers import *


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
    while 1:
        s,srcip = listener.accept()
        dstip = original_dst(s)
        print 'Incoming connection from %r to %r.' % (srcip,dstip)
        
