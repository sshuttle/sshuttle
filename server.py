import struct, socket, select
if not globals().get('skip_imports'):
    import ssnet, helpers
    from ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
    from helpers import *


def main():
    if helpers.verbose >= 1:
        helpers.logprefix = ' s: '
    else:
        helpers.logprefix = 'server: '
        
    # synchronization header
    sys.stdout.write('SSHUTTLE0001')
    sys.stdout.flush()

    handlers = []
    mux = Mux(socket.fromfd(sys.stdin.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM),
              socket.fromfd(sys.stdout.fileno(),
                            socket.AF_INET, socket.SOCK_STREAM))
    handlers.append(mux)

    def new_channel(channel, data):
        (dstip,dstport) = data.split(',', 1)
        dstport = int(dstport)
        outwrap = ssnet.connect_dst(dstip,dstport)
        handlers.append(Proxy(MuxWrapper(mux, channel), outwrap))
    
    mux.new_channel = new_channel

    while mux.ok:
        r = set()
        w = set()
        x = set()
        handlers = filter(lambda s: s.ok, handlers)
        for s in handlers:
            s.pre_select(r,w,x)
        debug2('Waiting: %d[%d,%d,%d] (fullness=%d/%d)...\n' 
               % (len(handlers), len(r), len(w), len(x),
                  mux.fullness, mux.too_full))
        (r,w,x) = select.select(r,w,x)
        #log('r=%r w=%r x=%r\n' % (r,w,x))
        ready = set(r) | set(w) | set(x)
        for s in handlers:
            #debug2('check: %r: %r\n' % (s, s.socks & ready))
            if s.socks & ready:
                s.callback()
        mux.check_fullness()
        mux.callback()
