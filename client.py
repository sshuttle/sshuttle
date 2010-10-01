import struct, socket, select, subprocess, errno, re
import helpers, ssnet, ssh
from ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from helpers import *

def original_dst(sock):
    try:
        SO_ORIGINAL_DST = 80
        SOCKADDR_MIN = 16
        sockaddr_in = sock.getsockopt(socket.SOL_IP,
                                      SO_ORIGINAL_DST, SOCKADDR_MIN)
        (proto, port, a,b,c,d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
        assert(socket.htons(proto) == socket.AF_INET)
        ip = '%d.%d.%d.%d' % (a,b,c,d)
        return (ip,port)
    except socket.error, e:
        if e.args[0] == errno.ENOPROTOOPT:
            return sock.getsockname()
        raise


class FirewallClient:
    def __init__(self, port, subnets_include, subnets_exclude):
        self.port = port
        self.auto_nets = []
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        argvbase = ([sys.argv[0]] +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--firewall', str(port)])
        argv_tries = [
            ['sudo'] + argvbase,
            ['su', '-c', ' '.join(argvbase)],
            argvbase
        ]

        # we can't use stdin/stdout=subprocess.PIPE here, as we normally would,
        # because stupid Linux 'su' requires that stdin be attached to a tty.
        # Instead, attach a *bidirectional* socket to its stdout, and use
        # that for talking in both directions.
        (s1,s2) = socket.socketpair()
        def setup():
            # run in the child process
            s2.close()
        e = None
        for argv in argv_tries:
            try:
                self.p = subprocess.Popen(argv, stdout=s1, preexec_fn=setup)
                e = None
                break
            except OSError, e:
                pass
        self.argv = argv
        s1.close()
        self.pfile = s2.makefile('wb+')
        if e:
            log('Spawning firewall manager: %r\n' % self.argv)
            raise Fatal(e)
        line = self.pfile.readline()
        self.check()
        if line != 'READY\n':
            raise Fatal('%r expected READY, got %r' % (self.argv, line))

    def check(self):
        rv = self.p.poll()
        if rv:
            raise Fatal('%r returned %d' % (self.argv, rv))

    def start(self):
        self.pfile.write('ROUTES\n')
        for (ip,width) in self.subnets_include+self.auto_nets:
            self.pfile.write('%d,0,%s\n' % (width, ip))
        for (ip,width) in self.subnets_exclude:
            self.pfile.write('%d,1,%s\n' % (width, ip))
        self.pfile.write('GO\n')
        self.pfile.flush()
        line = self.pfile.readline()
        self.check()
        if line != 'STARTED\n':
            raise Fatal('%r expected STARTED, got %r' % (self.argv, line))

    def sethostip(self, hostname, ip):
        assert(not re.search(r'[^-\w]', hostname))
        assert(not re.search(r'[^0-9.]', ip))
        self.pfile.write('HOST %s,%s\n' % (hostname, ip))
        self.pfile.flush()

    def done(self):
        self.pfile.close()
        rv = self.p.wait()
        if rv:
            raise Fatal('cleanup: %r returned %d' % (self.argv, rv))


def _main(listener, fw, use_server, remotename, python, seed_hosts, auto_nets):
    handlers = []
    if use_server:
        if helpers.verbose >= 1:
            helpers.logprefix = 'c : '
        else:
            helpers.logprefix = 'client: '
        debug1('connecting to server...\n')
        try:
            (serverproc, serversock) = ssh.connect(remotename, python)
        except socket.error, e:
            if e.errno == errno.EPIPE:
                raise Fatal("failed to establish ssh session")
            else:
                raise
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
        debug1('connected.\n')

    def onroutes(routestr):
        if auto_nets:
            for line in routestr.strip().split('\n'):
                (ip,width) = line.split(',', 1)
                fw.auto_nets.append((ip,int(width)))

        # we definitely want to do this *after* starting ssh, or we might end
        # up intercepting the ssh connection!
        #
        # Moreover, now that we have the --auto-nets option, we have to wait
        # for the server to send us that message anyway.  Even if we haven't
        # set --auto-nets, we might as well wait for the message first, then
        # ignore its contents.
        mux.got_routes = None
        fw.start()
    mux.got_routes = onroutes

    def onhostlist(hostlist):
        debug2('got host list: %r\n' % hostlist)
        for line in hostlist.strip().split():
            if line:
                name,ip = line.split(',', 1)
                fw.sethostip(name, ip)
    mux.got_host_list = onhostlist

    def onaccept():
        sock,srcip = listener.accept()
        dstip = original_dst(sock)
        debug1('Accept: %r:%r -> %r:%r.\n' % (srcip[0],srcip[1],
                                           dstip[0],dstip[1]))
        if dstip == listener.getsockname():
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

    if seed_hosts != None:
        debug1('seed_hosts: %r\n' % seed_hosts)
        mux.send(0, ssnet.CMD_HOST_REQ, '\n'.join(seed_hosts))
    
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
        if use_server:
            mux.callback()
            mux.check_fullness()


def main(listenip, use_server, remotename, python, seed_hosts, auto_nets,
         subnets_include, subnets_exclude):
    debug1('Starting sshuttle proxy.\n')
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if listenip[1]:
        ports = [listenip[1]]
    else:
        ports = xrange(12300,9000,-1)
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

    fw = FirewallClient(listenip[1], subnets_include, subnets_exclude)
    
    try:
        return _main(listener, fw, use_server, remotename,
                     python, seed_hosts, auto_nets)
    finally:
        fw.done()
