import struct, socket, select, errno, re, signal, time
import compat.ssubprocess as ssubprocess
import helpers, ssnet, ssh, ssyslog
from ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from helpers import *

_extra_fd = os.open('/dev/null', os.O_RDONLY)

def got_signal(signum, frame):
    log('exiting on signal %d\n' % signum)
    sys.exit(1)


_pidname = None
IP_TRANSPARENT = 19
def check_daemon(pidfile):
    global _pidname
    _pidname = os.path.abspath(pidfile)
    try:
        oldpid = open(_pidname).read(1024)
    except IOError, e:
        if e.errno == errno.ENOENT:
            return  # no pidfile, ok
        else:
            raise Fatal("can't read %s: %s" % (_pidname, e))
    if not oldpid:
        os.unlink(_pidname)
        return  # invalid pidfile, ok
    oldpid = int(oldpid.strip() or 0)
    if oldpid <= 0:
        os.unlink(_pidname)
        return  # invalid pidfile, ok
    try:
        os.kill(oldpid, 0)
    except OSError, e:
        if e.errno == errno.ESRCH:
            os.unlink(_pidname)
            return  # outdated pidfile, ok
        elif e.errno == errno.EPERM:
            pass
        else:
            raise
    raise Fatal("%s: sshuttle is already running (pid=%d)"
                % (_pidname, oldpid))


def daemonize():
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)

    outfd = os.open(_pidname, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0666)
    try:
        os.write(outfd, '%d\n' % os.getpid())
    finally:
        os.close(outfd)
    os.chdir("/")

    # Normal exit when killed, or try/finally won't work and the pidfile won't
    # be deleted.
    signal.signal(signal.SIGTERM, got_signal)
    
    si = open('/dev/null', 'r+')
    os.dup2(si.fileno(), 0)
    os.dup2(si.fileno(), 1)
    si.close()

    ssyslog.stderr_to_syslog()


def daemon_cleanup():
    try:
        os.unlink(_pidname)
    except OSError, e:
        if e.errno == errno.ENOENT:
            pass
        else:
            raise


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


class MultiListener:

    def __init__(self, type=socket.SOCK_STREAM, proto=0):
        self.v6 = socket.socket(socket.AF_INET6, type, proto)
        self.v4 = socket.socket(socket.AF_INET, type, proto)

    def setsockopt(self, level, optname, value):
        if self.v6:
            self.v6.setsockopt(level, optname, value)
        if self.v4:
            self.v4.setsockopt(level, optname, value)

    def add_handler(self, handlers, callback, method, mux):
        if self.v6:
            handlers.append(Handler([self.v6], lambda: callback(self.v6, method, mux, handlers)))
        if self.v4:
            handlers.append(Handler([self.v4], lambda: callback(self.v4, method, mux, handlers)))

    def listen(self, backlog):
        if self.v6:
            self.v6.listen(backlog)
        if self.v4:
            self.v4.listen(backlog)

    def bind(self, address_v6, address_v4):
        if address_v6 and self.v6:
            self.v6.bind(address_v6)
        else:
            self.v6 = None
        if address_v4 and self.v4:
            self.v4.bind(address_v4)
        else:
            self.v4 = None

    def print_listening(self, what):
        if self.v6:
            listenip = self.v6.getsockname()
            debug1('%s listening on %r.\n' % (what, listenip))
        if self.v4:
            listenip = self.v4.getsockname()
            debug1('%s listening on %r.\n' % (what, listenip))


class FirewallClient:
    def __init__(self, port_v6, port_v4, subnets_include, subnets_exclude, dnsport_v6, dnsport_v4, method):
        self.auto_nets = []
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        argvbase = ([sys.argv[1], sys.argv[0], sys.argv[1]] +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--firewall', str(port_v6), str(port_v4),
                                   str(dnsport_v6), str(dnsport_v4),
                                   method])
        if ssyslog._p:
            argvbase += ['--syslog']
        argv_tries = [
            ['sudo', '-p', '[local sudo] Password: '] + argvbase,
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
        if os.getuid() == 0:
            argv_tries = argv_tries[-1:]  # last entry only
        for argv in argv_tries:
            try:
                if argv[0] == 'su':
                    sys.stderr.write('[local su] ')
                self.p = ssubprocess.Popen(argv, stdout=s1, preexec_fn=setup)
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
        if line[0:5] != 'READY':
            raise Fatal('%r expected READY, got %r' % (self.argv, line))
        self.method = line[6:-1]

    def check(self):
        rv = self.p.poll()
        if rv:
            raise Fatal('%r returned %d' % (self.argv, rv))

    def start(self):
        self.pfile.write('ROUTES\n')
        for (family,ip,width) in self.subnets_include+self.auto_nets:
            self.pfile.write('%d,%d,0,%s\n' % (family, width, ip))
        for (family,ip,width) in self.subnets_exclude:
            self.pfile.write('%d,%d,1,%s\n' % (family, width, ip))
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


dnsreqs = {}
def expire_connections(now, mux):
    for chan,(peer,sock,timeout) in dnsreqs.items():
        if timeout < now:
            debug3('expiring dnsreqs channel=%d peer=%r\n' % (chan, peer))
            del mux.channels[chan]
            del dnsreqs[chan]
    debug3('Remaining DNS requests: %d\n' % len(dnsreqs))


def onaccept_tcp(listener, method, mux, handlers):
    global _extra_fd
    try:
        sock,srcip = listener.accept()
    except socket.error, e:
        if e.args[0] in [errno.EMFILE, errno.ENFILE]:
            debug1('Rejected incoming connection: too many open files!\n')
            # free up an fd so we can eat the connection
            os.close(_extra_fd)
            try:
                sock,srcip = listener.accept()
                sock.close()
            finally:
                _extra_fd = os.open('/dev/null', os.O_RDONLY)
            return
        else:
            raise
    if method == "tproxy":
        dstip = sock.getsockname();
    else:
        dstip = original_dst(sock)
    debug1('Accept TCP: %s:%r -> %s:%r.\n' % (srcip[0],srcip[1],
                                          dstip[0],dstip[1]))
    if dstip[1] == listener.getsockname()[1] and islocal(dstip[0], sock.family):
        debug1("-- ignored: that's my address!\n")
        sock.close()
        return
    chan = mux.next_channel()
    if not chan:
        log('warning: too many open channels.  Discarded connection.\n')
        sock.close()
        return
    mux.send(chan, ssnet.CMD_TCP_CONNECT, '%d,%s,%s' % (sock.family, dstip[0], dstip[1]))
    outwrap = MuxWrapper(mux, chan)
    handlers.append(Proxy(SockWrapper(sock, sock), outwrap))
    expire_connections(time.time(), mux)


def dns_done(chan, mux, data, method):
    peer,sock,timeout = dnsreqs.get(chan) or (None,None,None)
    debug3('dns_done: channel=%r peer=%r\n' % (chan, peer))
    if peer:
        del mux.channels[chan]
        del dnsreqs[chan]
        debug3('doing sendto %r\n' % (peer,))
        sock.sendto(data, peer)


def ondns(listener, method, mux, handlers):
    pkt,peer = listener.recvfrom(4096)
    now = time.time()
    if pkt:
        debug1('DNS request from %r: %d bytes\n' % (peer, len(pkt)))
        chan = mux.next_channel()
        dnsreqs[chan] = peer,listener,now+30
        mux.send(chan, ssnet.CMD_DNS_REQ, pkt)
        mux.channels[chan] = lambda cmd,data: dns_done(chan, mux, data, method)
    expire_connections(now, mux)


def _main(tcp_listener, fw, ssh_cmd, remotename, python, latency_control,
          dns_listener, method, seed_hosts, auto_nets,
          syslog, daemon):
    handlers = []
    if helpers.verbose >= 1:
        helpers.logprefix = 'c : '
    else:
        helpers.logprefix = 'client: '
    debug1('connecting to server...\n')

    try:
        (serverproc, serversock) = ssh.connect(ssh_cmd, remotename, python,
                        stderr=ssyslog._p and ssyslog._p.stdin,
                        options=dict(latency_control=latency_control))
    except socket.error, e:
        if e.args[0] == errno.EPIPE:
            raise Fatal("failed to establish ssh session (1)")
        else:
            raise
    mux = Mux(serversock, serversock)
    handlers.append(mux)

    expected = 'SSHUTTLE0001'
    
    try:
        v = 'x'
        while v and v != '\0':
            v = serversock.recv(1)
        v = 'x'
        while v and v != '\0':
            v = serversock.recv(1)
        initstring = serversock.recv(len(expected))
    except socket.error, e:
        if e.args[0] == errno.ECONNRESET:
            raise Fatal("failed to establish ssh session (2)")
        else:
            raise
    
    rv = serverproc.poll()
    if rv:
        raise Fatal('server died with error code %d' % rv)
        
    if initstring != expected:
        raise Fatal('expected server init string %r; got %r'
                        % (expected, initstring))
    debug1('connected.\n')
    print 'Connected.'
    sys.stdout.flush()
    if daemon:
        daemonize()
        log('daemonizing (%s).\n' % _pidname)
    elif syslog:
        debug1('switching to syslog.\n')
        ssyslog.stderr_to_syslog()

    def onroutes(routestr):
        if auto_nets:
            for line in routestr.strip().split('\n'):
                (family,ip,width) = line.split(',', 2)
                fw.auto_nets.append((family,ip,int(width)))

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

    tcp_listener.add_handler(handlers, onaccept_tcp, method, mux)

    if dns_listener:
        dns_listener.add_handler(handlers, ondns, method, mux)

    if seed_hosts != None:
        debug1('seed_hosts: %r\n' % seed_hosts)
        mux.send(0, ssnet.CMD_HOST_REQ, '\n'.join(seed_hosts))
    
    while 1:
        rv = serverproc.poll()
        if rv:
            raise Fatal('server died with error code %d' % rv)
        
        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()
        mux.callback()


def main(listenip_v6, listenip_v4,
         ssh_cmd, remotename, python, latency_control, dns,
         method, seed_hosts, auto_nets,
         subnets_include, subnets_exclude, syslog, daemon, pidfile):
    if syslog:
        ssyslog.start_syslog()
    if daemon:
        try:
            check_daemon(pidfile)
        except Fatal, e:
            log("%s\n" % e)
            return 5
    debug1('Starting sshuttle proxy.\n')

    if listenip_v6 and listenip_v6[1] and listenip_v4 and listenip_v4[1]:
        # if both ports given, no need to search for a spare port
        ports = [ 0, ]
    else:
        # if at least one port missing, we have to search
        ports = xrange(12300,9000,-1)

    # search for free ports and try to bind
    last_e = None
    redirectport_v6 = 0
    redirectport_v4 = 0
    bound = False
    debug2('Binding redirector:')
    for port in ports:
        debug2(' %d' % port)
        tcp_listener = MultiListener()
        tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        if listenip_v6 and listenip_v6[1]:
            lv6 = listenip_v6
            redirectport_v6 = lv6[1]
        elif listenip_v6:
            lv6 = (listenip_v6[0],port)
            redirectport_v6 = port
        else:
            lv6 = None
            redirectport_v6 = 0

        if listenip_v4 and listenip_v4[1]:
            lv4 = listenip_v4
            redirectport_v4 = lv4[1]
        elif listenip_v4:
            lv4 = (listenip_v4[0],port)
            redirectport_v4 = port
        else:
            lv4 = None
            redirectport_v4 = 0

        try:
            tcp_listener.bind(lv6, lv4)
            bound = True
            break
        except socket.error, e:
            if e.errno == errno.EADDRINUSE:
                last_e = e
            else:
                raise e
    debug2('\n')
    if not bound:
        assert(last_e)
        raise last_e
    tcp_listener.listen(10)
    tcp_listener.print_listening("TCP redirector")

    bound = False
    if dns:
        # search for spare port for DNS
        debug2('Binding DNS:')
        ports = xrange(12300,9000,-1)
        for port in ports:
            debug2(' %d' % port)
            dns_listener = MultiListener(socket.SOCK_DGRAM)
            dns_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            if listenip_v6:
                lv6 = (listenip_v6[0],port)
                dnsport_v6 = port
            else:
                lv6 = None
                dnsport_v6 = 0

            if listenip_v4:
                lv4 = (listenip_v4[0],port)
                dnsport_v4 = port
            else:
                lv4 = None
                dnsport_v4 = 0

            try:
                dns_listener.bind(lv6, lv4)
                bound = True
                break
            except socket.error, e:
                if e.errno == errno.EADDRINUSE:
                    last_e = e
                else:
                    raise e
        debug2('\n')
        dns_listener.print_listening("DNS")
        if not bound:
            assert(last_e)
            raise last_e
    else:
        dnsport_v6 = 0
        dnsport_v4 = 0
        dns_listener = None

    fw = FirewallClient(redirectport_v6, redirectport_v4, subnets_include, subnets_exclude, dnsport_v6, dnsport_v4, method)

    if fw.method == "tproxy":
        tcp_listener.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)

    try:
        return _main(tcp_listener, fw, ssh_cmd, remotename,
                     python, latency_control, dns_listener,
                     fw.method, seed_hosts, auto_nets, syslog,
                     daemon)
    finally:
        try:
            if daemon:
                # it's not our child anymore; can't waitpid
                fw.p.returncode = 0
            fw.done()
        finally:
            if daemon:
                daemon_cleanup()
