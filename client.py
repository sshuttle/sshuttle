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


class FirewallClient:
    def __init__(self, port, subnets_include, subnets_exclude, dnsport):
        self.port = port
        self.auto_nets = []
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        self.dnsport = dnsport
        argvbase = ([sys.argv[0]] +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--firewall', str(port), str(dnsport)])
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


def _main(listener, fw, ssh_cmd, remotename, python, latency_control,
          dnslistener, seed_hosts, auto_nets,
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
        dstip = original_dst(sock)
        debug1('Accept: %s:%r -> %s:%r.\n' % (srcip[0],srcip[1],
                                              dstip[0],dstip[1]))
        if dstip[1] == listener.getsockname()[1] and islocal(dstip[0]):
            debug1("-- ignored: that's my address!\n")
            sock.close()
            return
        chan = mux.next_channel()
        mux.send(chan, ssnet.CMD_CONNECT, '%s,%s' % dstip)
        outwrap = MuxWrapper(mux, chan)
        handlers.append(Proxy(SockWrapper(sock, sock), outwrap))
    handlers.append(Handler([listener], onaccept))

    dnsreqs = {}
    def dns_done(chan, data):
        peer,timeout = dnsreqs.get(chan) or (None,None)
        debug3('dns_done: channel=%r peer=%r\n' % (chan, peer))
        if peer:
            del dnsreqs[chan]
            debug3('doing sendto %r\n' % (peer,))
            dnslistener.sendto(data, peer)
    def ondns():
        pkt,peer = dnslistener.recvfrom(4096)
        now = time.time()
        if pkt:
            debug1('DNS request from %r: %d bytes\n' % (peer, len(pkt)))
            chan = mux.next_channel()
            dnsreqs[chan] = peer,now+30
            mux.send(chan, ssnet.CMD_DNS_REQ, pkt)
            mux.channels[chan] = lambda cmd,data: dns_done(chan,data)
        for chan,(peer,timeout) in dnsreqs.items():
            if timeout < now:
                del dnsreqs[chan]
        debug3('Remaining DNS requests: %d\n' % len(dnsreqs))
    if dnslistener:
        handlers.append(Handler([dnslistener], ondns))

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


def main(listenip, ssh_cmd, remotename, python, latency_control, dns,
         seed_hosts, auto_nets,
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

    dnsport = 0
    dnslistener = None
    if dns:
        dnslistener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dnslistener.bind((listenip[0], 0))
        dnsip = dnslistener.getsockname()
        debug1('DNS listening on %r.\n' % (dnsip,))
        dnsport = dnsip[1]

    fw = FirewallClient(listenip[1], subnets_include, subnets_exclude, dnsport)
    
    try:
        return _main(listener, fw, ssh_cmd, remotename,
                     python, latency_control, dnslistener,
                     seed_hosts, auto_nets, syslog, daemon)
    finally:
        try:
            if daemon:
                # it's not our child anymore; can't waitpid
                fw.p.returncode = 0
            fw.done()
        finally:
            if daemon:
                daemon_cleanup()
