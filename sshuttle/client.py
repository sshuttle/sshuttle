import errno
import re
import signal
import time
import subprocess as ssubprocess
import sshuttle.helpers as helpers
import os
import sshuttle.ssnet as ssnet
import sshuttle.ssh as ssh
import sshuttle.ssyslog as ssyslog
import sshuttle.sdnotify as sdnotify
import sys
import platform
from sshuttle.ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from sshuttle.helpers import log, debug1, debug2, debug3, Fatal, islocal, \
    resolvconf_nameservers
from sshuttle.methods import get_method, Features

try:
    # try getting recvmsg from python
    import socket as pythonsocket
    getattr(pythonsocket.socket, "recvmsg")
    socket = pythonsocket
except AttributeError:
    # try getting recvmsg from socket_ext library
    try:
        import socket_ext
        getattr(socket_ext.socket, "recvmsg")
        socket = socket_ext
    except ImportError:
        import socket

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
    except IOError as e:
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
    except OSError as e:
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

    outfd = os.open(_pidname, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        os.write(outfd, b'%d\n' % os.getpid())
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


def daemon_cleanup():
    try:
        os.unlink(_pidname)
    except OSError as e:
        if e.errno == errno.ENOENT:
            pass
        else:
            raise


class MultiListener:

    def __init__(self, type=socket.SOCK_STREAM, proto=0):
        self.type = type
        self.proto = proto
        self.v6 = None
        self.v4 = None
        self.bind_called = False

    def setsockopt(self, level, optname, value):
        assert(self.bind_called)
        if self.v6:
            self.v6.setsockopt(level, optname, value)
        if self.v4:
            self.v4.setsockopt(level, optname, value)

    def add_handler(self, handlers, callback, method, mux):
        assert(self.bind_called)
        socks = []
        if self.v6:
            socks.append(self.v6)
        if self.v4:
            socks.append(self.v4)

        handlers.append(
            Handler(
                socks,
                lambda sock: callback(sock, method, mux, handlers)
            )
        )

    def listen(self, backlog):
        assert(self.bind_called)
        if self.v6:
            self.v6.listen(backlog)
        if self.v4:
            try:
                self.v4.listen(backlog)
            except socket.error as e:
                # on some systems v4 bind will fail if the v6 suceeded,
                # in this case the v6 socket will receive v4 too.
                if e.errno == errno.EADDRINUSE and self.v6:
                    self.v4 = None
                else:
                    raise e

    def bind(self, address_v6, address_v4):
        assert(not self.bind_called)
        self.bind_called = True
        if address_v6 is not None:
            self.v6 = socket.socket(socket.AF_INET6, self.type, self.proto)
            self.v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.v6.bind(address_v6)
        else:
            self.v6 = None
        if address_v4 is not None:
            self.v4 = socket.socket(socket.AF_INET, self.type, self.proto)
            self.v4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.v4.bind(address_v4)
        else:
            self.v4 = None

    def print_listening(self, what):
        assert(self.bind_called)
        if self.v6:
            listenip = self.v6.getsockname()
            debug1('%s listening on %r.\n' % (what, listenip))
            debug2('%s listening with %r.\n' % (what, self.v6))
        if self.v4:
            listenip = self.v4.getsockname()
            debug1('%s listening on %r.\n' % (what, listenip))
            debug2('%s listening with %r.\n' % (what, self.v4))


class FirewallClient:

    def __init__(self, method_name):
        self.auto_nets = []
        python_path = os.path.dirname(os.path.dirname(__file__))
        argvbase = ([sys.executable, sys.argv[0]] +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--method', method_name] +
                    ['--firewall'])
        if ssyslog._p:
            argvbase += ['--syslog']
        argv_tries = [
            ['sudo', '-p', '[local sudo] Password: ',
                ('PYTHONPATH=%s' % python_path), '--'] + argvbase,
            argvbase
        ]

        # we can't use stdin/stdout=subprocess.PIPE here, as we normally would,
        # because stupid Linux 'su' requires that stdin be attached to a tty.
        # Instead, attach a *bidirectional* socket to its stdout, and use
        # that for talking in both directions.
        (s1, s2) = socket.socketpair()

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
            except OSError as e:
                pass
        self.argv = argv
        s1.close()
        if sys.version_info < (3, 0):
            # python 2.7
            self.pfile = s2.makefile('wb+')
        else:
            # python 3.5
            self.pfile = s2.makefile('rwb')
        if e:
            log('Spawning firewall manager: %r\n' % self.argv)
            raise Fatal(e)
        line = self.pfile.readline()
        self.check()
        if line[0:5] != b'READY':
            raise Fatal('%r expected READY, got %r' % (self.argv, line))
        method_name = line[6:-1]
        self.method = get_method(method_name.decode("ASCII"))
        self.method.set_firewall(self)

    def setup(self, subnets_include, subnets_exclude, nslist,
              redirectport_v6, redirectport_v4, dnsport_v6, dnsport_v4, udp):
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        self.nslist = nslist
        self.redirectport_v6 = redirectport_v6
        self.redirectport_v4 = redirectport_v4
        self.dnsport_v6 = dnsport_v6
        self.dnsport_v4 = dnsport_v4
        self.udp = udp

    def check(self):
        rv = self.p.poll()
        if rv:
            raise Fatal('%r returned %d' % (self.argv, rv))

    def start(self):
        self.pfile.write(b'ROUTES\n')
        for (family, ip, width, fport, lport) \
                in self.subnets_include + self.auto_nets:
            self.pfile.write(b'%d,%d,0,%s,%d,%d\n'
                    % (family, width, ip.encode("ASCII"), fport, lport))
        for (family, ip, width, fport, lport) in self.subnets_exclude:
            self.pfile.write(b'%d,%d,1,%s,%d,%d\n'
                    % (family, width, ip.encode("ASCII"), fport, lport))

        self.pfile.write(b'NSLIST\n')
        for (family, ip) in self.nslist:
            self.pfile.write(b'%d,%s\n'
                             % (family, ip.encode("ASCII")))

        self.pfile.write(
            b'PORTS %d,%d,%d,%d\n'
            % (self.redirectport_v6, self.redirectport_v4,
               self.dnsport_v6, self.dnsport_v4))

        udp = 0
        if self.udp:
            udp = 1

        self.pfile.write(b'GO %d\n' % udp)
        self.pfile.flush()

        line = self.pfile.readline()
        self.check()
        if line != b'STARTED\n':
            raise Fatal('%r expected STARTED, got %r' % (self.argv, line))

    def sethostip(self, hostname, ip):
        assert(not re.search(b'[^-\w]', hostname))
        assert(not re.search(b'[^0-9.]', ip))
        self.pfile.write(b'HOST %s,%s\n' % (hostname, ip))
        self.pfile.flush()

    def done(self):
        self.pfile.close()
        rv = self.p.wait()
        if rv:
            raise Fatal('cleanup: %r returned %d' % (self.argv, rv))


dnsreqs = {}
udp_by_src = {}


def expire_connections(now, mux):
    remove = []
    for chan, timeout in dnsreqs.items():
        if timeout < now:
            debug3('expiring dnsreqs channel=%d\n' % chan)
            remove.append(chan)
            del mux.channels[chan]
    for chan in remove:
        del dnsreqs[chan]
    debug3('Remaining DNS requests: %d\n' % len(dnsreqs))

    remove = []
    for peer, (chan, timeout) in udp_by_src.items():
        if timeout < now:
            debug3('expiring UDP channel channel=%d peer=%r\n' % (chan, peer))
            mux.send(chan, ssnet.CMD_UDP_CLOSE, b'')
            remove.append(peer)
            del mux.channels[chan]
    for peer in remove:
        del udp_by_src[peer]
    debug3('Remaining UDP channels: %d\n' % len(udp_by_src))


def onaccept_tcp(listener, method, mux, handlers):
    global _extra_fd
    try:
        sock, srcip = listener.accept()
    except socket.error as e:
        if e.args[0] in [errno.EMFILE, errno.ENFILE]:
            debug1('Rejected incoming connection: too many open files!\n')
            # free up an fd so we can eat the connection
            os.close(_extra_fd)
            try:
                sock, srcip = listener.accept()
                sock.close()
            finally:
                _extra_fd = os.open('/dev/null', os.O_RDONLY)
            return
        else:
            raise

    dstip = method.get_tcp_dstip(sock)
    debug1('Accept TCP: %s:%r -> %s:%r.\n' % (srcip[0], srcip[1],
                                              dstip[0], dstip[1]))
    if dstip[1] == sock.getsockname()[1] and islocal(dstip[0], sock.family):
        debug1("-- ignored: that's my address!\n")
        sock.close()
        return
    chan = mux.next_channel()
    if not chan:
        log('warning: too many open channels.  Discarded connection.\n')
        sock.close()
        return
    mux.send(chan, ssnet.CMD_TCP_CONNECT, b'%d,%s,%d' %
             (sock.family, dstip[0].encode("ASCII"), dstip[1]))
    outwrap = MuxWrapper(mux, chan)
    handlers.append(Proxy(SockWrapper(sock, sock), outwrap))
    expire_connections(time.time(), mux)


def udp_done(chan, data, method, sock, dstip):
    (src, srcport, data) = data.split(b",", 2)
    srcip = (src, int(srcport))
    debug3('doing send from %r to %r\n' % (srcip, dstip,))
    method.send_udp(sock, srcip, dstip, data)


def onaccept_udp(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t
    debug1('Accept UDP: %r -> %r.\n' % (srcip, dstip,))
    if srcip in udp_by_src:
        chan, timeout = udp_by_src[srcip]
    else:
        chan = mux.next_channel()
        mux.channels[chan] = lambda cmd, data: udp_done(
            chan, data, method, listener, dstip=srcip)
        mux.send(chan, ssnet.CMD_UDP_OPEN, b"%d" % listener.family)
    udp_by_src[srcip] = chan, now + 30

    hdr = b"%s,%d," % (dstip[0].encode("ASCII"), dstip[1])
    mux.send(chan, ssnet.CMD_UDP_DATA, hdr + data)

    expire_connections(now, mux)


def dns_done(chan, data, method, sock, srcip, dstip, mux):
    debug3('dns_done: channel=%d src=%r dst=%r\n' % (chan, srcip, dstip))
    del mux.channels[chan]
    del dnsreqs[chan]
    method.send_udp(sock, srcip, dstip, data)


def ondns(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t
    debug1('DNS request from %r to %r: %d bytes\n' % (srcip, dstip, len(data)))
    chan = mux.next_channel()
    dnsreqs[chan] = now + 30
    mux.send(chan, ssnet.CMD_DNS_REQ, data)
    mux.channels[chan] = lambda cmd, data: dns_done(
        chan, data, method, listener, srcip=dstip, dstip=srcip, mux=mux)
    expire_connections(now, mux)


def _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
          python, latency_control,
          dns_listener, seed_hosts, auto_hosts, auto_nets, daemon):

    debug1('Starting client with Python version %s\n'
           % platform.python_version())

    method = fw.method

    handlers = []
    if helpers.verbose >= 1:
        helpers.logprefix = 'c : '
    else:
        helpers.logprefix = 'client: '
    debug1('connecting to server...\n')

    try:
        (serverproc, serversock) = ssh.connect(
            ssh_cmd, remotename, python,
            stderr=ssyslog._p and ssyslog._p.stdin,
            options=dict(latency_control=latency_control,
                auto_hosts=auto_hosts))
    except socket.error as e:
        if e.args[0] == errno.EPIPE:
            raise Fatal("failed to establish ssh session (1)")
        else:
            raise
    mux = Mux(serversock, serversock)
    handlers.append(mux)

    expected = b'SSHUTTLE0001'

    try:
        v = 'x'
        while v and v != b'\0':
            v = serversock.recv(1)
        v = 'x'
        while v and v != b'\0':
            v = serversock.recv(1)
        initstring = serversock.recv(len(expected))
    except socket.error as e:
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
    log('Connected.\n')
    sys.stdout.flush()
    if daemon:
        daemonize()
        log('daemonizing (%s).\n' % _pidname)

    def onroutes(routestr):
        if auto_nets:
            for line in routestr.strip().split(b'\n'):
                (family, ip, width) = line.split(b',', 2)
                family = int(family)
                width = int(width)
                ip = ip.decode("ASCII")
                if family == socket.AF_INET6 and tcp_listener.v6 is None:
                    debug2("Ignored auto net %d/%s/%d\n" % (family, ip, width))
                if family == socket.AF_INET and tcp_listener.v4 is None:
                    debug2("Ignored auto net %d/%s/%d\n" % (family, ip, width))
                else:
                    debug2("Adding auto net %d/%s/%d\n" % (family, ip, width))
                    fw.auto_nets.append((family, ip, width, 0, 0))

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
                name, ip = line.split(b',', 1)
                fw.sethostip(name, ip)
    mux.got_host_list = onhostlist

    tcp_listener.add_handler(handlers, onaccept_tcp, method, mux)

    if udp_listener:
        udp_listener.add_handler(handlers, onaccept_udp, method, mux)

    if dns_listener:
        dns_listener.add_handler(handlers, ondns, method, mux)

    if seed_hosts is not None:
        debug1('seed_hosts: %r\n' % seed_hosts)
        mux.send(0, ssnet.CMD_HOST_REQ, str.encode('\n'.join(seed_hosts)))

    sdnotify.send(sdnotify.ready(),
                  sdnotify.status('Connected to %s.' % remotename))

    while 1:
        rv = serverproc.poll()
        if rv:
            raise Fatal('server died with error code %d' % rv)

        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()


def main(listenip_v6, listenip_v4,
         ssh_cmd, remotename, python, latency_control, dns, nslist,
         method_name, seed_hosts, auto_hosts, auto_nets,
         subnets_include, subnets_exclude, daemon, pidfile):

    if daemon:
        try:
            check_daemon(pidfile)
        except Fatal as e:
            log("%s\n" % e)
            return 5
    debug1('Starting sshuttle proxy.\n')

    fw = FirewallClient(method_name)

    # Get family specific subnet lists
    if dns:
        nslist += resolvconf_nameservers()

    subnets = subnets_include + subnets_exclude  # we don't care here
    subnets_v6 = [i for i in subnets if i[0] == socket.AF_INET6]
    nslist_v6 = [i for i in nslist if i[0] == socket.AF_INET6]
    subnets_v4 = [i for i in subnets if i[0] == socket.AF_INET]
    nslist_v4 = [i for i in nslist if i[0] == socket.AF_INET]

    # Check features available
    avail = fw.method.get_supported_features()
    required = Features()

    if listenip_v6 == "auto":
        if avail.ipv6:
            listenip_v6 = ('::1', 0)
        else:
            listenip_v6 = None

    required.ipv6 = len(subnets_v6) > 0 or listenip_v6 is not None
    required.ipv4 = len(subnets_v4) > 0 or listenip_v4 is not None
    required.udp = avail.udp
    required.dns = len(nslist) > 0

    # if IPv6 not supported, ignore IPv6 DNS servers
    if not required.ipv6:
        nslist_v6 = []
        nslist = nslist_v4

    fw.method.assert_features(required)

    if required.ipv6 and listenip_v6 is None:
        raise Fatal("IPv6 required but not listening.")

    # display features enabled
    debug1("IPv6 enabled: %r\n" % required.ipv6)
    debug1("UDP enabled: %r\n" % required.udp)
    debug1("DNS enabled: %r\n" % required.dns)

    # bind to required ports
    if listenip_v4 == "auto":
        listenip_v4 = ('127.0.0.1', 0)

    if required.ipv4 and \
            not any(listenip_v4[0] == sex[1] for sex in subnets_v4):
        subnets_exclude.append((socket.AF_INET, listenip_v4[0], 32, 0, 0))

    if required.ipv6 and \
            not any(listenip_v6[0] == sex[1] for sex in subnets_v6):
        subnets_exclude.append((socket.AF_INET6, listenip_v6[0], 128, 0, 0))

    if listenip_v6 and listenip_v6[1] and listenip_v4 and listenip_v4[1]:
        # if both ports given, no need to search for a spare port
        ports = [0, ]
    else:
        # if at least one port missing, we have to search
        ports = range(12300, 9000, -1)

    # search for free ports and try to bind
    last_e = None
    redirectport_v6 = 0
    redirectport_v4 = 0
    bound = False
    debug2('Binding redirector:')
    for port in ports:
        debug2(' %d' % port)
        tcp_listener = MultiListener()

        if required.udp:
            udp_listener = MultiListener(socket.SOCK_DGRAM)
        else:
            udp_listener = None

        if listenip_v6 and listenip_v6[1]:
            lv6 = listenip_v6
            redirectport_v6 = lv6[1]
        elif listenip_v6:
            lv6 = (listenip_v6[0], port)
            redirectport_v6 = port
        else:
            lv6 = None
            redirectport_v6 = 0

        if listenip_v4 and listenip_v4[1]:
            lv4 = listenip_v4
            redirectport_v4 = lv4[1]
        elif listenip_v4:
            lv4 = (listenip_v4[0], port)
            redirectport_v4 = port
        else:
            lv4 = None
            redirectport_v4 = 0

        try:
            tcp_listener.bind(lv6, lv4)
            if udp_listener:
                udp_listener.bind(lv6, lv4)
            bound = True
            break
        except socket.error as e:
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
    if udp_listener:
        udp_listener.print_listening("UDP redirector")

    bound = False
    if required.dns:
        # search for spare port for DNS
        debug2('Binding DNS:')
        ports = range(12300, 9000, -1)
        for port in ports:
            debug2(' %d' % port)
            dns_listener = MultiListener(socket.SOCK_DGRAM)

            if listenip_v6:
                lv6 = (listenip_v6[0], port)
                dnsport_v6 = port
            else:
                lv6 = None
                dnsport_v6 = 0

            if listenip_v4:
                lv4 = (listenip_v4[0], port)
                dnsport_v4 = port
            else:
                lv4 = None
                dnsport_v4 = 0

            try:
                dns_listener.bind(lv6, lv4)
                bound = True
                break
            except socket.error as e:
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

    # Last minute sanity checks.
    # These should never fail.
    # If these do fail, something is broken above.
    if len(subnets_v6) > 0:
        assert required.ipv6
        if redirectport_v6 == 0:
            raise Fatal("IPv6 subnets defined but not listening")

    if len(nslist_v6) > 0:
        assert required.dns
        assert required.ipv6
        if dnsport_v6 == 0:
            raise Fatal("IPv6 ns servers defined but not listening")

    if len(subnets_v4) > 0:
        if redirectport_v4 == 0:
            raise Fatal("IPv4 subnets defined but not listening")

    if len(nslist_v4) > 0:
        if dnsport_v4 == 0:
            raise Fatal("IPv4 ns servers defined but not listening")

    # setup method specific stuff on listeners
    fw.method.setup_tcp_listener(tcp_listener)
    if udp_listener:
        fw.method.setup_udp_listener(udp_listener)
    if dns_listener:
        fw.method.setup_udp_listener(dns_listener)

    # start the firewall
    fw.setup(subnets_include, subnets_exclude, nslist,
             redirectport_v6, redirectport_v4, dnsport_v6, dnsport_v4,
             required.udp)

    # start the client process
    try:
        return _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
                     python, latency_control, dns_listener,
                     seed_hosts, auto_hosts, auto_nets, daemon)
    finally:
        try:
            if daemon:
                # it's not our child anymore; can't waitpid
                fw.p.returncode = 0
            fw.done()
        finally:
            if daemon:
                daemon_cleanup()
