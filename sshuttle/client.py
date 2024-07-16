import errno
import re
import signal
import time
import subprocess as ssubprocess
import os
import sys
import base64
import platform

import sshuttle.helpers as helpers
import sshuttle.ssnet as ssnet
import sshuttle.ssh as ssh
import sshuttle.ssyslog as ssyslog
import sshuttle.sdnotify as sdnotify
from sshuttle.ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from sshuttle.helpers import log, debug1, debug2, debug3, Fatal, islocal, \
    resolvconf_nameservers, which, is_admin_user, RWPair
from sshuttle.methods import get_method, Features
from sshuttle import __version__
try:
    from pwd import getpwnam
except ImportError:
    getpwnam = None
try:
    from grp import getgrnam
except ImportError:
    getgrnam = None

import socket

_extra_fd = os.open(os.devnull, os.O_RDONLY)


def got_signal(signum, frame):
    log('exiting on signal %d' % signum)
    sys.exit(1)


# Filename of the pidfile created by the sshuttle client.
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
    # Try to open the pidfile prior to forking. If there is a problem,
    # the client can then exit with a proper exit status code and
    # message.
    try:
        outfd = os.open(_pidname, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    except PermissionError:
        # User will have to look in syslog for error message since
        # --daemon implies --syslog, all output gets redirected to
        # syslog.
        raise Fatal("failed to create/write pidfile %s" % _pidname)

    # Create a daemon process with a new session id.
    if os.fork():
        os._exit(0)
    os.setsid()
    if os.fork():
        os._exit(0)

    # Write pid to the pidfile.
    try:
        os.write(outfd, b'%d\n' % os.getpid())
    finally:
        os.close(outfd)
    os.chdir("/")

    # Normal exit when killed, or try/finally won't work and the pidfile won't
    # be deleted.
    signal.signal(signal.SIGTERM, got_signal)

    si = open(os.devnull, 'r+')
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

    def __init__(self, kind=socket.SOCK_STREAM, proto=0):
        self.type = kind
        self.proto = proto
        self.v6 = None
        self.v4 = None
        self.bind_called = False

    def setsockopt(self, level, optname, value):
        assert self.bind_called
        if self.v6:
            self.v6.setsockopt(level, optname, value)
        if self.v4:
            self.v4.setsockopt(level, optname, value)

    def add_handler(self, handlers, callback, method, mux):
        assert self.bind_called
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
        assert self.bind_called
        if self.v6:
            self.v6.listen(backlog)
        if self.v4:
            try:
                self.v4.listen(backlog)
            except socket.error as e:
                # on some systems v4 bind will fail if the v6 succeeded,
                # in this case the v6 socket will receive v4 too.
                if e.errno == errno.EADDRINUSE and self.v6:
                    self.v4 = None
                else:
                    raise e

    def bind(self, address_v6, address_v4):
        assert not self.bind_called
        self.bind_called = True
        if address_v6 is not None:
            self.v6 = socket.socket(socket.AF_INET6, self.type, self.proto)
            try:
                self.v6.bind(address_v6)
            except OSError as e:
                if e.errno == errno.EADDRNOTAVAIL:
                    # On an IPv6 Linux machine, this situation occurs
                    # if you run the following prior to running
                    # sshuttle:
                    #
                    # echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
                    # echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
                    raise Fatal("Could not bind to an IPv6 socket with "
                                "address %s and port %s. "
                                "Potential workaround: Run sshuttle "
                                "with '--disable-ipv6'."
                                % (str(address_v6[0]), str(address_v6[1])))
                raise e
        else:
            self.v6 = None
        if address_v4 is not None:
            self.v4 = socket.socket(socket.AF_INET, self.type, self.proto)
            self.v4.bind(address_v4)
        else:
            self.v4 = None

    def print_listening(self, what):
        assert self.bind_called
        if self.v6:
            listenip = self.v6.getsockname()
            debug1('%s listening on %r.' % (what, listenip))
            debug2('%s listening with %r.' % (what, self.v6))
        if self.v4:
            listenip = self.v4.getsockname()
            debug1('%s listening on %r.' % (what, listenip))
            debug2('%s listening with %r.' % (what, self.v4))


class FirewallClient:

    def __init__(self, method_name, sudo_pythonpath):
        self.auto_nets = []

        argv0 = sys.argv[0]
        # argv0 is either be a normal Python file or an executable.
        # After installed as a package, sshuttle command points to an .exe in Windows and Python shebang script elsewhere.
        argvbase = (([sys.executable, sys.argv[0]] if argv0.endswith('.py') else [argv0]) +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--method', method_name] +
                    ['--firewall'])
        if ssyslog._p:
            argvbase += ['--syslog']

        # A list of commands that we can try to run to start the firewall.
        argv_tries = []

        if is_admin_user():  # No need to elevate privileges
            argv_tries.append(argvbase)
        else:
            if sys.platform == 'win32':
                # runas_path = which("runas")
                # if runas_path:
                #   argv_tries.append([runas_path , '/noprofile', '/user:Administrator',  'python'])
                # XXX: Attempt to elevate privilege using 'runas' in windows seems not working.
                # Because underlying ShellExecute() Windows api does not allow child process to inherit stdio.
                # TODO(nom3ad): Try to implement another way to achieve this.
                raise Fatal("Privilege elevation for Windows is not yet implemented. Please run from an administrator shell")

            # Linux typically uses sudo; OpenBSD uses doas. However, some
            # Linux distributions are starting to use doas.
            sudo_cmd = ['sudo', '-p', '[local sudo] Password: ']
            doas_cmd = ['doas']

            # For clarity, try to replace executable name with the
            # full path.
            doas_path = which("doas")
            if doas_path:
                doas_cmd[0] = doas_path
            sudo_path = which("sudo")
            if sudo_path:
                sudo_cmd[0] = sudo_path

            # sudo_pythonpath indicates if we should set the
            # PYTHONPATH environment variable when elevating
            # privileges. This can be adjusted with the
            # --no-sudo-pythonpath option.
            if sudo_pythonpath:
                pp_prefix = ['/usr/bin/env',
                             'PYTHONPATH=%s' %
                             os.path.dirname(os.path.dirname(__file__))]
                sudo_cmd = sudo_cmd + pp_prefix
                doas_cmd = doas_cmd + pp_prefix

            # Final order should be: sudo/doas command, env
            # pythonpath, and then argvbase (sshuttle command).
            sudo_cmd = sudo_cmd + argvbase
            doas_cmd = doas_cmd + argvbase

            # If we can find doas and not sudo or if we are on
            # OpenBSD, try using doas first.
            if (doas_path and not sudo_path) or platform.platform().startswith('OpenBSD'):
                argv_tries = [doas_cmd, sudo_cmd, argvbase]
            else:
                argv_tries = [sudo_cmd, doas_cmd, argvbase]

        # Try all commands in argv_tries in order. If a command
        # produces an error, try the next one. If command is
        # successful, set 'success' variable and break.
        success = False
        for argv in argv_tries:

            if sys.platform != 'win32':
                # we can't use stdin/stdout=subprocess.PIPE here, as we
                # normally would, because stupid Linux 'su' requires that
                # stdin be attached to a tty. Instead, attach a
                # *bidirectional* socket to its stdout, and use that for
                # talking in both directions.
                (s1, s2) = socket.socketpair()
                pstdout = s1
                pstdin = s1
                penv = None

                def preexec_fn():
                    # run in the child process
                    s2.close()

                def get_pfile():
                    s1.close()
                    return s2.makefile('rwb')

            else:
                # In Windows CPython, BSD sockets are not supported as subprocess stdio.
                # if client (and firewall) processes is running as admin user, pipe based stdio can be used for communication.
                # But if firewall process is spwaned in elevated mode by non-admin client process, access to stdio is lost.
                # To work around this, we can use a socketpair.
                # But socket need to be "shared" to child process as it can't be directly set as stdio.
                can_use_stdio = is_admin_user()

                preexec_fn = None
                penv = os.environ.copy()
                if can_use_stdio:
                    pstdout = ssubprocess.PIPE
                    pstdin = ssubprocess.PIPE

                    def get_pfile():
                        return RWPair(self.p.stdout, self.p.stdin)
                    penv['SSHUTTLE_FW_COM_CHANNEL'] = 'stdio'
                else:
                    pstdout = None
                    pstdin = None
                    (s1, s2) = socket.socketpair()
                    socket_share_data = s1.share(self.p.pid)
                    socket_share_data_b64 = base64.b64encode(socket_share_data)
                    penv['SSHUTTLE_FW_COM_CHANNEL'] = socket_share_data_b64

                    def get_pfile():
                        s1.close()
                        return s2.makefile('rwb')
            try:
                debug1("Starting firewall manager with command: %r" % argv)
                self.p = ssubprocess.Popen(argv, stdout=pstdout, stdin=pstdin, env=penv,
                                           preexec_fn=preexec_fn)
                # No env: Talking to `FirewallClient.start`, which has no i18n.
            except OSError as e:
                # This exception will occur if the program isn't
                # present or isn't executable.
                debug1('Unable to start firewall manager. Popen failed. '
                       'Command=%r Exception=%s' % (argv, e))
                continue
            self.argv = argv
            self.pfile = get_pfile()

            try:
                line = self.pfile.readline()
            except IOError:
                # happens when firewall subprocess exists
                line = ''

            rv = self.p.poll()   # Check if process is still running
            if rv:
                # We might get here if program runs and exits before
                # outputting anything. For example, someone might have
                # entered the wrong password to elevate privileges.
                debug1('Unable to start firewall manager. '
                       'Process exited too early. '
                       '%r returned %d' % (self.argv, rv))
                continue

            # Normally, READY will be the first text on the first
            # line. However, if an administrator replaced sudo with a
            # shell script that echos a message to stdout and then
            # runs sudo, READY won't be on the first line. To
            # workaround this problem, we read a limited number of
            # lines until we encounter "READY". Store all of the text
            # we skipped in case we need it for an error message.
            #
            # A proper way to print a sudo warning message is to use
            # sudo's lecture feature. sshuttle works correctly without
            # this hack if sudo's lecture feature is used instead.
            skipped_text = line
            for i in range(100):
                if line[0:5] == b'READY':
                    break
                line = self.pfile.readline()
                skipped_text += line

            if line[0:5] != b'READY':
                debug1('Unable to start firewall manager. '
                       'Expected READY, got %r. '
                       'Command=%r' % (skipped_text, self.argv))
                continue

            method_name = line[6:-1]
            self.method = get_method(method_name.decode("ASCII"))
            self.method.set_firewall(self)
            success = True
            break

        if not success:
            raise Fatal("All attempts to run firewall client process with elevated privileges were failed.")

    def setup(self, subnets_include, subnets_exclude, nslist,
              redirectport_v6, redirectport_v4, dnsport_v6, dnsport_v4, udp,
              user, group, tmark):
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        self.nslist = nslist
        self.redirectport_v6 = redirectport_v6
        self.redirectport_v4 = redirectport_v4
        self.dnsport_v6 = dnsport_v6
        self.dnsport_v4 = dnsport_v4
        self.udp = udp
        self.user = user
        self.group = group
        self.tmark = tmark

    def check(self):
        rv = self.p.poll()
        if rv:
            raise Fatal('%r returned %d' % (self.argv, rv))

    def start(self):
        self.pfile.write(b'ROUTES\n')
        for (family, ip, width, fport, lport) \
                in self.subnets_include + self.auto_nets:
            self.pfile.write(b'%d,%d,0,%s,%d,%d\n' % (family, width,
                                                      ip.encode("ASCII"),
                                                      fport, lport))
        for (family, ip, width, fport, lport) in self.subnets_exclude:
            self.pfile.write(b'%d,%d,1,%s,%d,%d\n' % (family, width,
                                                      ip.encode("ASCII"),
                                                      fport, lport))

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
        if self.user is None:
            user = b'-'
        elif isinstance(self.user, str):
            user = bytes(self.user, 'utf-8')
        else:
            user = b'%d' % self.user
        if self.group is None:
            group = b'-'
        elif isinstance(self.group, str):
            group = bytes(self.group, 'utf-8')
        else:
            group = b'%d' % self.group
        self.pfile.write(b'GO %d %s %s %s %d\n' %
                         (udp, user, group, bytes(self.tmark, 'ascii'), os.getpid()))
        self.pfile.flush()

        line = self.pfile.readline()
        self.check()
        if line != b'STARTED\n':
            raise Fatal('%r expected STARTED, got %r' % (self.argv, line))

    def sethostip(self, hostname, ip):
        assert not re.search(br'[^-\w\.]', hostname)
        assert not re.search(br'[^0-9.]', ip)
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
            debug3('expiring dnsreqs channel=%d' % chan)
            remove.append(chan)
            del mux.channels[chan]
    for chan in remove:
        del dnsreqs[chan]
    debug3('Remaining DNS requests: %d' % len(dnsreqs))

    remove = []
    for peer, (chan, timeout) in udp_by_src.items():
        if timeout < now:
            debug3('expiring UDP channel channel=%d peer=%r' % (chan, peer))
            mux.send(chan, ssnet.CMD_UDP_CLOSE, b'')
            remove.append(peer)
            del mux.channels[chan]
    for peer in remove:
        del udp_by_src[peer]
    debug3('Remaining UDP channels: %d' % len(udp_by_src))


def onaccept_tcp(listener, method, mux, handlers):
    global _extra_fd
    try:
        sock, srcip = listener.accept()
    except socket.error as e:
        if e.args[0] in [errno.EMFILE, errno.ENFILE]:
            debug1('Rejected incoming connection: too many open files!')
            # free up an fd so we can eat the connection
            os.close(_extra_fd)
            try:
                sock, srcip = listener.accept()
                sock.close()
            finally:
                _extra_fd = os.open(os.devnull, os.O_RDONLY)
            return
        else:
            raise

    dstip = method.get_tcp_dstip(sock)
    debug1('Accept TCP: %s:%r -> %s:%r.' % (srcip[0], srcip[1],
                                            dstip[0], dstip[1]))
    if dstip[1] == sock.getsockname()[1] and islocal(dstip[0], sock.family):
        debug1("-- ignored: that's my address!")
        sock.close()
        return
    chan = mux.next_channel()
    if not chan:
        log('warning: too many open channels.  Discarded connection.')
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
    debug3('doing send from %r to %r' % (srcip, dstip,))
    method.send_udp(sock, srcip, dstip, data)


def onaccept_udp(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t
    debug1('Accept UDP: %r -> %r.' % (srcip, dstip,))
    if srcip in udp_by_src:
        chan, _ = udp_by_src[srcip]
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
    debug3('dns_done: channel=%d src=%r dst=%r' % (chan, srcip, dstip))
    del mux.channels[chan]
    del dnsreqs[chan]
    method.send_udp(sock, srcip, dstip, data)


def ondns(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t
    # dstip is None if we are using a method where we can't determine
    # the destination IP of the DNS request that we captured from the client.
    if dstip is None:
        debug1('DNS request from %r: %d bytes' % (srcip, len(data)))
    else:
        debug1('DNS request from %r to %r: %d bytes' %
               (srcip, dstip, len(data)))
    chan = mux.next_channel()
    dnsreqs[chan] = now + 30
    mux.send(chan, ssnet.CMD_DNS_REQ, data)
    mux.channels[chan] = lambda cmd, data: dns_done(
        chan, data, method, listener, srcip=dstip, dstip=srcip, mux=mux)
    expire_connections(now, mux)


def _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
          python, latency_control, latency_buffer_size,
          dns_listener, seed_hosts, auto_hosts, auto_nets, daemon,
          to_nameserver, add_cmd_delimiter, remote_shell):

    helpers.logprefix = 'c : '
    debug1('Starting client with Python version %s'
           % platform.python_version())

    method = fw.method

    handlers = []
    debug1('Connecting to server...')

    try:
        (serverproc, rfile, wfile) = ssh.connect(
            ssh_cmd, remotename, python,
            stderr=ssyslog._p and ssyslog._p.stdin,
            add_cmd_delimiter=add_cmd_delimiter,
            remote_shell=remote_shell,
            options=dict(latency_control=latency_control,
                         latency_buffer_size=latency_buffer_size,
                         auto_hosts=auto_hosts,
                         to_nameserver=to_nameserver,
                         auto_nets=auto_nets))
    except socket.error as e:
        if e.args[0] == errno.EPIPE:
            debug3('Error: EPIPE: ' + repr(e))
            raise Fatal("failed to establish ssh session (1)")
        else:
            raise
    mux = Mux(rfile, wfile)
    handlers.append(mux)

    expected = b'SSHUTTLE0001'
    try:
        v = 'x'
        while v and v != b'\0':
            v = rfile.read(1)
        v = 'x'
        while v and v != b'\0':
            v = rfile.read(1)
        initstring = rfile.read(len(expected))
    except socket.error as e:
        if e.args[0] == errno.ECONNRESET:
            debug3('Error: ECONNRESET ' + repr(e))
            raise Fatal("failed to establish ssh session (2)")
        else:
            raise

    # Returns None if process is still running (or returns exit code)
    rv = serverproc.poll()
    if rv is not None:
        errmsg = "server died with error code %d\n" % rv

        # Our fatal exceptions return exit code 99
        if rv == 99:
            errmsg += "This error code likely means that python started and " \
                "the sshuttle server started. However, the sshuttle server " \
                "may have raised a 'Fatal' exception after it started."
        elif rv == 98:
            errmsg += "This error code likely means that we were able to " \
                "run python on the server, but that the program continued " \
                "to the line after we call python's exec() to execute " \
                "sshuttle's server code. Try specifying the python " \
                "executable to user on the server by passing --python " \
                "to sshuttle."

        # This error should only be possible when --python is not specified.
        elif rv == 97 and not python:
            errmsg += "This error code likely means that either we " \
                "couldn't find python3 or python in the PATH on the " \
                "server or that we do not have permission to run 'exec' in " \
                "the /bin/sh shell on the server. Try specifying the " \
                "python executable to use on the server by passing " \
                "--python to sshuttle."

        # POSIX sh standards says error code 127 is used when you try
        # to execute a program that does not exist. See section 2.8.2
        # of
        # https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_08
        elif rv == 127:
            if python:
                errmsg += "This error code likely means that we were not " \
                    "able to execute the python executable that specified " \
                    "with --python. You specified '%s'.\n" % python
                if python.startswith("/"):
                    errmsg += "\nTip for users in a restricted shell on the " \
                        "server: The server may refuse to run programs " \
                        "specified with an absolute path. Try specifying " \
                        "just the name of the python executable. However, " \
                        "if python is not in your PATH and you cannot " \
                        "run programs specified with an absolute path, " \
                        "it is possible that sshuttle will not work."
            else:
                errmsg += "This error code likely means that we were unable " \
                    "to execute /bin/sh on the remote server. This can " \
                    "happen if /bin/sh does not exist on the server or if " \
                    "you are in a restricted shell that does not allow you " \
                    "to run programs specified with an absolute path. " \
                    "Try rerunning sshuttle with the --python parameter."

        # When the redirected subnet includes the remote ssh host, the
        # firewall rules can interrupt the ssh connection to the
        # remote machine. This issue impacts some Linux machines. The
        # user sees that the server dies with a broken pipe error and
        # code 255.
        #
        # The solution to this problem is to exclude the remote
        # server.
        #
        # There are many github issues from users encountering this
        # problem. Most of the discussion on the topic is here:
        # https://github.com/sshuttle/sshuttle/issues/191
        elif rv == 255:
            errmsg += "It might be possible to resolve this error by " \
                "excluding the server that you are ssh'ing to. For example, " \
                "if you are running 'sshuttle -v -r example.com 0/0' to " \
                "redirect all traffic through example.com, then try " \
                "'sshuttle -v -r example.com -x example.com 0/0' to " \
                "exclude redirecting the connection to example.com itself " \
                "(i.e., sshuttle's firewall rules may be breaking the " \
                "ssh connection that it previously established). " \
                "Alternatively, you may be able to use 'sshuttle -v -r " \
                "example.com -x example.com:22 0/0' to redirect " \
                "everything except ssh connections between your machine " \
                "and example.com."

        raise Fatal(errmsg)

    if initstring != expected:
        raise Fatal('expected server init string %r; got %r'
                    % (expected, initstring))
    log('Connected to server.')
    sys.stdout.flush()

    if daemon:
        daemonize()
        log('daemonizing (%s).' % _pidname)

    def onroutes(routestr):
        if auto_nets:
            for line in routestr.strip().split(b'\n'):
                if not line:
                    continue
                (family, ip, width) = line.split(b',', 2)
                family = int(family)
                width = int(width)
                ip = ip.decode("ASCII")
                if family == socket.AF_INET6 and tcp_listener.v6 is None:
                    debug2("Ignored auto net %d/%s/%d" % (family, ip, width))
                if family == socket.AF_INET and tcp_listener.v4 is None:
                    debug2("Ignored auto net %d/%s/%d" % (family, ip, width))
                else:
                    debug2("Adding auto net %d/%s/%d" % (family, ip, width))
                    fw.auto_nets.append((family, ip, width, 0, 0))

        # we definitely want to do this *after* starting ssh, or we might end
        # up intercepting the ssh connection!
        #
        # Moreover, now that we have the --auto-nets option, we have to wait
        # for the server to send us that message anyway.  Even if we haven't
        # set --auto-nets, we might as well wait for the message first, then
        # ignore its contents.
        mux.got_routes = None
        serverready()

    mux.got_routes = onroutes

    def serverready():
        fw.start()
        sdnotify.send(sdnotify.ready(), sdnotify.status('Connected'))

    def onhostlist(hostlist):
        debug2('got host list: %r' % hostlist)
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
        debug1('seed_hosts: %r' % seed_hosts)
        mux.send(0, ssnet.CMD_HOST_REQ, str.encode('\n'.join(seed_hosts)))

    def check_ssh_alive():
        if daemon:
            # poll() won't tell us when process exited since the
            # process is no longer our child (it returns 0 all the
            # time).
            try:
                os.kill(serverproc.pid, 0)
            except OSError:
                raise Fatal('ssh connection to server (pid %d) exited.' %
                            serverproc.pid)
        else:
            rv = serverproc.poll()
            # poll returns None if process hasn't exited.
            if rv is not None:
                raise Fatal('ssh connection to server (pid %d) exited '
                            'with returncode %d' % (serverproc.pid, rv))

    while 1:
        check_ssh_alive()
        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()


def main(listenip_v6, listenip_v4,
         ssh_cmd, remotename, python, latency_control,
         latency_buffer_size, dns, nslist,
         method_name, seed_hosts, auto_hosts, auto_nets,
         subnets_include, subnets_exclude, daemon, to_nameserver, pidfile,
         user, group, sudo_pythonpath, add_cmd_delimiter, remote_shell, tmark):

    if not remotename:
        raise Fatal("You must use -r/--remote to specify a remote "
                    "host to route traffic through.")

    if daemon:
        try:
            check_daemon(pidfile)
        except Fatal as e:
            log("%s" % e)
            return 5
    debug1('Starting sshuttle proxy (version %s).' % __version__)
    helpers.logprefix = 'c : '

    fw = FirewallClient(method_name, sudo_pythonpath)

    # nslist is the list of name severs to intercept. If --dns is
    # used, we add all DNS servers in resolv.conf. Otherwise, the list
    # can be populated with the --ns-hosts option (which is already
    # stored in nslist). This list is used to setup the firewall so it
    # can redirect packets outgoing to this server to the remote host
    # instead.
    if dns:
        nslist += resolvconf_nameservers(True)

    # If we are intercepting DNS requests, we tell the remote host
    # where it should send the DNS requests to with the --to-ns
    # option.
    if len(nslist) > 0:
        if to_nameserver is not None:
            to_nameserver = "%s@%s" % tuple(to_nameserver[1:])
    else:  # if we are not intercepting DNS traffic
        # ...and the user specified a server to send DNS traffic to.
        if to_nameserver and len(to_nameserver) > 0:
            print("WARNING: --to-ns option is ignored unless "
                  "--dns or --ns-hosts is used.")
        to_nameserver = None

    # Get family specific subnet lists. Also, the user may not specify
    # any subnets if they use --auto-nets. In this case, our subnets
    # list will be empty and the forwarded subnets will be determined
    # later by the server.
    subnets_v4 = [i for i in subnets_include if i[0] == socket.AF_INET]
    subnets_v6 = [i for i in subnets_include if i[0] == socket.AF_INET6]
    nslist_v4 = [i for i in nslist if i[0] == socket.AF_INET]
    nslist_v6 = [i for i in nslist if i[0] == socket.AF_INET6]

    # Get available features from the firewall method
    avail = fw.method.get_supported_features()

    # A feature is "required" if the user supplies us parameters which
    # implies that the feature is needed.
    required = Features()

    # Select the default addresses to bind to / listen to.

    # Assume IPv4 is always available and should always be enabled. If
    # a method doesn't provide IPv4 support or if we wish to run
    # ipv6-only, changes to this code are required.
    assert avail.ipv4
    required.ipv4 = True

    # listenip_v4 contains user specified value or it is set to "auto".
    if listenip_v4 == "auto":
        listenip_v4 = ('127.0.0.1' if avail.loopback_proxy_port else '0.0.0.0', 0)
        debug1("Using default IPv4 listen address " + listenip_v4[0])

    # listenip_v6 is...
    #    None when IPv6 is disabled.
    #    "auto" when listen address is unspecified.
    #    The user specified address if provided by user
    if listenip_v6 is None:
        debug1("IPv6 disabled by --disable-ipv6")
    if listenip_v6 == "auto":
        if avail.ipv6:
            listenip_v6 = ('::1' if avail.loopback_proxy_port else '::', 0)
            debug1("IPv6 enabled: Using default IPv6 listen address " + listenip_v6[0])
        else:
            debug1("IPv6 disabled since it isn't supported by method "
                   "%s." % fw.method.name)
            listenip_v6 = None

    # Make final decision about enabling IPv6:
    required.ipv6 = False
    if listenip_v6:
        required.ipv6 = True

    # If we get here, it is possible that listenip_v6 was user
    # specified but not supported by the current method.
    if required.ipv6 and not avail.ipv6:
        raise Fatal("An IPv6 listen address was supplied, but IPv6 is "
                    "disabled at your request or is unsupported by the %s "
                    "method." % fw.method.name)

    if user is not None:
        if getpwnam is None:
            raise Fatal("Routing by user not available on this system.")
        try:
            user = getpwnam(user).pw_uid
        except KeyError:
            raise Fatal("User %s does not exist." % user)
    required.user = False if user is None else True

    if group is not None:
        if getgrnam is None:
            raise Fatal("Routing by group not available on this system.")
        try:
            group = getgrnam(group).gr_gid
        except KeyError:
            raise Fatal("Group %s does not exist." % user)
    required.group = False if group is None else True

    if not required.ipv6 and len(subnets_v6) > 0:
        print("WARNING: IPv6 subnets were ignored because IPv6 is disabled "
              "in sshuttle.")
        subnets_v6 = []
        subnets_include = subnets_v4

    required.udp = avail.udp  # automatically enable UDP if it is available
    required.dns = len(nslist) > 0

    # Remove DNS servers using IPv6.
    if required.dns:
        if not required.ipv6 and len(nslist_v6) > 0:
            print("WARNING: Your system is configured to use an IPv6 DNS "
                  "server but sshuttle is not using IPv6. Therefore DNS "
                  "traffic your system sends to the IPv6 DNS server won't "
                  "be redirected via sshuttle to the remote machine.")
            nslist_v6 = []
            nslist = nslist_v4

        if len(nslist) == 0:
            raise Fatal("Can't redirect DNS traffic since IPv6 is not "
                        "enabled in sshuttle and all of the system DNS "
                        "servers are IPv6.")

    # If we aren't using IPv6, we can safely ignore excluded IPv6 subnets.
    if not required.ipv6:
        orig_len = len(subnets_exclude)
        subnets_exclude = [i for i in subnets_exclude
                           if i[0] == socket.AF_INET]
        if len(subnets_exclude) < orig_len:
            print("WARNING: Ignoring one or more excluded IPv6 subnets "
                  "because IPv6 is not enabled.")

    # This will print error messages if we required a feature that
    # isn't available by the current method.
    fw.method.assert_features(required)

    # display features enabled
    def feature_status(label, enabled, available):
        msg = label + ": "
        if enabled:
            msg += "on"
        else:
            msg += "off "
            if available:
                msg += "(available)"
            else:
                msg += "(not available with %s method)" % fw.method.name
        debug1(msg)

    debug1("Method: %s" % fw.method.name)
    feature_status("IPv4", required.ipv4, avail.ipv4)
    feature_status("IPv6", required.ipv6, avail.ipv6)
    feature_status("UDP ", required.udp, avail.udp)
    feature_status("DNS ", required.dns, avail.dns)
    feature_status("User", required.user, avail.user)

    # Exclude traffic destined to our listen addresses.
    if required.ipv4 and \
            not any(listenip_v4[0] == sex[1] for sex in subnets_v4):
        subnets_exclude.append((socket.AF_INET, listenip_v4[0], 32, 0, 0))

    if required.ipv6 and \
            not any(listenip_v6[0] == sex[1] for sex in subnets_v6):
        subnets_exclude.append((socket.AF_INET6, listenip_v6[0], 128, 0, 0))

    # We don't print the IP+port of where we are listening here
    # because we do that below when we have identified the ports to
    # listen on.
    debug1("Subnets to forward through remote host (type, IP, cidr mask "
           "width, startPort, endPort):")
    for i in subnets_include:
        debug1("  "+str(i))
    if auto_nets:
        debug1("NOTE: Additional subnets to forward may be added below by "
               "--auto-nets.")
    debug1("Subnets to exclude from forwarding:")
    for i in subnets_exclude:
        debug1("  "+str(i))
    if required.dns:
        debug1("DNS requests normally directed at these servers will be "
               "redirected to remote:")
        for i in nslist:
            debug1("  "+str(i))

    if listenip_v6 and listenip_v6[1] and listenip_v4 and listenip_v4[1]:
        # if both ports given, no need to search for a spare port
        ports = [0, ]
    else:
        # if at least one port missing, we have to search
        ports = range(12300, 9000, -1)
        # keep track of failed bindings and used ports to avoid trying to
        # bind to the same socket address twice in different listeners
        used_ports = []

    # search for free ports and try to bind
    last_e = None
    redirectport_v6 = 0
    redirectport_v4 = 0
    bound = False
    for port in ports:
        debug2('Trying to bind redirector on port %d' % port)
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
            used_ports.append(port)
            break
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                last_e = e
                used_ports.append(port)
            else:
                raise e

    if not bound:
        assert last_e
        raise last_e
    tcp_listener.listen(10)
    tcp_listener.print_listening("TCP redirector")
    if udp_listener:
        udp_listener.print_listening("UDP redirector")

    bound = False
    if required.dns:
        # search for spare port for DNS
        ports = range(12300, 9000, -1)
        for port in ports:
            debug2('Trying to bind DNS redirector on port %d' % port)
            if port in used_ports:
                continue

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
                used_ports.append(port)
                break
            except socket.error as e:
                if e.errno == errno.EADDRINUSE:
                    last_e = e
                    used_ports.append(port)
                else:
                    raise e

        dns_listener.print_listening("DNS")
        if not bound:
            assert last_e
            raise last_e
    else:
        dnsport_v6 = 0
        dnsport_v4 = 0
        dns_listener = None

    # Last minute sanity checks.
    # These should never fail.
    # If these do fail, something is broken above.
    if subnets_v6:
        assert required.ipv6
        if redirectport_v6 == 0:
            raise Fatal("IPv6 subnets defined but not listening")

    if nslist_v6:
        assert required.dns
        assert required.ipv6
        if dnsport_v6 == 0:
            raise Fatal("IPv6 ns servers defined but not listening")

    if subnets_v4:
        if redirectport_v4 == 0:
            raise Fatal("IPv4 subnets defined but not listening")

    if nslist_v4:
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
             required.udp, user, group, tmark)

    # start the client process
    try:
        return _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
                     python, latency_control, latency_buffer_size,
                     dns_listener, seed_hosts, auto_hosts, auto_nets,
                     daemon, to_nameserver, add_cmd_delimiter, remote_shell)
    finally:
        try:
            if daemon:
                # it's not our child anymore; can't waitpid
                fw.p.returncode = 0
            fw.done()
            sdnotify.send(sdnotify.stop())

        finally:
            if daemon:
                daemon_cleanup()
