import errno
import re
import signal
import subprocess as ssubprocess
import sshuttle.helpers as helpers
import os
import sshuttle.ssnet as ssnet
import sshuttle.ssh as ssh
import sshuttle.ssyslog as ssyslog
import sys
import platform
import json
from dnslib import *
from sshuttle.ssnet import SockWrapper, Handler, Proxy, Mux, MuxWrapper
from sshuttle.helpers import log, debug1, debug2, debug3, Fatal, islocal, \
    resolvconf_nameservers
from sshuttle.methods import get_method, Features
import ipaddress
import threading
import redis
import time
try:
    from pwd import getpwnam
except ImportError:
    getpwnam = None

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

ALWAYS_CONNECTED_ON = "ON"
ALWAYS_CONNECTED_OFF = "OFF"

_pidname = None
_allowed_tcp_targets = {}
_allowed_udp_targets = {}
_allowed_sources = {}
_excluded_sources = {}
_acl_always_connected = {}
_allowed_targets_modified = False
_sources_modified = False
_always_connected = ALWAYS_CONNECTED_OFF

ALLOWED_TCP_ACL_TYPE = 1
DISALLOWED_ACL_TYPE = 2
ACL_SOURCES_TYPE = 3
ACL_EXCLUDED_SOURCES_TYPE = 4
ALLOWED_UDP_ACL_TYPE = 5
ALWAYS_CONNECTED_TYPE = 6
ACL_ALWAYS_CONNECTED_TYPE = 7

sshuttleAclTcp = "sshuttleAcl"
sshuttleAclUdp = "sshuttleAclUdp"
sshuttleAclSources = "sshuttleAclSources"
sshuttleAclExcluded = "sshuttleAclExcluded"
alwaysConnected = "alwaysConnected"
aclAlwaysConnected = "aclAlwaysConnected"
sshuttleAclEventsChannel = "aclEvents"

preferreddns = ''
notpreferreddns = ''

try:
    DNS_PROXY_SUFFIX1 = os.environ['DNS_PROXY_SUFFIX']
    DNS_PROXY_SUFFIX2 = DNS_PROXY_SUFFIX1 + '.'
    DNS_1 = os.environ['DNS_1']
    DNS_2 = os.environ['DNS_2']

    preferreddns = DNS_1
    notpreferreddns = DNS_2

except KeyError:
    log('Error: Could not read environment variables for DNS_PROXY_SUFFIX or DNS_1 or DNS_2\n')
    DNS_PROXY_SUFFIX1 = ''
    DNS_PROXY_SUFFIX2 = ''
    DNS_1 = ''
    DNS_2 = ''

REDIS_HOST = None
REDIS_PORT = None
try:
    REDIS_HOST = os.environ['REDIS_HOST']
    REDIS_PORT = os.environ['REDIS_PORT']
except KeyError:
    log('Error: Could not read environment variables for REDIS_HOST and/or REDIS_PORT\n')

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

    def __init__(self, kind=socket.SOCK_STREAM, proto=0):
        self.type = kind
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
            self.v6.bind(address_v6)
        else:
            self.v6 = None
        if address_v4 is not None:
            self.v4 = socket.socket(socket.AF_INET, self.type, self.proto)
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

        # Default to sudo unless on OpenBSD in which case use built in `doas`
        elevbin = 'sudo'
        if platform.platform().startswith('OpenBSD'):
            elevbin = 'doas'

        self.auto_nets = []
        python_path = os.path.dirname(os.path.dirname(__file__))
        argvbase = ([sys.executable, sys.argv[0]] +
                    ['-v'] * (helpers.verbose or 0) +
                    ['--method', method_name] +
                    ['--firewall'])
        if ssyslog._p:
            argvbase += ['--syslog']
        elev_prefix = [part % {'eb': elevbin, 'pp': python_path}
                       for part in ['%(eb)s', '-p',
                                    '[local %(eb)s] Password: ',
                                    '/usr/bin/env', 'PYTHONPATH=%(pp)s']]
        argv_tries = [elev_prefix + argvbase, argvbase]

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
              redirectport_v6, redirectport_v4, dnsport_v6, dnsport_v4, udp,
              user):
        self.subnets_include = subnets_include
        self.subnets_exclude = subnets_exclude
        self.nslist = nslist
        self.redirectport_v6 = redirectport_v6
        self.redirectport_v4 = redirectport_v4
        self.dnsport_v6 = dnsport_v6
        self.dnsport_v4 = dnsport_v4
        self.udp = udp
        self.user = user

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
        if self.user is None:
            user = b'-'
        elif isinstance(self.user, str):
            user = bytes(self.user, 'utf-8')
        else:
            user = b'%d' % self.user

        self.pfile.write(b'GO %d %s\n' % (udp, user))
        self.pfile.flush()

        line = self.pfile.readline()
        self.check()
        if line != b'STARTED\n':
            raise Fatal('%r expected STARTED, got %r' % (self.argv, line))

    def sethostip(self, hostname, ip):
        assert(not re.search(b'[^-\w\.]', hostname))
        assert(not re.search(b'[^0-9.]', ip))
        self.pfile.write(b'HOST %s,%s\n' % (hostname, ip))
        self.pfile.flush()

    def done(self):
        self.pfile.close()
        rv = self.p.wait()
        if rv:
            raise Fatal('cleanup: %r returned %d' % (self.argv, rv))


dnsreqs = {}
dnsreqs2 = {}
udp_by_src = {}
tcp_conns = []
active_tcp_conns = {}

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

def check_connections_allowed(mux):
    # we also want to close all TCP connections from sources that have expired their lease
    if not _allowed_targets_modified and not _sources_modified:
       return

    global tcp_conns
    new_tcp_conns = []
    for (srcip, dstip, s, sock) in tcp_conns:
        if tcp_connection_is_allowed_conditional(dstip[0], str(dstip[1]), srcip[0], _allowed_targets_modified, _sources_modified) and s.ok:
            new_tcp_conns.append((srcip, dstip, s, sock))
        else:
            try:
                # remove from list of active tcp connections
                del active_tcp_conns[sock]

                # really make sure we kill everything while we can
                s.ok = False
                s.wrap1.noread()
                s.wrap1.nowrite()
                s.wrap2.noread()
                s.wrap2.nowrite()
                del mux.channels[s.wrap2.channel]
                sock.close()
                sock.shutdown(2)
            except:
                # we may hit an exception if the socket has already been closed...that is ok
                pass

    tcp_conns = new_tcp_conns
    global _allowed_targets_modified
    global _sources_modified
    _allowed_targets_modified = False
    _sources_modified = False


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

    if not tcp_connection_is_allowed(dstip[0], str(dstip[1]), srcip[0]):
        debug1('Deny TCP: %s:%r -> %s:%r.\n' % (srcip[0], srcip[1],
                                                dstip[0], dstip[1]))
        sock.close()
        return

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
    s = Proxy(SockWrapper(sock, sock, None, None, lambda: connection_is_active(sock)), outwrap)
    handlers.append(s)
    active_tcp_conns[sock] = True
    tcp_conns.append((srcip, dstip, s, sock))
    expire_connections(time.time(), mux)

def port_in_range(port_range, port):

    parsed_range = port_range.split("-")
    port_start = int(parsed_range[0])
    port_end = int(parsed_range[1])
    dest_port = int(port)

    if (dest_port >= port_start and dest_port <= port_end):
        return True

    return False

def acl_entry_match(cidr, port, storeToCheck):
    debug3('Checking acl: %s for match with cidr: %s and port: %s' % (storeToCheck, cidr, port))

    if cidr in storeToCheck:
        return acl_port_match(port, storeToCheck[cidr])

    return False

def acl_port_match(port, acl_port_rule):
    for port_entry in acl_port_rule:
        if '-' in port_entry:
            if (port_in_range(port_entry, port)):
                debug3('port: %s is in acl port range: %s' % (port, port_entry))
                return True

            debug3('port: %s is NOT in acl port range: %s' % (port, port_entry))
        elif int(port_entry) == int(port):
            debug3('port: %s is in acl port rule: %s' % (port, acl_port_rule))
            return True

    return False

def matches_acl(dstip, dstport, store_to_check):
    if store_to_check is None:
        return False

    debug3('Checking for global IP rule ...')

    if (acl_entry_match('0.0.0.0/0', dstport, store_to_check)):
        debug3('Matched global IP rule')
        return True

    debug3('No global IP rule')
    debug3('Checking for single IP rule ...')

    cidr_for_single_ip = dstip + '/32'

    if (acl_entry_match(cidr_for_single_ip, dstport, store_to_check)):
        debug3('Matched single IP rule')
        return True

    debug3('No single IP rule')
    debug3('Checking for IP range rule (subnet/cidr block) ...')

    for cidr_entry in store_to_check:
        mask = int(cidr_entry.split('/')[1])
        is_range_rule = (cidr_entry != '0.0.0.0/0') and (mask != 32)

        if is_range_rule:
            try:
                acl_subnet = ipaddress.ip_network(cidr_entry, False)

                destination = ipaddress.ip_address(dstip)

                if destination in acl_subnet:
                    if (acl_port_match(dstport, store_to_check[cidr_entry])):
                        debug3('Matched IP range rule')
                        return True
            except:
                log('Failed to parse CIDR block %s' % cidr_entry)

    debug3('No IP range rule')

    debug3('Destination did not match the ACL')

    return False

def tcp_connection_is_allowed_conditional(dstip, dstport, srcip, check_acl, check_sources):

    if check_sources:
        ctime = time.time()
        if _excluded_sources and srcip in _excluded_sources and (_excluded_sources[srcip] / 1000.0) >= ctime:
            debug3("Connection from a source excluded from the ACL\n")
            return True

        check_allowed_sources = True
        if (_always_connected == ALWAYS_CONNECTED_ON) and (srcip in _acl_always_connected):
            debug3("TCP source allowed because alwaysConnected mode is ON and srcip is in aclAlwaysConnected\n")
            check_allowed_sources = False

        if check_allowed_sources:
            if not _allowed_sources:
                debug3("Connection not allowed - allowed sources exception - not _allowed_sources\n")
                return False
            if (srcip not in _allowed_sources):
                debug3("Connection not allowed - allowed sources exception - (srcip not in _allowed_sources)\n")
                return False
            if (srcip in _allowed_sources and (_allowed_sources[srcip] / 1000.0) < ctime):
                debug3("Connection not allowed - allowed sources exception - (srcip in _allowed_sources and (_allowed_sources[srcip] / 1000.0) < ctime)\n")
                return False

    if check_acl:
       if matches_acl(dstip, dstport, _allowed_tcp_targets):
           return True
    else:
       return True

def tcp_connection_is_allowed(dstip, dstport, srcip):

    return tcp_connection_is_allowed_conditional(dstip, dstport, srcip, True, True)

def udp_connection_is_allowed(dstip, dstport, srcip):

    ctime = time.time()
    if _excluded_sources and srcip in _excluded_sources and (_excluded_sources[srcip] / 1000.0) >= ctime:
        debug1("Connection from a source excluded from the ACL\n")
        return True

    check_allowed_sources = True
    if (_always_connected == ALWAYS_CONNECTED_ON) and (srcip in _acl_always_connected):
        debug3("UDP source allowed because alwaysConnected mode is ON and srcip is in aclAlwaysConnected\n")
        check_allowed_sources = False

    if check_allowed_sources:
        if not _allowed_sources:
            debug3("Connection not allowed - allowed sources exception - not _allowed_sources\n")
            return False
        if (srcip not in _allowed_sources):
            debug3("Connection not allowed - allowed sources exception - (srcip not in _allowed_sources)\n")
            return False
        if (srcip in _allowed_sources and (_allowed_sources[srcip] / 1000.0) < ctime):
            debug3("Connection not allowed - allowed sources exception - (srcip in _allowed_sources and (_allowed_sources[srcip] / 1000.0) < ctime)\n")
            return False

    if matches_acl(dstip, dstport, _allowed_udp_targets):
        return True

def connection_is_active(sock):
    return sock in active_tcp_conns

def udp_done(chan, data, method, sock, dstip):
    (src, srcport, data) = data.split(b",", 2)
    srcport_int = int(srcport)
    srcip = (src, srcport_int)
    debug3('doing send from %r to %r\n' % (srcip, dstip,))
    method.send_udp(sock, srcip, dstip, data)


def onaccept_udp(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t

    if not udp_connection_is_allowed(dstip[0], str(dstip[1]), srcip[0]):
        debug1('Deny UDP: %s:%r -> %s:%r.\n' % (srcip[0], srcip[1], dstip[0], dstip[1]))
        # sock.close()
        return

    debug1('Accept UDP: %s:%r -> %s:%r.\n' % (srcip[0], srcip[1], dstip[0], dstip[1]))
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
    debug3('dns_done: channel=%d src=%r dst=%r\n' % (chan, srcip, dstip))
    response = DNSRecord.parse(data)
    debug3('For the DNS request: %r   >>>>> DNS response: %r <<<<<<' % (dnsreqs2[chan], response))
    del mux.channels[chan]
    del dnsreqs[chan]
    del dnsreqs2[chan]
    method.send_udp(sock, srcip, dstip, data)


def ondns(listener, method, mux, handlers):
    now = time.time()
    t = method.recv_udp(listener, 4096)
    if t is None:
        return
    srcip, dstip, data = t
    request = DNSRecord.parse(data)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    chan = mux.next_channel()
    dnsreqs2[chan] = request
    dnsreqs[chan] = now + 30
    mux.channels[chan] = lambda cmd, data: dns_done(
        chan, data, method, listener, srcip=dstip, dstip=srcip, mux=mux)

    global preferreddns
    global notpreferreddns

    if preferreddns and notpreferreddns and DNS_PROXY_SUFFIX1 and \
            (qn.endswith(DNS_PROXY_SUFFIX1) or qn.endswith(DNS_PROXY_SUFFIX2)):
        try:
            response = send_udp(data, preferreddns, 53)
            dns_done(chan, response, method, listener, srcip=dstip, dstip=srcip, mux=mux)
        except socket.error:
            debug3('Error: Could not contact DNS server %r, now trying %r' % (preferreddns, notpreferreddns))

            _notpreferreddns = notpreferreddns
            notpreferreddns = preferreddns
            preferreddns = _notpreferreddns

            # try the other AD server if there was an error...
            try:
                response = send_udp(data, preferreddns, 53)
                dns_done(chan, response, method, listener, srcip=dstip, dstip=srcip, mux=mux)
            except socket.error:
                # fallback to agent if both AD servers are down.
                mux.send(chan, ssnet.CMD_DNS_REQ, data)
    else:
        mux.send(chan, ssnet.CMD_DNS_REQ, data)

    expire_connections(now, mux)

def send_udp(data, host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(data, (host, port))
    response, server = sock.recvfrom(8192)
    sock.close()
    return response


class AclHandler:

    def __init__(self, redisClient, acl_type):
        self.redisClient = redisClient
        self.acl_type = acl_type
        self.acl = {}

    def reload_acl_file(self):
        global _allowed_targets_modified
        global _sources_modified

        self.pullAcl()
        if (self.acl_type is ALLOWED_TCP_ACL_TYPE):
            self.reload_tcp_acl_targets_file()
            _allowed_targets_modified = True
        elif (self.acl_type is ALLOWED_UDP_ACL_TYPE):
            self.reload_udp_acl_targets_file()
            _allowed_targets_modified = True
        elif (self.acl_type is ACL_SOURCES_TYPE):
            self.reload_acl_sources_file()
            _sources_modified = True
        elif (self.acl_type is ACL_EXCLUDED_SOURCES_TYPE):
            self.reload_acl_excluded_sources_file()
            _sources_modified = True
        elif (self.acl_type is ALWAYS_CONNECTED_TYPE):
            self.reload_always_connected()
            _sources_modified = True
        elif (self.acl_type is ACL_ALWAYS_CONNECTED_TYPE):
            self.reload_acl_always_connected()
            _sources_modified = True


    def pullAcl(self):
        if (self.acl_type is ALLOWED_TCP_ACL_TYPE):
            self.acl = self.redisClient.get(sshuttleAclTcp)
        elif (self.acl_type is ALLOWED_UDP_ACL_TYPE):
            self.acl = self.redisClient.get(sshuttleAclUdp)
        elif (self.acl_type is ACL_SOURCES_TYPE):
            self.acl = self.redisClient.get(sshuttleAclSources)
        elif (self.acl_type is ACL_EXCLUDED_SOURCES_TYPE):
            self.acl = self.redisClient.get(sshuttleAclExcluded)
        elif (self.acl_type is ALWAYS_CONNECTED_TYPE):
            self.acl = self.redisClient.get(alwaysConnected)
        elif (self.acl_type is ACL_ALWAYS_CONNECTED_TYPE):
            self.acl = self.redisClient.get(aclAlwaysConnected)
        else:
            debug1("pullAcl() -> Unsupported ACL type %d\n" % self.acl_type)
            self.acl = None

        if self.acl is not None:
            self.acl = self.acl.decode('utf-8')

    def reload_acl_sources_file(self):
        global _allowed_sources

        if self.acl is not None:
            try:
                _new_allowed_sources = json.loads(self.acl, "utf-8")
                _allowed_sources = _new_allowed_sources
            except BaseException as e:
                debug3("An exception has occurred while loading the sources data: {}\n\n".format(e))
        else:
            _allowed_sources = None

        debug3("Network Connection Sources ACL \n\n%s" % _allowed_sources)

    def reload_acl_excluded_sources_file(self):

        global _excluded_sources

        if self.acl is not None:
            try:
                _new_excluded_sources = json.loads(self.acl, "utf-8")
                _excluded_sources = _new_excluded_sources
            except BaseException as e:
                debug3("An exception has occurred while loading the excluded sources data: {}\n\n".format(e))
        else:
            _excluded_sources = None

        debug3("Network Connection Excluded Sources ACL \n\n%s" % _excluded_sources)

    def reload_tcp_acl_targets_file(self):

        global _allowed_tcp_targets

        if self.acl is not None:
            try:
                _new_targets = json.loads(self.acl, "utf-8")
                _allowed_tcp_targets = _new_targets
            except BaseException as e:
                debug3("An exception has occurred while loading the TCP allowed targets (sshuttleAcl) data: {}\n\n".format(e))
        else:
            _allowed_tcp_targets = None

        if (not _allowed_tcp_targets):
            log("Allowed TCP ACL list is empty. Restricting all access\n")
        else:
            log("Network Connection TCP Allowed ACL \n\n%s" % _allowed_tcp_targets)

    def reload_udp_acl_targets_file(self):

        global _allowed_udp_targets

        if self.acl is not None:
            try:
                _new_targets = json.loads(self.acl, "utf-8")
                _allowed_udp_targets = _new_targets
            except BaseException as e:
                debug3("An exception has occurred while loading the UDP allowed targets (sshuttleAclUdp) data: {}\n\n".format(e))
        else:
            _allowed_udp_targets = None

        if (not _allowed_udp_targets):
            log("Allowed UDP ACL list is empty. Restricting all UDP ports access\n")
        else:
            log("Network Connection UDP Allowed ACL \n\n%s" % _allowed_udp_targets)

    def reload_always_connected(self):
        global _always_connected

        if self.acl is not None:
            _always_connected = self.acl
        else:
            _always_connected = ALWAYS_CONNECTED_OFF

        if (_always_connected == ALWAYS_CONNECTED_OFF):
            log("alwaysConnected mode is OFF")
        else:
            log("alwaysConnected mode is ON")

    def reload_acl_always_connected(self):
        global _acl_always_connected

        if self.acl is not None:
            try:
                _new_acl_always_connected = json.loads(self.acl, "utf-8")
                _acl_always_connected = _new_acl_always_connected
            except BaseException as e:
                debug3("An exception occurred while loading the aclAlwaysConnected data: {}\n\n".format(e))
        else:
            _acl_always_connected = None

        debug3("Always Connected ACL: \n\n%s" % _acl_always_connected)

class ChannelListener(threading.Thread):

    def __init__(self, redisHost, redisPort, channels):
        threading.Thread.__init__(self)
        self.redisHost = redisHost
        self.redisPort = redisPort
        self.channels = channels
        self.redisClient = None
        self.redisPubSub = None

    def connect(self):
        try:
            log("Connecting to redis server at %s:%s\n" % (self.redisHost, self.redisPort))
            self.redisClient = redis.Redis(host=self.redisHost, port=self.redisPort)
            self.redisClient.ping()
            log("Connected! (%s:%s)\n" % (self.redisHost, self.redisPort))
        except redis.ConnectionError as e:
            log("Error establishing connection to redis server: %s -- retrying\n" % e)
            time.sleep(2)
            self.connect()

    def initializePubSub(self):
        self.redisPubSub = self.redisClient.pubsub()
        self.redisPubSub.subscribe(self.channels)

    def initialize(self):
        self.connect()
        self.initializePubSub()
        self.reloadAllAcls()

    def reconnect(self):
        self.initialize()
        self.initializeChannelHandlers()

    def handlePubSubEvent(self, item):
        acl_type = None
        channel = item['channel'].decode('utf-8')
        if (channel == sshuttleAclEventsChannel and item['type'] == "message"):
            data = item['data'].decode('utf-8')
            if (data == sshuttleAclTcp):
                acl_type = ALLOWED_TCP_ACL_TYPE
            elif (data == sshuttleAclUdp):
                acl_type = ALLOWED_UDP_ACL_TYPE
            elif (data == sshuttleAclSources):
                acl_type = ACL_SOURCES_TYPE
            elif (data == sshuttleAclExcluded):
                acl_type = ACL_EXCLUDED_SOURCES_TYPE
            elif (data == alwaysConnected):
                acl_type = ALWAYS_CONNECTED_TYPE
            elif (data == aclAlwaysConnected):
                acl_type = ACL_ALWAYS_CONNECTED_TYPE
            else:
                debug3("Unsupported ACL type. Channel: %s, Data: %s\n" % (channel, data))

        if acl_type is not None:
            AclHandler(self.redisClient, acl_type).reload_acl_file()

    def reloadAllAcls(self):
        AclHandler(self.redisClient, ALLOWED_TCP_ACL_TYPE).reload_acl_file()
        AclHandler(self.redisClient, ALLOWED_UDP_ACL_TYPE).reload_acl_file()
        AclHandler(self.redisClient, ACL_SOURCES_TYPE).reload_acl_file()
        AclHandler(self.redisClient, ACL_EXCLUDED_SOURCES_TYPE).reload_acl_file()
        AclHandler(self.redisClient, ALWAYS_CONNECTED_TYPE).reload_acl_file()
        AclHandler(self.redisClient, ACL_ALWAYS_CONNECTED_TYPE).reload_acl_file()

    def initializeChannelHandlers(self):
        try:
            for item in self.redisPubSub.listen():
                self.handlePubSubEvent(item)
        except redis.ConnectionError as e:
            log("Something happened with the established redis connection: %s -- reconnecting\n" % e)
            self.reconnect()

    def run(self):
        self.initializeChannelHandlers()

def _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
          python, latency_control,
          dns_listener, seed_hosts, auto_hosts, auto_nets, daemon,
          to_nameserver):

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
                         auto_hosts=auto_hosts,
                         to_nameserver=to_nameserver))
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
                if not line: continue
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

    while 1:
        rv = serverproc.poll()
        if rv:
            raise Fatal('server died with error code %d' % rv)

        check_connections_allowed(mux)
        ssnet.runonce(handlers, mux)
        if latency_control:
            mux.check_fullness()


def main(listenip_v6, listenip_v4,
         ssh_cmd, remotename, python, latency_control, dns, nslist,
         method_name, seed_hosts, auto_hosts, auto_nets,
         subnets_include, subnets_exclude, daemon, to_nameserver, pidfile,
         user):

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
        if to_nameserver is not None:
            to_nameserver = "%s@%s" % tuple(to_nameserver[1:])
    else:
        # option doesn't make sense if we aren't proxying dns
        to_nameserver = None

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

    if user is not None:
        if getpwnam is None:
            raise Fatal("Routing by user not available on this system.")
        try:
            user = getpwnam(user).pw_uid
        except KeyError:
            raise Fatal("User %s does not exist." % user)

    required.ipv6 = len(subnets_v6) > 0 or listenip_v6 is not None
    required.ipv4 = len(subnets_v4) > 0 or listenip_v4 is not None
    required.udp = avail.udp
    required.dns = len(nslist) > 0
    required.user = False if user is None else True

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
    debug1("User enabled: %r\n" % required.user)

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
        # keep track of failed bindings and used ports to avoid trying to
        # bind to the same socket address twice in different listeners
        used_ports = []

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
            used_ports.append(port)
            break
        except socket.error as e:
            if e.errno == errno.EADDRINUSE:
                last_e = e
                used_ports.append(port)
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
            if port in used_ports: continue

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
             required.udp, user)

    if (REDIS_HOST is None or REDIS_PORT is None):
        raise Fatal("REDIS_HOST and REDIS_PORT environment variables must both be set!")

    channelSubscriptions = [sshuttleAclEventsChannel]
    channelListener = ChannelListener(REDIS_HOST, REDIS_PORT, channelSubscriptions)
    channelListener.setDaemon(True)
    channelListener.initialize()
    channelListener.start()

    # start the client process
    try:
        return _main(tcp_listener, udp_listener, fw, ssh_cmd, remotename,
                     python, latency_control, dns_listener,
                     seed_hosts, auto_hosts, auto_nets, daemon, to_nameserver)
    finally:
        try:
            if daemon:
                # it's not our child anymore; can't waitpid
                fw.p.returncode = 0
            fw.done()
        finally:
            if daemon:
                daemon_cleanup()
