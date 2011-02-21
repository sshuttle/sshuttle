import re, errno, socket, select, struct
import compat.ssubprocess as ssubprocess
import helpers, ssyslog
from helpers import *

# python doesn't have a definition for this
IPPROTO_DIVERT = 254


def nonfatal(func, *args):
    try:
        func(*args)
    except Fatal, e:
        log('error: %s\n' % e)


def ipt_chain_exists(name):
    argv = ['iptables', '-t', 'nat', '-nL']
    p = ssubprocess.Popen(argv, stdout = ssubprocess.PIPE)
    for line in p.stdout:
        if line.startswith('Chain %s ' % name):
            return True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def ipt(*args):
    argv = ['iptables', '-t', 'nat'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


_no_ttl_module = False
def ipt_ttl(*args):
    global _no_ttl_module
    if not _no_ttl_module:
        # we avoid infinite loops by generating server-side connections
        # with ttl 42.  This makes the client side not recapture those
        # connections, in case client == server.
        try:
            argsplus = list(args) + ['-m', 'ttl', '!', '--ttl', '42']
            ipt(*argsplus)
        except Fatal:
            ipt(*args)
            # we only get here if the non-ttl attempt succeeds
            log('sshuttle: warning: your iptables is missing '
                'the ttl module.\n')
            _no_ttl_module = True
    else:
        ipt(*args)



# We name the chain based on the transproxy port number so that it's possible
# to run multiple copies of sshuttle at the same time.  Of course, the
# multiple copies shouldn't have overlapping subnets, or only the most-
# recently-started one will win (because we use "-I OUTPUT 1" instead of
# "-A OUTPUT").
def do_iptables(port, dnsport, subnets):
    chain = 'sshuttle-%s' % port

    # basic cleanup/setup of chains
    if ipt_chain_exists(chain):
        nonfatal(ipt, '-D', 'OUTPUT', '-j', chain)
        nonfatal(ipt, '-D', 'PREROUTING', '-j', chain)
        nonfatal(ipt, '-F', chain)
        ipt('-X', chain)

    if subnets or dnsport:
        ipt('-N', chain)
        ipt('-F', chain)
        ipt('-I', 'OUTPUT', '1', '-j', chain)
        ipt('-I', 'PREROUTING', '1', '-j', chain)

    if subnets:
        # create new subnet entries.  Note that we're sorting in a very
        # particular order: we need to go from most-specific (largest swidth)
        # to least-specific, and at any given level of specificity, we want
        # excludes to come first.  That's why the columns are in such a non-
        # intuitive order.
        for swidth,sexclude,snet in sorted(subnets, reverse=True):
            if sexclude:
                ipt('-A', chain, '-j', 'RETURN',
                    '--dest', '%s/%s' % (snet,swidth),
                    '-p', 'tcp')
            else:
                ipt_ttl('-A', chain, '-j', 'REDIRECT',
                        '--dest', '%s/%s' % (snet,swidth),
                        '-p', 'tcp',
                        '--to-ports', str(port))
                
    if dnsport:
        nslist = resolvconf_nameservers()
        for ip in nslist:
            ipt_ttl('-A', chain, '-j', 'REDIRECT',
                    '--dest', '%s/32' % ip,
                    '-p', 'udp',
                    '--dport', '53',
                    '--to-ports', str(dnsport))


def ipfw_rule_exists(n):
    argv = ['ipfw', 'list']
    p = ssubprocess.Popen(argv, stdout = ssubprocess.PIPE)
    found = False
    for line in p.stdout:
        if line.startswith('%05d ' % n):
            if not ('ipttl 42' in line
                    or ('skipto %d' % (n+1)) in line
                    or 'check-state' in line):
                log('non-sshuttle ipfw rule: %r\n' % line.strip())
                raise Fatal('non-sshuttle ipfw rule #%d already exists!' % n)
            found = True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    return found


_oldctls = {}
def _fill_oldctls(prefix):
    argv = ['sysctl', prefix]
    p = ssubprocess.Popen(argv, stdout = ssubprocess.PIPE)
    for line in p.stdout:
        assert(line[-1] == '\n')
        (k,v) = line[:-1].split(': ', 1)
        _oldctls[k] = v
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    if not line:
        raise Fatal('%r returned no data' % (argv,))


def _sysctl_set(name, val):
    argv = ['sysctl', '-w', '%s=%s' % (name, val)]
    debug1('>> %s\n' % ' '.join(argv))
    return ssubprocess.call(argv, stdout = open('/dev/null', 'w'))


_changedctls = []
def sysctl_set(name, val, permanent=False):
    PREFIX = 'net.inet.ip'
    assert(name.startswith(PREFIX + '.'))
    val = str(val)
    if not _oldctls:
        _fill_oldctls(PREFIX)
    if not (name in _oldctls):
        debug1('>> No such sysctl: %r\n' % name)
        return
    oldval = _oldctls[name]
    if val != oldval:
        rv = _sysctl_set(name, val)
        if rv==0 and permanent:
            debug1('>>   ...saving permanently in /etc/sysctl.conf\n')
            f = open('/etc/sysctl.conf', 'a')
            f.write('\n'
                    '# Added by sshuttle\n'
                    '%s=%s\n' % (name, val))
            f.close()
        else:
            _changedctls.append(name)


def _udp_unpack(p):
    src = (socket.inet_ntoa(p[12:16]), struct.unpack('!H', p[20:22])[0])
    dst = (socket.inet_ntoa(p[16:20]), struct.unpack('!H', p[22:24])[0])
    return src, dst


def _udp_repack(p, src, dst):
    addrs = socket.inet_aton(src[0]) + socket.inet_aton(dst[0])
    ports = struct.pack('!HH', src[1], dst[1])
    return p[:12] + addrs + ports + p[24:]


_real_dns_server = [None]
def _handle_diversion(divertsock, dnsport):
    p,tag = divertsock.recvfrom(4096)
    src,dst = _udp_unpack(p)
    debug3('got diverted packet from %r to %r\n' % (src, dst))
    if dst[1] == 53:
        # outgoing DNS
        debug3('...packet is a DNS request.\n')
        _real_dns_server[0] = dst
        dst = ('127.0.0.1', dnsport)
    elif src[1] == dnsport:
        if islocal(src[0]):
            debug3('...packet is a DNS response.\n')
            src = _real_dns_server[0]
    else:
        log('weird?! unexpected divert from %r to %r\n' % (src, dst))
        assert(0)
    newp = _udp_repack(p, src, dst)
    divertsock.sendto(newp, tag)
    

def ipfw(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def do_ipfw(port, dnsport, subnets):
    sport = str(port)
    xsport = str(port+1)

    # cleanup any existing rules
    if ipfw_rule_exists(port):
        ipfw('delete', sport)

    while _changedctls:
        name = _changedctls.pop()
        oldval = _oldctls[name]
        _sysctl_set(name, oldval)

    if subnets or dnsport:
        sysctl_set('net.inet.ip.fw.enable', 1)
        sysctl_set('net.inet.ip.scopedroute', 0, permanent=True)

        ipfw('add', sport, 'check-state', 'ip',
             'from', 'any', 'to', 'any')

    if subnets:
        # create new subnet entries
        for swidth,sexclude,snet in sorted(subnets, reverse=True):
            if sexclude:
                ipfw('add', sport, 'skipto', xsport,
                     'log', 'tcp',
                     'from', 'any', 'to', '%s/%s' % (snet,swidth))
            else:
                ipfw('add', sport, 'fwd', '127.0.0.1,%d' % port,
                     'log', 'tcp',
                     'from', 'any', 'to', '%s/%s' % (snet,swidth),
                     'not', 'ipttl', '42', 'keep-state', 'setup')

    # This part is much crazier than it is on Linux, because MacOS (at least
    # 10.6, and probably other versions, and maybe FreeBSD too) doesn't
    # correctly fixup the dstip/dstport for UDP packets when it puts them
    # through a 'fwd' rule.  It also doesn't fixup the srcip/srcport in the
    # response packet.  In Linux iptables, all that happens magically for us,
    # so we just redirect the packets and relax.
    #
    # On MacOS, we have to fix the ports ourselves.  For that, we use a
    # 'divert' socket, which receives raw packets and lets us mangle them.
    #
    # Here's how it works.  Let's say the local DNS server is 1.1.1.1:53,
    # and the remote DNS server is 2.2.2.2:53, and the local transproxy port
    # is 10.0.0.1:12300, and a client machine is making a request from
    # 10.0.0.5:9999. We see a packet like this:
    #    10.0.0.5:9999 -> 1.1.1.1:53
    # Since the destip:port matches one of our local nameservers, it will
    # match a 'fwd' rule, thus grabbing it on the local machine.  However,
    # the local kernel will then see a packet addressed to *:53 and
    # not know what to do with it; there's nobody listening on port 53.  Thus,
    # we divert it, rewriting it into this:
    #    10.0.0.5:9999 -> 10.0.0.1:12300
    # This gets proxied out to the server, which sends it to 2.2.2.2:53,
    # and the answer comes back, and the proxy sends it back out like this:
    #    10.0.0.1:12300 -> 10.0.0.5:9999
    # But that's wrong!  The original machine expected an answer from
    # 1.1.1.1:53, so we have to divert the *answer* and rewrite it:
    #    1.1.1.1:53 -> 10.0.0.5:9999
    #
    # See?  Easy stuff.
    if dnsport:
        divertsock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                   IPPROTO_DIVERT)
        divertsock.bind(('0.0.0.0', port)) # IP field is ignored

        nslist = resolvconf_nameservers()
        for ip in nslist:
            # relabel and then catch outgoing DNS requests
            ipfw('add', sport, 'divert', sport,
                 'log', 'udp',
                 'from', 'any', 'to', '%s/32' % ip, '53',
                 'not', 'ipttl', '42')
        # relabel DNS responses
        ipfw('add', sport, 'divert', sport,
             'log', 'udp',
             'from', 'any', str(dnsport), 'to', 'any',
             'not', 'ipttl', '42')

        def do_wait():
            while 1:
                r,w,x = select.select([sys.stdin, divertsock], [], [])
                if divertsock in r:
                    _handle_diversion(divertsock, dnsport)
                if sys.stdin in r:
                    return
    else:
        do_wait = None
        
    return do_wait


def program_exists(name):
    paths = (os.getenv('PATH') or os.defpath).split(os.pathsep)
    for p in paths:
        fn = '%s/%s' % (p, name)
        if os.path.exists(fn):
            return not os.path.isdir(fn) and os.access(fn, os.X_OK)


hostmap = {}
def rewrite_etc_hosts(port):
    HOSTSFILE='/etc/hosts'
    BAKFILE='%s.sbak' % HOSTSFILE
    APPEND='# sshuttle-firewall-%d AUTOCREATED' % port
    old_content = ''
    st = None
    try:
        old_content = open(HOSTSFILE).read()
        st = os.stat(HOSTSFILE)
    except IOError, e:
        if e.errno == errno.ENOENT:
            pass
        else:
            raise
    if old_content.strip() and not os.path.exists(BAKFILE):
        os.link(HOSTSFILE, BAKFILE)
    tmpname = "%s.%d.tmp" % (HOSTSFILE, port)
    f = open(tmpname, 'w')
    for line in old_content.rstrip().split('\n'):
        if line.find(APPEND) >= 0:
            continue
        f.write('%s\n' % line)
    for (name,ip) in sorted(hostmap.items()):
        f.write('%-30s %s\n' % ('%s %s' % (ip,name), APPEND))
    f.close()

    if st:
        os.chown(tmpname, st.st_uid, st.st_gid)
        os.chmod(tmpname, st.st_mode)
    else:
        os.chown(tmpname, 0, 0)
        os.chmod(tmpname, 0644)
    os.rename(tmpname, HOSTSFILE)


def restore_etc_hosts(port):
    global hostmap
    hostmap = {}
    rewrite_etc_hosts(port)


# This is some voodoo for setting up the kernel's transparent
# proxying stuff.  If subnets is empty, we just delete our sshuttle rules;
# otherwise we delete it, then make them from scratch.
#
# This code is supposed to clean up after itself by deleting its rules on
# exit.  In case that fails, it's not the end of the world; future runs will
# supercede it in the transproxy list, at least, so the leftover rules
# are hopefully harmless.
def main(port, dnsport, syslog):
    assert(port > 0)
    assert(port <= 65535)
    assert(dnsport >= 0)
    assert(dnsport <= 65535)

    if os.getuid() != 0:
        raise Fatal('you must be root (or enable su/sudo) to set the firewall')

    if program_exists('ipfw'):
        do_it = do_ipfw
    elif program_exists('iptables'):
        do_it = do_iptables
    else:
        raise Fatal("can't find either ipfw or iptables; check your PATH")

    # because of limitations of the 'su' command, the *real* stdin/stdout
    # are both attached to stdout initially.  Clone stdout into stdin so we
    # can read from it.
    os.dup2(1, 0)

    if syslog:
        ssyslog.start_syslog()
        ssyslog.stderr_to_syslog()

    debug1('firewall manager ready.\n')
    sys.stdout.write('READY\n')
    sys.stdout.flush()

    # ctrl-c shouldn't be passed along to me.  When the main sshuttle dies,
    # I'll die automatically.
    os.setsid()

    # we wait until we get some input before creating the rules.  That way,
    # sshuttle can launch us as early as possible (and get sudo password
    # authentication as early in the startup process as possible).
    line = sys.stdin.readline(128)
    if not line:
        return  # parent died; nothing to do

    subnets = []
    if line != 'ROUTES\n':
        raise Fatal('firewall: expected ROUTES but got %r' % line)
    while 1:
        line = sys.stdin.readline(128)
        if not line:
            raise Fatal('firewall: expected route but got %r' % line)
        elif line == 'GO\n':
            break
        try:
            (width,exclude,ip) = line.strip().split(',', 2)
        except:
            raise Fatal('firewall: expected route or GO but got %r' % line)
        subnets.append((int(width), bool(int(exclude)), ip))
        
    try:
        if line:
            debug1('firewall manager: starting transproxy.\n')
            do_wait = do_it(port, dnsport, subnets)
            sys.stdout.write('STARTED\n')
        
        try:
            sys.stdout.flush()
        except IOError:
            # the parent process died for some reason; he's surely been loud
            # enough, so no reason to report another error
            return

        # Now we wait until EOF or any other kind of exception.  We need
        # to stay running so that we don't need a *second* password
        # authentication at shutdown time - that cleanup is important!
        while 1:
            if do_wait: do_wait()
            line = sys.stdin.readline(128)
            if line.startswith('HOST '):
                (name,ip) = line[5:].strip().split(',', 1)
                hostmap[name] = ip
                rewrite_etc_hosts(port)
            elif line:
                raise Fatal('expected EOF, got %r' % line)
            else:
                break
    finally:
        try:
            debug1('firewall manager: undoing changes.\n')
        except:
            pass
        do_it(port, 0, [])
        restore_etc_hosts(port)
