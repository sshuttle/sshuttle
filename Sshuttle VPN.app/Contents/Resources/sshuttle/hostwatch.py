import time, socket, re, select, errno
if not globals().get('skip_imports'):
    import compat.ssubprocess as ssubprocess
    import helpers
    from helpers import *

POLL_TIME = 60*15
NETSTAT_POLL_TIME = 30
CACHEFILE=os.path.expanduser('~/.sshuttle.hosts')


_nmb_ok = True
_smb_ok = True
hostnames = {}
queue = {}
try:
    null = open('/dev/null', 'wb')
except IOError, e:
    log('warning: %s\n' % e)
    null = os.popen("sh -c 'while read x; do :; done'", 'wb', 4096)


def _is_ip(s):
    return re.match(r'\d+\.\d+\.\d+\.\d+$', s)


def write_host_cache():
    tmpname = '%s.%d.tmp' % (CACHEFILE, os.getpid())
    try:
        f = open(tmpname, 'wb')
        for name,ip in sorted(hostnames.items()):
            f.write('%s,%s\n' % (name, ip))
        f.close()
        os.rename(tmpname, CACHEFILE)
    finally:
        try:
            os.unlink(tmpname)
        except:
            pass


def read_host_cache():
    try:
        f = open(CACHEFILE)
    except IOError, e:
        if e.errno == errno.ENOENT:
            return
        else:
            raise
    for line in f:
        words = line.strip().split(',')
        if len(words) == 2:
            (name,ip) = words
            name = re.sub(r'[^-\w]', '-', name).strip()
            ip = re.sub(r'[^0-9.]', '', ip).strip()
            if name and ip:
                found_host(name, ip)
                

def found_host(hostname, ip):
    hostname = re.sub(r'\..*', '', hostname)
    hostname = re.sub(r'[^-\w]', '_', hostname)
    if (ip.startswith('127.') or ip.startswith('255.') 
        or hostname == 'localhost'):
        return
    oldip = hostnames.get(hostname)
    if oldip != ip:
        hostnames[hostname] = ip
        debug1('Found: %s: %s\n' % (hostname, ip))
        sys.stdout.write('%s,%s\n' % (hostname, ip))
        write_host_cache()


def _check_etc_hosts():
    debug2(' > hosts\n')
    for line in open('/etc/hosts'):
        line = re.sub(r'#.*', '', line)
        words = line.strip().split()
        if not words:
            continue
        ip = words[0]
        names = words[1:]
        if _is_ip(ip):
            debug3('<    %s %r\n' % (ip, names))
            for n in names:
                check_host(n)
                found_host(n, ip)


def _check_revdns(ip):
    debug2(' > rev: %s\n' % ip)
    try:
        r = socket.gethostbyaddr(ip)
        debug3('<    %s\n' % r[0])
        check_host(r[0])
        found_host(r[0], ip)
    except socket.herror, e:
        pass


def _check_dns(hostname):
    debug2(' > dns: %s\n' % hostname)
    try:
        ip = socket.gethostbyname(hostname)
        debug3('<    %s\n' % ip)
        check_host(ip)
        found_host(hostname, ip)
    except socket.gaierror, e:
        pass


def _check_netstat():
    debug2(' > netstat\n')
    argv = ['netstat', '-n']
    try:
        p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, stderr=null)
        content = p.stdout.read()
        p.wait()
    except OSError, e:
        log('%r failed: %r\n' % (argv, e))
        return

    for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', content):
        debug3('<    %s\n' % ip)
        check_host(ip)
        

def _check_smb(hostname):
    return
    global _smb_ok
    if not _smb_ok:
        return
    argv = ['smbclient', '-U', '%', '-L', hostname]
    debug2(' > smb: %s\n' % hostname)
    try:
        p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, stderr=null)
        lines = p.stdout.readlines()
        p.wait()
    except OSError, e:
        log('%r failed: %r\n' % (argv, e))
        _smb_ok = False
        return

    lines.reverse()

    # junk at top
    while lines:
        line = lines.pop().strip()
        if re.match(r'Server\s+', line):
            break

    # server list section:
    #    Server   Comment
    #    ------   -------
    while lines:
        line = lines.pop().strip()
        if not line or re.match(r'-+\s+-+', line):
            continue
        if re.match(r'Workgroup\s+Master', line):
            break
        words = line.split()
        hostname = words[0].lower()
        debug3('<    %s\n' % hostname)
        check_host(hostname)

    # workgroup list section:
    #   Workgroup  Master
    #   ---------  ------
    while lines:
        line = lines.pop().strip()
        if re.match(r'-+\s+', line):
            continue
        if not line:
            break
        words = line.split()
        (workgroup, hostname) = (words[0].lower(), words[1].lower())
        debug3('<    group(%s) -> %s\n' % (workgroup, hostname))
        check_host(hostname)
        check_workgroup(workgroup)

    if lines:
        assert(0)


def _check_nmb(hostname, is_workgroup, is_master):
    return
    global _nmb_ok
    if not _nmb_ok:
        return
    argv = ['nmblookup'] + ['-M']*is_master + ['--', hostname]
    debug2(' > n%d%d: %s\n' % (is_workgroup, is_master, hostname))
    try:
        p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, stderr=null)
        lines = p.stdout.readlines()
        rv = p.wait()
    except OSError, e:
        log('%r failed: %r\n' % (argv, e))
        _nmb_ok = False
        return
    if rv:
        log('%r returned %d\n' % (argv, rv))
        return
    for line in lines:
        m = re.match(r'(\d+\.\d+\.\d+\.\d+) (\w+)<\w\w>\n', line)
        if m:
            g = m.groups()
            (ip, name) = (g[0], g[1].lower())
            debug3('<    %s -> %s\n' % (name, ip))
            if is_workgroup:
                _enqueue(_check_smb, ip)
            else:
                found_host(name, ip)
                check_host(name)


def check_host(hostname):
    if _is_ip(hostname):
        _enqueue(_check_revdns, hostname)
    else:
        _enqueue(_check_dns, hostname)
    _enqueue(_check_smb, hostname)
    _enqueue(_check_nmb, hostname, False, False)


def check_workgroup(hostname):
    _enqueue(_check_nmb, hostname, True, False)
    _enqueue(_check_nmb, hostname, True, True)


def _enqueue(op, *args):
    t = (op,args)
    if queue.get(t) == None:
        queue[t] = 0


def _stdin_still_ok(timeout):
    r,w,x = select.select([sys.stdin.fileno()], [], [], timeout)
    if r:
        b = os.read(sys.stdin.fileno(), 4096)
        if not b:
            return False
    return True


def hw_main(seed_hosts):
    if helpers.verbose >= 2:
        helpers.logprefix = 'HH: '
    else:
        helpers.logprefix = 'hostwatch: '

    read_host_cache()
        
    _enqueue(_check_etc_hosts)
    _enqueue(_check_netstat)
    check_host('localhost')
    check_host(socket.gethostname())
    check_workgroup('workgroup')
    check_workgroup('-')
    for h in seed_hosts:
        check_host(h)

    while 1:
        now = time.time()
        for t,last_polled in queue.items():
            (op,args) = t
            if not _stdin_still_ok(0):
                break
            maxtime = POLL_TIME
            if op == _check_netstat:
                maxtime = NETSTAT_POLL_TIME
            if now - last_polled > maxtime:
                queue[t] = time.time()
                op(*args)
            try:
                sys.stdout.flush()
            except IOError:
                break
                
        # FIXME: use a smarter timeout based on oldest last_polled
        if not _stdin_still_ok(1):
            break
