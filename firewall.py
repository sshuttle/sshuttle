import re, errno
import compat.ssubprocess as ssubprocess
import helpers
from helpers import *


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


# We name the chain based on the transproxy port number so that it's possible
# to run multiple copies of sshuttle at the same time.  Of course, the
# multiple copies shouldn't have overlapping subnets, or only the most-
# recently-started one will win (because we use "-I OUTPUT 1" instead of
# "-A OUTPUT").
def do_iptables(port, subnets):
    chain = 'sshuttle-%s' % port

    # basic cleanup/setup of chains
    if ipt_chain_exists(chain):
        ipt('-D', 'OUTPUT', '-j', chain)
        ipt('-D', 'PREROUTING', '-j', chain)
        ipt('-F', chain)
        ipt('-X', chain)

    if subnets:
        ipt('-N', chain)
        ipt('-F', chain)
        ipt('-I', 'OUTPUT', '1', '-j', chain)
        ipt('-I', 'PREROUTING', '1', '-j', chain)

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
                ipt('-A', chain, '-j', 'REDIRECT',
                    '--dest', '%s/%s' % (snet,swidth),
                    '-p', 'tcp',
                    '--to-ports', str(port),
                    '-m', 'ttl', '!', '--ttl', '42'  # to prevent infinite loops
                    )


def ipfw_rule_exists(n):
    argv = ['ipfw', 'list']
    p = ssubprocess.Popen(argv, stdout = ssubprocess.PIPE)
    found = False
    for line in p.stdout:
        if line.startswith('%05d ' % n):
            if not ('ipttl 42 setup keep-state' in line
                    or ('skipto %d' % (n+1)) in line
                    or 'check-state' in line):
                log('non-sshuttle ipfw rule: %r\n' % line.strip())
                raise Fatal('non-sshuttle ipfw rule #%d already exists!' % n)
            found = True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    return found


def sysctl_get(name):
    argv = ['sysctl', '-n', name]
    p = ssubprocess.Popen(argv, stdout = ssubprocess.PIPE)
    line = p.stdout.readline()
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
    if not line:
        raise Fatal('%r returned no data' % (argv,))
    assert(line[-1] == '\n')
    return line[:-1]


def _sysctl_set(name, val):
    argv = ['sysctl', '-w', '%s=%s' % (name, val)]
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv, stdout = open('/dev/null', 'w'))


_oldctls = []
def sysctl_set(name, val):
    oldval = sysctl_get(name)
    if str(val) != str(oldval):
        _oldctls.append((name, oldval))
        return _sysctl_set(name, val)
    

def ipfw(*args):
    argv = ['ipfw', '-q'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def do_ipfw(port, subnets):
    sport = str(port)
    xsport = str(port+1)

    # cleanup any existing rules
    if ipfw_rule_exists(port):
        ipfw('delete', sport)

    while _oldctls:
        (name,oldval) = _oldctls.pop()
        _sysctl_set(name, oldval)

    if subnets:
        sysctl_set('net.inet.ip.fw.enable', 1)
        sysctl_set('net.inet.ip.scopedroute', 0)

        ipfw('add', sport, 'check-state', 'ip',
             'from', 'any', 'to', 'any')
        
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
def main(port):
    assert(port > 0)
    assert(port <= 65535)

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
            do_it(port, subnets)
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
        do_it(port, [])
        restore_etc_hosts(port)
