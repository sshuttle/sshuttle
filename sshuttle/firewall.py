import errno
import socket
import signal
import sshuttle.ssyslog as ssyslog
import sys
import os
from sshuttle.helpers import debug1, debug2, Fatal
from sshuttle.methods import get_auto_method, get_method

hostmap = {}
HOSTSFILE = '/etc/hosts'


def rewrite_etc_hosts(port):
    BAKFILE = '%s.sbak' % HOSTSFILE
    APPEND = '# sshuttle-firewall-%d AUTOCREATED' % port
    old_content = ''
    st = None
    try:
        old_content = open(HOSTSFILE).read()
        st = os.stat(HOSTSFILE)
    except IOError as e:
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
    for (name, ip) in sorted(hostmap.items()):
        f.write('%-30s %s\n' % ('%s %s' % (ip, name), APPEND))
    f.close()

    if st:
        os.chown(tmpname, st.st_uid, st.st_gid)
        os.chmod(tmpname, st.st_mode)
    else:
        os.chown(tmpname, 0, 0)
        os.chmod(tmpname, 0o644)
    os.rename(tmpname, HOSTSFILE)


def restore_etc_hosts(port):
    global hostmap
    hostmap = {}
    rewrite_etc_hosts(port)


# Isolate function that needs to be replaced for tests
def setup_daemon():
    if os.getuid() != 0:
        raise Fatal('you must be root (or enable su/sudo) to set the firewall')

    # don't disappear if our controlling terminal or stdout/stderr
    # disappears; we still have to clean up.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # ctrl-c shouldn't be passed along to me.  When the main sshuttle dies,
    # I'll die automatically.
    os.setsid()

    # because of limitations of the 'su' command, the *real* stdin/stdout
    # are both attached to stdout initially.  Clone stdout into stdin so we
    # can read from it.
    os.dup2(1, 0)

    return sys.stdin, sys.stdout


# This is some voodoo for setting up the kernel's transparent
# proxying stuff.  If subnets is empty, we just delete our sshuttle rules;
# otherwise we delete it, then make them from scratch.
#
# This code is supposed to clean up after itself by deleting its rules on
# exit.  In case that fails, it's not the end of the world; future runs will
# supercede it in the transproxy list, at least, so the leftover rules
# are hopefully harmless.
def main(method_name, syslog):
    stdin, stdout = setup_daemon()

    if method_name == "auto":
        method = get_auto_method()
    else:
        method = get_method(method_name)

    if syslog:
        ssyslog.start_syslog()
        ssyslog.stderr_to_syslog()

    debug1('firewall manager ready method name %s.\n' % method.name)
    stdout.write('READY %s\n' % method.name)
    stdout.flush()

    # we wait until we get some input before creating the rules.  That way,
    # sshuttle can launch us as early as possible (and get sudo password
    # authentication as early in the startup process as possible).
    line = stdin.readline(128)
    if not line:
        return  # parent died; nothing to do

    subnets = []
    if line != 'ROUTES\n':
        raise Fatal('firewall: expected ROUTES but got %r' % line)
    while 1:
        line = stdin.readline(128)
        if not line:
            raise Fatal('firewall: expected route but got %r' % line)
        elif line.startswith("NSLIST\n"):
            break
        try:
            (family, width, exclude, ip) = line.strip().split(',', 3)
        except:
            raise Fatal('firewall: expected route or NSLIST but got %r' % line)
        subnets.append((int(family), int(width), bool(int(exclude)), ip))
    debug2('Got subnets: %r\n' % subnets)

    nslist = []
    if line != 'NSLIST\n':
        raise Fatal('firewall: expected NSLIST but got %r' % line)
    while 1:
        line = stdin.readline(128)
        if not line:
            raise Fatal('firewall: expected nslist but got %r' % line)
        elif line.startswith("PORTS "):
            break
        try:
            (family, ip) = line.strip().split(',', 1)
        except:
            raise Fatal('firewall: expected nslist or PORTS but got %r' % line)
        nslist.append((int(family), ip))
        debug2('Got partial nslist: %r\n' % nslist)
    debug2('Got nslist: %r\n' % nslist)

    if not line.startswith('PORTS '):
        raise Fatal('firewall: expected PORTS but got %r' % line)
    _, _, ports = line.partition(" ")
    ports = ports.split(",")
    if len(ports) != 4:
        raise Fatal('firewall: expected 4 ports but got %n' % len(ports))
    port_v6 = int(ports[0])
    port_v4 = int(ports[1])
    dnsport_v6 = int(ports[2])
    dnsport_v4 = int(ports[3])

    assert(port_v6 >= 0)
    assert(port_v6 <= 65535)
    assert(port_v4 >= 0)
    assert(port_v4 <= 65535)
    assert(dnsport_v6 >= 0)
    assert(dnsport_v6 <= 65535)
    assert(dnsport_v4 >= 0)
    assert(dnsport_v4 <= 65535)

    debug2('Got ports: %d,%d,%d,%d\n'
           % (port_v6, port_v4, dnsport_v6, dnsport_v4))

    line = stdin.readline(128)
    if not line:
        raise Fatal('firewall: expected GO but got %r' % line)
    elif not line.startswith("GO "):
        raise Fatal('firewall: expected GO but got %r' % line)

    _, _, udp = line.partition(" ")
    udp = bool(int(udp))
    debug2('Got udp: %r\n' % udp)

    try:
        do_wait = None
        debug1('firewall manager: starting transproxy.\n')

        nslist_v6 = [i for i in nslist if i[0] == socket.AF_INET6]
        subnets_v6 = [i for i in subnets if i[0] == socket.AF_INET6]
        if port_v6 > 0:
            do_wait = method.setup_firewall(
                port_v6, dnsport_v6, nslist_v6,
                socket.AF_INET6, subnets_v6, udp)
        elif len(subnets_v6) > 0:
            debug1("IPv6 subnets defined but IPv6 disabled\n")

        nslist_v4 = [i for i in nslist if i[0] == socket.AF_INET]
        subnets_v4 = [i for i in subnets if i[0] == socket.AF_INET]
        if port_v4 > 0:
            do_wait = method.setup_firewall(
                port_v4, dnsport_v4, nslist_v4,
                socket.AF_INET, subnets_v4, udp)
        elif len(subnets_v4) > 0:
            debug1('IPv4 subnets defined but IPv4 disabled\n')

        stdout.write('STARTED\n')

        try:
            stdout.flush()
        except IOError:
            # the parent process died for some reason; he's surely been loud
            # enough, so no reason to report another error
            return

        # Now we wait until EOF or any other kind of exception.  We need
        # to stay running so that we don't need a *second* password
        # authentication at shutdown time - that cleanup is important!
        while 1:
            if do_wait is not None:
                do_wait()
            line = stdin.readline(128)
            if line.startswith('HOST '):
                (name, ip) = line[5:].strip().split(',', 1)
                hostmap[name] = ip
                rewrite_etc_hosts(port_v6 or port_v4)
            elif line:
                if not method.firewall_command(line):
                    raise Fatal('expected EOF, got %r' % line)
            else:
                break
    finally:
        try:
            debug1('firewall manager: undoing changes.\n')
        except:
            pass
        if port_v6:
            method.setup_firewall(port_v6, 0, [], socket.AF_INET6, [], udp)
        if port_v4:
            method.setup_firewall(port_v4, 0, [], socket.AF_INET, [], udp)
        restore_etc_hosts(port_v6 or port_v4)
