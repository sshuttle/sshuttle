import errno
import socket
import signal
import sshuttle.ssyslog as ssyslog
import sys
import os
import platform
import traceback
from sshuttle.helpers import debug1, debug2, Fatal
from sshuttle.methods import get_auto_method, get_method

HOSTSFILE = '/etc/hosts'


def rewrite_etc_hosts(hostmap, port):
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

    if st is not None:
        os.chown(tmpname, st.st_uid, st.st_gid)
        os.chmod(tmpname, st.st_mode)
    else:
        os.chown(tmpname, 0, 0)
        os.chmod(tmpname, 0o600)
    os.rename(tmpname, HOSTSFILE)


def restore_etc_hosts(port):
    rewrite_etc_hosts({}, port)


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


# Note that we're sorting in a very particular order:
# we need to go from most-specific (largest swidth) to least-specific,
# and at any given level of specificity, smaller port ranges come
# before larger port ranges. On ties excludes come first.
# s:(inet, subnet width, exclude flag, subnet, first port, last port)
def subnet_weight(s):
    return (s[1], s[-2] or -65535 - s[-1], s[2])


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
    hostmap = {}

    debug1('firewall manager: Starting firewall with Python version %s\n'
           % platform.python_version())

    if method_name == "auto":
        method = get_auto_method()
    else:
        method = get_method(method_name)

    if syslog:
        ssyslog.start_syslog()
        ssyslog.stderr_to_syslog()

    debug1('firewall manager: ready method name %s.\n' % method.name)
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
            (family, width, exclude, ip, fport, lport) = \
                    line.strip().split(',', 5)
        except:
            raise Fatal('firewall: expected route or NSLIST but got %r' % line)
        subnets.append((
            int(family),
            int(width),
            bool(int(exclude)),
            ip,
            int(fport),
            int(lport)))
    debug2('firewall manager: Got subnets: %r\n' % subnets)

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
        debug2('firewall manager: Got partial nslist: %r\n' % nslist)
    debug2('firewall manager: Got nslist: %r\n' % nslist)

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

    debug2('firewall manager: Got ports: %d,%d,%d,%d\n'
           % (port_v6, port_v4, dnsport_v6, dnsport_v4))

    line = stdin.readline(128)
    if not line:
        raise Fatal('firewall: expected GO but got %r' % line)
    elif not line.startswith("GO "):
        raise Fatal('firewall: expected GO but got %r' % line)

    _, _, udp = line.partition(" ")
    udp = bool(int(udp))
    debug2('firewall manager: Got udp: %r\n' % udp)

    subnets_v6 = [i for i in subnets if i[0] == socket.AF_INET6]
    nslist_v6 = [i for i in nslist if i[0] == socket.AF_INET6]
    subnets_v4 = [i for i in subnets if i[0] == socket.AF_INET]
    nslist_v4 = [i for i in nslist if i[0] == socket.AF_INET]

    try:
        debug1('firewall manager: setting up.\n')

        if len(subnets_v6) > 0 or len(nslist_v6) > 0:
            debug2('firewall manager: setting up IPv6.\n')
            method.setup_firewall(
                port_v6, dnsport_v6, nslist_v6,
                socket.AF_INET6, subnets_v6, udp)

        if len(subnets_v4) > 0 or len(nslist_v4) > 0:
            debug2('firewall manager: setting up IPv4.\n')
            method.setup_firewall(
                port_v4, dnsport_v4, nslist_v4,
                socket.AF_INET, subnets_v4, udp)

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
            line = stdin.readline(128)
            if line.startswith('HOST '):
                (name, ip) = line[5:].strip().split(',', 1)
                hostmap[name] = ip
                debug2('firewall manager: setting up /etc/hosts.\n')
                rewrite_etc_hosts(hostmap, port_v6 or port_v4)
            elif line:
                if not method.firewall_command(line):
                    raise Fatal('firewall: expected command, got %r' % line)
            else:
                break
    finally:
        try:
            sdnotify.send(sdnotify.stop())
            debug1('firewall manager: undoing changes.\n')
        except:
            pass

        try:
            if len(subnets_v6) > 0 or len(nslist_v6) > 0:
                debug2('firewall manager: undoing IPv6 changes.\n')
                method.restore_firewall(port_v6, socket.AF_INET6, udp)
        except:
            try:
                debug1("firewall manager: "
                       "Error trying to undo IPv6 firewall.\n")
                for line in traceback.format_exc().splitlines():
                    debug1("---> %s\n" % line)
            except:
                pass

        try:
            if len(subnets_v4) > 0 or len(nslist_v4) > 0:
                debug2('firewall manager: undoing IPv4 changes.\n')
                method.restore_firewall(port_v4, socket.AF_INET, udp)
        except:
            try:
                debug1("firewall manager: "
                       "Error trying to undo IPv4 firewall.\n")
                for line in traceback.format_exc().splitlines():
                    debug1("firewall manager: ---> %s\n" % line)
            except:
                pass

        try:
            debug2('firewall manager: undoing /etc/hosts changes.\n')
            restore_etc_hosts(port_v6 or port_v4)
        except:
            try:
                debug1("firewall manager: "
                       "Error trying to undo /etc/hosts changes.\n")
                for line in traceback.format_exc().splitlines():
                    debug1("firewall manager: ---> %s\n" % line)
            except:
                pass
