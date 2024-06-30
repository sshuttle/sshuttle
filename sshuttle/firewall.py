import errno
import shutil
import socket
import signal
import sys
import os
import platform
import traceback
import subprocess as ssubprocess
import base64
import io

import sshuttle.ssyslog as ssyslog
import sshuttle.helpers as helpers
from sshuttle.helpers import is_admin_user, log, debug1, debug2, debug3, Fatal
from sshuttle.methods import get_auto_method, get_method

if sys.platform == 'win32':
    HOSTSFILE = r"C:\Windows\System32\drivers\etc\hosts"
else:
    HOSTSFILE = '/etc/hosts'
sshuttle_pid = None


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
        try:
            os.link(HOSTSFILE, BAKFILE)
        except OSError:
            # file is locked - performing non-atomic copy
            shutil.copyfile(HOSTSFILE, BAKFILE)
    tmpname = "%s.%d.tmp" % (HOSTSFILE, port)
    f = open(tmpname, 'w')
    for line in old_content.rstrip().split('\n'):
        if line.find(APPEND) >= 0:
            continue
        f.write('%s\n' % line)
    for (name, ip) in sorted(hostmap.items()):
        f.write('%-30s %s\n' % ('%s %s' % (ip, name), APPEND))
    f.close()

    if sys.platform != 'win32':
        if st is not None:
            os.chown(tmpname, st.st_uid, st.st_gid)
            os.chmod(tmpname, st.st_mode)
        else:
            os.chown(tmpname, 0, 0)
            os.chmod(tmpname, 0o644)
    try:
        os.rename(tmpname, HOSTSFILE)
    except OSError:
        # file is locked - performing non-atomic copy
        log('Warning: Using a non-atomic way to overwrite %s that can corrupt the file if '
            'multiple processes write to it simultaneously.' % HOSTSFILE)
        shutil.move(tmpname, HOSTSFILE)


def restore_etc_hosts(hostmap, port):
    # Only restore if we added hosts to /etc/hosts previously.
    if len(hostmap) > 0:
        debug2('undoing /etc/hosts changes.')
        rewrite_etc_hosts({}, port)


def firewall_exit(signum, frame):
    # The typical sshuttle exit is that the main sshuttle process
    # exits, closes file descriptors it uses, and the firewall process
    # notices that it can't read from stdin anymore and exits
    # (cleaning up firewall rules).
    #
    # However, in some cases, Ctrl+C might get sent to the firewall
    # process. This might caused if someone manually tries to kill the
    # firewall process, or if sshuttle was started using sudo's use_pty option
    # and they try to exit by pressing Ctrl+C. Here, we forward the
    # Ctrl+C/SIGINT to the main sshuttle process which should trigger
    # the typical exit process as described above.
    global sshuttle_pid
    if sshuttle_pid:
        debug1("Relaying interupt signal to sshuttle process %d" % sshuttle_pid)
        if sys.platform == 'win32':
            sig = signal.CTRL_C_EVENT
        else:
            sig = signal.SIGINT
        os.kill(sshuttle_pid, sig)


def _setup_daemon_for_unix_like():
    if not is_admin_user():
        raise Fatal('You must have root privileges (or enable su/sudo) to set the firewall')

    # don't disappear if our controlling terminal or stdout/stderr
    # disappears; we still have to clean up.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, firewall_exit)
    signal.signal(signal.SIGINT, firewall_exit)

    # Calling setsid() here isn't strictly necessary. However, it forces
    # Ctrl+C to get sent to the main sshuttle process instead of to
    # the firewall process---which is our preferred way to shutdown.
    # Nonetheless, if the firewall process receives a SIGTERM/SIGINT
    # signal, it will relay a SIGINT to the main sshuttle process
    # automatically.
    try:
        os.setsid()
    except OSError:
        # setsid() fails if sudo is configured with the use_pty option.
        pass

    return sys.stdin.buffer, sys.stdout.buffer


def _setup_daemon_for_windows():
    if not is_admin_user():
        raise Fatal('You must be administrator to set the firewall')

    signal.signal(signal.SIGTERM, firewall_exit)
    signal.signal(signal.SIGINT, firewall_exit)

    com_chan = os.environ.get('SSHUTTLE_FW_COM_CHANNEL')
    if com_chan == 'stdio':
        debug3('Using inherited stdio for communicating with sshuttle client process')
    else:
        debug3('Using shared socket for communicating with sshuttle client process')
        socket_share_data = base64.b64decode(com_chan)
        sock = socket.fromshare(socket_share_data)  # type: socket.socket
        sys.stdin = io.TextIOWrapper(sock.makefile('rb', buffering=0))
        sys.stdout = io.TextIOWrapper(sock.makefile('wb', buffering=0), write_through=True)
        sock.close()
    return sys.stdin.buffer, sys.stdout.buffer


# Isolate function that needs to be replaced for tests
if sys.platform == 'win32':
    setup_daemon = _setup_daemon_for_windows
else:
    setup_daemon = _setup_daemon_for_unix_like


# Note that we're sorting in a very particular order:
# we need to go from smaller, more specific, port ranges, to larger,
# less-specific, port ranges. At each level, we order by subnet
# width, from most-specific subnets (largest swidth) to
# least-specific. On ties, excludes come first.
# s:(inet, subnet width, exclude flag, subnet, first port, last port)
def subnet_weight(s):
    return (-s[-1] + (s[-2] or -65535), s[1], s[2])


def flush_systemd_dns_cache():
    # If the user is using systemd-resolve for DNS resolution, it is
    # possible for the request to go through systemd-resolve before we
    # see it...and it may use a cached result instead of sending a
    # request that we can intercept. When sshuttle starts and stops,
    # this means that we should clear the cache!
    #
    # The command to do this was named systemd-resolve, but changed to
    # resolvectl in systemd 239.
    # https://github.com/systemd/systemd/blob/f8eb41003df1a4eab59ff9bec67b2787c9368dbd/NEWS#L3816

    p = None
    if helpers.which("resolvectl"):
        debug2("Flushing systemd's DNS resolver cache: "
               "resolvectl flush-caches")
        p = ssubprocess.Popen(["resolvectl", "flush-caches"],
                              stdout=ssubprocess.PIPE, env=helpers.get_env())
    elif helpers.which("systemd-resolve"):
        debug2("Flushing systemd's DNS resolver cache: "
               "systemd-resolve --flush-caches")
        p = ssubprocess.Popen(["systemd-resolve", "--flush-caches"],
                              stdout=ssubprocess.PIPE, env=helpers.get_env())

    if p:
        # Wait so flush is finished and process doesn't show up as defunct.
        rv = p.wait()
        if rv != 0:
            log("Received non-zero return code %d when flushing DNS resolver "
                "cache." % rv)


# This is some voodoo for setting up the kernel's transparent
# proxying stuff.  If subnets is empty, we just delete our sshuttle rules;
# otherwise we delete it, then make them from scratch.
#
# This code is supposed to clean up after itself by deleting its rules on
# exit.  In case that fails, it's not the end of the world; future runs will
# supersede it in the transproxy list, at least, so the leftover rules
# are hopefully harmless.
def main(method_name, syslog):
    helpers.logprefix = 'fw: '
    stdin, stdout = setup_daemon()
    hostmap = {}
    debug1('Starting firewall with Python version %s'
           % platform.python_version())

    if method_name == "auto":
        method = get_auto_method()
    else:
        method = get_method(method_name)

    if syslog:
        ssyslog.start_syslog()
        ssyslog.stderr_to_syslog()

    if not method.is_supported():
        raise Fatal("The %s method is not supported on this machine. "
                    "Check that the appropriate programs are in your "
                    "PATH." % method_name)

    debug1('ready method name %s.' % method.name)
    stdout.write(('READY %s\n' % method.name).encode('ASCII'))
    stdout.flush()

    def _read_next_string_line():
        try:
            line = stdin.readline(128)
            if not line:
                return  # parent probably exited
            return line.decode('ASCII').strip()
        except IOError as e:
            # On windows, ConnectionResetError is thrown when parent process closes it's socket pair end
            debug3('read from stdin failed: %s' % (e,))
            return
    # we wait until we get some input before creating the rules.  That way,
    # sshuttle can launch us as early as possible (and get sudo password
    # authentication as early in the startup process as possible).
    try:
        line = _read_next_string_line()
        if not line:
            return  # parent probably exited
    except IOError as e:
        # On windows, ConnectionResetError is thrown when parent process closes it's socket pair end
        debug3('read from stdin failed: %s' % (e,))
        return

    subnets = []
    if line != 'ROUTES':
        raise Fatal('expected ROUTES but got %r' % line)
    while 1:
        line = _read_next_string_line()
        if not line:
            raise Fatal('expected route but got %r' % line)
        elif line.startswith("NSLIST"):
            break
        try:
            (family, width, exclude, ip, fport, lport) = line.split(',', 5)
        except Exception:
            raise Fatal('expected route or NSLIST but got %r' % line)
        subnets.append((
            int(family),
            int(width),
            bool(int(exclude)),
            ip,
            int(fport),
            int(lport)))
    debug2('Got subnets: %r' % subnets)

    nslist = []
    if line != 'NSLIST':
        raise Fatal('expected NSLIST but got %r' % line)
    while 1:
        line = _read_next_string_line()
        if not line:
            raise Fatal('expected nslist but got %r' % line)
        elif line.startswith("PORTS "):
            break
        try:
            (family, ip) = line.split(',', 1)
        except Exception:
            raise Fatal('expected nslist or PORTS but got %r' % line)
        nslist.append((int(family), ip))
        debug2('Got partial nslist: %r' % nslist)
    debug2('Got nslist: %r' % nslist)

    if not line.startswith('PORTS '):
        raise Fatal('expected PORTS but got %r' % line)
    _, _, ports = line.partition(" ")
    ports = ports.split(",")
    if len(ports) != 4:
        raise Fatal('expected 4 ports but got %d' % len(ports))
    port_v6 = int(ports[0])
    port_v4 = int(ports[1])
    dnsport_v6 = int(ports[2])
    dnsport_v4 = int(ports[3])

    assert port_v6 >= 0
    assert port_v6 <= 65535
    assert port_v4 >= 0
    assert port_v4 <= 65535
    assert dnsport_v6 >= 0
    assert dnsport_v6 <= 65535
    assert dnsport_v4 >= 0
    assert dnsport_v4 <= 65535

    debug2('Got ports: %d,%d,%d,%d'
           % (port_v6, port_v4, dnsport_v6, dnsport_v4))

    line = _read_next_string_line()
    if not line or not line.startswith("GO "):
        raise Fatal('expected GO but got %r' % line)

    _, _, args = line.partition(" ")
    global sshuttle_pid
    udp, user, group, tmark, sshuttle_pid = args.split(" ", 4)
    udp = bool(int(udp))
    sshuttle_pid = int(sshuttle_pid)
    if user == '-':
        user = None
    if group == '-':
        group = None
    debug2('Got udp: %r, user: %r, group: %r, tmark: %s, sshuttle_pid: %d' %
           (udp, user, group, tmark, sshuttle_pid))

    subnets_v6 = [i for i in subnets if i[0] == socket.AF_INET6]
    nslist_v6 = [i for i in nslist if i[0] == socket.AF_INET6]
    subnets_v4 = [i for i in subnets if i[0] == socket.AF_INET]
    nslist_v4 = [i for i in nslist if i[0] == socket.AF_INET]

    try:
        debug1('setting up.')

        if subnets_v6 or nslist_v6:
            debug2('setting up IPv6.')
            method.setup_firewall(
                port_v6, dnsport_v6, nslist_v6,
                socket.AF_INET6, subnets_v6, udp,
                user, group, tmark)

        if subnets_v4 or nslist_v4:
            debug2('setting up IPv4.')
            method.setup_firewall(
                port_v4, dnsport_v4, nslist_v4,
                socket.AF_INET, subnets_v4, udp,
                user, group, tmark)

        try:
            # For some methods (eg: windivert) firewall setup will be differed / will run asynchronously.
            # Such method implements wait_for_firewall_ready() to wait until firewall is up and running.
            method.wait_for_firewall_ready(sshuttle_pid)
        except NotImplementedError:
            pass

        if sys.platform == 'linux':
            flush_systemd_dns_cache()

        try:
            stdout.write(b'STARTED\n')
            stdout.flush()
        except IOError as e:  # the parent process probably died
            debug3('write to stdout failed: %s' % (e,))
            return

        # Now we wait until EOF or any other kind of exception.  We need
        # to stay running so that we don't need a *second* password
        # authentication at shutdown time - that cleanup is important!
        while 1:
            line = _read_next_string_line()
            if not line:
                return
            if line.startswith('HOST '):
                (name, ip) = line[5:].split(',', 1)
                hostmap[name] = ip
                debug2('setting up /etc/hosts.')
                rewrite_etc_hosts(hostmap, port_v6 or port_v4)
            elif line:
                if not method.firewall_command(line):
                    raise Fatal('expected command, got %r' % line)
            else:
                break
    finally:
        try:
            debug1('undoing changes.')
        except Exception:
            debug2('An error occurred, ignoring it.')

        try:
            if subnets_v6 or nslist_v6:
                debug2('undoing IPv6 changes.')
                method.restore_firewall(port_v6, socket.AF_INET6, udp, user, group)
        except Exception:
            try:
                debug1("Error trying to undo IPv6 firewall.")
                debug1(traceback.format_exc())
            except Exception:
                debug2('An error occurred, ignoring it.')

        try:
            if subnets_v4 or nslist_v4:
                debug2('undoing IPv4 changes.')
                method.restore_firewall(port_v4, socket.AF_INET, udp, user, group)
        except Exception:
            try:
                debug1("Error trying to undo IPv4 firewall.")
                debug1(traceback.format_exc())
            except Exception:
                debug2('An error occurred, ignoring it.')

        try:
            # debug2() message printed in restore_etc_hosts() function.
            restore_etc_hosts(hostmap, port_v6 or port_v4)
        except Exception:
            try:
                debug1("Error trying to undo /etc/hosts changes.")
                debug1(traceback.format_exc())
            except Exception:
                debug2('An error occurred, ignoring it.')

        if sys.platform == 'linux':
            try:
                flush_systemd_dns_cache()
            except Exception:
                try:
                    debug1("Error trying to flush systemd dns cache.")
                    debug1(traceback.format_exc())
                except Exception:
                    debug2("An error occurred, ignoring it.")
