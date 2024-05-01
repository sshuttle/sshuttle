import sys
import socket
import errno
import os
import threading
import subprocess
import traceback
import re

if sys.platform != "win32":
    import fcntl

logprefix = ''
verbose = 0


def b(s):
    return s.encode("ASCII")


def get_verbose_level():
    return verbose


def log(s):
    global logprefix
    try:
        sys.stdout.flush()
    except (IOError, ValueError):  # ValueError ~ I/O operation on closed file
        pass
    try:
        # Put newline at end of string if line doesn't have one.
        if not s.endswith("\n"):
            s = s+"\n"

        prefix = logprefix
        s = s.rstrip("\n")
        for line in s.split("\n"):
            sys.stderr.write(prefix + line + "\n")
            prefix = "    "
        sys.stderr.flush()
    except (IOError, ValueError):  # ValueError ~ I/O operation on closed file
        # this could happen if stderr gets forcibly disconnected, eg. because
        # our tty closes.  That sucks, but it's no reason to abort the program.
        pass


def debug1(s):
    if verbose >= 1:
        log(s)


def debug2(s):
    if verbose >= 2:
        log(s)


def debug3(s):
    if verbose >= 3:
        log(s)


class Fatal(Exception):
    pass


def resolvconf_nameservers(systemd_resolved):
    """Retrieves a list of tuples (address type, address as a string) of
    the DNS servers used by the system to resolve hostnames.

    If parameter is False, DNS servers are retrieved from only
    /etc/resolv.conf. This behavior makes sense for the sshuttle
    server.

    If parameter is True, we retrieve information from both
    /etc/resolv.conf and /run/systemd/resolve/resolv.conf (if it
    exists). This behavior makes sense for the sshuttle client.

    """

    # Historically, we just needed to read /etc/resolv.conf.
    #
    # If systemd-resolved is active, /etc/resolv.conf will point to
    # localhost and the actual DNS servers that systemd-resolved uses
    # are stored in /run/systemd/resolve/resolv.conf. For programs
    # that use the localhost DNS server, having sshuttle read
    # /etc/resolv.conf is sufficient. However, resolved provides other
    # ways of resolving hostnames (such as via dbus) that may not
    # route requests through localhost. So, we retrieve a list of DNS
    # servers that resolved uses so we can intercept those as well.
    #
    # For more information about systemd-resolved, see:
    # https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html
    #
    # On machines without systemd-resolved, we expect opening the
    # second file will fail.
    files = ['/etc/resolv.conf']
    if systemd_resolved:
        files += ['/run/systemd/resolve/resolv.conf']

    nsservers = []
    for f in files:
        this_file_nsservers = []
        try:
            for line in open(f):
                words = line.lower().split()
                if len(words) >= 2 and words[0] == 'nameserver':
                    this_file_nsservers.append(family_ip_tuple(words[1]))
            debug2("Found DNS servers in %s: %s" %
                   (f, [n[1] for n in this_file_nsservers]))
            nsservers += this_file_nsservers
        except OSError as e:
            debug3("Failed to read %s when looking for DNS servers: %s" %
                   (f, e.strerror))

    return nsservers


def windows_nameservers():
    out = subprocess.check_output(["powershell", "-NonInteractive", "-NoProfile", "-Command", "Get-DnsClientServerAddress"],
                                  encoding="utf-8")
    servers = set()
    for line in out.splitlines():
        if line.startswith("Loopback "):
            continue
        m = re.search(r'{.+}', line)
        if not m:
            continue
        for s in m.group().strip('{}').split(','):
            s = s.strip()
            if s.startswith('fec0:0:0:ffff'):
                continue
            servers.add(s)
    debug2("Found DNS servers: %s" % servers)
    return [(socket.AF_INET6 if ':' in s else socket.AF_INET, s) for s in servers]


def get_random_nameserver():
    """Return a random nameserver selected from servers produced by
    resolvconf_nameservers()/windows_nameservers()
    """
    if sys.platform == "win32":
        if globals().get('_nameservers') is None:
            ns_list = windows_nameservers()
            globals()['_nameservers'] = ns_list
        else:
            ns_list = globals()['_nameservers']
    else:
        ns_list = resolvconf_nameservers(systemd_resolved=False)
    if ns_list:
        if len(ns_list) > 1:
            # don't import this unless we really need it
            import random
            random.shuffle(ns_list)
        return ns_list[0]
    else:
        return (socket.AF_INET, '127.0.0.1')


def islocal(ip, family):
    sock = socket.socket(family)
    try:
        try:
            sock.bind((ip, 0))
        except socket.error:
            _, e = sys.exc_info()[:2]
            if e.args[0] == errno.EADDRNOTAVAIL:
                return False  # not a local IP
            else:
                raise
    finally:
        sock.close()
    return True  # it's a local IP, or there would have been an error


def family_ip_tuple(ip):
    if ':' in ip:
        return (socket.AF_INET6, ip)
    else:
        return (socket.AF_INET, ip)


def family_to_string(family):
    if family == socket.AF_INET6:
        return "AF_INET6"
    elif family == socket.AF_INET:
        return "AF_INET"
    else:
        return str(family)


def get_env():
    """An environment for sshuttle subprocesses. See get_path()."""
    env = {
        'PATH': get_path(),
        'LC_ALL': "C",
    }
    return env


def get_path():
    """Returns a string of paths separated by os.pathsep.

    Users might not have all of the programs sshuttle needs in their
    PATH variable (i.e., some programs might be in /sbin). Use PATH
    and a hardcoded set of paths to search through. This function is
    used by our which() and get_env() functions. If which() and the
    subprocess environments differ, programs that which() finds might
    not be found at run time (or vice versa).
    """
    path = []
    if "PATH" in os.environ:
        path += os.environ["PATH"].split(os.pathsep)
    # Python default paths.
    path += os.defpath.split(os.pathsep)
    # /sbin, etc are not in os.defpath and may not be in PATH either.
    # /bin/ and /usr/bin below are probably redundant.
    path += ['/bin', '/usr/bin', '/sbin', '/usr/sbin']

    # Remove duplicates. Not strictly necessary.
    path_dedup = []
    for i in path:
        if i not in path_dedup:
            path_dedup.append(i)

    return os.pathsep.join(path_dedup)


if sys.version_info >= (3, 3):
    from shutil import which as _which
else:
    # Although sshuttle does not officially support older versions of
    # Python, some still run the sshuttle server on remote machines
    # with old versions of python.
    def _which(file, mode=os.F_OK | os.X_OK, path=None):
        if path is not None:
            search_paths = path.split(os.pathsep)
        elif "PATH" in os.environ:
            search_paths = os.environ["PATH"].split(os.pathsep)
        else:
            search_paths = os.defpath.split(os.pathsep)

        for p in search_paths:
            filepath = os.path.join(p, file)
            if os.path.exists(filepath) and os.access(filepath, mode):
                return filepath
        return None


def which(file, mode=os.F_OK | os.X_OK):
    """A wrapper around shutil.which() that searches a predictable set of
    paths and is more verbose about what is happening. See get_path()
    for more information.
    """
    path = get_path()
    rv = _which(file, mode, path)
    if rv:
        debug2("which() found '%s' at %s" % (file, rv))
    else:
        debug2("which() could not find '%s' in %s" % (file, path))
    return rv


def is_admin_user():
    if sys.platform == 'win32':
        # https://stackoverflow.com/questions/130763/request-uac-elevation-from-within-a-python-script/41930586#41930586
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    # TODO(nom3ad): for sys.platform == 'linux', check capabilities for non-root users. (CAP_NET_ADMIN might be enough?)
    return os.getuid() == 0


def set_non_blocking_io(fd):
    if sys.platform != "win32":
        try:
            os.set_blocking(fd, False)
        except AttributeError:
            # python < 3.5
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
            flags |= os.O_NONBLOCK
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
    else:
        _sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
        _sock.setblocking(False)


class RWPair:
    def __init__(self, r, w):
        self.r = r
        self.w = w
        self.read = r.read
        self.readline = r.readline
        self.write = w.write
        self.flush = w.flush

    def close(self):
        for f in self.r, self.w:
            try:
                f.close()
            except Exception:
                pass


class SocketRWShim:
    __slots__ = ('_r', '_w', '_on_end', '_s1', '_s2', '_t1', '_t2')

    def __init__(self, r, w, on_end=None):
        self._r = r
        self._w = w
        self._on_end = on_end

        self._s1, self._s2 = socket.socketpair()
        debug3("[SocketShim] r=%r w=%r | s1=%r s2=%r" % (self._r, self._w, self._s1, self._s2))

        def stream_reader_to_sock():
            try:
                for data in iter(lambda:  self._r.read(16384), b''):
                    self._s1.sendall(data)
                    # debug3("[SocketRWShim] <<<<< r.read() %d %r..." % (len(data), data[:min(32, len(data))]))
            except Exception:
                traceback.print_exc(file=sys.stderr)
            finally:
                debug2("[SocketRWShim] Thread 'stream_reader_to_sock' exiting")
                self._s1.close()
                self._on_end and self._on_end()

        def stream_sock_to_writer():
            try:
                for data in iter(lambda: self._s1.recv(16384), b''):
                    while data:
                        n = self._w.write(data)
                        data = data[n:]
                    # debug3("[SocketRWShim] <<<<< w.write() %d %r..." % (len(data), data[:min(32, len(data))]))
            except Exception:
                traceback.print_exc(file=sys.stderr)
            finally:
                debug2("[SocketRWShim] Thread 'stream_sock_to_writer' exiting")
                self._s1.close()
                self._on_end and self._on_end()

        self._t1 = threading.Thread(target=stream_reader_to_sock,  name='stream_reader_to_sock', daemon=True).start()
        self._t2 = threading.Thread(target=stream_sock_to_writer, name='stream_sock_to_writer',  daemon=True).start()

    def makefiles(self):
        return self._s2.makefile("rb", buffering=0), self._s2.makefile("wb", buffering=0)
