import sys
import socket
import errno
import os

logprefix = ''
verbose = 0


def b(s):
    return s.encode("ASCII")


def log(s):
    global logprefix
    try:
        sys.stdout.flush()
        if s.find("\n") != -1:
            prefix = logprefix
            s = s.rstrip("\n")
            for line in s.split("\n"):
                sys.stderr.write(prefix + line + "\n")
                prefix = "---> "
        else:
            sys.stderr.write(logprefix + s)
        sys.stderr.flush()
    except IOError:
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


def resolvconf_nameservers():
    lines = []
    for line in open('/etc/resolv.conf'):
        words = line.lower().split()
        if len(words) >= 2 and words[0] == 'nameserver':
            lines.append(family_ip_tuple(words[1]))
    return lines


def resolvconf_random_nameserver():
    lines = resolvconf_nameservers()
    if lines:
        if len(lines) > 1:
            # don't import this unless we really need it
            import random
            random.shuffle(lines)
        return lines[0]
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
        debug2("which() found '%s' at %s\n" % (file, rv))
    else:
        debug2("which() could not find '%s' in %s\n" % (file, path))
    return rv
