import sys
import socket
import errno

logprefix = ''
verbose = 0


def log(s):
    try:
        sys.stdout.flush()
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


def list_contains_any(l, sub):
    for i in sub:
        if i in l:
            return True
    return False


def resolvconf_nameservers():
    l = []
    for line in open('/etc/resolv.conf'):
        words = line.lower().split()
        if len(words) >= 2 and words[0] == 'nameserver':
            if ':' in words[1]:
                l.append((socket.AF_INET6, words[1]))
            else:
                l.append((socket.AF_INET, words[1]))
    return l


def resolvconf_random_nameserver():
    l = resolvconf_nameservers()
    if l:
        if len(l) > 1:
            # don't import this unless we really need it
            import random
            random.shuffle(l)
        return l[0]
    else:
        return (socket.AF_INET, '127.0.0.1')


def islocal(ip, family):
    sock = socket.socket(family)
    try:
        try:
            sock.bind((ip, 0))
        except socket.error, e:
            if e.args[0] == errno.EADDRNOTAVAIL:
                return False  # not a local IP
            else:
                raise
    finally:
        sock.close()
    return True  # it's a local IP, or there would have been an error


def family_to_string(family):
    if family == socket.AF_INET6:
        return "AF_INET6"
    elif family == socket.AF_INET:
        return "AF_INET"
    else:
        return str(family)
