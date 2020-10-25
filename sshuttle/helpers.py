import sys
import socket
import errno

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
    """Retrieves a list of tuples (address type, address as a string) that
    the current system uses to resolve hostnames from /etc/resolv.conf
    and possibly other files.
    """

    # Historically, we just needed to read /etc/resolv.conf.
    #
    # If systemd-resolved is active, /etc/resolv.conf will point to
    # localhost and the actual DNS servers that systemd-resolved uses
    # are stored in /run/systemd/resolve/resolv.conf. For programs
    # that use the localhost DNS server, only reading /etc/resolv.conf
    # is sufficient. However, resolved provides other ways of
    # resolving hostnames (such as via dbus) that may not route
    # requests through localhost. So, we retrieve a list of DNS
    # servers that resolved uses so we can intercept those as well.
    #
    # For more information about systemd-resolved, see:
    # https://www.freedesktop.org/software/systemd/man/systemd-resolved.service.html
    #
    # On machines without systemd-resolved, we expect opening the
    # second file will fail.
    files = ['/etc/resolv.conf', '/run/systemd/resolve/resolv.conf']

    nsservers = []
    for f in files:
        this_file_nsservers = []
        try:
            for line in open(f):
                words = line.lower().split()
                if len(words) >= 2 and words[0] == 'nameserver':
                    this_file_nsservers.append(family_ip_tuple(words[1]))
            debug2("Found DNS servers in %s: %s\n" %
                   (f, [n[1] for n in this_file_nsservers]))
            nsservers += this_file_nsservers
        except OSError as e:
            debug3("Failed to read %s when looking for DNS servers: %s\n" %
                   (f, e.strerror))

    return nsservers


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
