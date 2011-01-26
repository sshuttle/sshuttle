import sys, os

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
            l.append(words[1])
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
        return '127.0.0.1'
    
    
