import sys, os, syslog

logprefix = ''
verbose = 0
do_syslog = False

def log(s):
    try:
        if do_syslog:
            syslog.syslog(logprefix + s)
        else:
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
