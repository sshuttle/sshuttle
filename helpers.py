import sys, os

logprefix = ''
verbose = 0

def log(s):
    sys.stdout.flush()
    sys.stderr.write(logprefix + s)
    sys.stderr.flush()

def debug1(s):
    if verbose >= 1:
        log(s)

def debug2(s):
    if verbose >= 2:
        log(s)


class Fatal(Exception):
    pass
