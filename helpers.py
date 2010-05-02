import sys, os

logprefix = ''

def log(s):
    sys.stdout.flush()
    sys.stderr.write(logprefix + s)
    sys.stderr.flush()
