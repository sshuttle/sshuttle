import sys, os
from compat import ssubprocess


_p = None
def start_syslog():
    global _p
    _p = ssubprocess.Popen(['logger',
                            '-p', 'daemon.notice',
                            '-t', 'sshuttle'], stdin=ssubprocess.PIPE)


def stderr_to_syslog():
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(_p.stdin.fileno(), 2)
