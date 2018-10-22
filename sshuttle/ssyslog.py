import sys
import os
import subprocess as ssubprocess


_p = None


def start_syslog():
    global _p
    with open(os.devnull, 'w') as devnull:
        _p = ssubprocess.Popen(
            ['logger', '-p', 'daemon.notice', '-t', 'sshuttle'],
            stdin=ssubprocess.PIPE,
            stdout=devnull,
            stderr=devnull
        )


def close_stdin():
    sys.stdin.close()


def stdout_to_syslog():
    sys.stdout.flush()
    os.dup2(_p.stdin.fileno(), sys.stdout.fileno())


def stderr_to_syslog():
    sys.stderr.flush()
    os.dup2(_p.stdin.fileno(), sys.stderr.fileno())
