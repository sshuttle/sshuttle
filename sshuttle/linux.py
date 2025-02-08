import socket
import subprocess as ssubprocess
from sshuttle.helpers import log, debug1, Fatal, family_to_string, get_env


def nonfatal(func, *args):
    try:
        func(*args)
    except Fatal as e:
        log('error: %s' % e)


def ipt_chain_exists(family, table, name):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-w', '-t', table, '-nL']
    try:
        output = ssubprocess.check_output(argv, env=get_env())
        for line in output.decode('ASCII', errors='replace').split('\n'):
            if line.startswith('Chain %s ' % name):
                return True
    except ssubprocess.CalledProcessError as e:
        raise Fatal('%r returned %d' % (argv, e.returncode))


def ipt(family, table, *args):
    if family == socket.AF_INET6:
        argv = ['ip6tables', '-w', '-t', table] + list(args)
    elif family == socket.AF_INET:
        argv = ['iptables', '-w', '-t', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('%s' % ' '.join(argv))
    rv = ssubprocess.call(argv, env=get_env())
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def nft(family, table, action, *args):
    if family in (socket.AF_INET, socket.AF_INET6):
        argv = ['nft', action, 'inet', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('%s' % ' '.join(argv))
    rv = ssubprocess.call(argv, env=get_env())
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))
