import socket
import subprocess as ssubprocess
from sshuttle.helpers import log, debug1, Fatal, family_to_string, get_env


def nonfatal(func, *args):
    try:
        func(*args)
    except Fatal as e:
        log('fw: error: %s\n' % e)


def ipt_chain_exists(family, table, name):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-t', table, '-nL']
    try:
        output = ssubprocess.check_output(argv, env=get_env())
        for line in output.decode('ASCII').split('\n'):
            if line.startswith('Chain %s ' % name):
                return True
    except ssubprocess.CalledProcessError as e:
        raise Fatal('fw: %r returned %d' % (argv, e.returncode))


def ipt(family, table, *args):
    if family == socket.AF_INET6:
        argv = ['ip6tables', '-t', table] + list(args)
    elif family == socket.AF_INET:
        argv = ['iptables', '-t', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('%s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv, env=get_env())
    if rv:
        raise Fatal('fw: %r returned %d' % (argv, rv))


def nft(family, table, action, *args):
    if family in (socket.AF_INET, socket.AF_INET6):
        argv = ['nft', action, 'inet', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('%s\n' % ' '.join(argv))
    rv = ssubprocess.call(argv, env=get_env())
    if rv:
        raise Fatal('fw: %r returned %d' % (argv, rv))


_no_ttl_module = False


def ipt_ttl(family, *args):
    global _no_ttl_module
    if not _no_ttl_module:
        # we avoid infinite loops by generating server-side connections
        # with ttl 63.  This makes the client side not recapture those
        # connections, in case client == server.
        try:
            argsplus = list(args)
            ipt(family, *argsplus)
        except Fatal:
            ipt(family, *args)
            # we only get here if the non-ttl attempt succeeds
            log('fw: WARNING: your iptables is missing '
                'the ttl module.\n')
            _no_ttl_module = True
    else:
        ipt(family, *args)
