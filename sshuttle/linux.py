import re
import os
import socket
import subprocess as ssubprocess

from sshuttle.helpers import log, debug1, Fatal, family_to_string


def nonfatal(func, *args):
    try:
        func(*args)
    except Fatal as e:
        log('error: %s\n' % e)


def ipt_chain_exists(family, table, name):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-t', table, '-nL']
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    try:
        output = ssubprocess.check_output(argv, env=env)
        for line in output.decode('ASCII').split('\n'):
            if line.startswith('Chain %s ' % name):
                return True
    except ssubprocess.CalledProcessError as e:
        raise Fatal('%r returned %d' % (argv, e.returncode))


def ipt(family, table, *args):
    if family == socket.AF_INET6:
        argv = ['ip6tables', '-t', table] + list(args)
    elif family == socket.AF_INET:
        argv = ['iptables', '-t', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('>> %s\n' % ' '.join(argv))
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    rv = ssubprocess.call(argv, env=env)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def nft(family, table, action, *args):
    if family == socket.AF_INET:
        argv = ['nft', action, 'ip', table] + list(args)
    elif family == socket.AF_INET6:
        argv = ['nft', action, 'ip6', table] + list(args)
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    debug1('>> %s\n' % ' '.join(argv))
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    rv = ssubprocess.call(argv, env=env)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def nft_chain_exists(family, table, name):
    if family == socket.AF_INET:
        fam = 'ip'
    elif family == socket.AF_INET6:
        fam = 'ip6'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = ['nft', 'list', 'chain', fam, table, name]
    debug1('>> %s\n' % ' '.join(argv))
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    try:
        table_exists = False
        output = ssubprocess.check_output(argv, env=env,
                                          stderr=ssubprocess.STDOUT)
        for line in output.decode('ASCII').split('\n'):
            if line.startswith('table %s %s ' % (fam, table)):
                table_exists = True
            if table_exists and ('chain %s {' % name) in line:
                return True
    except ssubprocess.CalledProcessError:
        return False


def nft_get_handle(expression, chain):
    cmd = 'nft'
    argv = [cmd, 'list', expression, '-a']
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    try:
        output = ssubprocess.check_output(argv, env=env)
        for line in output.decode('utf-8').split('\n'):
            if ('jump %s' % chain) in line:
                return re.sub('.*# ', '', line)
    except ssubprocess.CalledProcessError as e:
        raise Fatal('%r returned %d' % (argv, e.returncode))


_no_ttl_module = False


def ipt_ttl(family, *args):
    global _no_ttl_module
    if not _no_ttl_module:
        # we avoid infinite loops by generating server-side connections
        # with ttl 42.  This makes the client side not recapture those
        # connections, in case client == server.
        try:
            argsplus = list(args) + ['-m', 'ttl', '!', '--ttl', '42']
            ipt(family, *argsplus)
        except Fatal:
            ipt(family, *args)
            # we only get here if the non-ttl attempt succeeds
            log('sshuttle: warning: your iptables is missing '
                'the ttl module.\n')
            _no_ttl_module = True
    else:
        ipt(family, *args)
