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
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=env)
    for line in p.stdout:
        if line.startswith(b'Chain %s ' % name.encode("ASCII")):
            return True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


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


def nft_get_handle(expression, chain):
    cmd = 'nft'
    argv = [cmd, 'list', expression, '-a']
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=env)
    for line in p.stdout:
        if (b'jump %s' % chain.encode('utf-8')) in line:
            return re.sub('.*# ', '', line.decode('utf-8'))
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))




def ipt_ttl(family, *args):
    ipt(family, *args)
