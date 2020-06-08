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
    argv = [cmd, '-w', '-t', table, '-nL']
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

def ipt_rule_exists(family, table, chain, name):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-w', '-t', table, '-nL', chain]
    debug1('>> %s\n' % ' '.join(argv))
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, env=env)
    for line in p.stdout:
        if line.startswith(name.encode("ASCII")):
            return True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def ipt_rule_count(family, table, chain):
    if family == socket.AF_INET6:
        cmd = 'ip6tables'
    elif family == socket.AF_INET:
        cmd = 'iptables'
    else:
        raise Exception('Unsupported family "%s"' % family_to_string(family))
    argv = [cmd, '-w', '-t', table, '-L', chain]
    argv1 = ['grep',  '-Ecv', "^$|^Chain |^target"]
    debug1('>> %s\n' % ' '.join(argv))
    env = {
        'PATH': os.environ['PATH'],
        'LC_ALL': "C",
    }
    iptables_process = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, shell=False, env=env)
    grep_process = ssubprocess.Popen(argv1, stdin=iptables_process.stdout, stdout=ssubprocess.PIPE, shell=False, env=env)
    iptables_process.stdout.close()
    return int(grep_process.communicate()[0])


def ipt(family, table, *args):
    if family == socket.AF_INET6:
        argv = ['ip6tables', '-w', '-t', table] + list(args)
    elif family == socket.AF_INET:
        argv = ['iptables', '-w', '-t', table] + list(args)
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
