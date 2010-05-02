import subprocess, re
from helpers import *


def chain_exists(name):
    argv = ['iptables', '-t', 'nat', '-nL']
    p = subprocess.Popen(argv, stdout = subprocess.PIPE)
    for line in p.stdout:
        if line.startswith('Chain %s ' % name):
            return True
    rv = p.wait()
    if rv:
        raise Exception('%r returned %d' % (argv, rv))


def ipt(*args):
    argv = ['iptables', '-t', 'nat'] + list(args)
    log('>> %s\n' % ' '.join(argv))
    rv = subprocess.call(argv)
    if rv:
        raise Exception('%r returned %d' % (argv, rv))


# FIXME: this prints scary-looking errors
def main(port, subnets):
    assert(port > 0)
    assert(port <= 65535)

    chain = 'sshuttle-%s' % port

    # basic cleanup/setup of chains
    if chain_exists(chain):
        ipt('-D', 'OUTPUT', '-j', chain)
        ipt('-F', chain)
        ipt('-X', chain)

    if subnets:
        ipt('-N', chain)
        ipt('-F', chain)
        ipt('-I', 'OUTPUT', '1', '-j', chain)

        # create new subnet entries
        for snet,swidth in subnets:
            ipt('-A', chain, '-j', 'REDIRECT',
                '--dest', '%s/%s' % (snet,swidth),
                '-p', 'tcp',
                '--to-ports', str(port),
                '-m', 'ttl', '!', '--ttl', '42'  # to prevent infinite loops
                )
    subnets_str = ['%s/%d' % (ip,width) for ip,width in subnets]
