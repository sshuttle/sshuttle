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


# This is some iptables voodoo for setting up the Linux kernel's transparent
# proxying stuff.  If subnets is empty, we just delete our sshuttle chain;
# otherwise we delete it, then make it from scratch.
#
# We name the chain based on the transproxy port number so that it's possible
# to run multiple copies of sshuttle at the same time.  Of course, the
# multiple copies shouldn't have overlapping subnets, or only the most-
# recently-started one will win (because we use "-I OUTPUT 1" instead of
# "-A OUTPUT").
#
# sshuttle is supposed to clean up after itself by deleting extra chains on
# exit.  In case that fails, it's not the end of the world; future runs will
# supercede it in the transproxy list, at least, so the leftover iptables
# chains are mostly harmless.
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
