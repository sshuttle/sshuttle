import subprocess, re
import helpers
from helpers import *


def chain_exists(name):
    argv = ['iptables', '-t', 'nat', '-nL']
    p = subprocess.Popen(argv, stdout = subprocess.PIPE)
    for line in p.stdout:
        if line.startswith('Chain %s ' % name):
            return True
    rv = p.wait()
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def ipt(*args):
    argv = ['iptables', '-t', 'nat'] + list(args)
    debug1('>> %s\n' % ' '.join(argv))
    rv = subprocess.call(argv)
    if rv:
        raise Fatal('%r returned %d' % (argv, rv))


def do_it(port, subnets):
    chain = 'sshuttle-%s' % port

    # basic cleanup/setup of chains
    if chain_exists(chain):
        ipt('-D', 'OUTPUT', '-j', chain)
        ipt('-D', 'PREROUTING', '-j', chain)
        ipt('-F', chain)
        ipt('-X', chain)

    if subnets:
        ipt('-N', chain)
        ipt('-F', chain)
        ipt('-I', 'OUTPUT', '1', '-j', chain)
        ipt('-I', 'PREROUTING', '1', '-j', chain)

        # create new subnet entries
        for snet,swidth in subnets:
            ipt('-A', chain, '-j', 'REDIRECT',
                '--dest', '%s/%s' % (snet,swidth),
                '-p', 'tcp',
                '--to-ports', str(port),
                '-m', 'ttl', '!', '--ttl', '42'  # to prevent infinite loops
                )


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
# This code is supposed to clean up after itself by deleting extra chains on
# exit.  In case that fails, it's not the end of the world; future runs will
# supercede it in the transproxy list, at least, so the leftover iptables
# chains are mostly harmless.
def main(port, subnets):
    assert(port > 0)
    assert(port <= 65535)

    if os.getuid() != 0:
        raise Fatal('you must be root (or enable su/sudo) to set up iptables')

    # because of limitations of the 'su' command, the *real* stdin/stdout
    # are both attached to stdout initially.  Clone stdout into stdin so we
    # can read from it.
    os.dup2(1, 0)

    debug1('iptables manager ready.\n')
    sys.stdout.write('READY\n')
    sys.stdout.flush()

    # ctrl-c shouldn't be passed along to me.  When the main sshuttle dies,
    # I'll die automatically.
    os.setsid()

    # we wait until we get some input before creating the rules.  That way,
    # sshuttle can launch us as early as possible (and get sudo password
    # authentication as early in the startup process as possible).
    sys.stdin.readline(128)
    try:
        do_it(port, subnets)

        sys.stdout.write('STARTED\n')
        sys.stdout.flush()

        # Now we wait until EOF or any other kind of exception.  We need
        # to stay running so that we don't need a *second* password
        # authentication at shutdown time - that cleanup is important!
        while sys.stdin.readline(128):
            pass
    finally:
        do_it(port, [])
