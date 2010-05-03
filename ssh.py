import sys, os, re, subprocess, socket
import helpers
from helpers import *

def connect(rhost):
    main_exe = sys.argv[0]
    nicedir = os.path.split(os.path.abspath(main_exe))[0]
    nicedir = re.sub(r':', "_", nicedir)
    myhome = os.path.expanduser('~') + '/'
    if nicedir.startswith(myhome):
        nicedir2 = nicedir[len(myhome):]
    else:
        nicedir2 = nicedir
    if rhost == '-':
        rhost = None
    if not rhost:
        argv = ['sshuttle', '--server'] + ['-v']*(helpers.verbose or 0)
    else:
        # WARNING: shell quoting security holes are possible here, so we
        # have to be super careful.  We have to use 'sh -c' because
        # csh-derived shells can't handle PATH= notation.  We can't
        # set PATH in advance, because ssh probably replaces it.  We
        # can't exec *safely* using argv, because *both* ssh and 'sh -c'
        # allow shellquoting.  So we end up having to double-shellquote
        # stuff here.
        escapedir  = re.sub(r'([^\w/])', r'\\\\\\\1', nicedir)
        escapedir2 = re.sub(r'([^\w/])', r'\\\\\\\1', nicedir2)
        cmd = r"""
                   sh -c PATH=%s:'$HOME'/%s:'$PATH exec sshuttle --server%s'
               """ % (escapedir, escapedir2,
                      ' -v' * (helpers.verbose or 0))
        argv = ['ssh', rhost, '--', cmd.strip()]
        debug2('executing: %r\n' % argv)
    (s1,s2) = socket.socketpair()
    def setup():
        # runs in the child process
        s2.close()
        if not rhost:
            os.environ['PATH'] = ':'.join([nicedir,
                                           os.environ.get('PATH', '')])
        os.setsid()
    s1a,s1b = os.dup(s1.fileno()), os.dup(s1.fileno())
    s1.close()
    p = subprocess.Popen(argv, stdin=s1a, stdout=s1b, preexec_fn=setup,
                         close_fds=True)
    os.close(s1a)
    os.close(s1b)
    return p, s2
