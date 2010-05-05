import sys, os, re, subprocess, socket, zlib
import helpers
from helpers import *


def readfile(name):
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    fullname = os.path.join(basedir, name)
    return open(fullname, 'rb').read()


def empackage(z, filename):
    content = z.compress(readfile(filename))
    content += z.flush(zlib.Z_SYNC_FLUSH)
    return '%s\n%d\n%s' % (filename,len(content), content)


def connect(rhostport):
    main_exe = sys.argv[0]
    l = (rhostport or '').split(':', 1)
    rhost = l[0]
    portl = []
    if len(l) > 1:
        portl = ['-p', str(int(l[1]))]

    if rhost == '-':
        rhost = None

    z = zlib.compressobj(1)
    content = readfile('assembler.py')
    content2 = (empackage(z, 'helpers.py') +
                empackage(z, 'ssnet.py') +
                empackage(z, 'server.py') +
                "\n")
    
    pyscript = r"""
                import sys;
                skip_imports=1;
                verbosity=%d;
                exec compile(sys.stdin.read(%d), "assembler.py", "exec")
                """ % (helpers.verbose or 0, len(content))
    pyscript = re.sub(r'\s+', ' ', pyscript.strip())

        
    if not rhost:
        argv = ['python', '-c', pyscript]
    else:
        argv = ['ssh'] + portl + [rhost, '--', "python -c '%s'" % pyscript]
    (s1,s2) = socket.socketpair()
    def setup():
        # runs in the child process
        s2.close()
        os.setsid()
    s1a,s1b = os.dup(s1.fileno()), os.dup(s1.fileno())
    s1.close()
    debug2('executing: %r\n' % argv)
    p = subprocess.Popen(argv, stdin=s1a, stdout=s1b, preexec_fn=setup,
                         close_fds=True)
    os.close(s1a)
    os.close(s1b)
    s2.sendall(content)
    s2.sendall(content2)
    return p, s2
