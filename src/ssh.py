import sys, os, re, socket, zlib
import compat.ssubprocess as ssubprocess
import helpers
from helpers import *


def readfile(name):
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    path = [basedir] + sys.path
    for d in path:
        fullname = os.path.join(d, name)
        if os.path.exists(fullname):
            return open(fullname, 'rb').read()
    raise Exception("can't find file %r in any of %r" % (name, path))


def empackage(z, filename, data=None):
    (path,basename) = os.path.split(filename)
    if not data:
        data = readfile(filename)
    content = z.compress(data)
    content += z.flush(zlib.Z_SYNC_FLUSH)
    return '%s\n%d\n%s' % (basename, len(content), content)


def connect(ssh_cmd, rhostport, python, stderr, options):
    main_exe = sys.argv[0]
    portl = []

    if (rhostport or '').count(':') > 1:
        if rhostport.count(']') or rhostport.count('['):
            result = rhostport.split(']')
            rhost = result[0].strip('[')
            if len(result) > 1:
                result[1] = result[1].strip(':')
                if result[1] is not '':
                    portl = ['-p', str(int(result[1]))]
        else: # can't disambiguate IPv6 colons and a port number. pass the hostname through.
            rhost = rhostport
    else: # IPv4
        l = (rhostport or '').split(':', 1)
        rhost = l[0]
        if len(l) > 1:
            portl = ['-p', str(int(l[1]))]

    if rhost == '-':
        rhost = None

    z = zlib.compressobj(1)
    content = readfile('assembler.py')
    optdata = ''.join("%s=%r\n" % (k,v) for (k,v) in options.items())
    content2 = (empackage(z, 'cmdline_options.py', optdata) +
                empackage(z, 'helpers.py') +
                empackage(z, 'compat/ssubprocess.py') +
                empackage(z, 'ssnet.py') +
                empackage(z, 'hostwatch.py') +
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
        # ignore the --python argument when running locally; we already know
        # which python version works.
        argv = [sys.argv[1], '-c', pyscript]
    else:
        if ssh_cmd:
            sshl = ssh_cmd.split(' ')
        else:
            sshl = ['ssh']
        if python:
            pycmd = "'%s' -c '%s'" % (python, pyscript)
        else:
            pycmd = ("P=python2; $P -V 2>/dev/null || P=python; "
                     "exec \"$P\" -c '%s'") % pyscript
        argv = (sshl + 
                portl + 
                [rhost, '--', pycmd])
    (s1,s2) = socket.socketpair()
    def setup():
        # runs in the child process
        s2.close()
    s1a,s1b = os.dup(s1.fileno()), os.dup(s1.fileno())
    s1.close()
    debug2('executing: %r\n' % argv)
    p = ssubprocess.Popen(argv, stdin=s1a, stdout=s1b, preexec_fn=setup,
                          close_fds=True, stderr=stderr)
    os.close(s1a)
    os.close(s1b)
    s2.sendall(content)
    s2.sendall(content2)
    return p, s2
