import sys
import os
import re
import socket
import zlib
import imp
import subprocess as ssubprocess
import shlex
import sshuttle.helpers as helpers
from sshuttle.helpers import debug2

try:
    # Python >= 3.5
    from shlex import quote
except ImportError:
    # Python 2.x
    from pipes import quote


def readfile(name):
    tokens = name.split(".")
    f = None

    token = tokens[0]
    token_name = [token]
    token_str = ".".join(token_name)

    try:
        f, pathname, description = imp.find_module(token_str)

        for token in tokens[1:]:
            module = imp.load_module(token_str, f, pathname, description)
            if f is not None:
                f.close()

            token_name.append(token)
            token_str = ".".join(token_name)

            f, pathname, description = imp.find_module(
                token, module.__path__)

        if f is not None:
            contents = f.read()
        else:
            contents = ""

    finally:
        if f is not None:
            f.close()

    return contents.encode("UTF8")


def empackage(z, name, data=None):
    if not data:
        data = readfile(name)
    content = z.compress(data)
    content += z.flush(zlib.Z_SYNC_FLUSH)

    return b'%s\n%d\n%s' % (name.encode("ASCII"), len(content), content)


def parse_hostport(rhostport):
    # default define variable
    port = ""
    username = re.split(r'\s*:', rhostport)[0]
    password = ""

    try:
        password = re.split(r'\s*:', rhostport)[1]
        if "@" in password:
            password = password.split("@")[0]
    except IndexError:
        pass
    host = None

    if "@" in password:
        # default define password
        password = None
        host = password

    if host is None:

        try:
            host = re.split(r'\s*:', rhostport)[1]
        except IndexError:
            host = re.split(r'\s*:', rhostport)[0]

        # it's IPv4
        if "@" in host:
            if host.split("@")[1] == "":
                # it's IPv4
                host = "{}".format(re.split(r'\s*@', rhostport)[1])

                # try if port define
                try:
                    port = re.split(r'\s*:', rhostport)[2].split('@')[0]
                except IndexError:
                    pass

        # it's IPv6
        else:
            host = "{}".format(re.split(r'\s*@', rhostport)[1]).split("@")[0]

            # try if port define
            try:
                port = re.split(r'\s*:', rhostport)[2].split('@')[0]
            except IndexError:
                pass

    if port is "":
        port = 22

    if password is "":
        password = False

    return username, password, port, host

def connect(ssh_cmd, rhostport, python, stderr, options):
    username, password, port, host = parse_hostport(rhostport)

    rhost = "{}@{}".format(username, host)

    z = zlib.compressobj(1)
    content = readfile('sshuttle.assembler')
    optdata = ''.join("%s=%r\n" % (k, v) for (k, v) in list(options.items()))
    optdata = optdata.encode("UTF8")
    content2 = (empackage(z, 'sshuttle') +
                empackage(z, 'sshuttle.cmdline_options', optdata) +
                empackage(z, 'sshuttle.helpers') +
                empackage(z, 'sshuttle.ssnet') +
                empackage(z, 'sshuttle.hostwatch') +
                empackage(z, 'sshuttle.server') +
                b"\n")

    pyscript = r"""
                import sys, os;
                verbosity=%d;
                sys.stdin = os.fdopen(0, "rb");
                exec(compile(sys.stdin.read(%d), "assembler.py", "exec"))
                """ % (helpers.verbose or 0, len(content))
    pyscript = re.sub(r'\s+', ' ', pyscript.strip())

    if not rhost:
        # ignore the --python argument when running locally; we already know
        # which python version works.
        argv = [sys.executable, '-c', pyscript]
    else:
        if ssh_cmd:
            sshl = shlex.split(ssh_cmd)
        else:
            sshl = ['ssh']
        if python:
            pycmd = "'%s' -c '%s'" % (python, pyscript)
        else:
            pycmd = ("P=python3; $P -V 2>%s || P=python; "
                     "exec \"$P\" -c %s") % (os.devnull, quote(pyscript))
            pycmd = ("/bin/sh -c {}".format(quote(pycmd)))

        if password is not None:
            os.environ['SSHPASS'] = str(password)
            argv = (["sshpass", "-e"] + sshl +
                    ["-p", str(port)] +
                    [rhost, '--', pycmd])

        else:
            argv = (sshl +
                    ["-p", str(port)] +
                    [rhost, '--', pycmd])
    (s1, s2) = socket.socketpair()

    def setup():
        # runs in the child process
        s2.close()
    s1a, s1b = os.dup(s1.fileno()), os.dup(s1.fileno())
    s1.close()
    debug2('executing: %r\n' % argv)
    p = ssubprocess.Popen(argv, stdin=s1a, stdout=s1b, preexec_fn=setup,
                          close_fds=True, stderr=stderr)
    os.close(s1a)
    os.close(s1b)
    s2.sendall(content)
    s2.sendall(content2)
    return p, s2
