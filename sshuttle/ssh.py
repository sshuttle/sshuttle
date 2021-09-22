import sys
import os
import re
import socket
import zlib
import importlib
import importlib.util
import subprocess as ssubprocess
import shlex
from shlex import quote
import ipaddress
from urllib.parse import urlparse

import sshuttle.helpers as helpers
from sshuttle.helpers import debug2, which, get_path, Fatal


def get_module_source(name):
    spec = importlib.util.find_spec(name)
    with open(spec.origin, "rt") as f:
        return f.read().encode("utf-8")


def empackage(z, name, data=None):
    if not data:
        data = get_module_source(name)
    content = z.compress(data)
    content += z.flush(zlib.Z_SYNC_FLUSH)

    return b'%s\n%d\n%s' % (name.encode("ASCII"), len(content), content)


def parse_hostport(rhostport):
    """
    parses the given rhostport variable, looking like this:

            [username[:password]@]host[:port]

    if only host is given, can be a hostname, IPv4/v6 address or a ssh alias
    from ~/.ssh/config

    and returns a tuple (username, password, port, host)
    """
    # leave use of default port to ssh command to prevent overwriting
    # ports configured in ~/.ssh/config when no port is given
    if rhostport is None or len(rhostport) == 0:
        return None, None, None, None
    port = None
    username = None
    password = None
    host = rhostport

    if "@" in host:
        # split username (and possible password) from the host[:port]
        username, host = host.rsplit("@", 1)
        # Fix #410 bad username error detect
        if ":" in username:
            # this will even allow for the username to be empty
            username, password = username.split(":")

    if ":" in host:
        # IPv6 address and/or got a port specified

        # If it is an IPv6 address with port specification,
        # then it will look like: [::1]:22

        try:
            # try to parse host as an IP address,
            # if that works it is an IPv6 address
            host = str(ipaddress.ip_address(host))
        except ValueError:
            # if that fails parse as URL to get the port
            parsed = urlparse('//{}'.format(host))
            try:
                host = str(ipaddress.ip_address(parsed.hostname))
            except ValueError:
                # else if both fails, we have a hostname with port
                host = parsed.hostname
            port = parsed.port

    if password is None or len(password) == 0:
        password = None

    return username, password, port, host


def connect(ssh_cmd, rhostport, python, stderr, options):
    username, password, port, host = parse_hostport(rhostport)
    if username:
        rhost = "{}@{}".format(username, host)
    else:
        rhost = host

    z = zlib.compressobj(1)
    content = get_module_source('sshuttle.assembler')
    optdata = ''.join("%s=%r\n" % (k, v) for (k, v) in list(options.items()))
    optdata = optdata.encode("UTF8")
    content2 = (empackage(z, 'sshuttle') +
                empackage(z, 'sshuttle.cmdline_options', optdata) +
                empackage(z, 'sshuttle.helpers') +
                empackage(z, 'sshuttle.ssnet') +
                empackage(z, 'sshuttle.hostwatch') +
                empackage(z, 'sshuttle.server') +
                b"\n")

    # If the exec() program calls sys.exit(), it should exit python
    # and the sys.exit(98) call won't be reached (so we try to only
    # exit that way in the server). However, if the code that we
    # exec() simply returns from main, then we will return from
    # exec(). If the server's python process dies, it should stop
    # executing and also won't reach sys.exit(98).
    #
    # So, we shouldn't reach sys.exit(98) and we certainly shouldn't
    # reach it immediately after trying to start the server.
    pyscript = r"""
                import sys, os;
                verbosity=%d;
                sys.stdin = os.fdopen(0, "rb");
                exec(compile(sys.stdin.read(%d), "assembler.py", "exec"));
                sys.exit(98);
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
        if port is not None:
            portl = ["-p", str(port)]
        else:
            portl = []
        if python:
            pycmd = "'%s' -c '%s'" % (python, pyscript)
        else:
            # By default, we run the following code in a shell.
            # However, with restricted shells and other unusual
            # situations, there can be trouble. See the RESTRICTED
            # SHELL section in "man bash" for more information. The
            # code makes many assumptions:
            #
            # (1) That /bin/sh exists and that we can call it.
            # Restricted shells often do *not* allow you to run
            # programs specified with an absolute path like /bin/sh.
            # Either way, if there is trouble with this, it should
            # return error code 127.
            #
            # (2) python3 or python exists in the PATH and is
            # executable. If they aren't, then exec won't work (see (4)
            # below).
            #
            # (3) In /bin/sh, that we can redirect stderr in order to
            # hide the version that "python3 -V" might print (some
            # restricted shells don't allow redirection, see
            # RESTRICTED SHELL section in 'man bash'). However, if we
            # are in a restricted shell, we'd likely have trouble with
            # assumption (1) above.
            #
            # (4) The 'exec' command should work except if we failed
            # to exec python because it doesn't exist or isn't
            # executable OR if exec isn't allowed (some restricted
            # shells don't allow exec). If the exec succeeded, it will
            # not return and not get to the "exit 97" command. If exec
            # does return, we exit with code 97.
            #
            # Specifying the exact python program to run with --python
            # avoids many of the issues above. However, if
            # you have a restricted shell on remote, you may only be
            # able to run python if it is in your PATH (and you can't
            # run programs specified with an absolute path). In that
            # case, sshuttle might not work at all since it is not
            # possible to run python on the remote machine---even if
            # it is present.
            pycmd = ("P=python3; $P -V 2>%s || P=python; "
                     "exec \"$P\" -c %s; exit 97") % \
                     (os.devnull, quote(pyscript))
            pycmd = ("/bin/sh -c {}".format(quote(pycmd)))

        if password is not None:
            os.environ['SSHPASS'] = str(password)
            argv = (["sshpass", "-e"] + sshl +
                    portl +
                    [rhost, '--', pycmd])

        else:
            argv = (sshl +
                    portl +
                    [rhost, '--', pycmd])

    # Our which() function searches for programs in get_path()
    # directories (which include PATH). This step isn't strictly
    # necessary if ssh is already in the user's PATH, but it makes the
    # error message friendlier if the user incorrectly passes in a
    # custom ssh command that we cannot find.
    abs_path = which(argv[0])
    if abs_path is None:
        raise Fatal("Failed to find '%s' in path %s" % (argv[0], get_path()))
    argv[0] = abs_path

    (s1, s2) = socket.socketpair()

    def setup():
        # runs in the child process
        s2.close()
    s1a, s1b = os.dup(s1.fileno()), os.dup(s1.fileno())
    s1.close()

    debug2('executing: %r' % argv)
    p = ssubprocess.Popen(argv, stdin=s1a, stdout=s1b, preexec_fn=setup,
                          close_fds=True, stderr=stderr)
    os.close(s1a)
    os.close(s1b)
    s2.sendall(content)
    s2.sendall(content2)
    return p, s2
