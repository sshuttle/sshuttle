import sys
import os
import re
import socket
import zlib
import imp
import subprocess as ssubprocess
import shlex
import ipaddress

# ensure backwards compatiblity with python2.7
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

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
    """
    parses the given rhostport variable, looking like this:

            [username[:password]@]host[:port]

    if only host is given, can be a hostname, IPv4/v6 address or a ssh alias
    from ~/.ssh/config

    and returns a tuple (username, password, port, host)
    """
    # default port for SSH is TCP port 22
    port = 22
    username = None
    password = None
    host = rhostport

    if "@" in host:
        # split username (and possible password) from the host[:port]
        username, host = host.split("@")
        # Fix #410 bad username error detect
        # username cannot contain an @ sign in this scenario
        if ":" in username:
            # this will even allow for the username to be empty
            username, password = username.split(":")

    if ":" in host:
        # IPv6 address and/or got a port specified

        # If it is an IPv6 adress with port specification,
        # then it will look like: [::1]:22

        try:
            # try to parse host as an IP adress,
            # if that works it is an IPv6 address
            host = ipaddress.ip_address(host)
        except ValueError:
            # if that fails parse as URL to get the port
            parsed = urlparse('//{}'.format(host))
            try:
                host = ipaddress.ip_address(parsed.hostname)
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
