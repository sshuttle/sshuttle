import os
import ctypes
import ctypes.util

from sshuttle.helpers import Fatal, debug1, debug2


CLONE_NEWNET = 0x40000000
NETNS_RUN_DIR = "/var/run/netns"


def enter_namespace(namespace, namespace_pid):
    if namespace:
        namespace_dir = f'{NETNS_RUN_DIR}/{namespace}'
    else:
        namespace_dir = f'/proc/{namespace_pid}/ns/net'
    
    if not os.path.exists(namespace_dir):
        raise Fatal('The namespace %r does not exists.' % namespace_dir)

    debug2('loading libc')
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    
    default_errcheck = libc.setns.errcheck

    def errcheck(ret, *args):
        if ret == -1:
            e = ctypes.get_errno()
            raise Fatal(e, os.strerror(e))
        if default_errcheck:
            return default_errcheck(ret, *args)
    
    libc.setns.errcheck = errcheck # type: ignore

    debug1('Entering namespace %r' % namespace_dir)

    with open(namespace_dir) as fd:
        libc.setns(fd.fileno(), CLONE_NEWNET)

    debug1('Namespace %r successfully set' % namespace_dir)
