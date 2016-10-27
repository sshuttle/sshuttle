import socket
import os
from sshuttle.helpers import debug1

def _notify(message):
    addr = os.environ.get("NOTIFY_SOCKET", None)

    if not addr or len(addr) == 1 or addr[0] not in ('/', '@'):
        return False

    addr = '\0' + addr[1:] if addr[0] == '@' else addr
    
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    except (OSError, IOError) as e:
        debug1("Error creating socket to notify systemd: %s\n" % e)
        return False

    if not message: 
        return False

    assert isinstance(message, bytes)

    try:
        return (sock.sendto(message, addr) > 0)
    except (OSError, IOError) as e:
        debug1("Error notifying systemd: %s\n" % e)
        return False

def send(*messages):
    return _notify(b'\n'.join(messages))

def ready():
    return b"READY=1"

def stop():
    return b"STOPPING=1"

def status(message):
    return b"STATUS=%s" % message.encode('utf8')
