"""When sshuttle is run via a systemd service file, we can communicate
to systemd about the status of the sshuttle process. In particular, we
can send READY status to tell systemd that sshuttle has completed
startup and send STOPPING to indicate that sshuttle is beginning
shutdown.

For details, see:
https://www.freedesktop.org/software/systemd/man/sd_notify.html
"""

import socket
import os

from sshuttle.helpers import debug1


def _notify(message):
    """Send a notification message to systemd."""
    addr = os.environ.get("NOTIFY_SOCKET", None)

    if not addr or len(addr) == 1 or addr[0] not in ('/', '@'):
        return False

    addr = '\0' + addr[1:] if addr[0] == '@' else addr

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    except (OSError, IOError) as e:
        debug1("Error creating socket to notify systemd: %s" % e)
        return False

    if not message:
        return False

    assert isinstance(message, bytes)

    try:
        return (sock.sendto(message, addr) > 0)
    except (OSError, IOError) as e:
        debug1("Error notifying systemd: %s" % e)
        return False


def send(*messages):
    """Send multiple messages to systemd."""
    return _notify(b'\n'.join(messages))


def ready():
    """Constructs a message that is appropriate to send upon completion of
sshuttle startup."""
    return b"READY=1"


def stop():
    """Constructs a message that is appropriate to send when sshuttle is
beginning to shutdown."""
    return b"STOPPING=1"


def status(message):
    """Constructs a status message to be sent to systemd."""
    return b"STATUS=%s" % message.encode('utf8')
