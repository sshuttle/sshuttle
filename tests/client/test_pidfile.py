import os

import pytest

from sshuttle import client
from sshuttle.helpers import Fatal


def test_check_daemon_no_pidfile(tmp_path):
    client.check_daemon(str(tmp_path / "sshuttle.pid"))


@pytest.mark.parametrize('content', ['', '\n', '0\n', 'garbage', '12abc\n'])
def test_check_daemon_removes_invalid_pidfile(tmp_path, content):
    pidfile = tmp_path / "sshuttle.pid"
    pidfile.write_text(content)
    client.check_daemon(str(pidfile))
    assert not pidfile.exists()


def test_check_daemon_already_running(tmp_path):
    pidfile = tmp_path / "sshuttle.pid"
    pidfile.write_text('%d\n' % os.getpid())
    with pytest.raises(Fatal, match='sshuttle is already running'):
        client.check_daemon(str(pidfile))
    assert pidfile.exists()
