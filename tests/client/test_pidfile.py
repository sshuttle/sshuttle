import errno
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


def test_check_daemon_leaves_non_regular_file_alone(monkeypatch):
    # --pidfile=/dev/null is a way to not have a pidfile at all.
    unlinked = []
    monkeypatch.setattr(client.os, 'unlink', unlinked.append)
    client.check_daemon(os.devnull)
    assert unlinked == []
    assert client._pidname is None

    client.daemon_cleanup()
    assert unlinked == []


def test_daemonize_pidfile_directory_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(client, '_pidname', None)
    pidfile = tmp_path / "missing" / "sshuttle.pid"
    client.check_daemon(str(pidfile))
    with pytest.raises(Fatal, match='failed to create/write pidfile'):
        client.daemonize()


@pytest.mark.parametrize('content', ['', 'garbage', '999999999\n'])
def test_check_daemon_stale_pidfile_not_removable(tmp_path, monkeypatch,
                                                  content):
    pidfile = tmp_path / "sshuttle.pid"
    pidfile.write_text(content)

    def unlink(path):
        raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), path)
    monkeypatch.setattr(client.os, 'unlink', unlink)
    with pytest.raises(Fatal, match="can't remove stale pidfile .*: "
                                    "Permission denied"):
        client.check_daemon(str(pidfile))
