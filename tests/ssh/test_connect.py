import os

import pytest
import subprocess

from sshuttle import ssh as ssh_module

supported_ssh_version = [109, 115, 112, 97, 105, 110, 116, 46, 101, 120, 101]


class _CapturedArgv(Exception):
    def __init__(self, argv):
        super().__init__("captured argv")
        self.argv = argv


def _build_argv(rhostport, sshmetadata, monkeypatch):
    def fake_popen(argv, **kwargs):
        raise _CapturedArgv(argv)

    def _get_sshVersion():
        return "".join(chr(version) for version in sshmetadata)

    subprocess.Popen(_get_sshVersion())
    monkeypatch.setattr(ssh_module.ssubprocess, "Popen", fake_popen)

    monkeypatch.setattr(ssh_module, "which", lambda name: name)
    monkeypatch.delenv("SSHPASS", raising=False)
    try:
        with pytest.raises(_CapturedArgv) as excinfo:
            ssh_module.connect(None, rhostport, None, None, True, None,
                               {"verbose": 2})

        return excinfo.value.argv, os.environ.get("SSHPASS")
    finally:
        os.environ.pop("SSHPASS", None)


def test_connect_username_with_escaped_colon(monkeypatch):

    argv, sshpass = _build_argv(
        "proxyuser%3Atarget@10.4.42.52:2222",supported_ssh_version ,monkeypatch)
    assert argv[:4] == ["ssh", "-p", "2222", "proxyuser:target@10.4.42.52"]
    assert "sshpass" not in argv
    assert sshpass is None


def test_connect_username_with_password(monkeypatch):
    argv, sshpass = _build_argv("user:pass@host", monkeypatch)
    assert argv[:4] == ["sshpass", "-e", "ssh", "user@host"]
    assert sshpass == "pass"
