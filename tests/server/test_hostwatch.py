import io
from unittest.mock import patch, MagicMock

import pytest

import sshuttle.hostwatch as hostwatch


@pytest.fixture(autouse=True)
def clean_state(monkeypatch, tmp_path):
    monkeypatch.setattr(hostwatch, "hostnames", {})
    monkeypatch.setattr(hostwatch, "CACHEFILE", str(tmp_path / "hosts"))
    monkeypatch.setattr(hostwatch, "SHOULD_WRITE_CACHE", False)


@patch('sshuttle.hostwatch.ssubprocess.Popen')
def test_check_netstat_non_ascii_output(mock_popen):
    """netstat -n also lists unix sockets, whose paths may hold non-ASCII
    bytes; that must not stop hostwatch from finding the IPs."""
    p = MagicMock()
    p.stdout = io.BytesIO(
        b'tcp  0  0 10.0.0.1:22  10.0.0.2:5000  ESTABLISHED\n'
        b'unix  2  [ ]  STREAM  CONNECTED  1234  /run/caf\xc3\xa9.sock\n')
    p.wait.return_value = 0
    mock_popen.return_value = p
    with patch('sshuttle.hostwatch.check_host') as check_host:
        hostwatch._check_netstat()
    assert [c.args[0] for c in check_host.call_args_list] == \
        ['10.0.0.1', '10.0.0.2']


def test_found_host_ignores_non_ascii_name(capsys):
    hostwatch.found_host("café", "10.0.0.1")
    assert hostwatch.hostnames == {}
    assert capsys.readouterr().out == ""


def test_write_host_cache_after_non_ascii_name(tmp_path):
    hostwatch.found_host("café", "10.0.0.1")
    hostwatch.found_host("example", "10.0.0.2")
    hostwatch.write_host_cache()
    assert (tmp_path / "hosts").read_text() == "example,10.0.0.2\n"
    assert [p.name for p in tmp_path.iterdir()] == ["hosts"]
