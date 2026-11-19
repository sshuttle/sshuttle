import pytest

import sshuttle.hostwatch as hostwatch


@pytest.fixture(autouse=True)
def clean_state(monkeypatch, tmp_path):
    monkeypatch.setattr(hostwatch, "hostnames", {})
    monkeypatch.setattr(hostwatch, "CACHEFILE", str(tmp_path / "hosts"))
    monkeypatch.setattr(hostwatch, "SHOULD_WRITE_CACHE", False)


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
