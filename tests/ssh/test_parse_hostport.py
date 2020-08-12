from sshuttle.ssh import parse_hostport


def test_host_only():
    assert parse_hostport("host") == (None, None, None, "host")
    assert parse_hostport("1.2.3.4") == (None, None, None, "1.2.3.4")
    assert parse_hostport("2001::1") == (None, None, None, "2001::1")
    assert parse_hostport("[2001::1]") == (None, None, None, "2001::1")


def test_host_and_port():
    assert parse_hostport("host:22") == (None, None, 22, "host")
    assert parse_hostport("1.2.3.4:22") == (None, None, 22, "1.2.3.4")
    assert parse_hostport("[2001::1]:22") == (None, None, 22, "2001::1")


def test_username_and_host():
    assert parse_hostport("user@host") == ("user", None, None, "host")
    assert parse_hostport("user:@host") == ("user", None, None, "host")
    assert parse_hostport("user:pass@host") == ("user", "pass", None, "host")
