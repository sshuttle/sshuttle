import sshuttle.server


def test__ipmatch():
    assert sshuttle.server._ipmatch("1.2.3.4") is not None
    assert sshuttle.server._ipmatch("::1") is not None
    assert sshuttle.server._ipmatch("42 Example Street, Melbourne") is None
