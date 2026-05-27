import os
import re
from pathlib import Path

import sshuttle.sudoers


def test_build_config_pythonpath_is_site_packages_parent():
    """PYTHONPATH in the sudoers config must point at the directory that
    *contains* the sshuttle package (e.g. .../site-packages), not at the
    package directory itself (.../site-packages/sshuttle).

    If the wrong path is generated, the Cmnd_Alias in the user's sudoers
    file no longer matches the command sudo actually sees when sshuttle
    re-invokes itself for the firewall subprocess, so the user keeps
    being prompted for a password.

    Regression test for:
      * https://github.com/sshuttle/sshuttle/issues/1096
      * https://github.com/sshuttle/sshuttle/issues/1164
    """
    config = sshuttle.sudoers.build_config("alice")

    match = re.search(r"PYTHONPATH=(\S+)", config)
    assert match is not None, (
        "build_config() output is missing a PYTHONPATH= entry:\n%s" % config
    )
    pythonpath = match.group(1)

    expected = str(Path(os.path.abspath(sshuttle.sudoers.__file__)).parent.parent)
    assert pythonpath == expected, (
        "PYTHONPATH in sudoers config points at %r, expected %r. "
        "It must be the directory that contains the sshuttle package, "
        "not the package directory itself." % (pythonpath, expected)
    )

    # The package directory itself (parent of sudoers.py) is one level
    # deeper than site-packages and must NOT be what we emit.
    package_dir = os.path.dirname(os.path.abspath(sshuttle.sudoers.__file__))
    assert pythonpath != package_dir, (
        "PYTHONPATH must not point at the sshuttle package directory %r; "
        "it should point at its parent." % package_dir
    )


def test_build_config_contains_user_name_and_cmd_alias():
    """The generated config references the requested user and binds them
    to a Cmnd_Alias of the form SSHUTTLE<HEX>."""
    config = sshuttle.sudoers.build_config("alice")

    alias_match = re.search(r"Cmnd_Alias\s+(SSHUTTLE[0-9A-F]+)\s*=", config)
    assert alias_match is not None, (
        "build_config() output is missing a 'Cmnd_Alias SSHUTTLE...' line:\n%s"
        % config
    )
    cmd_alias = alias_match.group(1)

    assert re.search(
        r"^alice\s+ALL=NOPASSWD:\s+" + re.escape(cmd_alias) + r"\s*$",
        config,
        re.MULTILINE,
    ), (
        "build_config() output is missing the user grant line for 'alice' "
        "bound to %s:\n%s" % (cmd_alias, config)
    )
