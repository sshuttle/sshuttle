import io
from unittest.mock import patch, MagicMock

import sshuttle.hostwatch as hostwatch


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
