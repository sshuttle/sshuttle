import sys
from unittest.mock import patch

import pytest

from sshuttle import client, cmdline


def _tmark_passed_to_client(tmark):
    argv = ['sshuttle', '--tmark', tmark, '-r', 'example.invalid', '0/0']
    with patch.object(sys, 'argv', argv), \
            patch.dict('os.environ', {}, clear=True), \
            patch.object(client, 'main', return_value=0) as main:
        cmdline.main()
    return main.call_args.args[23]


@pytest.mark.parametrize('tmark, expected', [
    ('1', '0x1'),
    ('0x01', '0x01'),
    ('0XFF', '0xff'),
    ('ffffffff', '0xffffffff'),
])
def test_tmark_accepts_hex(tmark, expected):
    assert _tmark_passed_to_client(tmark) == expected


@pytest.mark.parametrize('tmark', [
    '-1', '+3', ' 5', '1_0', '0x', 'g', '1ffffffff',
])
def test_tmark_rejects_non_hex(tmark, capsys):
    with pytest.raises(SystemExit) as excinfo:
        _tmark_passed_to_client(tmark)
    assert excinfo.value.code == 2
    assert '--tmark must be a hexadecimal value' in capsys.readouterr().err
