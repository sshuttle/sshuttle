import sys
from unittest.mock import Mock, patch

import pytest

from sshuttle import client, cmdline, firewall, options
from test_firewall import setup_daemon


def test_no_flush_dns_option_defaults_to_flushing():
    assert not options.parser.parse_args([]).no_flush_dns
    assert options.parser.parse_args(['--no-flush-dns']).no_flush_dns


@pytest.mark.parametrize('disabled', [False, True])
def test_no_flush_dns_reaches_client(disabled):
    argv = ['sshuttle', '-r', 'example.invalid', '0/0']
    if disabled:
        argv.append('--no-flush-dns')
    with patch.object(sys, 'argv', argv), \
            patch.dict('os.environ', {}, clear=True), \
            patch.object(client, 'main', return_value=0) as main:
        assert cmdline.main() == 0
    assert main.call_args.kwargs['flush_dns'] is not disabled


@pytest.mark.parametrize('disabled', [False, True])
def test_no_flush_dns_reaches_firewall_entrypoint(disabled):
    argv = ['sshuttle', '--firewall']
    if disabled:
        argv.append('--no-flush-dns')
    with patch.object(sys, 'argv', argv), \
            patch.dict('os.environ', {}, clear=True), \
            patch.object(firewall, 'main') as main:
        cmdline.main()
    assert main.call_args.kwargs['flush_dns'] is not disabled


@pytest.mark.parametrize('flush_dns', [False, True])
@pytest.mark.parametrize('platform', ['linux', 'darwin'])
def test_flush_dns_lifecycle(flush_dns, platform):
    stdin, stdout = setup_daemon()
    method = Mock()
    method.name = 'test'
    with patch.object(firewall, 'setup_daemon', return_value=(stdin, stdout)), \
            patch.object(firewall, 'get_method', return_value=method), \
            patch.object(firewall, 'rewrite_etc_hosts'), \
            patch.object(firewall, 'restore_etc_hosts'), \
            patch.object(firewall.sys, 'platform', platform), \
            patch.object(firewall, 'flush_systemd_dns_cache') as flush:
        firewall.main('test', False, flush_dns=flush_dns)
    assert flush.call_count == (2 if flush_dns and platform == 'linux' else 0)
    assert method.restore_firewall.call_count == 2


@pytest.mark.parametrize('flush_dns', [False, True])
def test_firewall_helper_receives_no_flush_dns(flush_dns):
    parent, child = Mock(), Mock()
    child.makefile.return_value.readline.return_value = b'READY test\n'
    with patch.object(client, 'is_admin_user', return_value=True), \
            patch.object(client.sys, 'argv', ['sshuttle']), \
            patch.object(client.socket, 'socketpair', return_value=(parent, child)), \
            patch.object(client.ssubprocess, 'Popen') as popen, \
            patch.object(client.ssyslog, '_p', None), \
            patch.object(client, 'get_method'):
        popen.return_value.poll.return_value = None
        helper = client.FirewallClient('test', False, flush_dns=flush_dns)
    assert ('--no-flush-dns' in helper.argv) is not flush_dns
