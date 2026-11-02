import inspect
from unittest.mock import Mock, patch

import pytest

from sshuttle import client
from sshuttle.helpers import Fatal
from sshuttle.methods import get_method


def test_unknown_group_is_reported_by_name():
    fw = Mock()
    fw.method = get_method('nat')
    args = {name: None for name in inspect.signature(client.main).parameters}
    args.update(listenip_v4='auto', remotename='example.invalid', nslist=[],
                subnets_include=[], subnets_exclude=[], daemon=False,
                group='nosuchgroup')
    with patch.object(client, 'FirewallClient', return_value=fw), \
            patch.object(client, 'getgrnam', side_effect=KeyError('nosuchgroup')):
        with pytest.raises(Fatal, match='Group nosuchgroup does not exist'):
            client.main(**args)


@pytest.mark.parametrize('method_name', ['nft', 'tproxy', 'pf', 'ipfw'])
def test_group_is_rejected_by_methods_without_support(method_name):
    method = get_method(method_name)
    features = method.get_supported_features()
    features.group = True
    with pytest.raises(Fatal, match='Feature group not supported'):
        method.assert_features(features)
