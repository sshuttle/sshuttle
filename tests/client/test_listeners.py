import errno
import inspect
import socket
from unittest.mock import Mock, patch

import pytest

from sshuttle import client
from sshuttle.methods import Features


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
@pytest.mark.parametrize("ipv4", [True, False])
def test_ipv6_only_set_before_bind_only_with_ipv4(kind, ipv4):
    v6 = Mock()
    v4 = Mock()
    with patch.object(client.socket, "socket", side_effect=[v6, v4]):
        listener = client.MultiListener(kind)
        listener.bind(("::", 12300), ("0.0.0.0", 12300) if ipv4 else None)
    if ipv4:
        assert v6.mock_calls[:2] == [
            ("setsockopt", (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1), {}),
            ("bind", (("::", 12300),), {}),
        ]
        v4.bind.assert_called_once_with(("0.0.0.0", 12300))
    else:
        v6.setsockopt.assert_not_called()
    v6.bind.assert_called_once_with(("::", 12300))


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_ipv4_only_does_not_set_ipv6_option(kind):
    sock = Mock()
    with patch.object(client.socket, "socket", return_value=sock) as create:
        client.MultiListener(kind).bind(None, ("0.0.0.0", 12300))
    create.assert_called_once_with(socket.AF_INET, kind, 0)
    sock.setsockopt.assert_not_called()


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_dual_wildcard_real_sockets(kind):
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    listener = client.MultiListener(kind)
    try:
        try:
            listener.bind(("::", 0), None)
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
                pytest.skip("IPv6 unavailable on this host")
            raise
        port = listener.v6.getsockname()[1]
        listener.v6.close()
        listener = client.MultiListener(kind)
        listener.bind(("::", port), ("0.0.0.0", port))
        assert listener.v6.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
        if kind == socket.SOCK_STREAM:
            listener.listen(1)
        assert listener.v4.getsockname()[1] == port
    finally:
        for sock in (listener.v6, listener.v4):
            if sock is not None:
                sock.close()


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_real_occupied_ipv4_port_still_raises(kind):
    occupied = socket.socket(socket.AF_INET, kind)
    listener = client.MultiListener(kind)
    try:
        occupied.bind(("0.0.0.0", 0))
        if kind == socket.SOCK_STREAM:
            occupied.listen(1)
        with pytest.raises(OSError) as exc:
            listener.bind(None, ("0.0.0.0", occupied.getsockname()[1]))
        assert exc.value.errno == errno.EADDRINUSE
    finally:
        occupied.close()
        if listener.v4 is not None:
            listener.v4.close()


@pytest.mark.parametrize("ports", [(12300, 12300), (12300, 12299), (0, 0), (12300, 0), (0, 12300), (12299, 0), (0, 12299)])
@pytest.mark.parametrize("dns", [False, True])
@pytest.mark.parametrize("udp", [False, True])
def test_startup_port_bookkeeping(ports, dns, udp):
    features = Features()
    for name in ("ipv4", "ipv6", "dns", "loopback_proxy_port"):
        setattr(features, name, True)
    features.udp = udp
    features.user = features.group = False
    fw = Mock()
    fw.method.assert_features = Mock()
    fw.method.get_supported_features.return_value = features
    fw.method.name = "fake"
    listeners = []

    def make_listener(*args):
        listener = Mock()
        listeners.append(listener)
        return listener

    args = {name: None for name in inspect.signature(client.main).parameters}
    args.update(listenip_v6=("::1", ports[0]), listenip_v4=("127.0.0.1", ports[1]),
                remotename="example.invalid", nslist=[(socket.AF_INET, "192.0.2.1")] if dns else [],
                subnets_include=[], subnets_exclude=[], daemon=False)
    with patch.object(client, "FirewallClient", return_value=fw), \
            patch.object(client, "MultiListener", side_effect=make_listener), \
            patch.object(client.ssh, "parse_hostname", return_value=(None, None, None)), \
            patch.object(client, "_main", return_value=0):
        assert client.main(**args) == 0
    tcp_ports = {address[1] for address in listeners[0].bind.call_args.args}
    if dns:
        dns_ports = {address[1] for address in listeners[-1].bind.call_args.args}
        assert tcp_ports.isdisjoint(dns_ports)
    fw.setup.assert_called_once()
    fw.done.assert_called_once()


@pytest.mark.parametrize("error", [errno.EADDRINUSE, errno.EACCES])
def test_separate_ipv4_bind_errors_are_not_hidden(error):
    v6, v4 = Mock(), Mock()
    v4.bind.side_effect = OSError(error, "test bind failure")
    with patch.object(client.socket, "socket", side_effect=[v6, v4]):
        with pytest.raises(OSError) as exc:
            client.MultiListener().bind(("::", 12300), ("0.0.0.0", 12300))
    assert exc.value.errno == error
