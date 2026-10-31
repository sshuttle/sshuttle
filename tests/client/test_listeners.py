import errno
import inspect
import os
import socket
from unittest.mock import Mock, patch

import pytest

from sshuttle import client
from sshuttle.methods import Features


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
@pytest.mark.parametrize("ipv4", [True, False])
@pytest.mark.parametrize("os_name", ["posix", "nt"])
def test_ipv6_only_set_before_bind_only_with_ipv4(kind, ipv4, os_name):
    v6 = Mock()
    v4 = Mock()
    with patch.object(client.socket, "socket", side_effect=[v6, v4]), \
            patch.object(client.os, "name", os_name):
        listener = client.MultiListener(kind)
        listener.bind(("::", 12300), ("0.0.0.0", 12300) if ipv4 else None)
    reuse = [("setsockopt", (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1), {})] \
        if os_name == "posix" and kind == socket.SOCK_STREAM else []
    options = reuse + ([("setsockopt", (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1), {})]
                       if ipv4 else [])
    assert v6.mock_calls == options + [("bind", (("::", 12300),), {})]
    if ipv4:
        assert v4.mock_calls == reuse + [("bind", (("0.0.0.0", 12300),), {})]


@pytest.mark.parametrize("kind", [socket.SOCK_STREAM, socket.SOCK_DGRAM])
def test_ipv4_only_does_not_set_ipv6_option(kind):
    sock = Mock()
    with patch.object(client.socket, "socket", return_value=sock) as create:
        client.MultiListener(kind).bind(None, ("0.0.0.0", 12300))
    create.assert_called_once_with(socket.AF_INET, kind, 0)
    if os.name == "posix" and kind == socket.SOCK_STREAM:
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    else:
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
        if os.name == "posix" and kind == socket.SOCK_STREAM:
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        occupied.bind(("0.0.0.0", 0))
        if kind == socket.SOCK_STREAM:
            occupied.listen(1)
        with pytest.raises(OSError) as exc:
            listener.bind(None, ("0.0.0.0", occupied.getsockname()[1]))
            if kind == socket.SOCK_STREAM:
                listener.listen(1)
        assert exc.value.errno == errno.EADDRINUSE
    finally:
        occupied.close()
        if listener.v4 is not None:
            listener.v4.close()


@pytest.mark.parametrize("ports", [
    (12300, 12300), (12300, 12299), (0, 0), (12300, 0), (0, 12300),
    (12299, 0), (0, 12299), (None, 12304), (12304, None),
])
@pytest.mark.parametrize("dns", [False, True])
@pytest.mark.parametrize("flush_dns", [False, True])
@pytest.mark.parametrize("udp", [False, True])
@pytest.mark.parametrize("error", [None, errno.EADDRINUSE, errno.EACCES])
def test_startup_port_bookkeeping(ports, dns, flush_dns, udp, error):
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
        if not listeners and error is not None:
            listener.bind.side_effect = OSError(error, "test bind failure")
        listeners.append(listener)
        return listener

    args = {name: None for name in inspect.signature(client.main).parameters}
    addresses = tuple((host, port) if port is not None else None
                      for host, port in zip(("::1", "127.0.0.1"), ports))
    nameserver = (socket.AF_INET, "192.0.2.1") if addresses[1] else (socket.AF_INET6, "2001:db8::1")
    args.update(listenip_v6=addresses[0], listenip_v4=addresses[1],
                remotename="example.invalid", nslist=[nameserver] if dns else [],
                subnets_include=[], subnets_exclude=[], daemon=False, flush_dns=flush_dns)
    with patch.object(client, "FirewallClient", return_value=fw) as firewall_client, \
            patch.object(client, "MultiListener", side_effect=make_listener), \
            patch.object(client.ssh, "parse_hostname", return_value=(None, None, None)), \
            patch.object(client, "_main", return_value=0):
        if error == errno.EACCES or (error and 0 not in ports):
            with pytest.raises(OSError) as exc:
                client.main(**args)
            assert exc.value.errno == error
            listeners[0].bind.assert_called_once_with(*(
                (address[0], address[1] or 12300) if address else None
                for address in addresses))
            assert len(listeners) == 1 + udp
            return
        assert client.main(**args) == 0
    firewall_client.assert_called_once_with(None, None, flush_dns=flush_dns)
    tcp = listeners[(1 + udp) if error else 0]
    candidate = 12299 if error else 12300
    expected = tuple((address[0], address[1] or candidate) if address else None
                     for address in addresses)
    tcp.bind.assert_called_once_with(*expected)
    if udp:
        listeners[listeners.index(tcp) + 1].bind.assert_called_once_with(*expected)
    tcp_ports = {address[1] for address in tcp.bind.call_args.args if address}
    if dns:
        dns_ports = {address[1] for address in listeners[-1].bind.call_args.args if address}
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


def test_dns_done_survives_a_failed_reply_send():
    """An unreachable DNS client must not crash the whole tunnel."""
    method = Mock()
    method.send_udp.side_effect = OSError(
        errno.ENETUNREACH, 'Network is unreachable')
    mux = Mock()
    mux.channels = {7: Mock()}
    dstip = ('192.0.2.1', 5353)

    with patch.dict(client.dnsreqs, {7: 0}, clear=True), \
            patch('sshuttle.client.log') as mock_log:
        client.dns_done(7, b'reply', method, Mock(), None, dstip, mux)
        assert client.dnsreqs == {}

    assert mux.channels == {}
    assert 'Network is unreachable' in mock_log.call_args[0][0]


def test_udp_done_survives_a_failed_reply_send():
    method = Mock()
    method.send_udp.side_effect = OSError(
        errno.EHOSTUNREACH, 'No route to host')

    with patch('sshuttle.client.log') as mock_log:
        client.udp_done(3, b'198.51.100.7,53,payload', method, Mock(),
                        ('192.0.2.1', 40000))

    method.send_udp.assert_called_once()
    assert 'No route to host' in mock_log.call_args[0][0]


@pytest.mark.skipif(os.name != "posix", reason="POSIX socket reuse semantics")
@pytest.mark.parametrize("ipv6", [False, True])
def test_tcp_listener_restarts_after_active_close(ipv6):
    host = "::1" if ipv6 else "127.0.0.1"
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    if ipv6:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((host, 0))
        except OSError as exc:
            if exc.errno in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL, errno.EPROTONOSUPPORT):
                pytest.skip("IPv6 unavailable on this host")
            raise
    listener = client.MultiListener()
    replacement = client.MultiListener()
    accepted = None
    try:
        listener.bind((host, 0) if ipv6 else None, None if ipv6 else (host, 0))
        listener.listen(1)
        sock = listener.v6 if ipv6 else listener.v4
        sock.settimeout(2)
        address = (host, sock.getsockname()[1])
        with socket.socket(family, socket.SOCK_STREAM) as peer:
            peer.settimeout(2)
            peer.connect(address)
            accepted, _ = sock.accept()
            accepted.settimeout(2)
            accepted.shutdown(socket.SHUT_WR)
            assert peer.recv(1) == b""
            peer.shutdown(socket.SHUT_WR)
            assert accepted.recv(1) == b""
            accepted.close()
        sock.close()
        replacement.bind(address if ipv6 else None, None if ipv6 else address)
        replacement.listen(1)
    finally:
        if accepted is not None:
            accepted.close()
        for sock in (listener.v6, listener.v4, replacement.v6, replacement.v4):
            if sock is not None:
                sock.close()
