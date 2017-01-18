import os
import importlib
import socket
import struct
import errno
from sshuttle.helpers import Fatal, debug3


def original_dst(sock):
    try:
        SO_ORIGINAL_DST = 80
        SOCKADDR_MIN = 16
        sockaddr_in = sock.getsockopt(socket.SOL_IP,
                                      SO_ORIGINAL_DST, SOCKADDR_MIN)
        (proto, port, a, b, c, d) = struct.unpack('!HHBBBB', sockaddr_in[:8])
        # FIXME: decoding is IPv4 only.
        assert(socket.htons(proto) == socket.AF_INET)
        ip = '%d.%d.%d.%d' % (a, b, c, d)
        return (ip, port)
    except socket.error as e:
        if e.args[0] == errno.ENOPROTOOPT:
            return sock.getsockname()
        raise


class Features(object):
    pass


class BaseMethod(object):
    def __init__(self, name):
        self.firewall = None
        self.name = name

    def set_firewall(self, firewall):
        self.firewall = firewall

    def get_supported_features(self):
        result = Features()
        result.ipv6 = False
        result.udp = False
        result.dns = True
        return result

    def get_tcp_dstip(self, sock):
        return original_dst(sock)

    def recv_udp(self, udp_listener, bufsize):
        debug3('Accept UDP using recvfrom.\n')
        data, srcip = udp_listener.recvfrom(bufsize)
        return (srcip, None, data)

    def send_udp(self, sock, srcip, dstip, data):
        if srcip is not None:
            Fatal("Method %s send_udp does not support setting srcip to %r"
                  % (self.name, srcip))
        sock.sendto(data, dstip)

    def setup_tcp_listener(self, tcp_listener):
        pass

    def setup_udp_listener(self, udp_listener):
        pass

    def assert_features(self, features):
        avail = self.get_supported_features()
        for key in ["udp", "dns", "ipv6"]:
            if getattr(features, key) and not getattr(avail, key):
                raise Fatal(
                    "Feature %s not supported with method %s.\n" %
                    (key, self.name))

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp):
        raise NotImplementedError()

    def restore_firewall(self, port, family, udp):
        raise NotImplementedError()

    def firewall_command(self, line):
        return False


def _program_exists(name):
    paths = (os.getenv('PATH') or os.defpath).split(os.pathsep)
    for p in paths:
        fn = '%s/%s' % (p, name)
        if os.path.exists(fn):
            return not os.path.isdir(fn) and os.access(fn, os.X_OK)


def get_method(method_name):
    module = importlib.import_module("sshuttle.methods.%s" % method_name)
    return module.Method(method_name)


def get_auto_method():
    if _program_exists('iptables'):
        method_name = "nat"
    elif _program_exists('pfctl'):
        method_name = "pf"
    elif _program_exists('ipfw'):
        method_name = "ipfw"
    else:
        raise Fatal(
            "can't find either iptables or pfctl; check your PATH")

    return get_method(method_name)
