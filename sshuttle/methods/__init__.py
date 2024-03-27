import importlib
import socket
import struct
import sys
import errno
import ipaddress
from sshuttle.helpers import Fatal, debug3


def original_dst(sock):
    try:
        family = sock.family
        SO_ORIGINAL_DST = 80

        if family == socket.AF_INET:
            SOCKADDR_MIN = 16
            sockaddr_in = sock.getsockopt(socket.SOL_IP,
                                          SO_ORIGINAL_DST, SOCKADDR_MIN)
            port, raw_ip = struct.unpack_from('!2xH4s', sockaddr_in[:8])
            ip = str(ipaddress.IPv4Address(raw_ip))
        elif family == socket.AF_INET6:
            sockaddr_in = sock.getsockopt(41, SO_ORIGINAL_DST, 64)
            port, raw_ip = struct.unpack_from("!2xH4x16s", sockaddr_in)
            ip = str(ipaddress.IPv6Address(raw_ip))
        else:
            raise Fatal("fw: Unknown family type.")
    except socket.error as e:
        if e.args[0] == errno.ENOPROTOOPT:
            return sock.getsockname()
        raise
    return (ip, port)


class Features(object):
    pass


class BaseMethod(object):
    def __init__(self, name):
        self.firewall = None
        self.name = name

    def set_firewall(self, firewall):
        self.firewall = firewall

    @staticmethod
    def get_supported_features():
        result = Features()
        result.loopback_proxy_port = True
        result.ipv4 = True
        result.ipv6 = False
        result.udp = False
        result.dns = True
        result.user = False
        result.group = False
        return result

    @staticmethod
    def is_supported():
        """Returns true if it appears that this method will work on this
        machine."""
        return False

    @staticmethod
    def get_tcp_dstip(sock):
        return original_dst(sock)

    @staticmethod
    def recv_udp(udp_listener, bufsize):
        debug3('Accept UDP using recvfrom.')
        data, srcip = udp_listener.recvfrom(bufsize)
        return (srcip, None, data)

    def send_udp(self, sock, srcip, dstip, data):
        if srcip is not None:
            raise Fatal("Method %s send_udp does not support setting srcip to %r"
                        % (self.name, srcip))
        sock.sendto(data, dstip)

    def setup_tcp_listener(self, tcp_listener):
        pass

    def setup_udp_listener(self, udp_listener):
        pass

    def assert_features(self, features):
        avail = self.get_supported_features()
        for key in ["udp", "dns", "ipv6", "ipv4", "user"]:
            if getattr(features, key) and not getattr(avail, key):
                raise Fatal(
                    "Feature %s not supported with method %s." %
                    (key, self.name))

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, group, tmark):
        raise NotImplementedError()

    def restore_firewall(self, port, family, udp, user, group):
        raise NotImplementedError()

    def wait_for_firewall_ready(self, sshuttle_pid):
        raise NotImplementedError()

    @staticmethod
    def firewall_command(line):
        return False


def get_method(method_name):
    module = importlib.import_module("sshuttle.methods.%s" % method_name)
    return module.Method(method_name)


def get_auto_method():
    debug3("Selecting a method automatically...")
    # Try these methods, in order:
    methods_to_try = ["nat", "nft", "pf", "ipfw"] if sys.platform != "win32" else ["windivert"]
    for m in methods_to_try:
        method = get_method(m)
        if method.is_supported():
            debug3("Method '%s' was automatically selected." % m)
            return method

    raise Fatal("Unable to automatically find a supported method. Check that "
                "the appropriate programs are in your PATH. We tried "
                "methods: %s" % str(methods_to_try))
