import os
import sys
from ipaddress import ip_address, ip_network
import threading
from collections import namedtuple
import socket
import subprocess
import re
from multiprocessing import shared_memory
from struct import Struct
from functools import wraps
from enum import IntEnum
import time
import traceback


from sshuttle.methods import BaseMethod
from sshuttle.helpers import log, debug3, debug1, debug2, get_verbose_level, Fatal

try:
    # https://reqrypt.org/windivert-doc.html#divert_iphdr
    # https://www.reqrypt.org/windivert-changelog.txt
    import pydivert
except ImportError:
    raise Exception("Could not import pydivert module. windivert requires https://pypi.org/project/pydivert")


ConnectionTuple = namedtuple(
    "ConnectionTuple",
    ["protocol", "ip_version", "src_addr", "src_port", "dst_addr", "dst_port", "state_epoch", "state"],
)


WINDIVERT_MAX_CONNECTIONS = int(os.environ.get('WINDIVERT_MAX_CONNECTIONS', 1024))


class IPProtocol(IntEnum):
    TCP = socket.IPPROTO_TCP
    UDP = socket.IPPROTO_UDP

    @property
    def filter(self):
        return "tcp" if self == IPProtocol.TCP else "udp"


class IPFamily(IntEnum):
    IPv4 = socket.AF_INET
    IPv6 = socket.AF_INET6

    @staticmethod
    def from_ip_version(version):
        return IPFamily.IPv6 if version == 4 else IPFamily.IPv4

    @property
    def filter(self):
        return "ip" if self == socket.AF_INET else "ipv6"

    @property
    def version(self):
        return 4 if self == socket.AF_INET else 6

    @property
    def loopback_addr(self):
        return ip_address("127.0.0.1" if self == socket.AF_INET else "::1")


class ConnState(IntEnum):
    TCP_SYN_SENT = 11  # SYN sent
    TCP_ESTABLISHED = 12  # SYN+ACK received
    TCP_FIN_WAIT_1 = 91  # FIN sent
    TCP_CLOSE_WAIT = 92  # FIN received

    @staticmethod
    def can_timeout(state):
        return state in (ConnState.TCP_SYN_SENT, ConnState.TCP_FIN_WAIT_1, ConnState.TCP_CLOSE_WAIT)


def repr_pkt(p):
    try:
        direction = p.direction.name
        if p.is_loopback:
            direction += "/lo"
    except AttributeError:  # windiver > 2.0
        direction = 'OUT' if p.address.Outbound == 1 else 'IN'
        if p.address.Loopback == 1:
            direction += '/lo'
    r = f"{direction} {p.src_addr}:{p.src_port}->{p.dst_addr}:{p.dst_port}"
    if p.tcp:
        t = p.tcp
        r += f" {len(t.payload)}B ("
        r += "+".join(
            f.upper() for f in ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr", "ns") if getattr(t, f)
        )
        r += f") SEQ#{t.seq_num}"
        if t.ack:
            r += f" ACK#{t.ack_num}"
        r += f" WZ={t.window_size}"
    else:
        r += f" {p.udp=} {p.icmpv4=} {p.icmpv6=}"
    return f"<Pkt {r}>"


def synchronized_method(lock):
    def decorator(method):
        @wraps(method)
        def wrapped(self, *args, **kwargs):
            with getattr(self, lock):
                return method(self, *args, **kwargs)

        return wrapped

    return decorator


class ConnTrack:

    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = object.__new__(cls)
            return cls._instance
        raise RuntimeError("ConnTrack can not be instantiated multiple times")

    def __init__(self, name, max_connections=0) -> None:
        self.struct_full_tuple = Struct(">" + "".join(("B", "B", "16s", "H", "16s", "H", "L", "B")))
        self.struct_src_tuple = Struct(">" + "".join(("B", "B", "16s", "H")))
        self.struct_state_tuple = Struct(">" + "".join(("L", "B")))

        try:
            self.max_connections = max_connections
            self.shm_list = shared_memory.ShareableList(
                [bytes(self.struct_full_tuple.size) for _ in range(max_connections)], name=name
            )
            self.is_owner = True
            self.next_slot = 0
            self.used_slots = set()
            self.rlock = threading.RLock()
        except FileExistsError:
            self.is_owner = False
            self.shm_list = shared_memory.ShareableList(name=name)
            self.max_connections = len(self.shm_list)

        debug2(
            f"ConnTrack: is_owner={self.is_owner} cap={len(self.shm_list)} item_sz={self.struct_full_tuple.size}B"
            f"shm_name={self.shm_list.shm.name} shm_sz={self.shm_list.shm.size}B"
        )

    @synchronized_method("rlock")
    def add(self, proto, src_addr, src_port, dst_addr, dst_port, state):
        if not self.is_owner:
            raise RuntimeError("Only owner can mutate ConnTrack")
        if len(self.used_slots) >= self.max_connections:
            raise RuntimeError(f"No slot available in ConnTrack {len(self.used_slots)}/{self.max_connections}")

        if self.get(proto, src_addr, src_port):
            return

        for _ in range(self.max_connections):
            if self.next_slot not in self.used_slots:
                break
            self.next_slot = (self.next_slot + 1) % self.max_connections
        else:
            raise RuntimeError("No slot available in ConnTrack")  # should not be here

        src_addr = ip_address(src_addr)
        dst_addr = ip_address(dst_addr)
        assert src_addr.version == dst_addr.version
        ip_version = src_addr.version
        state_epoch = int(time.time())
        entry = (proto, ip_version, src_addr.packed, src_port, dst_addr.packed, dst_port, state_epoch, state)
        packed = self.struct_full_tuple.pack(*entry)
        self.shm_list[self.next_slot] = packed
        self.used_slots.add(self.next_slot)
        proto = IPProtocol(proto)
        debug3(
            f"ConnTrack: added ({proto.name} {src_addr}:{src_port}->{dst_addr}:{dst_port} @{state_epoch}:{state.name}) to "
            f"slot={self.next_slot} | #ActiveConn={len(self.used_slots)}"
        )

    @synchronized_method("rlock")
    def update(self, proto, src_addr, src_port, state):
        if not self.is_owner:
            raise RuntimeError("Only owner can mutate ConnTrack")
        src_addr = ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for i in self.used_slots:
            if self.shm_list[i].startswith(packed):
                state_epoch = int(time.time())
                self.shm_list[i] = self.shm_list[i][:-5] + self.struct_state_tuple.pack(state_epoch, state)
                debug3(
                    f"ConnTrack: updated ({proto.name} {src_addr}:{src_port} @{state_epoch}:{state.name}) from slot={i} | "
                    f"#ActiveConn={len(self.used_slots)}"
                )
                return self._unpack(self.shm_list[i])
            else:
                debug3(
                    f"ConnTrack: ({proto.name} src={src_addr}:{src_port}) is not found to update to {state.name} | "
                    f"#ActiveConn={len(self.used_slots)}"
                )

    @synchronized_method("rlock")
    def remove(self, proto, src_addr, src_port):
        if not self.is_owner:
            raise RuntimeError("Only owner can mutate ConnTrack")
        src_addr = ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for i in self.used_slots:
            if self.shm_list[i].startswith(packed):
                conn = self._unpack(self.shm_list[i])
                self.shm_list[i] = b""
                self.used_slots.remove(i)
                debug3(
                    f"ConnTrack: removed ({proto.name} src={src_addr}:{src_port}  state={conn.state.name}) from slot={i} | "
                    f"#ActiveConn={len(self.used_slots)}"
                )
                return conn
        else:
            debug3(
                f"ConnTrack: ({proto.name} src={src_addr}:{src_port}) is not found to remove |"
                f" #ActiveConn={len(self.used_slots)}"
            )

    def get(self, proto, src_addr, src_port):
        src_addr = ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for entry in self.shm_list:
            if entry and entry.startswith(packed):
                return self._unpack(entry)

    def dump(self):
        for entry in self.shm_list:
            if not entry:
                continue
            conn = self._unpack(entry)
            proto, ip_version, src_addr, src_port, dst_addr, dst_port, state_epoch, state = conn
            log(f"{proto.name}/{ip_version} {src_addr}:{src_port} -> {dst_addr}:{dst_port}  {state.name}@{state_epoch}")

    @synchronized_method("rlock")
    def gc(self, connection_timeout_sec=15):
        # self.dump()
        now = int(time.time())
        n = 0
        for i in tuple(self.used_slots):
            state_packed = self.shm_list[i][-5:]
            (state_epoch, state) = self.struct_state_tuple.unpack(state_packed)
            if (now - state_epoch) < connection_timeout_sec:
                continue
            if ConnState.can_timeout(state):
                conn = self._unpack(self.shm_list[i])
                self.shm_list[i] = b""
                self.used_slots.remove(i)
                n += 1
                debug3(
                    f"ConnTrack: GC: removed ({conn.protocol.name} src={conn.src_addr}:{conn.src_port} state={conn.state.name})"
                    f" from slot={i} | #ActiveConn={len(self.used_slots)}"
                )
        debug3(f"ConnTrack: GC: collected {n} connections | #ActiveConn={len(self.used_slots)}")

    def _unpack(self, packed):
        (
            proto,
            ip_version,
            src_addr_packed,
            src_port,
            dst_addr_packed,
            dst_port,
            state_epoch,
            state,
        ) = self.struct_full_tuple.unpack(packed)
        dst_addr = ip_address(dst_addr_packed if ip_version == 6 else dst_addr_packed[:4]).exploded
        src_addr = ip_address(src_addr_packed if ip_version == 6 else src_addr_packed[:4]).exploded
        proto = IPProtocol(proto)
        state = ConnState(state)
        return ConnectionTuple(proto, ip_version, src_addr, src_port, dst_addr, dst_port, state_epoch, state)

    def __iter__(self):
        def conn_iter():
            for i in self.used_slots:
                yield self._unpack(self.shm_list[i])

        return conn_iter()

    def __repr__(self):
        return f"<ConnTrack(n={len(self.used_slots) if self.is_owner else '?'},cap={len(self.shm_list)},owner={self.is_owner})>"


class Method(BaseMethod):

    network_config = {}

    def __init__(self, name):
        super().__init__(name)

    def _get_bind_address_for_port(self, port, family):
        proto = "TCPv6" if family.version == 6 else "TCP"
        for line in subprocess.check_output(["netstat", "-a", "-n", "-p", proto]).decode(errors='ignore').splitlines():
            try:
                _, local_addr, _, state, *_ = re.split(r"\s+", line.strip())
            except ValueError:
                continue
            port_suffix = ":" + str(port)
            if state == "LISTENING" and local_addr.endswith(port_suffix):
                return ip_address(local_addr[:-len(port_suffix)].strip("[]"))
        raise Fatal("Could not find listening address for {}/{}".format(port, proto))

    def setup_firewall(self, proxy_port, dnsport, nslist, family, subnets, udp, user, group, tmark):
        debug2(f"{proxy_port=}, {dnsport=}, {nslist=}, {family=}, {subnets=}, {udp=}, {user=}, {group=} {tmark=}")

        if nslist or user or udp or group:
            raise NotImplementedError("user, group, nslist, udp are not supported")

        family = IPFamily(family)

        proxy_ip = None
        # using loopback only proxy binding won't work with windivert.
        # See: https://github.com/basil00/Divert/issues/17#issuecomment-341100167 https://github.com/basil00/Divert/issues/82)
        # As a workaround, finding another interface ip instead. (client should not bind proxy to loopback address)
        proxy_bind_addr = self._get_bind_address_for_port(proxy_port, family)
        if proxy_bind_addr.is_loopback:
            raise Fatal("Windivert method requires proxy to be reachable by a non loopback address.")
        if not proxy_bind_addr.is_unspecified:
            proxy_ip = proxy_bind_addr
        else:
            local_addresses = [ip_address(info[4][0]) for info in socket.getaddrinfo(socket.gethostname(), 0, family=family)]
            for addr in local_addresses:
                if not addr.is_loopback and not addr.is_link_local:
                    proxy_ip = addr
                    break
            else:
                raise Fatal("Windivert method requires proxy to be reachable by a non loopback address."
                            f"No address found for {family.name} in {local_addresses}")
        debug2(f"Found non loopback address to connect to proxy: {proxy_ip}")
        subnet_addresses = []
        for (_, mask, exclude, network_addr, fport, lport) in subnets:
            if fport and lport:
                if lport > fport:
                    raise Fatal("lport must be less than or equal to fport")
                ports = (fport, lport)
            else:
                ports = None
            subnet_addresses.append((ip_network(f"{network_addr}/{mask}"), ports, exclude))

        self.network_config[family] = {
            "subnets": subnet_addresses,
            "nslist": nslist,
            "proxy_addr": (proxy_ip, proxy_port)
        }

    def wait_for_firewall_ready(self, sshuttle_pid):
        debug2(f"network_config={self.network_config}")
        self.conntrack = ConnTrack(f"sshuttle-windivert-{sshuttle_pid}", WINDIVERT_MAX_CONNECTIONS)
        if not self.conntrack.is_owner:
            raise Fatal("ConnTrack should be owner in wait_for_firewall_ready()")
        thread_target_funcs = (self._egress_divert, self._ingress_divert, self._connection_gc)
        ready_events = []
        for fn in thread_target_funcs:
            ev = threading.Event()
            ready_events.append(ev)

            def _target():
                try:
                    fn(ev.set)
                except Exception:
                    debug2(f"thread {fn.__name__} exiting due to: " + traceback.format_exc())
                    sys.stdin.close()  # this will exist main thread
                    sys.stdout.close()

            threading.Thread(name=fn.__name__, target=_target, daemon=True).start()
        for ev in ready_events:
            if not ev.wait(5):  # at most 5 sec
                raise Fatal("timeout in wait_for_firewall_ready()")

    def restore_firewall(self, port, family, udp, user, group):
        pass

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.loopback_proxy_port = False
        result.user = False
        result.dns = False
        # ipv6 only able to support with Windivert 2.x due to bugs in filter parsing
        # TODO(nom3ad): Enable ipv6 once https://github.com/ffalcinelli/pydivert/pull/57 merged
        result.ipv6 = False
        return result

    def get_tcp_dstip(self, sock):
        if not hasattr(self, "conntrack"):
            self.conntrack = ConnTrack(f"sshuttle-windivert-{os.getpid()}")
            if self.conntrack.is_owner:
                raise Fatal("ConnTrack should not be owner in get_tcp_dstip()")

        src_addr, src_port = sock.getpeername()
        c = self.conntrack.get(IPProtocol.TCP, src_addr, src_port)
        if not c:
            return (src_addr, src_port)
        return (c.dst_addr, c.dst_port)

    def is_supported(self):
        if sys.platform == "win32":
            return True
        return False

    def _egress_divert(self, ready_cb):
        """divert outgoing packets to proxy"""
        proto = IPProtocol.TCP
        filter = f"outbound and {proto.filter}"
        af_filters = []
        for af, c in self.network_config.items():
            subnet_include_filters = []
            subnet_exclude_filters = []
            for ip_net, ports, exclude in c["subnets"]:
                first_ip = ip_net.network_address.exploded
                last_ip = ip_net.broadcast_address.exploded
                if first_ip == last_ip:
                    _subnet_filter = f"{af.filter}.DstAddr=={first_ip}"
                else:
                    _subnet_filter = f"{af.filter}.DstAddr>={first_ip} and {af.filter}.DstAddr<={last_ip}"
                if ports:
                    if ports[0] == ports[1]:
                        _subnet_filter += f" and {proto.filter}.DstPort=={ports[0]}"
                    else:
                        _subnet_filter += f" and tcp.DstPort>={ports[0]} and tcp.DstPort<={ports[1]}"
                (subnet_exclude_filters if exclude else subnet_include_filters).append(f"({_subnet_filter})")
            _af_filter = f"{af.filter}"
            if subnet_include_filters:
                _af_filter += f" and ({' or '.join(subnet_include_filters)})"
            if subnet_exclude_filters:
                # TODO(noma3ad) use not() operator with Windivert2 after upgrade
                _af_filter += f" and (({' or '.join(subnet_exclude_filters)})? false : true)"
            proxy_ip, proxy_port = c["proxy_addr"]
            # Avoids proxy outbound traffic getting directed to itself
            proxy_guard_filter = f"(({af.filter}.DstAddr=={proxy_ip.exploded} and tcp.DstPort=={proxy_port})? false : true)"
            _af_filter += f" and {proxy_guard_filter}"
            af_filters.append(_af_filter)
        if not af_filters:
            raise Fatal("At least one ipv4 or ipv6 subnet is expected")

        filter = f"{filter} and ({' or '.join(af_filters)})"
        debug1(f"[EGRESS] {filter=}")
        with pydivert.WinDivert(filter, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.DEFAULT) as w:
            proxy_ipv4, proxy_ipv6 = None, None
            if IPFamily.IPv4 in self.network_config:
                proxy_ipv4 = self.network_config[IPFamily.IPv4]["proxy_addr"]
                proxy_ipv4 = proxy_ipv4[0].exploded, proxy_ipv4[1]
            if IPFamily.IPv6 in self.network_config:
                proxy_ipv6 = self.network_config[IPFamily.IPv6]["proxy_addr"]
                proxy_ipv6 = proxy_ipv6[0].exploded, proxy_ipv6[1]
            ready_cb()
            verbose = get_verbose_level()
            for pkt in w:
                verbose >= 3 and debug3("[EGRESS] " + repr_pkt(pkt))
                if pkt.tcp.syn and not pkt.tcp.ack:
                    # SYN sent (start of 3-way handshake connection establishment from our side, we wait for SYN+ACK)
                    self.conntrack.add(
                        socket.IPPROTO_TCP,
                        pkt.src_addr,
                        pkt.src_port,
                        pkt.dst_addr,
                        pkt.dst_port,
                        ConnState.TCP_SYN_SENT,
                    )
                if pkt.tcp.fin:
                    # FIN sent (start of graceful close our side, and we wait for ACK)
                    self.conntrack.update(IPProtocol.TCP, pkt.src_addr, pkt.src_port, ConnState.TCP_FIN_WAIT_1)
                if pkt.tcp.rst:
                    # RST sent (initiate abrupt connection teardown from our side, so we don't expect any reply)
                    self.conntrack.remove(IPProtocol.TCP, pkt.src_addr, pkt.src_port)

                # DNAT
                if pkt.ipv4 and proxy_ipv4:
                    pkt.dst_addr, pkt.tcp.dst_port = proxy_ipv4
                if pkt.ipv6 and proxy_ipv6:
                    pkt.dst_addr, pkt.tcp.dst_port = proxy_ipv6

                # XXX: If we set loopback proxy address (DNAT), then we should do SNAT as well
                #  by setting src_addr to loopback address.
                # Otherwise injecting packet will be ignored by Windows network stack
                #   as they packet has to cross public to private address space.
                # See: https://github.com/basil00/Divert/issues/82
                # Managing SNAT is more trickier, as we have to restore the original source IP address for reply packets.
                # >>> pkt.dst_addr = proxy_ipv4
                w.send(pkt, recalculate_checksum=True)

    def _ingress_divert(self, ready_cb):
        """handles incoming packets from proxy"""
        proto = IPProtocol.TCP
        # Windivert treats all local process traffic as outbound, regardless of origin external/loopback iface
        direction = "outbound"
        proxy_addr_filters = []
        for af, c in self.network_config.items():
            if not c["subnets"]:
                continue
            proxy_ip, proxy_port = c["proxy_addr"]
            # "ip.SrcAddr=={hex(int(proxy_ip))}" # only Windivert >=2 supports this
            proxy_addr_filters.append(f"{af.filter}.SrcAddr=={proxy_ip.exploded} and tcp.SrcPort=={proxy_port}")
        if not proxy_addr_filters:
            raise Fatal("At least one ipv4 or ipv6 address is expected")
        filter = f"{direction} and {proto.filter} and ({' or '.join(proxy_addr_filters)})"
        debug1(f"[INGRESS] {filter=}")
        with pydivert.WinDivert(filter, layer=pydivert.Layer.NETWORK, flags=pydivert.Flag.DEFAULT) as w:
            ready_cb()
            verbose = get_verbose_level()
            for pkt in w:
                verbose >= 3 and debug3("[INGRESS] " + repr_pkt(pkt))
                if pkt.tcp.syn and pkt.tcp.ack:
                    # SYN+ACK received (connection established from proxy
                    conn = self.conntrack.update(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port, ConnState.TCP_ESTABLISHED)
                elif pkt.tcp.rst:
                    # RST received - Abrupt connection teardown initiated by proxy. Don't expect anymore packets
                    conn = self.conntrack.remove(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port)
                # https://wiki.wireshark.org/TCP-4-times-close.md
                elif pkt.tcp.fin and pkt.tcp.ack:
                    # FIN+ACK received (Passive close by proxy. Don't expect any more packets. proxy expects an ACK)
                    conn = self.conntrack.remove(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port)
                elif pkt.tcp.fin:
                    # FIN received (proxy initiated graceful close.  Expect a final ACK for a FIN packet)
                    conn = self.conntrack.update(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port, ConnState.TCP_CLOSE_WAIT)
                else:
                    # data fragments and ACKs
                    conn = self.conntrack.get(socket.IPPROTO_TCP, pkt.dst_addr, pkt.dst_port)
                if not conn:
                    verbose >= 2 and debug2("Unexpected packet: " + repr_pkt(pkt))
                    continue
                pkt.src_addr = conn.dst_addr
                pkt.tcp.src_port = conn.dst_port
                w.send(pkt, recalculate_checksum=True)

    def _connection_gc(self, ready_cb):
        ready_cb()
        while True:
            time.sleep(5)
            self.conntrack.gc()
