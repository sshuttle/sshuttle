import os
import sys
import ipaddress
import threading
from collections import namedtuple
import socket
from multiprocessing import shared_memory
import struct
from functools import wraps
from enum import IntEnum
import time
import traceback

try:
    import pydivert
except ImportError:
    raise Fatal('Could not import pydivert module. windivert requires https://pypi.org/project/pydivert')

from sshuttle.methods import BaseMethod
from sshuttle.helpers import debug3, log, debug1, debug2, Fatal

# https://reqrypt.org/windivert-doc.html#divert_iphdr


ConnectionTuple = namedtuple(
    "ConnectionTuple", ["protocol", "ip_version", "src_addr", "src_port", "dst_addr", "dst_port", "state_epoch", 'state']
)


WINDIVERT_MAX_CONNECTIONS = 10_000

class IPProtocol(IntEnum):
    TCP = socket.IPPROTO_TCP
    UDP = socket.IPPROTO_UDP

    @property
    def filter(self):
        return 'tcp' if self == IPProtocol.TCP else 'udp'

class IPFamily(IntEnum):
    IPv4 =  socket.AF_INET
    IPv6 =  socket.AF_INET6

    @property
    def filter(self):
        return 'ip' if self == socket.AF_INET else 'ipv6'

    @property
    def version(self):
        return 4 if self == socket.AF_INET else 6

    @property
    def loopback_addr(self):
        return '127.0.0.1' if self == socket.AF_INET else '::1'


class ConnState(IntEnum):
    TCP_SYN_SENT  = 11     # SYN sent
    TCP_ESTABLISHED  = 12  # SYN+ACK received
    TCP_FIN_WAIT_1 = 91    # FIN sent
    TCP_CLOSE_WAIT = 92    # FIN received

    @staticmethod
    def can_timeout(state):
        return state in (ConnState.TCP_SYN_SENT, ConnState.TCP_FIN_WAIT_1, ConnState.TCP_CLOSE_WAIT)


def repr_pkt(p):
    r = f"{p.direction.name} {p.src_addr}:{p.src_port}->{p.dst_addr}:{p.dst_port}"
    if p.tcp:
        t = p.tcp
        r += f" {len(t.payload)}B ("
        r += '+'.join(f.upper() for f in ('fin','syn', "rst", "psh", 'ack', 'urg', 'ece', 'cwr', 'ns') if getattr(t, f))
        r += f') SEQ#{t.seq_num}'
        if t.ack:
            r += f' ACK#{t.ack_num}'
        r += f' WZ={t.window_size}'
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

    _instance =None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = object.__new__(cls)
            return cls._instance
        raise RuntimeError("ConnTrack can not be instantiated multiple times")

    def __init__(self, name, max_connections=0) -> None:
        self.struct_full_tuple = struct.Struct('>' + ''.join(('B', 'B', '16s', 'H',  '16s', 'H', 'L', 'B')))
        self.struct_src_tuple = struct.Struct('>' + ''.join(('B', 'B', '16s', 'H')))
        self.struct_state_tuple = struct.Struct('>' + ''.join(('L', 'B')))

        try:
            self.max_connections = max_connections
            self.shm_list = shared_memory.ShareableList([bytes(self.struct_full_tuple.size) for _ in range(max_connections)], name=name)
            self.is_owner = True
            self.next_slot = 0
            self.used_slots = set()
            self.rlock = threading.RLock()
        except FileExistsError:
            self.is_owner = False
            self.shm_list = shared_memory.ShareableList(name=name)
            self.max_connections = len(self.shm_list)

        debug2(f"ConnTrack: is_owner={self.is_owner} entry_size={self.struct_full_tuple.size} shm_name={self.shm_list.shm.name} shm_size={self.shm_list.shm.size}B")

    @synchronized_method('rlock')
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
            self.next_slot =  (self.next_slot +1) % self.max_connections
        else:
            raise RuntimeError("No slot available in ConnTrack") # should not be here

        src_addr = ipaddress.ip_address(src_addr)
        dst_addr = ipaddress.ip_address(dst_addr)
        assert src_addr.version == dst_addr.version
        ip_version = src_addr.version
        state_epoch = int(time.time()) 
        entry = (proto, ip_version, src_addr.packed, src_port, dst_addr.packed, dst_port, state_epoch, state)
        packed = self.struct_full_tuple.pack(*entry)
        self.shm_list[self.next_slot] = packed
        self.used_slots.add(self.next_slot)
        proto = IPProtocol(proto)
        debug3(f"ConnTrack: added ({proto.name} {src_addr}:{src_port}->{dst_addr}:{dst_port} @{state_epoch}:{state.name}) to slot={self.next_slot} | #ActiveConn={len(self.used_slots)}")

    @synchronized_method('rlock')
    def update(self, proto, src_addr, src_port, state):
        if not self.is_owner:
            raise RuntimeError("Only owner can mutate ConnTrack")
        src_addr = ipaddress.ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for i in self.used_slots:
            if self.shm_list[i].startswith(packed):
                state_epoch = int(time.time())
                self.shm_list[i] = self.shm_list[i][:-5] + self.struct_state_tuple.pack(state_epoch, state)
                debug3(f"ConnTrack: updated ({proto.name} {src_addr}:{src_port} @{state_epoch}:{state.name}) from slot={i} | #ActiveConn={len(self.used_slots)}")
                return self._unpack(self.shm_list[i])
            else:
                debug3(f"ConnTrack: ({proto.name} src={src_addr}:{src_port}) is not found to update to {state.name} | #ActiveConn={len(self.used_slots)}")

    @synchronized_method('rlock')
    def remove(self, proto, src_addr, src_port):
        if not self.is_owner:
            raise RuntimeError("Only owner can mutate ConnTrack")
        src_addr = ipaddress.ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for i in self.used_slots:
            if self.shm_list[i].startswith(packed):
                conn = self._unpack(self.shm_list[i])
                self.shm_list[i] = b''
                self.used_slots.remove(i)
                debug3(f"ConnTrack: removed ({proto.name} src={src_addr}:{src_port}  state={conn.state.name}) from slot={i} | #ActiveConn={len(self.used_slots)}")
                return conn
        else:
            debug3(f"ConnTrack: ({proto.name} src={src_addr}:{src_port}) is not found to remove | #ActiveConn={len(self.used_slots)}")


    def get(self, proto, src_addr, src_port):
        src_addr = ipaddress.ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for entry in self.shm_list:
            if entry and entry.startswith(packed):
                return self._unpack(entry)

    @synchronized_method('rlock')
    def gc(self, connection_timeout_sec=15):
        now = int(time.time())
        n = 0
        for i in tuple(self.used_slots):
            state_packed = self.shm_list[i][-5:]
            (state_epoch, state) = self.struct_state_tuple.unpack(state_packed)
            if (now - state_epoch) < connection_timeout_sec:
                continue
            if ConnState.can_timeout(state):
                conn = self._unpack(self.shm_list[i])
                self.shm_list[i] = b''
                self.used_slots.remove(i)
                n += 1
                debug3(f"ConnTrack: GC: removed ({conn.protocol.name} src={conn.src_addr}:{conn.src_port} state={conn.state.name}) from slot={i} | #ActiveConn={len(self.used_slots)}")
        debug3(f"ConnTrack: GC: collected {n} connections | #ActiveConn={len(self.used_slots)}")

    def _unpack(self, packed):
                (proto, ip_version, src_addr_packed, src_port, dst_addr_packed, dst_port, state_epoch, state) = self.struct_full_tuple.unpack(packed)
                dst_addr = str(ipaddress.ip_address(dst_addr_packed if ip_version == 6 else dst_addr_packed[:4]))
                src_addr = str(ipaddress.ip_address(src_addr_packed if ip_version == 6 else src_addr_packed[:4]))
                return ConnectionTuple(IPProtocol(proto), ip_version, src_addr, src_port, dst_addr, dst_port, state_epoch, ConnState(state))
    
    def __iter__(self):
        def conn_iter():
            for i in self.used_slots:
                yield self._unpack(self.shm_list[i])
        return conn_iter()

    def __repr__(self):
        return f"<ConnTrack(n={len(self.used_slots) if self.is_owner else '?'}, cap={len(self.shm_list)}, owner={self.is_owner})>"


class Method(BaseMethod):

    network_config = {}
    proxy_port = None
    proxy_addr = {  IPFamily.IPv4: None,  IPFamily.IPv6: None }

    def __init__(self, name):
        super().__init__(name)

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, tmark):
        log( f"{port=}, {dnsport=}, {nslist=}, {family=}, {subnets=}, {udp=}, {user=}, {tmark=}")

        if nslist or user or udp:
            raise NotImplementedError()

        family = IPFamily(family)

        # using loopback proxy address never worked. See: https://github.com/basil00/Divert/issues/17#issuecomment-341100167 ,https://github.com/basil00/Divert/issues/82)
        # As a workaround we use another interface ip instead.
        # self.proxy_addr[family] = family.loopback_addr
        for addr in (ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(socket.gethostname(), None)):
            if addr.is_loopback or addr.version != family.version:
                continue
            self.proxy_addr[family] = str(addr)
            break
        else:
            raise Fatal(f"Could not find a non loopback proxy address for {family.name}")

        self.proxy_port = port

        subnet_addresses = []
        for (_, mask, exclude, network_addr, fport, lport) in subnets:
            if exclude:
                continue
            assert fport == 0, 'custom port range not supported'
            assert lport == 0,  'custom port range not supported'
            subnet_addresses.append("%s/%s" % (network_addr, mask))

        self.network_config[family] = { 
            'subnets': subnet_addresses,
            "nslist": nslist,
        }



    def wait_for_firewall_ready(self):
        debug2(f"network_config={self.network_config} proxy_addr={self.proxy_addr}")
        self.conntrack = ConnTrack(f'sshuttle-windivert-{os.getppid()}', WINDIVERT_MAX_CONNECTIONS)
        methods = (self._egress_divert, self._ingress_divert, self._connection_gc)
        ready_events = []
        for fn in methods:
            ev = threading.Event()
            ready_events.append(ev)
            def _target():
                try:
                    fn(ev.set)
                except:
                    debug2(f'thread {fn.__name__} exiting due to: ' + traceback.format_exc())
                    sys.stdin.close()  # this will exist main thread
                    sys.stdout.close()
            threading.Thread(name=fn.__name__, target=_target, daemon=True).start()
        for ev in ready_events:
            if not ev.wait(5): # at most 5 sec
                raise Fatal(f"timeout in wait_for_firewall_ready()")
        
    def restore_firewall(self, port, family, udp, user):
        pass

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.user = False
        result.dns = False
        result.ipv6 = False
        return result

    def get_tcp_dstip(self, sock):
        if not hasattr(self, 'conntrack'):
            self.conntrack = ConnTrack(f'sshuttle-windivert-{os.getpid()}')

        src_addr , src_port = sock.getpeername()
        c = self.conntrack.get(IPProtocol.TCP , src_addr, src_port)
        if not c:
            return (src_addr , src_port)
        return (c.dst_addr, c.dst_port)

    def is_supported(self):
        if sys.platform == 'win32':
            return True
        return False

    def _egress_divert(self, ready_cb):
        proto = IPProtocol.TCP
        filter = f"outbound and {proto.filter}"

        # with pydivert.WinDivert(f"outbound and tcp and ip.DstAddr == {subnet}") as w:
        family_filters = []
        for af, c in self.network_config.items():
            subnet_filters = []          
            for cidr in c['subnets']:
                ip_network = ipaddress.ip_network(cidr)
                first_ip = ip_network.network_address
                last_ip = ip_network.broadcast_address
                subnet_filters.append(f"(ip.DstAddr>={first_ip} and ip.DstAddr<={last_ip})")
            family_filters.append(f"{af.filter} and ({' or '.join(subnet_filters)}) ")

        filter = f"{filter} and ({' or '.join(family_filters)})"

        debug1(f"[OUTBOUND] {filter=}")
        with pydivert.WinDivert(filter) as w:
            ready_cb()
            proxy_port = self.proxy_port
            proxy_addr_ipv4 = self.proxy_addr[IPFamily.IPv4]
            proxy_addr_ipv6 = self.proxy_addr[IPFamily.IPv6]
            for pkt in w:
                debug3(">>> " + repr_pkt(pkt))
                if pkt.tcp.syn and not pkt.tcp.ack:  # SYN sent (start of 3-way handshake connection establishment from our side, we wait for SYN+ACK)
                    self.conntrack.add(socket.IPPROTO_TCP, pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port, ConnState.TCP_SYN_SENT)
                if pkt.tcp.fin: # FIN sent (start of graceful close our side, and we wait for ACK)
                    self.conntrack.update(IPProtocol.TCP, pkt.src_addr, pkt.src_port, ConnState.TCP_FIN_WAIT_1)
                if pkt.tcp.rst :  # RST sent (initiate abrupt connection teardown from our side, so we don't expect any reply)
                    self.conntrack.remove(IPProtocol.TCP, pkt.src_addr, pkt.src_port)

                # DNAT
                if pkt.ipv4 and proxy_addr_ipv4:
                    pkt.dst_addr = proxy_addr_ipv4
                if pkt.ipv6 and proxy_addr_ipv6:
                    pkt.dst_addr = proxy_addr_ipv6
                pkt.tcp.dst_port = proxy_port

                # XXX: If we set loopback proxy address (DNAT), then we should do SNAT as well by setting src_addr to loopback address. 
                # Otherwise injecting packet will be ignored by Windows network stack as teh packet has to cross public to private address space.
                # See: https://github.com/basil00/Divert/issues/82
                # Managing SNAT is more trickier, as we have to restore the original source IP address for reply packets.
                # >>> pkt.dst_addr = proxy_addr_ipv4   

                w.send(pkt, recalculate_checksum=True)


    def _ingress_divert(self, ready_cb):
        proto = IPProtocol.TCP
        direction = 'inbound'  # only when proxy address is not loopback address (Useful for testing)
        ip_filters = []
        for addr in (ipaddress.ip_address(a) for a in self.proxy_addr.values() if a):
            if addr.is_loopback:  # Windivert treats all loopback traffic as outbound
                direction = "outbound"
            if addr.version == 4:
                ip_filters.append(f"ip.SrcAddr=={addr}")
            else:
                # ip_checks.append(f"ip.SrcAddr=={hex(int(addr))}") # only Windivert >=2 supports this
                ip_filters.append(f"ipv6.SrcAddr=={addr}")
        filter = f"{direction} and {proto.filter} and ({' or '.join(ip_filters)}) and tcp.SrcPort=={self.proxy_port}"
        debug2(f"[INGRESS] {filter=}")
        with pydivert.WinDivert(filter) as w:
            ready_cb()
            for pkt in w:
                debug3("<<< " + repr_pkt(pkt))
                if pkt.tcp.syn and pkt.tcp.ack:  # SYN+ACK received (connection established)
                    conn = self.conntrack.update(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port, ConnState.TCP_ESTABLISHED)
                elif pkt.tcp.rst:  # RST received - Abrupt connection teardown initiated by other side. We don't expect anymore packets
                    conn = self.conntrack.remove(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port)
                # https://wiki.wireshark.org/TCP-4-times-close.md
                elif pkt.tcp.fin and pkt.tcp.ack:  # FIN+ACK received (Passive close by other side. We don't expect any more packets. Other side expects an ACK)
                    conn = self.conntrack.remove(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port)
                elif pkt.tcp.fin:  # FIN received (Other side initiated graceful close.  We expects a final ACK for a FIN packet)
                    conn = self.conntrack.update(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port, ConnState.TCP_CLOSE_WAIT)
                else:
                    conn = self.conntrack.get(socket.IPPROTO_TCP, pkt.dst_addr, pkt.dst_port)
                if not conn:
                    debug2("Unexpected packet: " +  repr_pkt(pkt))
                    continue
                pkt.src_addr = conn.dst_addr
                pkt.tcp.src_port = conn.dst_port
                w.send(pkt, recalculate_checksum=True)

    def _connection_gc(self, ready_cb):
        ready_cb()
        while True:
            time.sleep(5)
            self.conntrack.gc()
