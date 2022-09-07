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

class ConnState(IntEnum):
    TCP_SYN_SEND  = 10
    TCP_SYN_ACK_RECV  = 11
    TCP_FIN_SEND = 20
    TCP_FIN_RECV = 21

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
        debug3(f"ConnTrack: added connection ({proto.name} {src_addr}:{src_port}->{dst_addr}:{dst_port} @{state_epoch}:{state.name}) to slot={self.next_slot} | #ActiveConn={len(self.used_slots)}")

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
                debug3(f"ConnTrack: updated connection ({proto.name} {src_addr}:{src_port} @{state_epoch}:{state.name}) from slot={i} | #ActiveConn={len(self.used_slots)}")
                return self._unpack(self.shm_list[i])
            else:
                debug3(f"ConnTrack: connection ({proto.name} src={src_addr}:{src_port}) is not found to update to {state.name} | #ActiveConn={len(self.used_slots)}")

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
                debug3(f"ConnTrack: removed connection ({proto.name} src={src_addr}:{src_port}) from slot={i} | #ActiveConn={len(self.used_slots)}")
                return conn
        else:
            debug3(f"ConnTrack: connection ({proto.name} src={src_addr}:{src_port}) is not found to remove | #ActiveConn={len(self.used_slots)}")


    def get(self, proto, src_addr, src_port):
        src_addr = ipaddress.ip_address(src_addr)
        packed = self.struct_src_tuple.pack(proto, src_addr.version, src_addr.packed, src_port)
        for entry in self.shm_list:
            if entry and entry.startswith(packed):
                return self._unpack(entry)

    def _unpack(self, packed):
                (proto, ip_version, src_addr_packed, src_port, dst_addr_packed, dst_port, state_epoch, state) = self.struct_full_tuple.unpack(packed)
                dst_addr = str(ipaddress.ip_address(dst_addr_packed if ip_version == 6 else dst_addr_packed[:4]))
                src_addr = str(ipaddress.ip_address(src_addr_packed if ip_version == 6 else src_addr_packed[:4]))
                return ConnectionTuple(IPProtocol(proto), ip_version, src_addr, src_port, dst_addr, dst_port, state_epoch, ConnState(state))
        
    def __repr__(self):
        return f"<ConnTrack(n={len(self.used_slots) if self.is_owner else '?'}, cap={len(self.shm_list)}, owner={self.is_owner})>"


class Method(BaseMethod):

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, tmark):
        log( f"{port=}, {dnsport=}, {nslist=}, {family=}, {subnets=}, {udp=}, {user=}, {tmark=}")
        self.conntrack = ConnTrack(f'sshuttle-windivert-{os.getppid()}', WINDIVERT_MAX_CONNECTIONS)
        proxy_addr = "10.0.2.15"

        subnet_addresses = []
        for (_, mask, exclude, network_addr, fport, lport) in subnets:
            if exclude:
                continue
            assert fport == 0, 'custom port range not supported'
            assert lport == 0,  'custom port range not supported'
            subnet_addresses.append("%s/%s" % (network_addr, mask))

        debug2("setup_firewall() subnet_addresses=%s proxy_addr=%s:%s" % (subnet_addresses,proxy_addr,port))

        # check permission
        with pydivert.WinDivert('false'):
            pass

        threading.Thread(name='outbound_divert', target=self._outbound_divert, args=(subnet_addresses, proxy_addr, port),  daemon=True).start()
        threading.Thread(name='inbound_divert', target=self._inbound_divert, args=(proxy_addr, port),  daemon=True).start()

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





    def _outbound_divert(self, subnets, proxy_addr, proxy_port):
        # with pydivert.WinDivert(f"outbound and tcp and ip.DstAddr == {subnet}") as w:
        filter = "outbound and ip and tcp"
        subnet_selectors = []
        for cidr in subnets:
            ip_network = ipaddress.ip_network(cidr)
            first_ip = ip_network.network_address
            last_ip = ip_network.broadcast_address
            subnet_selectors.append(f"(ip.DstAddr >= {first_ip} and ip.DstAddr <= {last_ip})")
        filter = f"{filter} and ({'or'.join(subnet_selectors)}) "

        debug1(f"[OUTBOUND] {filter=}")
        with pydivert.WinDivert(filter) as w:
            for pkt in w:
                debug3(">>> " + repr_pkt(pkt))
                if pkt.tcp.syn and not pkt.tcp.ack:  # SYN  (start of 3-way handshake connection establishment)
                    self.conntrack.add(socket.IPPROTO_TCP, pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port, ConnState.TCP_SYN_SEND)
                if pkt.tcp.fin: # FIN (start of graceful close)
                    self.conntrack.update(IPProtocol.TCP, pkt.src_addr, pkt.src_port, ConnState.TCP_FIN_SEND)
                if pkt.tcp.rst :  # RST
                    self.conntrack.remove(IPProtocol.TCP, pkt.src_addr, pkt.src_port)
                pkt.ipv4.dst_addr = proxy_addr
                pkt.tcp.dst_port = proxy_port
                w.send(pkt, recalculate_checksum=True)


    def _inbound_divert(self, proxy_addr, proxy_port):
        filter = f"inbound and ip and tcp and ip.SrcAddr == {proxy_addr} and tcp.SrcPort == {proxy_port}"
        debug2(f"[INBOUND] {filter=}")
        with pydivert.WinDivert(filter) as w:
            for pkt in w:
                debug3("<<< " + repr_pkt(pkt))
                if pkt.tcp.syn and pkt.tcp.ack:  # SYN+ACK  connection established
                    conn = self.conntrack.update(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port, ConnState.TCP_SYN_ACK_RECV)
                elif pkt.tcp.rst or (pkt.tcp.fin and pkt.tcp.ack):  # RST or FIN+ACK  Connection teardown
                    conn = self.conntrack.remove(IPProtocol.TCP, pkt.dst_addr, pkt.dst_port)
                else:
                    conn = self.conntrack.get(socket.IPPROTO_TCP, pkt.dst_addr, pkt.dst_port)
                if not conn:
                    debug2("Unexpected packet: " +  repr_pkt(pkt))
                    continue
                pkt.ipv4.src_addr = conn.dst_addr
                pkt.tcp.src_port = conn.dst_port
                w.send(pkt, recalculate_checksum=True)


