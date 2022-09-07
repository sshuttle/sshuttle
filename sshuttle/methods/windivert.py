import sys
import ipaddress
import threading
from collections import namedtuple


try:
    import pydivert
except ImportError:
    raise Fatal('Could not import pydivert module. windivert requires https://pypi.org/project/pydivert')

from sshuttle.methods import BaseMethod
from sshuttle.helpers import log, debug1, debug2, Fatal

# https://reqrypt.org/windivert-doc.html#divert_iphdr


ConnectionTuple = namedtuple(
    "ConnectionTuple", ["protocol", "src_addr", "src_port", "dst_addr", "dst_port"]
)

class ConnectionTracker:
    def __init__(self) -> None:
        self.d = {}

    def add_tcp(self, src_addr, src_port, dst_addr, dst_port):
        k = ("TCP", src_addr, src_port)
        v = (dst_addr, dst_port)
        if self.d.get(k) != v:
            debug1("Adding tcp connection to tracker:" + repr((src_addr, src_port, dst_addr, dst_port)))
            self.d[k] = v

    def get_tcp(self, src_addr, src_port):
        try:
            return ConnectionTuple(
                "TCP", src_addr, src_port, *self.d[("TCP", src_addr, src_port)]
            )
        except KeyError:
            return None


class Method(BaseMethod):

    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, tmark):
        log( f"{port=}, {dnsport=}, {nslist=}, {family=}, {subnets=}, {udp=}, {user=}, {tmark=}")
        #  port=12300, dnsport=0, nslist=[], family=<AddressFamily.AF_INET: 2>, 
        # subnets=[(2, 24, False, '10.111.10.0', 0, 0), (2, 16, False, '169.254.0.0', 0, 0), (2, 24, False, '172.31.0.0', 0, 0), (2, 16, False, '192.168.0.0', 0, 0), (2, 32, True, '0.0.0.0', 0, 0)],
        #  udp=False, user=None, tmark='0x01' 
        self.conntrack = ConnectionTracker()
        proxy_addr = "10.0.2.15"

        subnet_addreses = []
        for (_, mask, exclude, network_addr, fport, lport) in subnets:
            if exclude:
                continue
            assert fport == 0, 'custom port range not supported'
            assert lport == 0,  'custom port range not supported'
            subnet_addreses.append("%s/%s" % (network_addr, mask))

        debug2("subnet_addreses=%s proxy_addr=%s:%s" % (subnet_addreses,proxy_addr,port))

        # check permission
        with pydivert.WinDivert('false'):
            pass

        threading.Thread(name='outbound_divert', target=self._outbound_divert, args=(subnet_addreses, proxy_addr, port),  daemon=True).start()
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
        return ('172.31.0.141', 80)

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
                # debug3(repr(pkt))
                self.conntrack.add_tcp(pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port)
                pkt.ipv4.dst_addr = proxy_addr
                pkt.tcp.dst_port = proxy_port
                w.send(pkt, recalculate_checksum=True)


    def _inbound_divert(self, proxy_addr, proxy_port):
        filter = f"inbound and ip and tcp and ip.SrcAddr == {proxy_addr} and tcp.SrcPort == {proxy_port}"
        debug2(f"[INBOUND] {filter=}")
        with pydivert.WinDivert(filter) as w:
            for pkt in w:
                # debug2(repr(conntrack.d))
                # debug2(repr((pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port)))
                conn = self.conntrack.get_tcp(pkt.dst_addr, pkt.dst_port)
                if not conn:
                    debug2("Unexpcted packet:" + repr((pkt.protocol,pkt.src_addr,pkt.src_port,pkt.dst_addr,pkt.dst_port)))
                    continue
                pkt.ipv4.src_addr = conn.dst_addr
                pkt.tcp.src_port = conn.dst_port
                w.send(pkt, recalculate_checksum=True)


