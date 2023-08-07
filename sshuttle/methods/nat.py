import socket
from sshuttle.firewall import subnet_weight
from sshuttle.helpers import family_to_string, which, debug2
from sshuttle.linux import ipt, ipt_chain_exists, nonfatal
from sshuttle.methods import BaseMethod


class Method(BaseMethod):

    # We name the chain based on the transproxy port number so that it's
    # possible to run multiple copies of sshuttle at the same time.  Of course,
    # the multiple copies shouldn't have overlapping subnets, or only the most-
    # recently-started one will win (because we use "-I OUTPUT 1" instead of
    # "-A OUTPUT").
    def setup_firewall(self, port, dnsport, nslist, family, subnets, udp,
                       user, group, tmark):
        if family != socket.AF_INET and family != socket.AF_INET6:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")
        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipm(*args):
            return ipt(family, "mangle", *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        self.restore_firewall(port, family, udp, user, group)

        _ipt('-N', chain)
        _ipt('-F', chain)
        if user is not None or group is not None:
            margs = ['-I', 'OUTPUT', '1', '-m', 'owner']
            if user is not None:
                margs += ['--uid-owner', str(user)]
            if group is not None:
                margs += ['--gid-owner', str(group)]
            margs += ['-j', 'MARK', '--set-mark', str(port)]
            nonfatal(_ipm, *margs)
            args = '-m', 'mark', '--mark', str(port), '-j', chain
        else:
            args = '-j', chain

        _ipt('-I', 'OUTPUT', '1', *args)
        _ipt('-I', 'PREROUTING', '1', *args)

        # Redirect DNS traffic as requested. This includes routing traffic
        # to localhost DNS servers through sshuttle.
        for _, ip in [i for i in nslist if i[0] == family]:
            _ipt('-A', chain, '-j', 'REDIRECT',
                 '--dest', '%s' % ip,
                 '-p', 'udp',
                 '--dport', '53',
                 '--to-ports', str(dnsport))

        # create new subnet entries.
        for _, swidth, sexclude, snet, fport, lport \
                in sorted(subnets, key=subnet_weight, reverse=True):
            tcp_ports = ('-p', 'tcp')
            if fport:
                tcp_ports = tcp_ports + ('--dport', '%d:%d' % (fport, lport))

            if sexclude:
                _ipt('-A', chain, '-j', 'RETURN',
                     '--dest', '%s/%s' % (snet, swidth),
                     *tcp_ports)
            else:
                _ipt('-A', chain, '-j', 'REDIRECT',
                     '--dest', '%s/%s' % (snet, swidth),
                     *(tcp_ports + ('--to-ports', str(port))))

        # Don't route any remaining local traffic through sshuttle.
        _ipt('-A', chain, '-j', 'RETURN',
             '-m', 'addrtype',
             '--dst-type', 'LOCAL')

    def restore_firewall(self, port, family, udp, user, group):
        # only ipv4 supported with NAT
        if family != socket.AF_INET and family != socket.AF_INET6:
            raise Exception(
                'Address family "%s" unsupported by nat method_name'
                % family_to_string(family))
        if udp:
            raise Exception("UDP not supported by nat method_name")

        table = "nat"

        def _ipt(*args):
            return ipt(family, table, *args)

        def _ipm(*args):
            return ipt(family, "mangle", *args)

        chain = 'sshuttle-%s' % port

        # basic cleanup/setup of chains
        if ipt_chain_exists(family, table, chain):
            if user is not None or group is not None:
                margs = ['-D', 'OUTPUT', '-m', 'owner']
                if user is not None:
                    margs += ['--uid-owner', str(user)]
                if group is not None:
                    margs += ['--gid-owner', str(group)]
                margs += ['-j', 'MARK', '--set-mark', str(port)]
                nonfatal(_ipm, *margs)

                args = '-m', 'mark', '--mark', str(port), '-j', chain
            else:
                args = '-j', chain
            nonfatal(_ipt, '-D', 'OUTPUT', *args)
            nonfatal(_ipt, '-D', 'PREROUTING', *args)
            nonfatal(_ipt, '-F', chain)
            _ipt('-X', chain)

    def get_supported_features(self):
        result = super(Method, self).get_supported_features()
        result.user = True
        result.ipv6 = True
        result.group = True
        return result

    def is_supported(self):
        if which("iptables"):
            return True
        debug2("nat method not supported because 'iptables' command "
               "is missing.")
        return False
