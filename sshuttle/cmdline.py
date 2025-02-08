import os
import re
import shlex
import socket
import sys
import sshuttle.helpers as helpers
import sshuttle.client as client
import sshuttle.firewall as firewall
import sshuttle.hostwatch as hostwatch
import sshuttle.ssyslog as ssyslog
from sshuttle.options import parser, parse_ipport
from sshuttle.helpers import family_ip_tuple, log, Fatal
from sshuttle.sudoers import sudoers
from sshuttle.namespace import enter_namespace


def main():
    if 'SSHUTTLE_ARGS' in os.environ:
        env_args = shlex.split(os.environ['SSHUTTLE_ARGS'])
    else:
        env_args = []
    args = [*env_args, *sys.argv[1:]]

    opt = parser.parse_args(args)

    if opt.sudoers_no_modify:
        # sudoers() calls exit() when it completes
        sudoers(user_name=opt.sudoers_user)

    if opt.daemon:
        opt.syslog = 1
    if opt.wrap:
        import sshuttle.ssnet as ssnet
        ssnet.MAX_CHANNEL = opt.wrap
    if opt.latency_buffer_size:
        import sshuttle.ssnet as ssnet
        ssnet.LATENCY_BUFFER_SIZE = opt.latency_buffer_size
    helpers.verbose = opt.verbose

    try:
        # Since namespace and namespace-pid options are only available
        # in linux, we must check if it exists with getattr
        namespace = getattr(opt, 'namespace', None)
        namespace_pid = getattr(opt, 'namespace_pid', None)
        if namespace or namespace_pid:
            prefix = helpers.logprefix
            helpers.logprefix = 'ns: '
            enter_namespace(namespace, namespace_pid)
            helpers.logprefix = prefix

        if opt.firewall:
            if opt.subnets or opt.subnets_file:
                parser.error('exactly zero arguments expected')
            return firewall.main(opt.method, opt.syslog)
        elif opt.hostwatch:
            hostwatch.hw_main(opt.subnets, opt.auto_hosts)
            return 0
        else:
            # parse_subnetports() is used to create a list of includes
            # and excludes. It is called once for each parameter and
            # returns a list of one or more items for each subnet (it
            # can return more than one item when a hostname in the
            # parameter resolves to multiple IP addresses. Here, we
            # flatten these lists.
            includes = [item for sublist in opt.subnets+opt.subnets_file
                        for item in sublist]
            excludes = [item for sublist in opt.exclude for item in sublist]

            if not includes and not opt.auto_nets:
                parser.error('at least one subnet, subnet file, '
                             'or -N expected')
            remotename = opt.remote
            if remotename == '' or remotename == '-':
                remotename = None
            nslist = [family_ip_tuple(ns) for ns in opt.ns_hosts]
            if opt.seed_hosts:
                sh = re.split(r'[\s,]+', (opt.seed_hosts or "").strip())
            elif opt.auto_hosts:
                sh = []
            else:
                sh = None
            if opt.listen:
                ipport_v6 = None
                ipport_v4 = None
                lst = opt.listen.split(",")
                for ip in lst:
                    family, ip, port = parse_ipport(ip)
                    if family == socket.AF_INET6:
                        ipport_v6 = (ip, port)
                    else:
                        ipport_v4 = (ip, port)
            else:
                # parse_ipport4('127.0.0.1:0')
                ipport_v4 = "auto"
                # parse_ipport6('[::1]:0')
                ipport_v6 = "auto" if not opt.disable_ipv6 else None
            try:
                int(opt.tmark, 16)
            except ValueError:
                parser.error("--tmark must be a hexadecimal value")
            opt.tmark = opt.tmark.lower()   # make 'x' in 0x lowercase
            if not opt.tmark.startswith("0x"):  # accept without 0x prefix
                opt.tmark = "0x%s" % opt.tmark
            if opt.syslog:
                ssyslog.start_syslog()
                ssyslog.close_stdin()
                ssyslog.stdout_to_syslog()
                ssyslog.stderr_to_syslog()
            return_code = client.main(ipport_v6, ipport_v4,
                                      opt.ssh_cmd,
                                      remotename,
                                      opt.python,
                                      opt.latency_control,
                                      opt.latency_buffer_size,
                                      opt.dns,
                                      nslist,
                                      opt.method,
                                      sh,
                                      opt.auto_hosts,
                                      opt.auto_nets,
                                      includes,
                                      excludes,
                                      opt.daemon,
                                      opt.to_ns,
                                      opt.pidfile,
                                      opt.user,
                                      opt.group,
                                      opt.sudo_pythonpath,
                                      opt.add_cmd_delimiter,
                                      opt.remote_shell,
                                      opt.tmark)

            if return_code == 0:
                log('Normal exit code, exiting...')
            else:
                log('Abnormal exit code %d detected, failing...' % return_code)
            return return_code

    except Fatal as e:
        log('fatal: %s' % e)
        return 99
    except KeyboardInterrupt:
        log('\n')
        log('Keyboard interrupt: exiting.')
        return 1
