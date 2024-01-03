import time
import socket
import re
import select
import errno
import os
import sys
import platform

import subprocess as ssubprocess
import sshuttle.helpers as helpers
from sshuttle.helpers import log, debug1, debug2, debug3, get_env

POLL_TIME = 60 * 15
NETSTAT_POLL_TIME = 30
CACHEFILE = os.path.expanduser('~/.sshuttle.hosts')

# Have we already failed to write CACHEFILE?
CACHE_WRITE_FAILED = False

SHOULD_WRITE_CACHE = False

hostnames = {}
queue = {}
try:
    null = open(os.devnull, 'wb')
except IOError:
    _, e = sys.exc_info()[:2]
    log('warning: %s' % e)
    null = os.popen("sh -c 'while read x; do :; done'", 'wb', 4096)


def _is_ip(s):
    return re.match(r'\d+\.\d+\.\d+\.\d+$', s)


def write_host_cache():
    """If possible, write our hosts file to disk so future connections
       can reuse the hosts that we already found."""
    tmpname = '%s.%d.tmp' % (CACHEFILE, os.getpid())
    global CACHE_WRITE_FAILED
    try:
        f = open(tmpname, 'wb')
        for name, ip in sorted(hostnames.items()):
            f.write(('%s,%s\n' % (name, ip)).encode("ASCII"))
        f.close()
        os.chmod(tmpname, 384)  # 600 in octal, 'rw-------'
        os.rename(tmpname, CACHEFILE)
        CACHE_WRITE_FAILED = False
    except (OSError, IOError):
        # Write message if we haven't yet or if we get a failure after
        # a previous success.
        if not CACHE_WRITE_FAILED:
            log("Failed to write host cache to temporary file "
                "%s and rename it to %s" % (tmpname, CACHEFILE))
            CACHE_WRITE_FAILED = True

        try:
            os.unlink(tmpname)
        except Exception:
            pass


def read_host_cache():
    """If possible, read the cache file from disk to populate hosts that
       were found in a previous sshuttle run."""
    try:
        f = open(CACHEFILE)
    except (OSError, IOError):
        _, e = sys.exc_info()[:2]
        if e.errno == errno.ENOENT:
            return
        else:
            log("Failed to read existing host cache file %s on remote host"
                % CACHEFILE)
            return
    for line in f:
        words = line.strip().split(',')
        if len(words) == 2:
            (name, ip) = words
            name = re.sub(r'[^-\w\.]', '-', name).strip()
            # Remove characters that shouldn't be in IP
            ip = re.sub(r'[^0-9.]', '', ip).strip()
            if name and ip:
                found_host(name, ip)
    f.close()
    global SHOULD_WRITE_CACHE
    if SHOULD_WRITE_CACHE:
        write_host_cache()
        SHOULD_WRITE_CACHE = False


def found_host(name, ip):
    """The provided name maps to the given IP. Add the host to the
       hostnames list, send the host to the sshuttle client via
       stdout, and write the host to the cache file.
    """
    hostname = re.sub(r'\..*', '', name)
    hostname = re.sub(r'[^-\w\.]', '_', hostname)
    if (ip.startswith('127.') or ip.startswith('255.') or
            hostname == 'localhost'):
        return

    if hostname != name:
        found_host(hostname, ip)

    global SHOULD_WRITE_CACHE
    oldip = hostnames.get(name)
    if oldip != ip:
        hostnames[name] = ip
        debug1('Found: %s: %s' % (name, ip))
        sys.stdout.write('%s,%s\n' % (name, ip))
        SHOULD_WRITE_CACHE = True


def _check_etc_hosts():
    """If possible, read /etc/hosts to find hosts."""
    filename = '/etc/hosts'
    debug2(' > Reading %s on remote host' % filename)
    try:
        for line in open(filename):
            line = re.sub(r'#.*', '', line)  # remove comments
            words = line.strip().split()
            if not words:
                continue
            ip = words[0]
            if _is_ip(ip):
                names = words[1:]
                debug3('<    %s %r' % (ip, names))
                for n in names:
                    check_host(n)
                    found_host(n, ip)
    except (OSError, IOError):
        debug1("Failed to read %s on remote host" % filename)


def _check_revdns(ip):
    """Use reverse DNS to try to get hostnames from an IP addresses."""
    debug2(' > rev: %s' % ip)
    try:
        r = socket.gethostbyaddr(ip)
        debug3('<    %s' % r[0])
        check_host(r[0])
        found_host(r[0], ip)
    except (OSError, socket.error, UnicodeError):
        # This case is expected to occur regularly.
        # debug3('<    %s gethostbyaddr failed on remote host' % ip)
        pass


def _check_dns(hostname):
    debug2(' > dns: %s' % hostname)
    try:
        ip = socket.gethostbyname(hostname)
        debug3('<    %s' % ip)
        check_host(ip)
        found_host(hostname, ip)
    except (socket.gaierror, UnicodeError):
        pass


def _check_netstat():
    debug2(' > netstat')
    argv = ['netstat', '-n']
    try:
        p = ssubprocess.Popen(argv, stdout=ssubprocess.PIPE, stderr=null,
                              env=get_env())
        content = p.stdout.read().decode("ASCII")
        p.wait()
    except OSError:
        _, e = sys.exc_info()[:2]
        log('%r failed: %r' % (argv, e))
        return

    # The same IPs may appear multiple times. Consolidate them so the
    # debug message doesn't print the same IP repeatedly.
    ip_list = []
    for ip in re.findall(r'\d+\.\d+\.\d+\.\d+', content):
        if ip not in ip_list:
            ip_list.append(ip)

    for ip in sorted(ip_list):
        debug3('<    %s' % ip)
        check_host(ip)


def check_host(hostname):
    if _is_ip(hostname):
        _enqueue(_check_revdns, hostname)
    else:
        _enqueue(_check_dns, hostname)


def _enqueue(op, *args):
    t = (op, args)
    if queue.get(t) is None:
        queue[t] = 0


def _stdin_still_ok(timeout):
    r, _, _ = select.select([sys.stdin.fileno()], [], [], timeout)
    if r:
        b = os.read(sys.stdin.fileno(), 4096)
        if not b:
            return False
    return True


def hw_main(seed_hosts, auto_hosts):
    helpers.logprefix = 'HH: '

    debug1('Starting hostwatch with Python version %s'
           % platform.python_version())

    for h in seed_hosts:
        check_host(h)

    if auto_hosts:
        read_host_cache()
        _enqueue(_check_etc_hosts)
        _enqueue(_check_netstat)
        check_host('localhost')
        check_host(socket.gethostname())

    while 1:
        now = time.time()
        # For each item in the queue
        for t, last_polled in list(queue.items()):
            (op, args) = t
            if not _stdin_still_ok(0):
                break

            # Determine if we need to run.
            maxtime = POLL_TIME
            # netstat runs more often than other jobs
            if op == _check_netstat:
                maxtime = NETSTAT_POLL_TIME

            # Check if this jobs needs to run.
            if now - last_polled > maxtime:
                queue[t] = time.time()
                op(*args)
            try:
                sys.stdout.flush()
            except IOError:
                break

        # FIXME: use a smarter timeout based on oldest last_polled
        if not _stdin_still_ok(1):  # sleeps for up to 1 second
            break
