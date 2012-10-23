from AppKit import *
import my


configchange_callback = setconnect_callback = None
objc_validator = objc.signature('@@:N^@o^@')


def config_changed():
    if configchange_callback:
        configchange_callback()


def _validate_ip(v):
    parts = v.split('.')[:4]
    if len(parts) < 4:
        parts += ['0'] * (4 - len(parts))
    for i in range(4):
        n = my.atoi(parts[i])
        if n < 0:
            n = 0
        elif n > 255:
            n = 255
        parts[i] = str(n)
    return '.'.join(parts)


def _validate_width(v):
    n = my.atoi(v)
    if n < 0:
        n = 0
    elif n > 32:
        n = 32
    return n


class SshuttleNet(NSObject):
    def subnet(self):
        return getattr(self, '_k_subnet', None)
    def setSubnet_(self, v):
        self._k_subnet = v
        config_changed()
    @objc_validator
    def validateSubnet_error_(self, value, error):
        #print 'validateSubnet!'
        return True, _validate_ip(value), error

    def width(self):
        return getattr(self, '_k_width', 24)
    def setWidth_(self, v):
        self._k_width = v
        config_changed()
    @objc_validator
    def validateWidth_error_(self, value, error):
        #print 'validateWidth!'
        return True, _validate_width(value), error

NET_ALL = 0
NET_AUTO = 1
NET_MANUAL = 2

LAT_BANDWIDTH = 0
LAT_INTERACTIVE = 1

class SshuttleServer(NSObject):
    def init(self):
        self = super(SshuttleServer, self).init()
        config_changed()
        return self
    
    def wantConnect(self):
        return getattr(self, '_k_wantconnect', False)
    def setWantConnect_(self, v):
        self._k_wantconnect = v
        self.setError_(None)
        config_changed()
        if setconnect_callback: setconnect_callback(self)

    def connected(self):
        return getattr(self, '_k_connected', False)
    def setConnected_(self, v):
        print 'setConnected of %r to %r' % (self, v)
        self._k_connected = v
        if v: self.setError_(None)  # connected ok, so no error
        config_changed()

    def error(self):
        return getattr(self, '_k_error', None)
    def setError_(self, v):
        self._k_error = v
        config_changed()

    def isValid(self):
        if not self.host():
            return False
        if self.autoNets() == NET_MANUAL and not len(list(self.nets())):
            return False
        return True

    def title(self):
        host = self.host()
        if not host:
            return host
        an = self.autoNets()
        suffix = ""
        if an == NET_ALL:
            suffix = " (all traffic)"
        elif an == NET_MANUAL:
            n = self.nets()
            suffix = ' (%d subnet%s)' % (len(n), len(n)!=1 and 's' or '')
        return self.host() + suffix
    def setTitle_(self, v):
        # title is always auto-generated
        config_changed()
    
    def host(self):
        return getattr(self, '_k_host', None)
    def setHost_(self, v):
        self._k_host = v
        self.setTitle_(None)
        config_changed()
    @objc_validator
    def validateHost_error_(self, value, error):
        #print 'validatehost! %r %r %r' % (self, value, error)
        while value.startswith('-'):
            value = value[1:]
        return True, value, error

    def nets(self):
        return getattr(self, '_k_nets', [])
    def setNets_(self, v):
        self._k_nets = v
        self.setTitle_(None)
        config_changed()
    def netsHidden(self):
        #print 'checking netsHidden'
        return self.autoNets() != NET_MANUAL
    def setNetsHidden_(self, v):
        config_changed()
        #print 'setting netsHidden to %r' % v
        
    def autoNets(self):
        return getattr(self, '_k_autoNets', NET_AUTO)
    def setAutoNets_(self, v):
        self._k_autoNets = v
        self.setNetsHidden_(-1)
        self.setUseDns_(v == NET_ALL)
        self.setTitle_(None)
        config_changed()

    def autoHosts(self):
        return getattr(self, '_k_autoHosts', True)
    def setAutoHosts_(self, v):
        self._k_autoHosts = v
        config_changed()

    def useDns(self):
        return getattr(self, '_k_useDns', False)
    def setUseDns_(self, v):
        self._k_useDns = v
        config_changed()

    def latencyControl(self):
        return getattr(self, '_k_latencyControl', LAT_INTERACTIVE)
    def setLatencyControl_(self, v):
        self._k_latencyControl = v
        config_changed()
