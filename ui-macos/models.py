from AppKit import *
import my


configchange_callback = setconnect_callback = None


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
    @objc.accessor
    def validateSubnet_error_(self, value, error):
        print 'validateSubnet!'
        return True, _validate_ip(value), error

    def width(self):
        return getattr(self, '_k_width', 24)
    def setWidth_(self, v):
        self._k_width = v
        config_changed()
    @objc.accessor
    def validateWidth_error_(self, value, error):
        print 'validateWidth!'
        return True, _validate_width(value), error


class SshuttleServer(NSObject):
    def init(self):
        self = super(SshuttleServer, self).init()
        config_changed()
        return self
    
    def connected(self):
        return getattr(self, '_k_connected', False)
    def setConnected_(self, v):
        self._k_connected = v
        config_changed()
        if setconnect_callback: setconnect_callback(self)
    
    def host(self):
        return getattr(self, '_k_host', None)
    def setHost_(self, v):
        self._k_host = v
        config_changed()
    @objc.accessor
    def validateHost_error_(self, value, error):
        print 'validatehost! %r %r %r' % (self, value, error)
        while value.startswith('-'):
            value = value[1:]
        return True, value, error

    def nets(self):
        return getattr(self, '_k_nets', [])
    def setNets_(self, v):
        self._k_nets = v
        config_changed()
    def netsHidden(self):
        print 'checking netsHidden'
        return self.autoNets() != 2
    def setNetsHidden_(self, v):
        config_changed()
        print 'setting netsHidden to %r' % v
        pass
        
    def autoNets(self):
        return getattr(self, '_k_autoNets', 1)
    def setAutoNets_(self, v):
        self._k_autoNets = v
        self.setNetsHidden_(-1)
        config_changed()

    def autoHosts(self):
        return getattr(self, '_k_autoHosts', True)
    def setAutoHosts_(self, v):
        self._k_autoHosts = v
        config_changed()

