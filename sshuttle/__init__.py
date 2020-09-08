"""
sshuttle: where transparent proxy meets VPN meets ssh
"""
try:
    from sshuttle.version import version as __version__
except ImportError:
    __version__ = "unknown"
