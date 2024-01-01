"""Coverage.py's main entry point."""
import sys
import os
from sshuttle.cmdline import main
from sshuttle.helpers import debug3
from sshuttle import __version__

debug3("Starting cmd %r (pid:%s) | sshuttle: %s | Python: %s" % (sys.argv, os.getpid(), __version__, sys.version))
exit_code = main()
debug3("Exiting cmd %r (pid:%s) with code %s" % (sys.argv, os.getpid(), exit_code,))
sys.exit(exit_code)
