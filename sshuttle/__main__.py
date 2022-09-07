"""Coverage.py's main entry point."""
import sys
import os
from sshuttle.cmdline import main
from sshuttle.helpers import debug3
exit_code=main()
debug3("Exiting process %r (pid:%s) with code %s" % (sys.argv, os.getpid(), exit_code,))
sys.exit(exit_code)
