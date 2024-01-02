"""Coverage.py's main entry point."""
import sys
import os
from sshuttle.cmdline import main
from sshuttle.helpers import debug3

debug3("Start: (pid=%s, ppid=%s) %r" % (os.getpid(), os.getppid(), sys.argv))
exit_code = main()
debug3("Exit: (pid=%s, ppid=%s, code=%s) cmd %r" % (os.getpid(), os.getppid(), exit_code, sys.argv))
sys.exit(exit_code)
