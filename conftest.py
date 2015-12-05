import sys

if sys.version_info >= (3, 0):
    good_python = sys.version_info >= (3, 5)
else:
    good_python = sys.version_info >= (2, 7)

collect_ignore = []
if not good_python:
    collect_ignore.append("sshuttle/tests/client")
