import sys

good_python = sys.version_info >= (3, 5)

collect_ignore = []
if not good_python:
    collect_ignore.append("client")
