#!/usr/bin/env python
import sys, os, re, subprocess

prompt = ' '.join(sys.argv[1:2]).replace('"', "'")

if 'yes/no' in prompt:
    print "yes"
    sys.exit(0)

script="""
	tell application "Finder"
		activate
		display dialog "%s" \
			with title "Sshuttle SSH Connection" \
			default answer "" \
			with icon caution \
			with hidden answer
	end tell
""" % prompt

p = subprocess.Popen(['osascript', '-e', script], stdout=subprocess.PIPE)
out = p.stdout.read()
rv = p.wait()
if rv:
    # if they press the cancel button, it returns nonzero
    sys.exit(1)
g = re.match("text returned:(.*), button returned:.*", out)
if not g:
    sys.exit(2)
print g.group(1)

