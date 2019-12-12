import os
import sys
import getpass
from uuid import uuid4
from subprocess import Popen, PIPE
from sshuttle.helpers import log, debug1
from distutils import spawn

path_to_sshuttle = sys.argv[0]
path_to_dist_packages = os.path.dirname(os.path.abspath(__file__))[:-9]

# randomize command alias to avoid collisions
command_alias = 'SSHUTTLE%(num)s' % {'num': uuid4().hex[-3:].upper()}

# Template for the sudoers file
template = '''
Cmnd_Alias %(ca)s = /usr/bin/env PYTHONPATH=%(dist_packages)s %(py)s %(path)s *

%(user_name)s ALL=NOPASSWD: %(ca)s
'''


def build_config(user_name):
    content = template % {
        'ca': command_alias,
        'dist_packages': path_to_dist_packages,
        'py': sys.executable,
        'path': path_to_sshuttle,
        'user_name': user_name,
    }

    return content


def save_config(content, file_name):
    process = Popen([
        '/usr/bin/sudo',
        spawn.find_executable('sudoers-add'),
        file_name,
    ], stdout=PIPE, stdin=PIPE)

    process.stdin.write(content.encode())

    streamdata = process.communicate()[0]
    returncode = process.returncode

    if returncode:
        log('Failed updating sudoers file.\n')
        debug1(streamdata)
        exit(returncode)
    else:
        log('Success, sudoers file update.\n')
        exit(0)


def sudoers(user_name=None, no_modify=None, file_name=None):
    user_name = user_name or getpass.getuser()
    content = build_config(user_name)

    if no_modify:
        sys.stdout.write(content)
        exit(0)
    else:
        save_config(content, file_name)
