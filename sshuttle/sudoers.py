import os
import sys
import getpass
import random
from sshuttle.lib.base64ify import base64ify
from subprocess import Popen, PIPE
from sshuttle.helpers import log, debug1


path_to_sshuttle = sys.argv[0]
path_to_dist_packages = os.path.dirname(os.path.abspath(__file__))[:-9]
command_alias = 'SSHUTTLE%(num)d' % {'num': random.randrange(1,1000)}

template = '''
Cmnd_Alias %(command_alias)s = /usr/bin/env PYTHONPATH=%(path_to_dist_packages)s %(python_path)s %(path_to_sshuttle)s --method auto --firewall

%(user_name)s ALL=NOPASSWD: %(command_alias)s
'''

def build_config(user_name):
    content = template % {
        'command_alias': command_alias,
        'path_to_dist_packages': path_to_dist_packages,
        'python_path': sys.executable,
        'path_to_sshuttle': path_to_sshuttle,
        'user_name': user_name,
    }

    return content

def save_config(content):
    process = Popen([
        'sudo env "PATH=$PATH" sudoers-add sshuttle_auto',
    ], stdout=PIPE, stdin=PIPE, shell=True)

    process.stdin.write(content.encode())

    streamdata = process.communicate()[0]
    returncode = process.returncode

    if returncode:
        log('Failed updating sudoers file.\n');
        debug1(streamdata)
        exit(returncode)
    else:
        log('Success, sudoers file update.\n')
        exit(0)

def sudoers(user_name=None, no_modify=None):
    user_name = user_name or getpass.getuser()
    content = build_config(user_name)

    if no_modify:
        sys.stdout.write(content)
        exit(0)
    else:
        save_config(content)
