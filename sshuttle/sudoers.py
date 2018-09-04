import os
import sys
import subprocess
import getpass
import random
from sshuttle.helpers import log, debug1

path_to_sshuttle = sys.argv[0]
path_to_dist_packages = os.path.dirname(os.path.abspath(__file__))[:-9]
sudoers_path = '/etc/sudoers.d/sshuttle_auto'
command_alias = 'SSHUTTLE%(num)d' % {'num': random.randrange(1,1000)}

template = '''
Cmnd_Alias %(command_alias)s = /usr/bin/env PYTHONPATH=%(path_to_dist_packages)s /usr/bin/python3 %(path_to_sshuttle)s --method auto --firewall

%(user_name)s ALL=NOPASSWD: %(command_alias)s
'''

def sudoers_file(user_name):
    user_name = user_name or getpass.getuser()
    content = template % {
        'path_to_dist_packages': path_to_dist_packages,
        'path_to_sshuttle': path_to_sshuttle,
        'user_name': user_name,
        'command_alias': command_alias,
    }
            
    print(content)
    # User GUI sudo askpass app if available
    askpass = ''
    if os.environ.get('SUDO_ASKPASS') and os.environ.get('DISPLAY'):
        askpass = '-A'

    process = subprocess.Popen([
        'sudo',
        askpass,
        'bash',
        '-c',
        '''
            'touch %(sudoers_path)s;
            echo "%(content)s"> %(sudoers_path)s &&
            chmod 0400 %(sudoers_path)s'
        ''' % {'content': content, 'sudoers_path': sudoers_path}
    ], stdout=subprocess.PIPE)

    streamdata = process.communicate()[0]
    returncode = process.returncode

    if returncode:
        log('Failed updating sudoers file.\n');
        debug1(streamdata)
        exit(returncode)
    else:
        log('Success, sudoers file update.\n')
        exit(0)
