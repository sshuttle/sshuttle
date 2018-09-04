import os
import sys

path_to_sshuttle = sys.argv[0]
path_to_dist_packages = os.path.dirname(os.path.abspath(__file__))[:-9]

template = '''
Cmnd_Alias SSHUTTLE = /usr/bin/env PYTHONPATH={path_to_dist_packages} /usr/bin/python3 {path_to_sshuttle} --method auto --firewall

{user_name} ALL=NOPASSWD: SSHUTTLE
'''

def sudoers_file(user_name):
	user_name = user_name or os.getusername()
	content = template.format(
		path_to_dist_packages = path_to_dist_packages,
		path_to_sshuttle = path_to_sshuttle,
		user_name = user_name,
	)

	content