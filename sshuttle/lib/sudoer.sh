#!/usr/bin/env bash

content=$1

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

touch /tmp/sshuttle_auto

echo $content | base64 --decode >> /tmp/sshuttle_auto

visudo_out= visudo -c -f /tmp/sshuttle_auto

if [ $? -eq 0 ]; then
	rm /etc/sudoers.d/sshuttle_auto
    mv /tmp/sshuttle_auto /etc/sudoers.d/sshuttle_auto
    chmod 0440 /etc/sudoers.d/sshuttle_auto
    exit 0
else
	echo $visudo_out
    exit 1
fi