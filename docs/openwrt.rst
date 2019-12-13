OpenWRT
========

Run::

    opkg install python3 python3-pip iptables-mod-nat-extra iptables-mod-ipopt
    python3 /usr/bin/pip3 install sshuttle
    sshuttle -l 0.0.0.0 -r <IP> -x 192.168.1.1 0/0
