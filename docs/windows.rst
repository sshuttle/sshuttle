Microsoft Windows
=================
Currently there is no built in support for running sshuttle directly on
Microsoft Windows.

What we can really do is to create a Linux VM with Vagrant (or simply
Virtualbox if you like). In the Vagrant settings, remember to turn on bridged
NIC. Then, run sshuttle inside the VM like below::

    sshuttle -l 0.0.0.0 -x 10.0.0.0/8 -x 192.168.0.0/16 0/0

10.0.0.0/8 excludes NAT traffic of Vagrant and 192.168.0.0/16 excludes
traffic to local area network (assuming that we're using 192.168.0.0 subnet).

Assuming the VM has the IP 192.168.1.200 obtained on the bridge NIC (we can
configure that in Vagrant), we can then ask Windows to route all its traffic
via the VM by running the following in cmd.exe with admin right::

     route add 0.0.0.0 mask 0.0.0.0 192.168.1.200
