Microsoft Windows
=================
Experimental native support
---------------------------

Experimental built-in support for Windows is available through the ``windivert`` method.
You have to install the `pydivert package <https://pypi.org/project/pydivert/>`_. You need Administrator privileges to use the ``windivert`` method. Consider using the `windows_check.ps1 <https://raw.githubusercontent.com/sshuttle/sshuttle/refs/heads/master/windows_check.ps1>`_ PowerShell script from this repository. It can automatically handle installing the requirements and sshuttle in a virtual Python environment. It also makes sure SSH is available and can optionally run an SSH agent with a private key for you (use the ``-Key`` option on the script). To see the commands it executes, run it with ``-Verbose``.

PuTTY/Pageant Support
~~~~~~~~~~~~~~~~~~~~~

If you use PuTTY/Pageant on Windows, you need to either:

* Export your PuTTY SSH key (``*.ppk``) file using PuTTYgen. Open the key, select ``Conversions`` from the top menu, then select ``Export OpenSSH key``. Then use ``-Key`` and point the script to that key.

* Start Pageant with SSH agent mode enabled; see https://the.earth.li/~sgtatham/putty/0.58/htmldoc/Chapter9.html. Make sure you use Microsoft's OpenSSH for Windows, as not all Windows SSH clients will work with Pageant's implementation otherwise.

Limitations
~~~~~~~~~~~

* sshuttle should be executed from an administrator shell (automatic firewall-process elevation is not available).
* Only TCP/IPv4 is supported; IPv6, UDP, and DNS are not available.

Alternative Linux VM approach
-----------------------------

Instead of using the above experimental WinDivert method, you can run sshuttle inside a Linux virtual machine on Windows.

Use Linux VM on Windows::

What we can really do is to create a Linux VM with Vagrant (or simply
VirtualBox if you like). In the Vagrant settings, remember to turn on bridged
NIC. Then, run sshuttle inside the VM like below::

    sshuttle -l 0.0.0.0 -x 10.0.0.0/8 -x 192.168.0.0/16 0/0

10.0.0.0/8 excludes NAT traffic of Vagrant and 192.168.0.0/16 excludes
traffic to local area network (assuming that we're using 192.168.0.0 subnet).

Assuming the VM has the IP 192.168.1.200 obtained on the bridge NIC (we can
configure that in Vagrant), we can then ask Windows to route all its traffic
via the VM by running the following in cmd.exe with admin right::

    route add 0.0.0.0 mask 0.0.0.0 192.168.1.200