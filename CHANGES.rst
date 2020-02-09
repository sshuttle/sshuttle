==========
Change log
==========
All notable changes to this project will be documented in this file. The format
is based on `Keep a Changelog`_ and this project
adheres to `Semantic Versioning`_.

.. _`Keep a Changelog`: http://keepachangelog.com/
.. _`Semantic Versioning`: http://semver.org/


0.78.5 - 2019-01-28
-------------------

Added
~~~~~
* doas support as replacmeent for sudo on OpenBSD.
* Added ChromeOS section to documentation (#262)
* Add --no-sudo-pythonpath option

Fixed
~~~~~
* Fix forwarding to a single port.
* Various updates to documentation.
* Don't crash if we can't look up peername
* Fix missing string formatting argument
* Moved sshuttle/tests into tests.
* Updated bandit config.
* Replace path /dev/null by os.devnull.
* Added coverage report to tests.
* Fixes support for OpenBSD (6.1+) (#282).
* Close stdin, stdout, and stderr when using syslog or forking to daemon (#283).
* Changes pf exclusion rules precedence.
* Fix deadlock with iptables with large ruleset.
* docs: document --ns-hosts --to-ns and update --dns.
* Use subprocess.check_output instead of run.
* Fix potential deadlock condition in nft_get_handle.
* auto-nets: retrieve routes only if using auto-nets.


0.78.4 - 2018-04-02
-------------------

Added
~~~~~
* Add homebrew instructions.
* Route traffic by linux user.
* Add nat-like method using nftables instead of iptables.

Changed
~~~~~~~
* Talk to custom DNS server on pod, instead of the ones in /etc/resolv.conf.
* Add new option for overriding destination DNS server.
* Changed subnet parsing. Previously 10/8 become 10.0.0.0/8.  Now it gets
  parsed as 0.0.0.10/8.
* Make hostwatch find both fqdn and hostname.
* Use versions of python3 greater than 3.5 when available (e.g. 3.6).

Removed
~~~~~~~
* Remove Python 2.6 from automatic tests.

Fixed
~~~~~
* Fix case where there is no --dns.
* [pf] Avoid port forwarding from loopback address.
* Use getaddrinfo to obtain a correct sockaddr.
* Skip empty lines on incoming routes data.
* Just skip empty lines of routes data instead of stopping processing.
* [pf] Load pf kernel module when enabling pf.
* [pf] Test double restore (ipv4, ipv6) disables only once; test kldload.
* Fixes UDP and DNS proxies binding to the same socket address.
* Mock socket bind to avoid depending on local IPs being available in test box.
* Fix no value passed for argument auto_hosts in hw_main call.
* Fixed incorrect license information in setup.py.
* Preserve peer and port properly.
* Make --to-dns and --ns-host work well together.
* Remove test that fails under OSX.
* Specify pip requirements for tests.
* Use flake8 to find Python syntax errors or undefined names.
* Fix compatibility with the sudoers file.
* Stop using SO_REUSEADDR on sockets.
* Declare 'verbosity' as global variable to placate linters.
* Adds 'cd sshuttle' after 'git' to README and docs.
* Documentation for loading options from configuration file.
* Load options from a file.
* Fix firewall.py.
* Move sdnotify after setting up firewall rules.
* Fix tests on Macos.


0.78.3 - 2017-07-09
-------------------
The "I should have done a git pull" first release.

Fixed
~~~~~
* Order first by port range and only then by swidth


0.78.2 - 2017-07-09
-------------------

Added
~~~~~
* Adds support for tunneling specific port ranges (#144).
* Add support for iproute2.
* Allow remote hosts with colons in the username.
* Re-introduce ipfw support for sshuttle on FreeBSD with support for --DNS option as well.
* Add support for PfSense.
* Tests and documentation for systemd integration.
* Allow subnets to be given only by file (-s).

Fixed
~~~~~
* Work around non tabular headers in BSD netstat.
* Fix UDP and DNS support on Python 2.7 with tproxy method.
* Fixed tests after adding support for iproute2.
* Small refactoring of netstat/iproute parsing.
* Set started_by_sshuttle False after disabling pf.
* Fix punctuation and explain Type=notify.
* Move pytest-runner to tests_require.
* Fix warning: closed channel got=STOP_SENDING.
* Support sdnotify for better systemd integration.
* Fix #117 to allow for no subnets via file (-s).
* Fix argument splitting for multi-word arguments.
* requirements.rst: Fix mistakes.
* Fix typo, space not required here.
* Update installation instructions.
* Support using run from different directory.
* Ensure we update sshuttle/version.py in run.
* Don't print python version in run.
* Add CWD to PYTHONPATH in run.


0.78.1 - 2016-08-06
-------------------
* Fix readthedocs versioning.
* Don't crash on ENETUNREACH.
* Various bug fixes.
* Improvements to BSD and OSX support.


0.78.0 - 2016-04-08
-------------------

* Don't force IPv6 if IPv6 nameservers supplied. Fixes #74.
* Call /bin/sh as users shell may not be POSIX compliant. Fixes #77.
* Use argparse for command line processing. Fixes #75.
* Remove useless --server option.
* Support multiple -s (subnet) options. Fixes #86.
* Make server parts work with old versions of Python. Fixes #81.


0.77.2 - 2016-03-07
-------------------

* Accidentally switched LGPL2 license with GPL2 license in 0.77.1 - now fixed.


0.77.1 - 2016-03-07
-------------------

* Use semantic versioning. http://semver.org/
* Update GPL 2 license text.
* New release to fix PyPI.


0.77 - 2016-03-03
-----------------

* Various bug fixes.
* Fix Documentation.
* Add fix for MacOS X issue.
* Add support for OpenBSD.


0.76 - 2016-01-17
-----------------

* Add option to disable IPv6 support.
* Update documentation.
* Move documentation, including man page, to Sphinx.
* Use setuptools-scm for automatic versioning.


0.75 - 2016-01-12
-----------------

* Revert change that broke sshuttle entry point.


0.74 - 2016-01-10
-----------------

* Add CHANGES.rst file.
* Numerous bug fixes.
* Python 3.5 fixes.
* PF fixes, especially for BSD.
