==========
Change log
==========
All notable changes to this project will be documented in this file. The format
is based on `Keep a Changelog`_ and this project
adheres to `Semantic Versioning`_.

.. _`Keep a Changelog`: http://keepachangelog.com/
.. _`Semantic Versioning`: http://semver.org/


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
