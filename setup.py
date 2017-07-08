#!/usr/bin/env python

# Copyright 2012-2014 Brian May
#
# This file is part of python-tldap.
#
# python-tldap is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-tldap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-tldap  If not, see <http://www.gnu.org/licenses/>.

from setuptools import setup, find_packages


def version_scheme(version):
    from setuptools_scm.version import guess_next_dev_version
    version = guess_next_dev_version(version)
    return version.lstrip("v")


setup(
    name="sshuttle",
    use_scm_version={
        'write_to': "sshuttle/version.py",
        'version_scheme': version_scheme,
    },
    setup_requires=['setuptools_scm'],
    # version=version,
    url='https://github.com/sshuttle/sshuttle',
    author='Brian May',
    author_email='brian@linuxpenguins.xyz',
    description='Full-featured" VPN over an SSH tunnel',
    packages=find_packages(),
    license="GPL2+",
    long_description=open('README.rst').read(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: "
            "GNU General Public License v2 or later (GPLv2+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.5",
        "Topic :: System :: Networking",
    ],
    entry_points={
        'console_scripts': [
            'sshuttle = sshuttle.cmdline:main',
        ],
    },
    tests_require=['pytest', 'pytest-runner', 'mock'],
    keywords="ssh vpn",
)
