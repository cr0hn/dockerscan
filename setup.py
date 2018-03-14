# -*- coding: utf-8 -*-
#
# dockerscan
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the
# following disclaimer in the documentation and/or other materials provided
# with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
#  may be used to endorse or promote
# products derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import re
import os
import sys
import codecs

from os.path import dirname, join
from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand


if sys.version_info < (3, 5,):
    raise RuntimeError("dockerscan requires Python 3.5.0+")


#
# Get version software version
#
version_file = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "dockerscan")), '__init__.py')
with codecs.open(version_file, 'r', 'latin1') as fp:
    try:
        version = re.findall(r"^__version__ = ['\"]([^']+)['\"]\r?$",
                             fp.read(), re.M)[0]
    except IndexError:
        raise RuntimeError('Unable to determine version.')


with open(join(dirname(__file__), 'requirements.txt'), 'rb') as f:
    required = f.read().split(b"\n")

with open(join(dirname(__file__), 'requirements-performance.txt'), 'rb') as f:
    required_performance = f.read().split(b"\n")

with open(join(dirname(__file__), 'README.rst'), 'rb') as f:
    long_description = f.read()


class PyTest(TestCommand):
    user_options = []

    def run(self):
        import subprocess
        import sys
        errno = subprocess.call([sys.executable, '-m', 'pytest', '--cov-report', 'html', '--cov-report', 'term', '--cov', 'dockerscan/'])
        raise SystemExit(errno)


setup(
    name='dockerscan',
    version=version,
    install_requires=map(lambda s: s.decode("utf-8"), required),
    url='https://github.com/cr0hn/dockerscan',
    license='BSD',
    author='Daniel Garcia (cr0hn) / Roberto Munoz (robskye)',
    author_email='cr0hn@cr0hn.com',
    packages=find_packages(),
    include_package_data=True,
    extras_require={
        'performance': list(map(lambda s: s.decode("utf-8"), required_performance))
    },
    entry_points={'console_scripts': [
        'dockerscan = dockerscan.actions.cli:cli',
    ]},
    description='A Docker analysis tools',
    long_description=long_description.decode("utf-8"),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
    ],
    cmdclass=dict(test=PyTest)
)