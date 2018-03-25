# -*- coding: utf-8 -*-
#
# Copyright 2017 Gehirn Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import os

from setuptools import (
    setup,
    find_packages,
)

here = os.path.dirname(__file__)
requires = [
    'cryptography >= 1.7.2, < 2.*',
]

try:
    import typing
except ImportError:
    requires.append('typing == 3.5.3.0')
else:
    del typing


with open(os.path.join(here, './README.rst'), 'r') as fh:
    long_description = fh.read()


setup(
    name='jwt',
    version='0.5.2',

    description='JSON Web Token library for Python 3.',
    long_description=long_description,
    url='https://github.com/GehirnInc/python-jwt',

    author='Kohei YOSHIDA',
    author_email='kohei.yoshida@gehirn.co.jp',

    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],

    packages=find_packages(exclude=('jwt.tests', )),

    install_requires=requires,
    python_requires='>=3.4',
)
