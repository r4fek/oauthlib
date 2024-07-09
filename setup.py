#!/usr/bin/env python3
# Hack because logging + setuptools sucks.
import contextlib
with contextlib.suppress(ImportError):
    import multiprocessing


from os.path import dirname, join

from setuptools import find_packages, setup

import oauthlib


def fread(fn):
    with open(join(dirname(__file__), fn), 'r') as f:
        return f.read()


rsa_require = ['cryptography>=3.0.0']
signedtoken_require = ['cryptography>=3.0.0', 'pyjwt>=2.0.0,<3']
signals_require = ['blinker>=1.4.0']

setup(
    name='aoauthlib',
    version=oauthlib.__version__,
    description='A generic, spec-compliant, thorough implementation of the OAuth request-signing logic',
    long_description=fread('README.rst'),
    long_description_content_type='text/x-rst',
    author='The OAuthlib Community',
    author_email='idan@gazit.me',
    maintainer='Ib Lundgren',
    maintainer_email='ib.lundgren@gmail.com',
    url='https://github.com/oauthlib/oauthlib',
    platforms='any',
    license='BSD-3-Clause',
    packages=find_packages(exclude=('docs', 'tests', 'tests.*')),
    python_requires='>=3.8',
    extras_require={
        'rsa': rsa_require,
        'signedtoken': signedtoken_require,
        'signals': signals_require,
    },
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: Implementation',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
