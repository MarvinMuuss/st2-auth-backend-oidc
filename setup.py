# Copyright (C) 2020 Extreme Networks, Inc - All Rights Reserved
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

from setuptools import setup, find_packages
from dist_utils import check_pip_version
from dist_utils import fetch_requirements
from dist_utils import parse_version_string
# Monkey patch to avoid version normalization like '2.9dev' -> '2.9.dev0', (https://github.com/pypa/setuptools/issues/308)
# NOTE: This doesn't work under Bionic
# from setuptools.extern.packaging import version
# version.Version = version.LegacyVersion

check_pip_version()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, 'requirements.txt')
INIT_FILE = os.path.join(BASE_DIR, 'st2auth_oidc_backend', '__init__.py')

version = parse_version_string(INIT_FILE)
install_reqs, dep_links = fetch_requirements(REQUIREMENTS_FILE)

setup(
    name='st2-auth-backend-oidc',
    version=version,
    description='Custom RIAG Digital authentication backend for OIDC.',
    author='Marvin Muuss',
    author_email='marvin.muuss@riag-digital.com',
    url='https://riag.digital',
    license='Apache License (2.0)',
    download_url='https://stackstorm.com/',
    classifiers=[
        'License :: Other/Proprietary License'
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Environment :: Console',
    ],
    platforms=['Any'],
    scripts=[],
    provides=['st2auth_oidc_backend'],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_reqs,
    dependency_links=dep_links,
    test_suite='tests',
    entry_points={
        'st2auth.backends.backend': [
            'oidc = st2auth_oidc_backend.oidc_backend:OIDCAuthenticationBackend',
        ],
    },
    zip_safe=False
)
