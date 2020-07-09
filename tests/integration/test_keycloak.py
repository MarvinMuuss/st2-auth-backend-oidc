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
import unittest2

from st2auth_oidc_backend import oidc_backend


class KeycloakAuthenticationTest(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        super(KeycloakAuthenticationTest, cls).setUpClass()
        cls.base_url = os.environ.get('ST2_OIDC_URL', 'https://127.0.0.1:8443')
        cls.realm = os.environ.get('ST2_OIDC_REALM', 'Test')
        cls.client_name = os.environ.get('ST2_OIDC_CLIENT_NAME', 'spring-boot')
        cls.client_id = os.environ.get('ST2_OIDC_CLIENT_ID', 'ad26a226')
        cls.client_secret = os.environ.get('ST2_OIDC_CLIENT_SECRET', '45892b6')

    def test_authenticate(self):
        username = 'spring-user'
        passwd = 'xx'

        backend = oidc_backend.OIDCAuthenticationBackend(self.base_url, self.realm, self.client_name, self.client_id,
                                                         self.client_secret)
        authenticated = backend.authenticate(username, passwd)
        self.assertTrue(authenticated)

    def test_user(self):
        username = 'spring-user'

        backend = oidc_backend.OIDCAuthenticationBackend(self.base_url, self.realm, self.client_name, self.client_id,
                                                         self.client_secret)

        user = backend.get_user(username)
        self.assertIsNotNone(user)
        self.assertIn('id', user)
        self.assertIn('username', user)
        self.assertIn('firstName', user)
        self.assertIn('lastName', user)

    def test_groups_client_roles(self):
        username = 'spring-user'
        roles = ['client-spring-role', 'spring-group-role']

        backend = oidc_backend.OIDCAuthenticationBackend(self.base_url, self.realm, self.client_name, self.client_id,
                                                         self.client_secret)

        groups = backend.get_user_groups(username)
        self.assertIsNotNone(groups)
        for role in roles:
            self.assertIn(role, groups)

    def test_groups_realm_roles(self):
        username = 'grobp'
        roles = ['KeyCloak']

        backend = oidc_backend.OIDCAuthenticationBackend(self.base_url, self.realm, self.client_name, self.client_id,
                                                         self.client_secret, use_client_roles=False)

        groups = backend.get_user_groups(username)
        self.assertIsNotNone(groups)
        for role in roles:
            self.assertIn(role, groups)
