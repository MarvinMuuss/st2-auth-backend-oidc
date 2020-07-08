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
from unittest import mock

import unittest2

from st2auth_oidc_backend import oidc_backend

OIDC_URL = 'http://127.0.0.1'
OIDC_REALM = 'Test'
OIDC_CLIENT_NAME = 'test-client'
OIDC_CLIENT_ID = '1q2w3-e4r5t6z'
OIDC_CLIENT_SECRET = 'secret'
OIDC_SERVICE_ACCOUNT_NAME = 'sa_client'
OIDC_SERVICE_ACCOUNT_PASS = 'supersecret'


class OIDCBackendConfigurationTest(unittest2.TestCase):

    def test_null_url(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            None,
            OIDC_REALM,
            OIDC_CLIENT_NAME,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_SERVICE_ACCOUNT_NAME,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_realm(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            None,
            OIDC_CLIENT_NAME,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_SERVICE_ACCOUNT_NAME,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_client_name(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            OIDC_REALM,
            None,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_SERVICE_ACCOUNT_NAME,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_client_id(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            OIDC_REALM,
            OIDC_CLIENT_NAME,
            None,
            OIDC_CLIENT_SECRET,
            OIDC_SERVICE_ACCOUNT_NAME,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_client_secret(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            OIDC_REALM,
            OIDC_CLIENT_NAME,
            OIDC_CLIENT_ID,
            None,
            OIDC_SERVICE_ACCOUNT_NAME,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_sa_name(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            OIDC_REALM,
            OIDC_CLIENT_NAME,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            None,
            OIDC_SERVICE_ACCOUNT_PASS
        )

    def test_null_sa_pass(self):
        self.assertRaises(
            ValueError,
            oidc_backend.OIDCAuthenticationBackend,
            OIDC_URL,
            OIDC_REALM,
            OIDC_CLIENT_NAME,
            OIDC_CLIENT_ID,
            OIDC_CLIENT_SECRET,
            OIDC_SERVICE_ACCOUNT_NAME,
            None
        )
