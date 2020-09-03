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

# pylint: disable=no-member

from __future__ import absolute_import

import logging

import jwt
import requests
from cachetools import LRUCache
from st2auth.backends.constants import AuthBackendCapability

__all__ = [
    'OIDCAuthenticationBackend'
]

LOG = logging.getLogger(__name__)


class OIDCAuthenticationBackend(object):
    CAPABILITIES = (
        AuthBackendCapability.CAN_AUTHENTICATE_USER,
        AuthBackendCapability.HAS_USER_INFORMATION,
        AuthBackendCapability.HAS_GROUP_INFORMATION
    )

    def __init__(self, token_url, client_name, client_secret, jwt_roles_path,  http_proxy=None,
                 https_proxy=None, ftp_proxy=None, verify_ssl=True):

        if not token_url:
            raise ValueError('Token URL to connect to the OIDC server is not provided.')

        if not client_name:
            raise ValueError('Client name is not provided.')

        if not client_secret:
            raise ValueError('Client secret is not provided.')

        if not jwt_roles_path:
            raise ValueError('Path to roles in jwt is not provided.')

        self._token_url = token_url
        self._client_name = client_name
        self._client_secret = client_secret
        self._jwt_roles_path = jwt_roles_path
        self._proxy_dict = {
            "http": http_proxy,
            "https": https_proxy,
            "ftp": ftp_proxy
        }
        self._verify = verify_ssl
        if not verify_ssl:
            from urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        self._cache = LRUCache(maxsize=100)

    def authenticate(self, username, password):

        if not password:
            raise ValueError('password cannot be empty')

        result, resp = self._get_access_token(username, password)
        if result:
            LOG.info('Successfully authenticated user "%s".' % username)
            # resp = requests.get(self._base_url + '/auth/realms/' + self._realm + '/protocol/openid-connect/certs',
            #                     proxies=self._proxy_dict, verify=self._verify)
            # public_key = RSAAlgorithm.from_jwk(json.dumps(resp.json().get('keys')[0]))
            # self._cache[username] = jwt.decode(resp, public_key, algorithms=['RS256'], audience='account')
            public_key = None
            self._cache[username.lower()] = jwt.decode(resp, public_key, algorithms=['RS256'], audience='account', verify=False)
            return True
        else:
            LOG.exception(
                'Failed authenticating user ' + username + " with error: " + resp.json().get('error_description') + ".")
            return False

    def get_user(self, username):
        """
        Retrieve user information.

        :rtype: ``dict``
        """
        try:
            user = self._cache.get(username.lower())
        except Exception:
            LOG.exception('Failed to retrieve details for user ' + username)
            return None

        return user

    def get_user_groups(self, username):
        """
        Return a list of all the groups user is a member of.

        :rtype: ``list`` of ``str``
        """
        try:
            user = self._cache.get(username.lower())
            roles = user
            for level in self._jwt_roles_path.split('.'):
                roles = roles[level]
        except KeyError as ke:
            LOG.exception('Path to roles in jwt seems not correct %s' % ke)
            return None
        except Exception:
            LOG.exception('Failed to retrieve groups for user "%s"' % (username))
            return None
        return roles

    def _get_access_token(self, username, password):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {"grant_type": "password",
                "client_id": self._client_name,
                "client_secret": self._client_secret,
                "username": username,
                "password": password}

        resp = requests.post(self._token_url,
                             data=data,
                             headers=headers,
                             proxies=self._proxy_dict,
                             verify=self._verify)
        if resp.status_code == 200:
            return True, resp.json().get('access_token')
        else:
            LOG.exception("Failed to authenticate user " + username)
            return False, resp
