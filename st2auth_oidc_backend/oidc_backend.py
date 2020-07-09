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

import json
import logging

import jwt
import requests
from jwt.algorithms import RSAAlgorithm
from requests.auth import HTTPBasicAuth
from st2auth.backends.constants import AuthBackendCapability

__all__ = [
    'OIDCAuthenticationBackend'
]

LOG = logging.getLogger(__name__)

EXPECTED_PERMISSIONS = ['view-users', 'query-users', 'query-users']


class OIDCAuthenticationBackend(object):
    CAPABILITIES = (
        AuthBackendCapability.CAN_AUTHENTICATE_USER,
        AuthBackendCapability.HAS_USER_INFORMATION,
        AuthBackendCapability.HAS_GROUP_INFORMATION
    )

    def __init__(self, base_url, realm, client_name, client_id, client_secret, use_client_roles=True, http_proxy=None, https_proxy=None,
                 ftp_proxy=None):

        if not base_url:
            raise ValueError('Base URL to connect to the OIDC server is not provided.')
        elif base_url.endswith('/'):
            base_url = base_url[:-1]

        if not realm:
            raise ValueError('Realm name is not provided.')

        if not client_name:
            raise ValueError('Client name is not provided.')

        if not client_id:
            raise ValueError('Client Id is not provided.')

        if not client_secret:
            raise ValueError('Client secret is not provided.')

        self._base_url = base_url
        self._realm = realm
        self._client_name = client_name
        self._client_id = client_id
        self._client_secret = client_secret
        self._use_client_roles = use_client_roles
        self._proxy_dict = {
            "http": http_proxy,
            "https": https_proxy,
            "ftp": ftp_proxy
        }

        res, access_token = self._get_access_token_for_sa(client_name, client_secret)
        if not res:
            LOG.exception("Failed to fetch access token for service account.")
        else:
            resp = requests.get(self._base_url + '/auth/realms/' + self._realm + '/protocol/openid-connect/certs',
                                proxies=self._proxy_dict)
            public_key = RSAAlgorithm.from_jwk(json.dumps(resp.json().get('keys')[0]))
            decoded = jwt.decode(access_token, public_key, algorithms=['RS256'], audience='account')
            realm_roles = decoded.get('resource_access', {}).get('realm-management', {}).get('roles', [])
            for expected_perm in EXPECTED_PERMISSIONS:
                assert expected_perm in realm_roles, expected_perm + ' is not in mapped roles of service account.'

    def authenticate(self, username, password):

        if not password:
            raise ValueError('password cannot be empty')

        result, resp = self._get_access_token(username, password)
        if result:
            LOG.info('Successfully authenticated user "%s".' % username)
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
            result, access_token = self._get_access_token_for_sa(self._client_name, self._client_secret)
            if not result:
                LOG.exception("Failed to fetch access token for service account.")
            user = self._fetch_user(username, access_token)
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
            result, access_token = self._get_access_token_for_sa(self._client_name, self._client_secret)
            if not result:
                LOG.exception("Failed to fetch access token for service account.")
            user = self._fetch_user(username, access_token)
            role_url = '/auth/admin/realms/' + self._realm + '/users/' + user.get('id') + '/role-mappings'
            if self._use_client_roles:
                role_url = role_url + '/clients/' + self._client_id + '/composite'
            else:
                role_url = role_url + '/realm'
            resp = requests.get(
                self._base_url + role_url, headers={'Authorization': 'Bearer ' + access_token},
                proxies=self._proxy_dict)
            if resp.status_code != 200:
                LOG.exception("Failed to fetch user roles for " + username)
            groups = list(map(lambda role: role.get('name'), resp.json()))
        except Exception:
            LOG.exception('Failed to retrieve groups for user "%s"' % (username))
            return None

        return groups

    def _get_access_token_for_sa(self, sa_name, sa_pass):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {"grant_type": "client_credentials"}

        resp = requests.post(self._base_url + '/auth/realms/' + self._realm + '/protocol/openid-connect/token',
                             data=data,
                             headers=headers,
                             proxies=self._proxy_dict, auth=HTTPBasicAuth(sa_name, sa_pass))
        if resp.status_code == 200:
            return True, resp.json().get('access_token')
        else:
            LOG.exception("Failed to authenticate user " + sa_name)
            return False, resp

    def _get_access_token(self, username, password):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {"grant_type": "password",
                "client_id": self._client_name,
                "client_secret": self._client_secret,
                "username": username,
                "password": password}

        resp = requests.post(self._base_url + '/auth/realms/' + self._realm + '/protocol/openid-connect/token',
                             data=data,
                             headers=headers,
                             proxies=self._proxy_dict)
        if resp.status_code == 200:
            return True, resp.json().get('access_token')
        else:
            LOG.exception("Failed to authenticate user " + username)
            return False, resp

    def _fetch_user(self, username, access_token):
        resp = requests.get(self._base_url + '/auth/admin/realms/' + self._realm + '/users?username=' + username,
                            headers={'Authorization': 'Bearer ' + access_token}, proxies=self._proxy_dict)
        if resp.status_code != 200:
            LOG.exception("Failed to fetch users.")
        users = resp.json()
        if len(users) > 1:
            LOG.exception("Fetched more than one user!")
        elif len(users) == 0:
            LOG.exception("User with username " + username + " not found.")
        return users[0]
